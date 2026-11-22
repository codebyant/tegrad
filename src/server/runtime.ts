// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { chmodSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import type { CommandQueue } from "../agent/jobs";
import type { Logger } from "../agent/logger";
import {
  DEFAULT_SERVER_PORT,
  ProtocolError,
  type ServerConsoleSendBody,
  type ServerConsoleSubscribeBody,
  type ServerCreateBody,
  type ServerUpdateSettingsBody,
} from "../protocol";
import {
  type ConsoleEventEmitter,
  type ConsoleSubscriptionManager,
  type ConsoleTimerProvider,
  createConsoleSubscriptionManager,
  type FifoWriter,
  sendConsoleLine,
} from "./console";
import type { FetchLike } from "./download";
import { assertValidServerId, DEFAULT_RUN_DIR, DEFAULT_SERVERS_DIR, resolveServerDir } from "./id";
import { ensureJavaRuntime, getJavaBinPath, type RunFixedLike, selectJavaMajor } from "./java";
import { installServerLoader } from "./loaders";
import {
  checkMemoryForServer,
  DEFAULT_MEMINFO_PATH,
  type Meminfo,
  RESERVED_SYSTEM_MEMORY_MB,
  readMeminfo,
} from "./memory";
import {
  getEffectiveLaunchTarget,
  isEulaAccepted,
  listServerMetadata,
  readServerMetadata,
  type ServerMetadata,
  writeEulaFile,
  writeServerMetadata,
  writeServerProperties,
} from "./registry";
import { validateJvmArgs, writeStartScript } from "./start-script";
import {
  getUnitStatus,
  isUnitActive,
  isUnitStopped,
  type SystemdUnitStatus,
  startServerUnit,
  stopServerUnit,
} from "./systemd";

const SERVER_DIR_MODE = 0o750;

function isPosix(platform: NodeJS.Platform = process.platform): boolean {
  return platform !== "win32";
}

export interface ServerStatusReport {
  readonly server: ServerMetadata;
  readonly eula_accepted: boolean;
  readonly systemd: {
    readonly active_state: string;
    readonly sub_state: string;
    readonly main_pid: number;
    readonly memory_current_bytes: number | null;
  };
}

export interface ServerManagerOptions {
  readonly serversDir?: string;
  readonly runDir?: string;
  readonly meminfoPath?: string;
  readonly reservedSystemMb?: number;
  readonly readMeminfoImpl?: () => Meminfo;
  readonly runFixedImpl?: RunFixedLike;
  readonly fetchImpl?: FetchLike;
  readonly writeFifoImpl?: FifoWriter;
  readonly consoleTimers?: ConsoleTimerProvider;
  readonly consolePollIntervalMs?: number;
  readonly stopPollIntervalMs?: number;
  readonly stopTimeoutMs?: number;
  readonly sleepImpl?: (ms: number) => Promise<void>;
  readonly now?: () => number;
  readonly platform?: NodeJS.Platform;
  readonly logger?: Logger;
}

export interface ServerManager {
  createServer(params: ServerCreateBody): Promise<ServerMetadata>;
  startServer(serverId: string): Promise<void>;
  stopServer(serverId: string): Promise<SystemdUnitStatus>;
  restartServer(serverId: string): Promise<void>;
  deleteServer(serverId: string): Promise<void>;
  getServerStatus(serverId: string): Promise<ServerStatusReport>;
  listServers(): ServerMetadata[];
  updateServerSettings(params: ServerUpdateSettingsBody): ServerMetadata;
  sendConsole(serverId: string, line: string): void;
  subscribeConsole(
    serverId: string,
    fromOffset: number | undefined,
    sendEvent: ConsoleEventEmitter,
  ): void;
  unsubscribeConsole(serverId: string): void;
  readonly consoleManager: ConsoleSubscriptionManager;
  close(): void;
}

export function createServerManager(options: ServerManagerOptions = {}): ServerManager {
  const serversDir = options.serversDir ?? DEFAULT_SERVERS_DIR;
  const runDir = options.runDir ?? DEFAULT_RUN_DIR;
  const meminfoPath = options.meminfoPath ?? DEFAULT_MEMINFO_PATH;
  const now = options.now ?? (() => Date.now());
  const platform = options.platform ?? process.platform;

  const consoleManager = createConsoleSubscriptionManager({
    serversDir,
    ...(options.consolePollIntervalMs !== undefined
      ? { pollIntervalMs: options.consolePollIntervalMs }
      : {}),
    ...(options.consoleTimers !== undefined ? { timers: options.consoleTimers } : {}),
    now,
  });

  function readHostMeminfo(): Meminfo {
    if (options.readMeminfoImpl !== undefined) {
      return options.readMeminfoImpl();
    }
    return readMeminfo(meminfoPath);
  }

  async function computeRunningServersMemoryMb(excludeServerId: string): Promise<number> {
    const servers = listServerMetadata(serversDir);
    let totalMb = 0;

    for (const server of servers) {
      if (server.id === excludeServerId) {
        continue;
      }
      const status = await getUnitStatus(server.id, options.runFixedImpl);
      if (isUnitActive(status)) {
        totalMb += server.memory_mb;
      }
    }

    return totalMb;
  }

  async function createServer(params: ServerCreateBody): Promise<ServerMetadata> {
    const validId = assertValidServerId(params.server_id);
    const jvmArgs = validateJvmArgs(params.jvm_args ?? []);
    const port = params.port ?? DEFAULT_SERVER_PORT;
    const serverDir = resolveServerDir(serversDir, validId);

    if (existsSync(serverDir)) {
      throw new ProtocolError("server_already_exists", `Server already exists: ${validId}`);
    }

    mkdirSync(serverDir, { recursive: true, mode: SERVER_DIR_MODE });
    const logsDir = join(serverDir, "logs");
    mkdirSync(logsDir, { recursive: true, mode: SERVER_DIR_MODE });
    if (isPosix(platform)) {
      chmodSync(serverDir, SERVER_DIR_MODE);
      chmodSync(logsDir, SERVER_DIR_MODE);
    }

    try {
      const javaRuntime = await ensureJavaRuntime({
        serversDir,
        minecraftVersion: params.minecraft_version,
        platform,
        ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
        ...(options.runFixedImpl !== undefined ? { runFixedImpl: options.runFixedImpl } : {}),
      });

      const loaderResult = await installServerLoader({
        serverDir,
        minecraftVersion: params.minecraft_version,
        loader: params.loader,
        javaBin: javaRuntime.javaBin,
        ...(params.loader_version !== undefined ? { loaderVersion: params.loader_version } : {}),
        ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
        ...(options.runFixedImpl !== undefined ? { runFixedImpl: options.runFixedImpl } : {}),
      });

      writeEulaFile(serverDir, params.eula_accepted);
      writeServerProperties(serverDir, { port, forceOnlineMode: true });
      writeStartScript(serverDir, {
        javaBin: javaRuntime.javaBin,
        memoryMb: params.memory_mb,
        jvmArgs,
        launchTarget: loaderResult.launchTarget,
      });

      const metadata: ServerMetadata = {
        v: 1,
        id: validId,
        name: params.name.trim(),
        minecraft_version: loaderResult.minecraftVersion,
        loader: loaderResult.loader,
        loader_version: loaderResult.loaderVersion,
        memory_mb: params.memory_mb,
        jvm_args: [...jvmArgs],
        port,
        created_at: now(),
        launch_target: loaderResult.launchTarget,
      };
      writeServerMetadata(serversDir, metadata);

      options.logger?.info("Created Minecraft server", {
        serverId: validId,
        loader: metadata.loader,
        minecraftVersion: metadata.minecraft_version,
      });

      return metadata;
    } catch (err) {
      if (existsSync(serverDir)) {
        rmSync(serverDir, { recursive: true, force: true });
      }
      throw err;
    }
  }

  async function startServer(serverId: string): Promise<void> {
    const validId = assertValidServerId(serverId);
    const meta = readServerMetadata(serversDir, validId);
    const serverDir = resolveServerDir(serversDir, validId);

    if (!isEulaAccepted(serverDir)) {
      throw new ProtocolError(
        "eula_not_accepted",
        `Minecraft EULA has not been accepted for server: ${validId}`,
      );
    }

    const currentStatus = await getUnitStatus(validId, options.runFixedImpl);
    if (isUnitActive(currentStatus)) {
      throw new ProtocolError("server_running", `Server is already running: ${validId}`);
    }

    const runningServersMemoryMb = await computeRunningServersMemoryMb(validId);
    const meminfo = readHostMeminfo();
    checkMemoryForServer({
      requestedMemoryMb: meta.memory_mb,
      runningServersMemoryMb,
      meminfo,
      reservedSystemMb: options.reservedSystemMb ?? RESERVED_SYSTEM_MEMORY_MB,
    });

    await startServerUnit(validId, meta.memory_mb, {
      ...(options.runFixedImpl !== undefined ? { runFixedImpl: options.runFixedImpl } : {}),
      ...(options.logger !== undefined ? { logger: options.logger } : {}),
    });
  }

  async function stopServer(serverId: string): Promise<SystemdUnitStatus> {
    const validId = assertValidServerId(serverId);
    readServerMetadata(serversDir, validId);

    return stopServerUnit(validId, {
      runDir,
      now,
      ...(options.runFixedImpl !== undefined ? { runFixedImpl: options.runFixedImpl } : {}),
      ...(options.writeFifoImpl !== undefined ? { writeFifoImpl: options.writeFifoImpl } : {}),
      ...(options.stopPollIntervalMs !== undefined
        ? { pollIntervalMs: options.stopPollIntervalMs }
        : {}),
      ...(options.stopTimeoutMs !== undefined ? { stopTimeoutMs: options.stopTimeoutMs } : {}),
      ...(options.sleepImpl !== undefined ? { sleepImpl: options.sleepImpl } : {}),
    });
  }

  async function restartServer(serverId: string): Promise<void> {
    const validId = assertValidServerId(serverId);
    readServerMetadata(serversDir, validId);
    const serverDir = resolveServerDir(serversDir, validId);

    if (!isEulaAccepted(serverDir)) {
      throw new ProtocolError(
        "eula_not_accepted",
        `Minecraft EULA has not been accepted for server: ${validId}`,
      );
    }

    const currentStatus = await getUnitStatus(validId, options.runFixedImpl);
    if (!isUnitStopped(currentStatus)) {
      await stopServer(validId);
    }

    await startServer(validId);
  }

  async function deleteServer(serverId: string): Promise<void> {
    const validId = assertValidServerId(serverId);
    readServerMetadata(serversDir, validId);

    consoleManager.unsubscribe(validId);

    const status = await getUnitStatus(validId, options.runFixedImpl);
    if (!isUnitStopped(status)) {
      await stopServer(validId);
      const afterStop = await getUnitStatus(validId, options.runFixedImpl);
      if (!isUnitStopped(afterStop)) {
        throw new ProtocolError(
          "server_running",
          `Refusing to delete server ${validId}: unit is still ${afterStop.activeState}`,
        );
      }
    }

    const serverDir = resolveServerDir(serversDir, validId);
    rmSync(serverDir, { recursive: true, force: true });
    options.logger?.info("Deleted Minecraft server", { serverId: validId });
  }

  async function getServerStatus(serverId: string): Promise<ServerStatusReport> {
    const validId = assertValidServerId(serverId);
    const server = readServerMetadata(serversDir, validId);
    const serverDir = resolveServerDir(serversDir, validId);
    const status = await getUnitStatus(validId, options.runFixedImpl);

    return {
      server,
      eula_accepted: isEulaAccepted(serverDir),
      systemd: {
        active_state: status.activeState,
        sub_state: status.subState,
        main_pid: status.mainPid,
        memory_current_bytes: status.memoryCurrentBytes,
      },
    };
  }

  function listServers(): ServerMetadata[] {
    return listServerMetadata(serversDir);
  }

  function updateServerSettings(params: ServerUpdateSettingsBody): ServerMetadata {
    const validId = assertValidServerId(params.server_id);
    const existing = readServerMetadata(serversDir, validId);
    const serverDir = resolveServerDir(serversDir, validId);

    const nextMemoryMb = params.memory_mb ?? existing.memory_mb;
    const nextJvmArgs =
      params.jvm_args !== undefined
        ? [...validateJvmArgs(params.jvm_args)]
        : [...existing.jvm_args];
    const nextPort = params.port ?? existing.port;

    const updated: ServerMetadata = {
      ...existing,
      memory_mb: nextMemoryMb,
      jvm_args: nextJvmArgs,
      port: nextPort,
    };

    writeServerMetadata(serversDir, updated);
    writeServerProperties(serverDir, { port: nextPort });

    if (params.eula_accepted !== undefined) {
      writeEulaFile(serverDir, params.eula_accepted);
    }

    const javaMajor = selectJavaMajor(updated.minecraft_version);
    const javaBin = getJavaBinPath(serversDir, javaMajor, platform);
    writeStartScript(serverDir, {
      javaBin,
      memoryMb: updated.memory_mb,
      jvmArgs: updated.jvm_args,
      launchTarget: getEffectiveLaunchTarget(updated),
    });

    return updated;
  }

  function sendConsole(serverId: string, line: string): void {
    const validId = assertValidServerId(serverId);
    sendConsoleLine({
      runDir,
      serverId: validId,
      line,
      ...(options.writeFifoImpl !== undefined ? { writeFifoImpl: options.writeFifoImpl } : {}),
    });
  }

  function subscribeConsole(
    serverId: string,
    fromOffset: number | undefined,
    sendEvent: ConsoleEventEmitter,
  ): void {
    consoleManager.subscribe({
      serverId,
      sendEvent,
      ...(fromOffset !== undefined ? { fromOffset } : {}),
    });
  }

  function unsubscribeConsole(serverId: string): void {
    consoleManager.unsubscribe(serverId);
  }

  return {
    createServer,
    startServer,
    stopServer,
    restartServer,
    deleteServer,
    getServerStatus,
    listServers,
    updateServerSettings,
    sendConsole,
    subscribeConsole,
    unsubscribeConsole,
    consoleManager,
    close(): void {
      consoleManager.closeAll();
    },
  };
}

export function registerServerHandlers(queue: CommandQueue, manager: ServerManager): void {
  queue.registerHandler("server.create", async (opened, ctx) => {
    const body = opened.body as ServerCreateBody;
    const server = await manager.createServer(body);
    ctx.sendEvent("server.created", { server });
  });

  queue.registerHandler("server.start", async (opened, ctx) => {
    const body = opened.body as { readonly server_id: string };
    await manager.startServer(body.server_id);
    ctx.sendEvent("server.started", { server_id: body.server_id });
  });

  queue.registerHandler("server.stop", async (opened, ctx) => {
    const body = opened.body as { readonly server_id: string };
    await manager.stopServer(body.server_id);
    ctx.sendEvent("server.stopped", { server_id: body.server_id });
  });

  queue.registerHandler("server.restart", async (opened, ctx) => {
    const body = opened.body as { readonly server_id: string };
    await manager.restartServer(body.server_id);
    ctx.sendEvent("server.restarted", { server_id: body.server_id });
  });

  queue.registerHandler("server.delete", async (opened, ctx) => {
    const body = opened.body as { readonly server_id: string };
    await manager.deleteServer(body.server_id);
    ctx.sendEvent("server.deleted", { server_id: body.server_id });
  });

  queue.registerHandler("server.status", async (opened, ctx) => {
    const body = opened.body as { readonly server_id: string };
    const status = await manager.getServerStatus(body.server_id);
    ctx.sendEvent("server.status.result", status);
  });

  queue.registerHandler("server.list", (_opened, ctx) => {
    const servers = manager.listServers();
    ctx.sendEvent("server.list.result", { servers });
  });

  queue.registerHandler("server.update_settings", (opened, ctx) => {
    const body = opened.body as ServerUpdateSettingsBody;
    const server = manager.updateServerSettings(body);
    ctx.sendEvent("server.settings.updated", { server });
  });

  queue.registerHandler("server.console.send", (opened) => {
    const body = opened.body as ServerConsoleSendBody;
    manager.sendConsole(body.server_id, body.line);
  });

  queue.registerHandler("server.console.subscribe", (opened, ctx) => {
    const body = opened.body as ServerConsoleSubscribeBody;
    manager.subscribeConsole(body.server_id, body.from_offset, (type, eventBody) => {
      ctx.sendEvent(type, eventBody);
    });
  });

  queue.registerHandler("server.console.unsubscribe", (opened) => {
    const body = opened.body as { readonly server_id: string };
    manager.unsubscribeConsole(body.server_id);
  });
}
