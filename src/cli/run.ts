// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
import {
  type AgentConnection,
  type CommandQueue,
  createAgentApiClient,
  createAgentConnection,
  createCommandQueue,
  createFileTrustContext,
  createLogger,
  type FetchLike,
  type FileTrustContext,
  isInsecureAllowed,
  type Logger,
  loadConfig,
  loadOrCreateIdentity,
  loadTrust,
  type TimerProvider,
  type WebSocketFactory,
} from "../agent";
import { type BackupManager, createBackupManager, registerBackupHandlers } from "../backup";
import { fingerprint } from "../crypto";
import { FileManager, registerFileCommandHandlers } from "../files";
import {
  type CommandRegistry,
  createCoreRegistry,
  signAgentAuth,
  type TransportFrame,
} from "../protocol";
import {
  createServerManager,
  createServerStatusWatcher,
  registerServerHandlers,
  type ServerManager,
  type ServerStatusWatcher,
} from "../server";
import { createStateManager, registerStateHandlers, type StateManager } from "../state";
import {
  createPlayitTunnelManager,
  type PlayitTunnelManager,
  registerTunnelHandlers,
} from "../tunnel";
import { type AutoUpdater, createAutoUpdater } from "../update";

export const SHUTDOWN_DRAIN_TIMEOUT_MS = 10_000;

const rootEnvSchema = z.object({
  TEGRAD_ALLOW_ROOT: z.string().optional(),
});

export function assertNotRoot(
  env: Readonly<Record<string, string | undefined>> = process.env,
  geteuid: () => number = () => process.geteuid?.() ?? -1,
): void {
  const parsed = rootEnvSchema.parse({ TEGRAD_ALLOW_ROOT: env.TEGRAD_ALLOW_ROOT });
  if (geteuid() === 0 && parsed.TEGRAD_ALLOW_ROOT !== "1") {
    throw new Error(
      'Refusing to start tegrad as root (euid 0). Run as the dedicated "tegrad" user (or set TEGRAD_ALLOW_ROOT=1 for local development only).',
    );
  }
}

export interface AgentRuntime {
  readonly agentId: string;
  readonly connection: AgentConnection;
  readonly queue: CommandQueue;
  readonly trust: FileTrustContext;
  readonly updater: AutoUpdater;
  readonly logger: Logger;
  readonly serverManager?: ServerManager;
  readonly fileManager: FileManager;
  readonly stateManager: StateManager;
  readonly backupManager: BackupManager;
  readonly tunnelManager: PlayitTunnelManager;
  start(): void;
  shutdown(drainTimeoutMs?: number): Promise<void>;
}

export interface CreateAgentRuntimeOptions {
  readonly stateDir: string;
  readonly serversDir?: string;
  readonly backupsDir?: string;
  readonly runDir?: string;
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly logger?: Logger;
  readonly registry?: CommandRegistry;
  readonly webSocketFactory?: WebSocketFactory;
  readonly fetch?: FetchLike;
  readonly timers?: TimerProvider;
  readonly now?: () => number;
  readonly geteuid?: () => number;
}

export async function createAgentRuntime(
  options: CreateAgentRuntimeOptions,
): Promise<AgentRuntime> {
  const env = options.env ?? process.env;
  assertNotRoot(env, options.geteuid);
  const logger = options.logger ?? createLogger({ env });
  const config = loadConfig(options.stateDir, { env });
  const agentKeyPair = await loadOrCreateIdentity(options.stateDir);
  const trustedAccountKeys = await loadTrust(options.stateDir);
  const agentId = fingerprint(agentKeyPair.publicKey);
  const registry = options.registry ?? createCoreRegistry();

  const trust = createFileTrustContext({
    stateDir: options.stateDir,
    agentKeyPair,
    trustedAccountKeys,
    ...(options.now !== undefined ? { now: options.now } : {}),
  });

  let connectionRef: AgentConnection | null = null;
  const queue = createCommandQueue({
    trust,
    registry,
    logger,
    sendFrame: (frame: TransportFrame) => {
      connectionRef?.send(frame);
    },
  });

  const configuredServersDir = options.serversDir ?? env.TEGRAD_SERVERS_DIR?.trim();
  const configuredRunDir = options.runDir ?? env.TEGRAD_RUN_DIR?.trim();
  const serverManager = createServerManager({
    logger,
    ...(configuredServersDir && configuredServersDir.length > 0
      ? { serversDir: configuredServersDir }
      : {}),
    ...(configuredRunDir && configuredRunDir.length > 0 ? { runDir: configuredRunDir } : {}),
    ...(options.now !== undefined ? { now: options.now } : {}),
  });
  const statusWatcher: ServerStatusWatcher = createServerStatusWatcher({
    listServerIds: () => serverManager.listServers().map((server) => server.id),
    getState: (serverId) => serverManager.getServerState(serverId),
    emit: (change) => {
      queue.publish("server.status", "server.status.changed", change, {
        serverId: change.server_id,
      });
    },
    shouldPoll: () => queue.subscriberCount() > 0,
    ...(options.now !== undefined ? { now: options.now } : {}),
    ...(options.timers !== undefined
      ? {
          timers: {
            setInterval: (fn: () => void, ms: number) => options.timers?.setInterval(fn, ms),
            clearInterval: (handle: unknown) => options.timers?.clearInterval(handle),
          },
        }
      : {}),
  });
  registerServerHandlers(queue, serverManager, {
    onStateChanged: (serverId) => {
      void statusWatcher.refresh(serverId);
    },
    onDeleted: (serverId) => statusWatcher.forget(serverId),
  });

  const apiClient = createAgentApiClient({
    apiUrl: config.apiUrl,
    agentKeyPair,
    allowInsecure: isInsecureAllowed(env),
    ...(options.fetch !== undefined ? { fetch: options.fetch } : {}),
    ...(options.now !== undefined ? { now: options.now } : {}),
  });

  const fileManager = new FileManager(
    configuredServersDir && configuredServersDir.length > 0
      ? { serversBaseDir: configuredServersDir }
      : {},
  );
  registerFileCommandHandlers(queue, fileManager);

  const configuredBackupsDir = options.backupsDir ?? env.TEGRAD_BACKUPS_DIR?.trim();
  const backupManager = createBackupManager({
    stateDir: options.stateDir,
    logger,
    ...(configuredServersDir && configuredServersDir.length > 0
      ? { serversBaseDir: configuredServersDir }
      : {}),
    ...(configuredBackupsDir && configuredBackupsDir.length > 0
      ? { localBackupsDir: configuredBackupsDir }
      : {}),
    runtime: {
      isRunning: async (serverId: string): Promise<boolean> => {
        try {
          const status = await serverManager.getServerStatus(serverId);
          return (
            status.systemd.active_state === "active" || status.systemd.active_state === "activating"
          );
        } catch {
          return false;
        }
      },
      sendConsole: (serverId: string, line: string): void => {
        serverManager.sendConsole(serverId, line);
      },
    },
    ...(options.fetch !== undefined ? { cloudFetchImpl: options.fetch } : {}),
    cloudUploadUrlProvider: (request) => apiClient.requestBackupUploadUrl(request),
    ...(options.timers !== undefined
      ? {
          timers: {
            setInterval: (fn: () => void, ms: number) => ({
              id: options.timers?.setInterval(fn, ms),
            }),
            clearInterval: (handle: { readonly id?: unknown }) => {
              options.timers?.clearInterval(handle.id);
            },
          },
        }
      : {}),
    ...(options.now !== undefined ? { now: options.now } : {}),
  });
  registerBackupHandlers(queue, backupManager);

  const configuredCdnHost = config.tegraCdnHost ?? config.cdnHost;
  const stateManager = createStateManager({
    logger,
    ...(configuredServersDir && configuredServersDir.length > 0
      ? { serversDir: configuredServersDir }
      : {}),
    ...(configuredCdnHost !== undefined ? { cdnHost: configuredCdnHost } : {}),
    backupHook: backupManager.createBackupHook(),
    ...(options.fetch !== undefined ? { fetchImpl: options.fetch } : {}),
    ...(options.now !== undefined ? { now: options.now } : {}),
  });
  registerStateHandlers(queue, stateManager);

  const tunnelManager = createPlayitTunnelManager({
    stateDir: options.stateDir,
    logger,
    ...(options.fetch !== undefined ? { fetchImpl: options.fetch } : {}),
    ...(options.now !== undefined ? { now: options.now } : {}),
  });
  registerTunnelHandlers(queue, tunnelManager);

  const connection = createAgentConnection({
    apiUrl: config.apiUrl,
    agentId,
    logger,
    answerHello: (hello) => signAgentAuth({ agentKeyPair, hello, ts: (options.now ?? Date.now)() }),
    onFrame: (frame) => {
      if (frame.kind === "command") {
        void queue.enqueue(frame);
      }
    },
    ...(options.webSocketFactory !== undefined
      ? { webSocketFactory: options.webSocketFactory }
      : {}),
    ...(options.timers !== undefined ? { timers: options.timers } : {}),
  });
  connectionRef = connection;

  const updater = createAutoUpdater({
    stateDir: options.stateDir,
    logger,
    ...(config.update?.channel !== undefined ? { channel: config.update.channel } : {}),
    ...(config.update?.auto !== undefined ? { auto: config.update.auto } : {}),
    ...(config.update?.manifestBaseUrl !== undefined
      ? { manifestBaseUrl: config.update.manifestBaseUrl }
      : {}),
    ...(options.fetch !== undefined ? { fetch: options.fetch } : {}),
    ...(options.timers !== undefined ? { timers: options.timers } : {}),
    ...(options.now !== undefined ? { now: options.now } : {}),
  });

  let shutdownPromise: Promise<void> | null = null;

  return {
    agentId,
    connection,
    queue,
    trust,
    updater,
    logger,
    ...(serverManager !== undefined ? { serverManager } : {}),
    fileManager,
    stateManager,
    backupManager,
    tunnelManager,

    start(): void {
      logger.info("Starting tegrad", { agentId });
      connection.start();
      statusWatcher.start();
      updater.start();
      backupManager.start();
    },

    shutdown(drainTimeoutMs: number = SHUTDOWN_DRAIN_TIMEOUT_MS): Promise<void> {
      if (shutdownPromise !== null) {
        return shutdownPromise;
      }
      shutdownPromise = (async () => {
        logger.info("Shutting down tegrad");
        updater.stop();
        statusWatcher.stop();
        backupManager.close();
        await tunnelManager.close();
        serverManager?.close();
        connection.stop();
        const drained = await queue.drain(drainTimeoutMs);
        if (!drained) {
          logger.warn("Shutdown drain timeout elapsed before active command finished", {
            drainTimeoutMs,
          });
        }
        fileManager.dispose();
        trust.flush();
        logger.info("Shutdown complete");
      })();
      return shutdownPromise;
    },
  };
}

export interface RunAgentLoopOptions extends CreateAgentRuntimeOptions {
  readonly signalTarget?: Pick<NodeJS.Process, "on" | "off">;
  readonly drainTimeoutMs?: number;
}

export async function runAgentLoop(options: RunAgentLoopOptions): Promise<number> {
  const runtime = await createAgentRuntime(options);
  const signalTarget = options.signalTarget ?? process;
  const drainTimeoutMs = options.drainTimeoutMs ?? SHUTDOWN_DRAIN_TIMEOUT_MS;

  return await new Promise<number>((resolve) => {
    let stopping = false;

    const handleSignal = (): void => {
      if (stopping) {
        return;
      }
      stopping = true;
      signalTarget.off("SIGINT", handleSignal);
      signalTarget.off("SIGTERM", handleSignal);
      void runtime.shutdown(drainTimeoutMs).then(() => resolve(0));
    };

    signalTarget.on("SIGINT", handleSignal);
    signalTarget.on("SIGTERM", handleSignal);
    runtime.start();
  });
}
