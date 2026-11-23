// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { chmodSync, lstatSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import type { CommandQueue } from "../agent/jobs";
import type { Logger } from "../agent/logger";
import { ProtocolError, type TunnelPlayitSetKeyBody } from "../protocol";
import {
  ensurePlayitBinary,
  type PinnedPlayitAsset,
  PLAYIT_VERSION,
  type TunnelFetchLike,
} from "./binary";
import { assertPlayitSecretKey, hasPlayitSecretKey, savePlayitSecretKey } from "./key";

export const DEFAULT_TUNNEL_STOP_TIMEOUT_MS = 5_000;

export interface PlayitSpawnSpec {
  readonly binaryPath: string;
  readonly args: readonly string[];
  readonly env: Readonly<Record<string, string>>;
}

export interface SpawnedTunnelProcess {
  readonly pid: number;
  readonly exited: Promise<number>;
  kill(signal?: number | NodeJS.Signals): void;
}

export type TunnelSpawnLike = (
  cmd: readonly string[],
  options: {
    readonly stdin: "ignore";
    readonly stdout: "pipe";
    readonly stderr: "pipe";
    readonly env: Readonly<Record<string, string>>;
  },
) => SpawnedTunnelProcess;

export interface PlayitTunnelStatus {
  readonly configured: boolean;
  readonly running: boolean;
  readonly pid: number | null;
  readonly version: string;
  readonly started_at: number | null;
  readonly last_exit_code: number | null;
  readonly last_error: string | null;
}

export interface PlayitTunnelManagerOptions {
  readonly stateDir: string;
  readonly asset?: PinnedPlayitAsset;
  readonly platform?: NodeJS.Platform;
  readonly arch?: string;
  readonly fetchImpl?: TunnelFetchLike;
  readonly spawnImpl?: TunnelSpawnLike;
  readonly allowInsecure?: boolean;
  readonly stopTimeoutMs?: number;
  readonly now?: () => number;
  readonly logger?: Logger;
}

export interface PlayitTunnelManager {
  setKey(secretKey: string): void;
  start(): Promise<PlayitTunnelStatus>;
  stop(): Promise<PlayitTunnelStatus>;
  status(): PlayitTunnelStatus;
  close(): Promise<void>;
}

function buildMinimalTunnelEnv(
  platform: NodeJS.Platform = process.platform,
): Record<string, string> {
  if (platform === "win32") {
    const env: Record<string, string> = {};
    if (process.env.PATH !== undefined) {
      env.PATH = process.env.PATH;
    } else if (process.env.Path !== undefined) {
      env.PATH = process.env.Path;
    }
    if (process.env.SystemRoot !== undefined) {
      env.SystemRoot = process.env.SystemRoot;
    }
    return env;
  }

  return {
    PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    LC_ALL: "C",
  };
}

/**
 * Builds the fixed argv and minimal environment for spawning playitd headlessly.
 * Never invokes a shell and never puts the secret key in argv or environment.
 */
export function buildPlayitSpawnSpec(options: {
  readonly binaryPath: string;
  readonly stateDir: string;
  readonly keyPath: string;
  readonly platform?: NodeJS.Platform;
}): PlayitSpawnSpec {
  const socketPath = join(options.stateDir, "playit.sock");
  const certDir = join(options.stateDir, "playit-certs");

  return {
    binaryPath: options.binaryPath,
    args: ["--secret-path", options.keyPath, "--socket-path", socketPath, "--cert-dir", certDir],
    env: buildMinimalTunnelEnv(options.platform),
  };
}

function drainStream(stream: ReadableStream<Uint8Array> | number | undefined): void {
  if (stream === undefined || typeof stream === "number") {
    return;
  }
  const reader = stream.getReader();
  void (async () => {
    try {
      while (true) {
        const { done } = await reader.read();
        if (done) {
          break;
        }
      }
    } catch {
      // ignore stream read errors on process exit
    } finally {
      reader.releaseLock();
    }
  })();
}

function defaultSpawn(
  cmd: readonly string[],
  options: {
    readonly stdin: "ignore";
    readonly stdout: "pipe";
    readonly stderr: "pipe";
    readonly env: Readonly<Record<string, string>>;
  },
): SpawnedTunnelProcess {
  const proc = Bun.spawn([...cmd], {
    stdin: options.stdin,
    stdout: options.stdout,
    stderr: options.stderr,
    env: { ...options.env },
  });
  drainStream(proc.stdout);
  drainStream(proc.stderr);
  return {
    pid: proc.pid,
    exited: proc.exited,
    kill(signal?: number | NodeJS.Signals) {
      proc.kill(signal);
    },
  };
}

export function createPlayitTunnelManager(
  options: PlayitTunnelManagerOptions,
): PlayitTunnelManager {
  const now = options.now ?? (() => Date.now());
  const spawnImpl = options.spawnImpl ?? defaultSpawn;
  const stopTimeoutMs = options.stopTimeoutMs ?? DEFAULT_TUNNEL_STOP_TIMEOUT_MS;
  const version = options.asset?.version ?? PLAYIT_VERSION;

  let activeProc: SpawnedTunnelProcess | null = null;
  let starting = false;
  let startedAt: number | null = null;
  let lastExitCode: number | null = null;
  let lastError: string | null = null;

  function status(): PlayitTunnelStatus {
    return {
      configured: hasPlayitSecretKey(options.stateDir),
      running: activeProc !== null,
      pid: activeProc?.pid ?? null,
      version,
      started_at: startedAt,
      last_exit_code: lastExitCode,
      last_error: lastError,
    };
  }

  function setKey(secretKey: string): void {
    savePlayitSecretKey(options.stateDir, secretKey);
    lastError = null;
    options.logger?.info("Updated playit tunnel secret key", {
      configured: true,
    });
  }

  async function start(): Promise<PlayitTunnelStatus> {
    if (activeProc !== null || starting) {
      throw new ProtocolError("tunnel_already_running", "Playit tunnel is already running");
    }
    starting = true;

    try {
      const keyPath = assertPlayitSecretKey(options.stateDir);
      const binaryPath = await ensurePlayitBinary({
        stateDir: options.stateDir,
        ...(options.asset !== undefined ? { asset: options.asset } : {}),
        ...(options.platform !== undefined ? { platform: options.platform } : {}),
        ...(options.arch !== undefined ? { arch: options.arch } : {}),
        ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
        ...(options.allowInsecure !== undefined ? { allowInsecure: options.allowInsecure } : {}),
      });

      const certDir = join(options.stateDir, "playit-certs");
      const existingCertDir = lstatSync(certDir, { throwIfNoEntry: false });
      if (existingCertDir !== undefined) {
        if (existingCertDir.isSymbolicLink() || !existingCertDir.isDirectory()) {
          throw new ProtocolError("tunnel_failed", "Playit certificate directory is invalid");
        }
      } else {
        mkdirSync(certDir, { recursive: true, mode: 0o700 });
      }
      if (process.platform !== "win32") {
        chmodSync(certDir, 0o700);
      }

      const spec = buildPlayitSpawnSpec({
        binaryPath,
        stateDir: options.stateDir,
        keyPath,
        ...(options.platform !== undefined ? { platform: options.platform } : {}),
      });

      const proc = spawnImpl([spec.binaryPath, ...spec.args], {
        stdin: "ignore",
        stdout: "pipe",
        stderr: "pipe",
        env: spec.env,
      });

      activeProc = proc;
      startedAt = now();
      lastError = null;

      options.logger?.info("Started playit tunnel process", {
        pid: proc.pid,
        version,
      });

      void proc.exited
        .then((code) => {
          if (activeProc === proc) {
            activeProc = null;
            startedAt = null;
          }
          lastExitCode = code;
          if (code !== 0) {
            lastError = `Playit process exited with code ${code}`;
            options.logger?.warn("Playit tunnel process exited with non-zero code", {
              pid: proc.pid,
              code,
            });
          } else {
            options.logger?.info("Playit tunnel process exited cleanly", {
              pid: proc.pid,
              code,
            });
          }
        })
        .catch(() => {
          if (activeProc === proc) {
            activeProc = null;
            startedAt = null;
          }
          lastError = "Playit process terminated unexpectedly";
        });

      return status();
    } finally {
      starting = false;
    }
  }

  async function stop(): Promise<PlayitTunnelStatus> {
    if (activeProc === null) {
      throw new ProtocolError("tunnel_not_running", "Playit tunnel is not running");
    }

    const proc = activeProc;
    try {
      proc.kill("SIGTERM");
    } catch {
      // Process may have already exited
    }

    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const exitedInTime = await Promise.race([
        proc.exited.then(() => true),
        new Promise<boolean>((resolve) => {
          timer = setTimeout(() => resolve(false), stopTimeoutMs);
        }),
      ]);
      if (!exitedInTime) {
        try {
          proc.kill("SIGKILL");
        } catch {
          // ignore
        }
      }
    } finally {
      if (timer !== undefined) {
        clearTimeout(timer);
      }
    }

    if (activeProc === proc) {
      activeProc = null;
      startedAt = null;
    }

    return status();
  }

  async function close(): Promise<void> {
    if (activeProc !== null) {
      try {
        await stop();
      } catch {
        // ignore stop errors on shutdown
      }
    }
  }

  return {
    setKey,
    start,
    stop,
    status,
    close,
  };
}

export function registerTunnelHandlers(queue: CommandQueue, manager: PlayitTunnelManager): void {
  queue.registerHandler("tunnel.playit.set_key", (opened, ctx) => {
    const body = opened.body as TunnelPlayitSetKeyBody;
    manager.setKey(body.secret_key);
    ctx.sendEvent("tunnel.playit.key_updated", {
      configured: true,
    });
  });

  queue.registerHandler("tunnel.playit.start", async (_opened, ctx) => {
    const current = await manager.start();
    ctx.sendEvent("tunnel.playit.started", current);
  });

  queue.registerHandler("tunnel.playit.stop", async (_opened, ctx) => {
    const current = await manager.stop();
    ctx.sendEvent("tunnel.playit.stopped", current);
  });

  queue.registerHandler("tunnel.playit.status", (_opened, ctx) => {
    const current = manager.status();
    ctx.sendEvent("tunnel.playit.status.result", current);
  });
}
