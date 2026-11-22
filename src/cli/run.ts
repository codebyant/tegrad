// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
import {
  type AgentConnection,
  type CommandQueue,
  createAgentConnection,
  createCommandQueue,
  createFileTrustContext,
  createLogger,
  type FileTrustContext,
  type Logger,
  loadConfig,
  loadOrCreateIdentity,
  loadTrust,
  type TimerProvider,
  type WebSocketFactory,
} from "../agent";
import { fingerprint } from "../crypto";
import { type CommandRegistry, createCoreRegistry, type TransportFrame } from "../protocol";
import { createServerManager, registerServerHandlers, type ServerManager } from "../server";

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
  readonly logger: Logger;
  readonly serverManager?: ServerManager;
  start(): void;
  shutdown(drainTimeoutMs?: number): Promise<void>;
}

export interface CreateAgentRuntimeOptions {
  readonly stateDir: string;
  readonly serversDir?: string;
  readonly runDir?: string;
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly logger?: Logger;
  readonly registry?: CommandRegistry;
  readonly webSocketFactory?: WebSocketFactory;
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
  let serverManager: ServerManager | undefined;
  if (configuredServersDir && configuredServersDir.length > 0) {
    serverManager = createServerManager({
      serversDir: configuredServersDir,
      logger,
      ...(configuredRunDir && configuredRunDir.length > 0 ? { runDir: configuredRunDir } : {}),
      ...(options.now !== undefined ? { now: options.now } : {}),
    });
    registerServerHandlers(queue, serverManager);
  }

  const connection = createAgentConnection({
    apiUrl: config.apiUrl,
    agentId,
    logger,
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

  let shutdownPromise: Promise<void> | null = null;

  return {
    agentId,
    connection,
    queue,
    trust,
    logger,
    ...(serverManager !== undefined ? { serverManager } : {}),

    start(): void {
      logger.info("Starting tegrad", { agentId });
      connection.start();
    },

    shutdown(drainTimeoutMs: number = SHUTDOWN_DRAIN_TIMEOUT_MS): Promise<void> {
      if (shutdownPromise !== null) {
        return shutdownPromise;
      }
      shutdownPromise = (async () => {
        logger.info("Shutting down tegrad");
        serverManager?.close();
        connection.stop();
        const drained = await queue.drain(drainTimeoutMs);
        if (!drained) {
          logger.warn("Shutdown drain timeout elapsed before active command finished", {
            drainTimeoutMs,
          });
        }
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
