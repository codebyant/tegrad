// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { fingerprint } from "../crypto";
import {
  type CommandRegistry,
  type OpenedCommand,
  openCommand,
  PROTOCOL_VERSION,
  ProtocolError,
  sealAgentMessage,
  type TransportFrame,
  type TrustContext,
} from "../protocol";
import type { Logger } from "./logger";

export const DEFAULT_MAX_IDEMPOTENCY_ENTRIES = 4096;

export type TransportCommandFrame = Extract<TransportFrame, { kind: "command" }>;
export type TransportAckFrame = Extract<TransportFrame, { kind: "ack" }>;
export type TransportEventFrame = Extract<TransportFrame, { kind: "event" }>;

export interface CommandHandlerContext {
  sendEvent(type: string, body: unknown): void;
  now(): number;
  readonly logger: Logger;
}

export type CommandHandler = (
  opened: OpenedCommand,
  ctx: CommandHandlerContext,
) => unknown | Promise<unknown>;

export interface CommandQueueOptions {
  readonly trust: TrustContext;
  readonly registry: CommandRegistry;
  readonly sendFrame: (frame: TransportFrame) => void;
  readonly logger: Logger;
  readonly maxIdempotencyEntries?: number;
}

export interface CommandQueue {
  registerHandler(type: string, handler: CommandHandler): void;
  enqueue(frame: TransportCommandFrame): Promise<void>;
  drain(timeoutMs: number): Promise<boolean>;
}

interface CompletedAckEntry {
  readonly sig: string;
  readonly ack: TransportAckFrame;
}

export function createCommandQueue(options: CommandQueueOptions): CommandQueue {
  const { trust, registry, sendFrame, logger } = options;
  const maxIdempotencyEntries = options.maxIdempotencyEntries ?? DEFAULT_MAX_IDEMPOTENCY_ENTRIES;
  const agentId = fingerprint(trust.agentKeyPair.publicKey);
  const handlers = new Map<string, CommandHandler>();
  const completedAcks = new Map<string, CompletedAckEntry>();

  let nextEventSeq = 1;
  let tail: Promise<void> = Promise.resolve();
  let pendingCount = 0;

  function recordCompletedAck(id: string, sig: string, ack: TransportAckFrame): void {
    if (completedAcks.has(id)) {
      completedAcks.delete(id);
    } else if (completedAcks.size >= maxIdempotencyEntries) {
      const oldestKey = completedAcks.keys().next().value;
      if (oldestKey !== undefined) {
        completedAcks.delete(oldestKey);
      }
    }
    completedAcks.set(id, { sig, ack });
  }

  function makeAckOk(id: string): TransportAckFrame {
    return {
      v: PROTOCOL_VERSION,
      kind: "ack",
      route: { agent: agentId },
      body: { id, ok: true },
    };
  }

  function makeAckError(id: string, code: string): TransportAckFrame {
    return {
      v: PROTOCOL_VERSION,
      kind: "ack",
      route: { agent: agentId },
      body: { id, ok: false, code },
    };
  }

  async function processCommand(frame: TransportCommandFrame): Promise<void> {
    const commandId = frame.body.header.id;
    let opened: OpenedCommand;

    try {
      opened = await openCommand(frame.body, trust, registry);
    } catch (err) {
      if (err instanceof ProtocolError) {
        if (err.code === "replayed") {
          const cached = completedAcks.get(commandId);
          if (cached !== undefined && cached.sig === frame.body.sig) {
            sendFrame(cached.ack);
            return;
          }
        }
        logger.warn("Command rejected by protocol verification", {
          commandId,
          code: err.code,
        });
        sendFrame(makeAckError(commandId, err.code));
        return;
      }

      logger.error("Unexpected error while opening command", {
        commandId,
        errName: err instanceof Error ? err.name : "Error",
      });
      sendFrame(makeAckError(commandId, "invalid_format"));
      return;
    }

    const handler = handlers.get(opened.header.type);
    if (!handler) {
      logger.warn("No handler registered for command", {
        commandId: opened.header.id,
        type: opened.header.type,
        code: "no_handler",
      });
      sendFrame(makeAckError(opened.header.id, "no_handler"));
      return;
    }

    const ctx: CommandHandlerContext = {
      sendEvent(type: string, body: unknown): void {
        const recipientPublicKey = trust.isTrustedAccountKey(opened.accountId);
        if (recipientPublicKey === null) {
          throw new Error("Trusted account key unavailable for event recipient");
        }
        const seq = nextEventSeq++;
        const sealed = sealAgentMessage({
          type,
          body,
          agentKeyPair: trust.agentKeyPair,
          recipientPublicKey,
          sentAt: trust.now(),
          seq,
        });
        const eventFrame: TransportEventFrame = {
          v: PROTOCOL_VERSION,
          kind: "event",
          route: {
            agent: agentId,
            recipient: opened.accountId,
          },
          body: sealed,
        };
        sendFrame(eventFrame);
      },
      now(): number {
        return trust.now();
      },
      logger,
    };

    try {
      await handler(opened, ctx);
    } catch (err) {
      logger.error("Command handler threw an exception", {
        commandId: opened.header.id,
        type: opened.header.type,
        code: "handler_error",
        errName: err instanceof Error ? err.name : "Error",
      });
      sendFrame(makeAckError(opened.header.id, "handler_error"));
      return;
    }

    const ack = makeAckOk(opened.header.id);
    recordCompletedAck(opened.header.id, frame.body.sig, ack);
    sendFrame(ack);
  }

  function registerHandler(type: string, handler: CommandHandler): void {
    handlers.set(type, handler);
  }

  registerHandler("agent.ping", (_opened, ctx) => {
    ctx.sendEvent("agent.pong", { at: ctx.now() });
  });

  return {
    registerHandler,

    enqueue(frame: TransportCommandFrame): Promise<void> {
      pendingCount++;
      const run = tail.then(async () => {
        try {
          await processCommand(frame);
        } finally {
          pendingCount--;
        }
      });
      tail = run.catch(() => {});
      return run;
    },

    async drain(timeoutMs: number): Promise<boolean> {
      if (pendingCount === 0) {
        return true;
      }
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        return await Promise.race([
          tail.then(() => true),
          new Promise<boolean>((resolve) => {
            timer = setTimeout(() => resolve(false), timeoutMs);
          }),
        ]);
      } finally {
        if (timer !== undefined) {
          clearTimeout(timer);
        }
      }
    },
  };
}
