// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { fingerprint, type PublicKey } from "../crypto";
import {
  type AgentMembersRevokeBody,
  type AgentMembersSetBody,
  type AgentSubscribeBody,
  type CommandRegistry,
  type KeyId,
  type MemberStore,
  type OpenedCommand,
  openCommand,
  PROTOCOL_VERSION,
  ProtocolError,
  type RevocationList,
  type Role,
  roleAtLeast,
  type SubscriptionTopic,
  sealAgentMessage,
  type TransportFrame,
  type TrustContext,
  wrapEventBody,
} from "../protocol";
import type { Logger } from "./logger";
import { applyMembersRevoke, applyMembersSet } from "./members";

export const DEFAULT_MAX_IDEMPOTENCY_ENTRIES = 4096;
export const MAX_SUBSCRIBERS = 16;
/** Subscription lifetime when the signer is an account key (no certificate to bound it). */
export const ACCOUNT_SUBSCRIPTION_TTL_MS = 24 * 60 * 60 * 1000;

export type TransportCommandFrame = Extract<TransportFrame, { kind: "command" }>;
export type TransportAckFrame = Extract<TransportFrame, { kind: "ack" }>;
export type TransportEventFrame = Extract<TransportFrame, { kind: "event" }>;

export interface CommandHandlerContext {
  /**
   * Sends an event for this command. The decrypted body is
   * `{ in_reply_to: <command id>, data }`, sealed to the command's `reply_to`
   * key (or the account key when absent).
   */
  sendEvent(type: string, data: unknown): void;
  now(): number;
  /** Role of the command's account on a server, or null without access. */
  roleFor(serverId: string): Role | null;
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

export interface PublishScope {
  readonly serverId?: string;
}

export interface CommandQueue {
  registerHandler(type: string, handler: CommandHandler): void;
  /**
   * Sends an event to every live subscriber of `topic` whose account may see
   * the scope (viewer or better on `scope.serverId`).
   */
  publish(topic: SubscriptionTopic, type: string, data: unknown, scope?: PublishScope): void;
  subscriberCount(): number;
  enqueue(frame: TransportCommandFrame): Promise<void>;
  drain(timeoutMs: number): Promise<boolean>;
}

interface Subscriber {
  readonly key: PublicKey;
  readonly keyId: KeyId;
  readonly account: KeyId;
  readonly sessionId: string | undefined;
  readonly notAfter: number;
  inReplyTo: string;
  readonly topics: Set<SubscriptionTopic>;
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

  const subscribers = new Map<KeyId, Subscriber>();
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

  function resolveRecipientKey(opened: OpenedCommand): PublicKey | null {
    return opened.replyTo ?? trust.isTrustedAccountKey(opened.accountId);
  }

  /**
   * Events can outlive their command (console streams). Before each one, check
   * that the certificate has not expired, the session is not revoked and the
   * account still holds the role the command needed.
   */
  function stillAuthorized(opened: OpenedCommand): boolean {
    if (opened.sessionNotAfter !== undefined && trust.now() >= opened.sessionNotAfter) {
      return false;
    }
    if (opened.sessionId !== undefined && trust.isSessionRevoked(opened.sessionId)) {
      return false;
    }
    if (trust.isTrustedAccountKey(opened.accountId) === null) {
      return false;
    }
    const definition = registry.get(opened.header.type);
    const body = opened.body;
    const scope =
      typeof body === "object" &&
      body !== null &&
      "server_id" in body &&
      typeof (body as { server_id: unknown }).server_id === "string"
        ? (body as { server_id: string }).server_id
        : "*";
    return roleAtLeast(trust.roleFor(opened.accountId, scope), definition?.minRole ?? "owner");
  }

  function sendSealedEvent(type: string, body: unknown, recipientPublicKey: PublicKey): void {
    const sealed = sealAgentMessage({
      type,
      body,
      agentKeyPair: trust.agentKeyPair,
      recipientPublicKey,
      sentAt: trust.now(),
      seq: nextEventSeq++,
    });
    const eventFrame: TransportEventFrame = {
      v: PROTOCOL_VERSION,
      kind: "event",
      route: {
        agent: agentId,
        recipient: sealed.header.recipient,
      },
      body: sealed,
    };
    sendFrame(eventFrame);
  }

  function pruneSubscribers(): void {
    const at = trust.now();
    for (const [keyId, sub] of subscribers) {
      const revoked = sub.sessionId !== undefined && trust.isSessionRevoked(sub.sessionId);
      if (at >= sub.notAfter || revoked || trust.isTrustedAccountKey(sub.account) === null) {
        subscribers.delete(keyId);
      }
    }
  }

  function publish(
    topic: SubscriptionTopic,
    type: string,
    data: unknown,
    scope?: PublishScope,
  ): void {
    pruneSubscribers();
    for (const sub of subscribers.values()) {
      if (!sub.topics.has(topic)) {
        continue;
      }
      if (!roleAtLeast(trust.roleFor(sub.account, scope?.serverId ?? "*"), "viewer")) {
        continue;
      }
      try {
        sendSealedEvent(type, wrapEventBody(sub.inReplyTo, data), sub.key);
      } catch (err) {
        logger.warn("Failed to publish event to subscriber", {
          type,
          errName: err instanceof Error ? err.name : "Error",
        });
      }
    }
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
      sendEvent(type: string, data: unknown): void {
        if (!stillAuthorized(opened)) {
          logger.warn("Dropping event: authorization for the command no longer holds", {
            commandId: opened.header.id,
            type: opened.header.type,
          });
          return;
        }
        const recipientPublicKey = resolveRecipientKey(opened);
        if (recipientPublicKey === null) {
          throw new Error("Trusted account key unavailable for event recipient");
        }
        sendSealedEvent(type, wrapEventBody(opened.header.id, data), recipientPublicKey);
      },
      now(): number {
        return trust.now();
      },
      roleFor(serverId: string): Role | null {
        return trust.roleFor(opened.accountId, serverId);
      },
      logger,
    };

    try {
      await handler(opened, ctx);
    } catch (err) {
      if (err instanceof ProtocolError) {
        logger.warn("Command handler rejected command", {
          commandId: opened.header.id,
          type: opened.header.type,
          code: err.code,
        });
        sendFrame(makeAckError(opened.header.id, err.code));
        return;
      }
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

  registerHandler("agent.subscribe", (opened, ctx) => {
    const body = opened.body as AgentSubscribeBody;
    const key = resolveRecipientKey(opened);
    if (key === null) {
      throw new ProtocolError("untrusted_signer", "Subscriber key is not available");
    }
    pruneSubscribers();
    const keyId = fingerprint(key);
    const existing = subscribers.get(keyId);
    if (existing === undefined && subscribers.size >= MAX_SUBSCRIBERS) {
      throw new ProtocolError("too_many_subscribers", "Subscriber limit reached");
    }
    const sub: Subscriber = existing ?? {
      key,
      keyId,
      account: opened.accountId,
      sessionId: opened.sessionId,
      notAfter: opened.sessionNotAfter ?? trust.now() + ACCOUNT_SUBSCRIPTION_TTL_MS,
      inReplyTo: opened.header.id,
      topics: new Set<SubscriptionTopic>(),
    };
    sub.inReplyTo = opened.header.id;
    for (const topic of body.topics) {
      sub.topics.add(topic);
    }
    subscribers.set(keyId, sub);
    ctx.sendEvent("agent.subscribed", { topics: [...sub.topics] });
  });

  registerHandler("agent.unsubscribe", (opened, ctx) => {
    const body = opened.body as AgentSubscribeBody;
    const key = resolveRecipientKey(opened);
    const sub = key === null ? undefined : subscribers.get(fingerprint(key));
    if (sub !== undefined) {
      for (const topic of body.topics) {
        sub.topics.delete(topic);
      }
      if (sub.topics.size === 0) {
        subscribers.delete(sub.keyId);
      }
    }
    ctx.sendEvent("agent.unsubscribed", { topics: [...body.topics] });
  });

  const memberStore = trust as TrustContext & Partial<MemberStore>;
  if (
    typeof memberStore.listMembers === "function" &&
    typeof memberStore.setMember === "function" &&
    typeof memberStore.revokeMembers === "function"
  ) {
    const store = memberStore as MemberStore;
    registerHandler("agent.members.set", (opened, ctx) => {
      const body = opened.body as AgentMembersSetBody;
      const entry = applyMembersSet(opened, body, { trust, store, agentId }, trust.now());
      ctx.sendEvent("agent.members.updated", {
        account: entry.account,
        role: entry.role,
        servers: entry.servers,
        ...(entry.expires_at !== undefined ? { expires_at: entry.expires_at } : {}),
      });
    });

    registerHandler("agent.members.revoke", (opened, ctx) => {
      const body = opened.body as AgentMembersRevokeBody;
      const count = applyMembersRevoke(opened, body, { trust, store, agentId });
      ctx.sendEvent("agent.members.revoked", { account: body.account, count });
    });
  }

  const revocationAware = trust as TrustContext & {
    readonly applyRevocationList?: (
      list: unknown,
    ) => Promise<{ readonly account: KeyId; readonly count: number }>;
  };
  if (typeof revocationAware.applyRevocationList === "function") {
    const applyRevocations = revocationAware.applyRevocationList.bind(revocationAware);
    registerHandler("agent.revocations.set", async (opened, ctx) => {
      const body = opened.body as { readonly list: RevocationList };
      const result = await applyRevocations(body.list);
      ctx.sendEvent("agent.revocations.applied", {
        account: result.account,
        count: result.count,
      });
    });
  }

  return {
    registerHandler,
    publish,
    subscriberCount(): number {
      pruneSubscribers();
      return subscribers.size;
    },

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
