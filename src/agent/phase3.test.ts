// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  fingerprint,
  generateSigningKeyPair,
  ready,
  type SigningKeyPair,
  toBase64Url,
} from "../crypto";
import {
  type CommandRegistry,
  createCoreRegistry,
  createHelloFrame,
  createInMemoryTrustContext,
  createSignedCommand,
  type GrantableRole,
  PROTOCOL_VERSION,
  type RoleGrant,
  type SessionCertificate,
  type SignedCommand,
  signRoleGrant,
  signSessionCertificate,
  type TransportFrame,
  type TrustContext,
  verifyAgentAuth,
  verifyAgentRequest,
} from "../protocol";
import { createServerStatusWatcher, mapUnitState } from "../server";
import { AgentApiError, createAgentApiClient } from "./api-client";
import {
  createAgentConnection,
  type WebSocketCloseEventLike,
  type WebSocketLike,
  type WebSocketMessageEventLike,
} from "./connection";
import {
  type CommandQueue,
  createCommandQueue,
  MAX_SUBSCRIBERS,
  type TransportCommandFrame,
} from "./jobs";
import { createLogger } from "./logger";
import { createPairingApiClient } from "./pairing-api";
import { getStatePaths } from "./paths";
import { createFileTrustContext, loadMembers } from "./state";
import { openTestEvent } from "./test-events";

const NOW = 1_700_000_000_000;
const tempDirs: string[] = [];

beforeAll(async () => {
  await ready();
});

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "tegrad-p3-"));
  tempDirs.push(dir);
  return dir;
}

const silentLogger = createLogger({ level: "error", stdout: () => {}, stderr: () => {} });

interface Harness {
  readonly agent: SigningKeyPair;
  readonly agentId: string;
  readonly owner: SigningKeyPair;
  readonly registry: CommandRegistry;
  readonly trust: TrustContext;
  readonly queue: CommandQueue;
  readonly sent: TransportFrame[];
  readonly clock: { now: number };
  send(
    type: string,
    body: unknown,
    signer: SigningKeyPair,
    options?: { session?: SessionCertificate; replyTo?: Uint8Array; counter?: number },
  ): Promise<SignedCommand>;
}

function makeHarness(
  trustOverride?: (agent: SigningKeyPair, owner: SigningKeyPair) => TrustContext,
): Harness {
  const agent = generateSigningKeyPair();
  const owner = generateSigningKeyPair();
  const clock = { now: NOW };
  const trust =
    trustOverride?.(agent, owner) ??
    createInMemoryTrustContext({
      agentKeyPair: agent,
      trustedAccountKeys: [owner.publicKey],
      now: () => clock.now,
    });
  const registry = createCoreRegistry();
  const sent: TransportFrame[] = [];
  const queue = createCommandQueue({
    trust,
    registry,
    sendFrame: (frame) => sent.push(frame),
    logger: silentLogger,
  });
  const agentId = fingerprint(agent.publicKey);
  const counters = new Map<string, number>();

  return {
    agent,
    agentId,
    owner,
    registry,
    trust,
    queue,
    sent,
    clock,
    async send(type, body, signer, options = {}) {
      const key = fingerprint(signer.publicKey);
      const counter = options.counter ?? (counters.get(key) ?? 0) + 1;
      counters.set(key, counter);
      const command = createSignedCommand(
        {
          type,
          body,
          agentPublicKey: agent.publicKey,
          signer,
          counter,
          now: clock.now,
          ...(options.session !== undefined ? { session: options.session } : {}),
          ...(options.replyTo !== undefined ? { replyTo: options.replyTo } : {}),
        },
        registry,
      );
      const frame: TransportCommandFrame = {
        v: PROTOCOL_VERSION,
        kind: "command",
        route: { agent: agentId },
        body: command,
      };
      await queue.enqueue(frame);
      return command;
    },
  };
}

function lastAck(sent: readonly TransportFrame[]): { ok: boolean; code?: string } {
  for (let i = sent.length - 1; i >= 0; i--) {
    const frame = sent[i];
    if (frame?.kind === "ack") {
      return frame.body.code !== undefined
        ? { ok: frame.body.ok, code: frame.body.code }
        : { ok: frame.body.ok };
    }
  }
  throw new Error("no ack");
}

function eventsFor(
  sent: readonly TransportFrame[],
  agent: SigningKeyPair,
  recipient: SigningKeyPair,
) {
  const out: { type: string; inReplyTo: string | null; data: unknown }[] = [];
  for (const frame of sent) {
    if (frame.kind === "event" && frame.route.recipient === fingerprint(recipient.publicKey)) {
      const opened = openTestEvent(frame.body, agent.publicKey, recipient);
      out.push({ type: opened.header.type, inReplyTo: opened.inReplyTo, data: opened.body });
    }
  }
  return out;
}

function makeSession(account: SigningKeyPair, notAfter = NOW + 3_600_000) {
  const key = generateSigningKeyPair();
  const certificate = signSessionCertificate({
    sessionPublicKey: key.publicKey,
    accountKeyPair: account,
    notBefore: NOW - 1000,
    notAfter,
  });
  return { key, certificate };
}

describe("event envelope and reply_to through the command queue", () => {
  test("events carry in_reply_to and are sealed to the session key; the account key cannot read them", async () => {
    const h = makeHarness();
    const session = makeSession(h.owner);

    const command = await h.send("agent.ping", {}, session.key, {
      session: session.certificate,
      replyTo: session.key.publicKey,
    });

    expect(lastAck(h.sent).ok).toBe(true);
    const event = h.sent.find((f) => f.kind === "event");
    expect(event?.kind).toBe("event");
    if (event?.kind !== "event") return;

    expect(event.route.recipient).toBe(fingerprint(session.key.publicKey));
    const opened = openTestEvent(event.body, h.agent.publicKey, session.key);
    expect(opened.header.type).toBe("agent.pong");
    expect(opened.inReplyTo).toBe(command.header.id);
    expect(opened.body).toEqual({ at: NOW });

    // Only the session can decrypt it: the account key is not the recipient.
    expect(() => openTestEvent(event.body, h.agent.publicKey, h.owner)).toThrow();
  });

  test("without reply_to the event is sealed to the account key (previous behaviour)", async () => {
    const h = makeHarness();
    const command = await h.send("agent.ping", {}, h.owner);
    const events = eventsFor(h.sent, h.agent, h.owner);
    expect(events).toHaveLength(1);
    expect(events[0]?.inReplyTo).toBe(command.header.id);
  });

  test("an account-signed command can direct replies to the active session key", async () => {
    const h = makeHarness();
    const session = makeSession(h.owner);
    await h.send("agent.ping", {}, h.owner, { replyTo: session.key.publicKey });
    expect(eventsFor(h.sent, h.agent, session.key)).toHaveLength(1);
    expect(eventsFor(h.sent, h.agent, h.owner)).toHaveLength(0);
  });

  test("a session command whose reply_to is another key is rejected with an error ack", async () => {
    const h = makeHarness();
    const session = makeSession(h.owner);
    const other = generateSigningKeyPair();
    await h.send("agent.ping", {}, session.key, {
      session: session.certificate,
      replyTo: other.publicKey,
    });
    expect(lastAck(h.sent)).toEqual({ ok: false, code: "wrong_recipient" });
    expect(h.sent.some((f) => f.kind === "event")).toBe(false);
  });
});

describe("agent.subscribe", () => {
  test("registers the session key, acks with agent.subscribed and publishes status changes", async () => {
    const h = makeHarness();
    const session = makeSession(h.owner);

    const subscribe = await h.send("agent.subscribe", { topics: ["server.status"] }, session.key, {
      session: session.certificate,
      replyTo: session.key.publicKey,
    });
    expect(lastAck(h.sent).ok).toBe(true);
    expect(h.queue.subscriberCount()).toBe(1);
    const subscribed = eventsFor(h.sent, h.agent, session.key);
    expect(subscribed[0]).toEqual({
      type: "agent.subscribed",
      inReplyTo: subscribe.header.id,
      data: { topics: ["server.status"] },
    });

    h.queue.publish(
      "server.status",
      "server.status.changed",
      { server_id: "survival", state: "running", at: NOW },
      { serverId: "survival" },
    );
    const events = eventsFor(h.sent, h.agent, session.key);
    expect(events).toHaveLength(2);
    expect(events[1]).toEqual({
      type: "server.status.changed",
      inReplyTo: subscribe.header.id,
      data: { server_id: "survival", state: "running", at: NOW },
    });
    // The account key never receives the session's subscription events.
    expect(eventsFor(h.sent, h.agent, h.owner)).toHaveLength(0);
  });

  test("the subscription expires with the session certificate", async () => {
    const h = makeHarness();
    const session = makeSession(h.owner, NOW + 60_000);
    await h.send("agent.subscribe", { topics: ["server.status"] }, session.key, {
      session: session.certificate,
      replyTo: session.key.publicKey,
    });

    const change = { server_id: "survival", state: "stopped", at: NOW };
    h.queue.publish("server.status", "server.status.changed", change, { serverId: "survival" });
    expect(eventsFor(h.sent, h.agent, session.key)).toHaveLength(2);

    h.clock.now = NOW + 60_000;
    h.queue.publish("server.status", "server.status.changed", change, { serverId: "survival" });
    expect(eventsFor(h.sent, h.agent, session.key)).toHaveLength(2);
    expect(h.queue.subscriberCount()).toBe(0);
  });

  test("a revoked session stops receiving events", async () => {
    const harness = makeHarness();
    const session = makeSession(harness.owner);
    await harness.send("agent.subscribe", { topics: ["server.status"] }, session.key, {
      session: session.certificate,
      replyTo: session.key.publicKey,
    });
    const trust = harness.trust as ReturnType<typeof createInMemoryTrustContext>;
    trust.revokeSession(session.certificate.id);
    harness.queue.publish(
      "server.status",
      "server.status.changed",
      { server_id: "a", state: "running", at: NOW },
      { serverId: "a" },
    );
    expect(eventsFor(harness.sent, harness.agent, session.key)).toHaveLength(1);
  });

  test("unsubscribe stops the events", async () => {
    const h = makeHarness();
    const session = makeSession(h.owner);
    const options = { session: session.certificate, replyTo: session.key.publicKey };
    await h.send("agent.subscribe", { topics: ["server.status"] }, session.key, options);
    await h.send("agent.unsubscribe", { topics: ["server.status"] }, session.key, options);
    expect(lastAck(h.sent).ok).toBe(true);
    expect(h.queue.subscriberCount()).toBe(0);
    const before = eventsFor(h.sent, h.agent, session.key).length;
    h.queue.publish(
      "server.status",
      "server.status.changed",
      { server_id: "a", state: "running", at: NOW },
      { serverId: "a" },
    );
    expect(eventsFor(h.sent, h.agent, session.key)).toHaveLength(before);
  });

  test("limits subscribers to 16 per agent but lets an existing one renew", async () => {
    const h = makeHarness();
    const sessions = Array.from({ length: MAX_SUBSCRIBERS + 1 }, () => makeSession(h.owner));
    for (const session of sessions.slice(0, MAX_SUBSCRIBERS)) {
      await h.send("agent.subscribe", { topics: ["server.status"] }, session.key, {
        session: session.certificate,
        replyTo: session.key.publicKey,
      });
      expect(lastAck(h.sent).ok).toBe(true);
    }
    expect(h.queue.subscriberCount()).toBe(MAX_SUBSCRIBERS);

    const extra = sessions[MAX_SUBSCRIBERS];
    if (!extra) throw new Error("missing session");
    await h.send("agent.subscribe", { topics: ["server.status"] }, extra.key, {
      session: extra.certificate,
      replyTo: extra.key.publicKey,
    });
    expect(lastAck(h.sent)).toEqual({ ok: false, code: "too_many_subscribers" });

    const first = sessions[0];
    if (!first) throw new Error("missing session");
    await h.send("agent.subscribe", { topics: ["server.status"] }, first.key, {
      session: first.certificate,
      replyTo: first.key.publicKey,
    });
    expect(lastAck(h.sent).ok).toBe(true);
  });

  test("rejects unknown topics and extra fields", async () => {
    const h = makeHarness();
    expect(() =>
      createSignedCommand(
        {
          type: "agent.subscribe",
          body: { topics: ["server.console"] },
          agentPublicKey: h.agent.publicKey,
          signer: h.owner,
          counter: 1,
          now: NOW,
        },
        h.registry,
      ),
    ).toThrow();
    expect(() =>
      createSignedCommand(
        {
          type: "agent.subscribe",
          body: { topics: [] },
          agentPublicKey: h.agent.publicKey,
          signer: h.owner,
          counter: 1,
          now: NOW,
        },
        h.registry,
      ),
    ).toThrow();
  });
});

describe("team roles through the command queue", () => {
  function memberHarness() {
    const h = makeHarness();
    const member = generateSigningKeyPair();
    const memberSession = makeSession(member);
    return { h, member, memberSession };
  }

  function grantFor(
    h: Harness,
    granter: SigningKeyPair,
    member: SigningKeyPair,
    role: GrantableRole,
    servers: readonly string[] | "*",
    extra: { agent?: string; issuedAt?: number; expiresAt?: number } = {},
  ): RoleGrant {
    return signRoleGrant({
      granter,
      accountPublicKey: member.publicKey,
      agent: extra.agent ?? h.agentId,
      servers,
      role,
      issuedAt: extra.issuedAt ?? NOW,
      ...(extra.expiresAt !== undefined ? { expiresAt: extra.expiresAt } : {}),
    });
  }

  test("an owner grants a role, the member can act within it and nowhere else", async () => {
    const { h, member } = memberHarness();
    const grant = grantFor(h, h.owner, member, "operator", ["alpha"]);
    await h.send("agent.members.set", { grant }, h.owner);
    expect(lastAck(h.sent).ok).toBe(true);
    const updated = eventsFor(h.sent, h.agent, h.owner).find(
      (e) => e.type === "agent.members.updated",
    );
    expect(updated?.data).toEqual({
      account: fingerprint(member.publicKey),
      role: "operator",
      servers: ["alpha"],
    });

    // A handler is only registered for some commands in this harness; a role rejection comes first.
    await h.send("server.start", { server_id: "alpha" }, member);
    expect(lastAck(h.sent)).toEqual({ ok: false, code: "no_handler" });
    await h.send("server.start", { server_id: "beta" }, member);
    expect(lastAck(h.sent)).toEqual({ ok: false, code: "insufficient_role" });
    await h.send("files.read", { server_id: "alpha", path: "a" }, member);
    expect(lastAck(h.sent)).toEqual({ ok: false, code: "insufficient_role" });
  });

  test("a grant signed by someone other than the sender is refused", async () => {
    const { h, member } = memberHarness();
    const forger = generateSigningKeyPair();
    const forged = grantFor(h, forger, member, "admin", "*");
    await h.send("agent.members.set", { grant: forged }, h.owner);
    expect(lastAck(h.sent)).toEqual({ ok: false, code: "role_grant_invalid" });
    await h.send("server.start", { server_id: "alpha" }, member);
    expect(lastAck(h.sent).code).toBe("untrusted_signer");
  });

  test("a grant that is for another agent, expired, or tampered is refused", async () => {
    const { h, member } = memberHarness();
    const otherAgent = fingerprint(generateSigningKeyPair().publicKey);

    await h.send(
      "agent.members.set",
      { grant: grantFor(h, h.owner, member, "viewer", "*", { agent: otherAgent }) },
      h.owner,
    );
    expect(lastAck(h.sent).code).toBe("role_grant_invalid");

    await h.send(
      "agent.members.set",
      {
        grant: grantFor(h, h.owner, member, "viewer", "*", {
          issuedAt: NOW - 10_000,
          expiresAt: NOW - 1,
        }),
      },
      h.owner,
    );
    expect(lastAck(h.sent).code).toBe("role_grant_invalid");

    const good = grantFor(h, h.owner, member, "viewer", ["alpha"]);
    await h.send("agent.members.set", { grant: { ...good, servers: "*" } }, h.owner);
    expect(lastAck(h.sent).code).toBe("role_grant_invalid");
    await h.send("agent.members.set", { grant: { ...good, role: "admin" } }, h.owner);
    expect(lastAck(h.sent).code).toBe("role_grant_invalid");

    expect(h.trust.roleFor(fingerprint(member.publicKey), "alpha")).toBeNull();
  });

  test("members.set and members.revoke are sensitive: a session signature is refused", async () => {
    const h = makeHarness();
    const session = makeSession(h.owner);
    const member = generateSigningKeyPair();
    await h.send(
      "agent.members.set",
      { grant: grantFor(h, h.owner, member, "viewer", "*") },
      session.key,
      { session: session.certificate, replyTo: session.key.publicKey },
    );
    expect(lastAck(h.sent)).toEqual({ ok: false, code: "sensitive_requires_account_key" });

    await h.send("agent.members.revoke", { account: fingerprint(member.publicKey) }, session.key, {
      session: session.certificate,
      replyTo: session.key.publicKey,
    });
    expect(lastAck(h.sent)).toEqual({ ok: false, code: "sensitive_requires_account_key" });
  });

  test("an admin can grant up to editor but not admin, and cannot touch owners or equal roles", async () => {
    const h = makeHarness();
    const admin = generateSigningKeyPair();
    const peer = generateSigningKeyPair();
    const viewer = generateSigningKeyPair();
    await h.send(
      "agent.members.set",
      { grant: grantFor(h, h.owner, admin, "admin", "*") },
      h.owner,
    );
    await h.send("agent.members.set", { grant: grantFor(h, h.owner, peer, "admin", "*") }, h.owner);
    await h.send(
      "agent.members.set",
      { grant: grantFor(h, h.owner, viewer, "viewer", "*") },
      h.owner,
    );
    expect(lastAck(h.sent).ok).toBe(true);

    const newcomer = generateSigningKeyPair();
    await h.send(
      "agent.members.set",
      { grant: grantFor(h, admin, newcomer, "editor", ["alpha"]) },
      admin,
    );
    expect(lastAck(h.sent).ok).toBe(true);
    expect(h.trust.roleFor(fingerprint(newcomer.publicKey), "alpha")).toBe("editor");

    const another = generateSigningKeyPair();
    await h.send("agent.members.set", { grant: grantFor(h, admin, another, "admin", "*") }, admin);
    expect(lastAck(h.sent).code).toBe("role_grant_invalid");

    // Cannot demote/replace a peer admin or an owner.
    await h.send("agent.members.set", { grant: grantFor(h, admin, peer, "viewer", "*") }, admin);
    expect(lastAck(h.sent).code).toBe("role_grant_invalid");
    await h.send("agent.members.set", { grant: grantFor(h, admin, h.owner, "viewer", "*") }, admin);
    expect(lastAck(h.sent).code).toBe("role_grant_invalid");
    await h.send("agent.members.revoke", { account: fingerprint(peer.publicKey) }, admin);
    expect(lastAck(h.sent).code).toBe("role_grant_invalid");
    await h.send("agent.members.revoke", { account: fingerprint(h.owner.publicKey) }, admin);
    expect(lastAck(h.sent).code).toBe("role_grant_invalid");

    // A viewer cannot manage members at all.
    await h.send(
      "agent.members.set",
      { grant: grantFor(h, viewer, another, "viewer", "*") },
      viewer,
    );
    expect(lastAck(h.sent).code).toBe("insufficient_role");

    // An admin cannot grant itself or turn a grant into something it could not give.
    await h.send("agent.members.set", { grant: grantFor(h, admin, admin, "viewer", "*") }, admin);
    expect(lastAck(h.sent).code).toBe("role_grant_invalid");
  });

  test("revoke removes access, scoped or entirely", async () => {
    const { h, member } = memberHarness();
    await h.send(
      "agent.members.set",
      { grant: grantFor(h, h.owner, member, "operator", ["a", "b"]) },
      h.owner,
    );
    const id = fingerprint(member.publicKey);
    expect(h.trust.roleFor(id, "a")).toBe("operator");

    await h.send("agent.members.revoke", { account: id, servers: ["a"] }, h.owner);
    expect(lastAck(h.sent).ok).toBe(true);
    expect(h.trust.roleFor(id, "a")).toBeNull();
    expect(h.trust.roleFor(id, "b")).toBe("operator");

    await h.send("agent.members.revoke", { account: id }, h.owner);
    const revoked = eventsFor(h.sent, h.agent, h.owner).filter(
      (e) => e.type === "agent.members.revoked",
    );
    expect(revoked.at(-1)?.data).toEqual({ account: id, count: 1 });
    expect(h.trust.roleFor(id, "b")).toBeNull();
    await h.send("server.start", { server_id: "b" }, member);
    expect(lastAck(h.sent).code).toBe("untrusted_signer");
  });

  test("an expired role stops working", async () => {
    const { h, member } = memberHarness();
    await h.send(
      "agent.members.set",
      { grant: grantFor(h, h.owner, member, "viewer", "*", { expiresAt: NOW + 5000 }) },
      h.owner,
    );
    await h.send("agent.ping", {}, member);
    expect(lastAck(h.sent).ok).toBe(true);
    h.clock.now = NOW + 5000;
    await h.send("agent.ping", {}, member);
    expect(lastAck(h.sent).code).toBe("untrusted_signer");
  });

  test("status events are only published to subscribers that may see the server", async () => {
    const { h, member } = memberHarness();
    await h.send(
      "agent.members.set",
      { grant: grantFor(h, h.owner, member, "viewer", ["alpha"]) },
      h.owner,
    );
    const memberSessionKey = makeSession(member);
    await h.send("agent.subscribe", { topics: ["server.status"] }, memberSessionKey.key, {
      session: memberSessionKey.certificate,
      replyTo: memberSessionKey.key.publicKey,
    });
    expect(lastAck(h.sent).ok).toBe(true);

    h.queue.publish(
      "server.status",
      "server.status.changed",
      { server_id: "alpha", state: "running", at: NOW },
      { serverId: "alpha" },
    );
    h.queue.publish(
      "server.status",
      "server.status.changed",
      { server_id: "beta", state: "running", at: NOW },
      { serverId: "beta" },
    );
    const events = eventsFor(h.sent, h.agent, memberSessionKey.key).filter(
      (e) => e.type === "server.status.changed",
    );
    expect(events.map((e) => (e.data as { server_id: string }).server_id)).toEqual(["alpha"]);
  });

  test("members persist in members.json with 0600 and survive a restart", async () => {
    const dir = makeTempDir();
    const owner = generateSigningKeyPair();
    const agent = generateSigningKeyPair();
    const member = generateSigningKeyPair();
    const clock = { now: NOW };
    const build = () => {
      const trust = createFileTrustContext({
        stateDir: dir,
        agentKeyPair: agent,
        trustedAccountKeys: [owner.publicKey],
        now: () => clock.now,
      });
      const registry = createCoreRegistry();
      const sent: TransportFrame[] = [];
      const queue = createCommandQueue({
        trust,
        registry,
        sendFrame: (f) => sent.push(f),
        logger: silentLogger,
      });
      return { trust, registry, sent, queue };
    };

    const first = build();
    const grant = signRoleGrant({
      granter: owner,
      accountPublicKey: member.publicKey,
      agent: fingerprint(agent.publicKey),
      servers: ["alpha"],
      role: "editor",
      issuedAt: NOW,
    });
    const command = createSignedCommand(
      {
        type: "agent.members.set",
        body: { grant },
        agentPublicKey: agent.publicKey,
        signer: owner,
        counter: 1,
        now: NOW,
      },
      first.registry,
    );
    await first.queue.enqueue({
      v: PROTOCOL_VERSION,
      kind: "command",
      route: { agent: fingerprint(agent.publicKey) },
      body: command,
    });
    expect(lastAck(first.sent).ok).toBe(true);

    const { membersPath } = getStatePaths(dir);
    expect(existsSync(membersPath)).toBe(true);
    if (process.platform !== "win32") {
      expect(statSync(membersPath).mode & 0o777).toBe(0o600);
    }
    expect(loadMembers(dir)).toHaveLength(1);

    const second = build();
    const id = fingerprint(member.publicKey);
    expect(second.trust.roleFor(id, "alpha")).toBe("editor");
    expect(second.trust.roleFor(id, "beta")).toBeNull();
    expect(second.trust.roleFor(fingerprint(owner.publicKey), "beta")).toBe("owner");
    expect(second.trust.isTrustedAccountKey(id)).not.toBeNull();
  });
});

describe("connection hello / auth", () => {
  class FakeSocket implements WebSocketLike {
    readyState = 0;
    onopen: (() => void) | null = null;
    onmessage: ((event: WebSocketMessageEventLike) => void) | null = null;
    onclose: ((event: WebSocketCloseEventLike) => void) | null = null;
    onerror: ((event: unknown) => void) | null = null;
    readonly sent: string[] = [];
    readonly closes: { code?: number; reason?: string }[] = [];
    send(data: string): void {
      this.sent.push(data);
    }
    close(code?: number, reason?: string): void {
      this.closes.push({
        ...(code !== undefined ? { code } : {}),
        ...(reason !== undefined ? { reason } : {}),
      });
      this.readyState = 3;
      this.onclose?.({ ...(code !== undefined ? { code } : {}) });
    }
    open(): void {
      this.readyState = 1;
      this.onopen?.();
    }
    receive(frame: unknown): void {
      this.onmessage?.({ data: JSON.stringify(frame) });
    }
  }

  const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

  test("queued frames wait for the auth frame; the API can verify it; commands arrive afterwards", async () => {
    const agent = generateSigningKeyPair();
    const agentId = fingerprint(agent.publicKey);
    const sockets: FakeSocket[] = [];
    const received: TransportFrame[] = [];
    const { signAgentAuth } = await import("../protocol");

    const connection = createAgentConnection({
      apiUrl: "https://api.tegra.example",
      agentId,
      logger: silentLogger,
      webSocketFactory: (url) => {
        expect(url).toBe(`wss://api.tegra.example/v1/agents/connect?agent=${agentId}`);
        const socket = new FakeSocket();
        sockets.push(socket);
        return socket;
      },
      answerHello: (hello) => signAgentAuth({ agentKeyPair: agent, hello, ts: NOW }),
      onFrame: (frame) => received.push(frame),
    });

    connection.start();
    const socket = sockets[0];
    if (!socket) throw new Error("no socket");
    socket.open();
    await tick();

    // Before the challenge there is nothing sent and the connection is not usable.
    expect(connection.isConnected()).toBe(false);
    const ping: TransportFrame = {
      v: PROTOCOL_VERSION,
      kind: "ping",
      route: { agent: agentId },
      body: { ts: 1 },
    };
    expect(connection.send(ping)).toBe(false);
    expect(socket.sent).toHaveLength(0);

    // Frames other than hello are dropped while waiting for it.
    socket.receive(ping);
    expect(received).toHaveLength(0);

    const hello = createHelloFrame({ agent: agentId, serverTime: NOW });
    socket.receive(hello);
    await tick();

    expect(socket.sent.length).toBeGreaterThanOrEqual(2);
    const auth = JSON.parse(socket.sent[0] ?? "null");
    expect(auth.kind).toBe("auth");
    expect(() =>
      verifyAgentAuth(auth, {
        agentPublicKey: agent.publicKey,
        expectedNonce: hello.body.nonce,
        now: NOW,
      }),
    ).not.toThrow();
    expect(JSON.parse(socket.sent[1] ?? "null").kind).toBe("ping");
    expect(connection.isConnected()).toBe(true);

    socket.receive(ping);
    expect(received).toHaveLength(1);

    // A hello after authentication is not forwarded and does not trigger a second auth.
    const sentBefore = socket.sent.length;
    socket.receive(createHelloFrame({ agent: agentId, serverTime: NOW }));
    await tick();
    expect(socket.sent).toHaveLength(sentBefore);
    expect(received).toHaveLength(1);
    connection.stop();
  });

  test("reconnects when no hello arrives in time", async () => {
    const agent = generateSigningKeyPair();
    const agentId = fingerprint(agent.publicKey);
    const sockets: FakeSocket[] = [];
    const { signAgentAuth } = await import("../protocol");
    const connection = createAgentConnection({
      apiUrl: "https://api.tegra.example",
      agentId,
      logger: silentLogger,
      webSocketFactory: () => {
        const socket = new FakeSocket();
        sockets.push(socket);
        return socket;
      },
      answerHello: (hello) => signAgentAuth({ agentKeyPair: agent, hello, ts: NOW }),
      onFrame: () => {},
      helloTimeoutMs: 20,
    });
    connection.start();
    sockets[0]?.open();
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(sockets[0]?.closes[0]?.code).toBe(4002);
    expect(connection.isConnected()).toBe(false);
    connection.stop();
  });

  test("a hello for another agent makes the connection drop instead of authenticating", async () => {
    const agent = generateSigningKeyPair();
    const agentId = fingerprint(agent.publicKey);
    const sockets: FakeSocket[] = [];
    const { signAgentAuth } = await import("../protocol");
    const connection = createAgentConnection({
      apiUrl: "https://api.tegra.example",
      agentId,
      logger: silentLogger,
      webSocketFactory: () => {
        const socket = new FakeSocket();
        sockets.push(socket);
        return socket;
      },
      answerHello: (hello) => signAgentAuth({ agentKeyPair: agent, hello, ts: NOW }),
      onFrame: () => {},
    });
    connection.start();
    const socket = sockets[0];
    socket?.open();
    await tick();
    const stranger = fingerprint(generateSigningKeyPair().publicKey);
    socket?.receive({
      v: PROTOCOL_VERSION,
      kind: "hello",
      route: { agent: stranger },
      body: {
        nonce: createHelloFrame({ agent: stranger, serverTime: NOW }).body.nonce,
        server_time: NOW,
      },
    });
    await tick();
    expect(socket?.sent).toHaveLength(0);
    expect(socket?.closes[0]?.code).toBe(4001);
    connection.stop();
  });
});

describe("agent API client", () => {
  test("signs the backup upload URL request and parses the target", async () => {
    const agent = generateSigningKeyPair();
    const seen: { url: string; method: string; body: string; headers: Headers }[] = [];
    const client = createAgentApiClient({
      apiUrl: "https://api.tegra.example",
      agentKeyPair: agent,
      now: () => NOW,
      fetch: async (input, init) => {
        seen.push({
          url: String(input),
          method: init?.method ?? "GET",
          body: String(init?.body ?? ""),
          headers: new Headers(init?.headers),
        });
        return new Response(
          JSON.stringify({
            put_url: "https://storage.tegra.example/put?sig=abc",
            headers: { "x-amz-meta-a": "1" },
            expires_at: NOW + 60_000,
            max_bytes: 1024,
          }),
          { status: 200 },
        );
      },
    });

    const target = await client.requestBackupUploadUrl({ server_id: "survival", size_bytes: 10 });
    expect(target).toEqual({
      put_url: "https://storage.tegra.example/put?sig=abc",
      headers: { "x-amz-meta-a": "1" },
      expires_at: NOW + 60_000,
      max_bytes: 1024,
    });
    const request = seen[0];
    if (!request) throw new Error("no request");
    expect(request.url).toBe("https://api.tegra.example/v1/agents/self/backup-upload-url");
    expect(request.method).toBe("POST");
    expect(JSON.parse(request.body)).toEqual({ server_id: "survival", size_bytes: 10 });

    // The API can verify exactly what was signed.
    const verify = () =>
      verifyAgentRequest({
        getHeader: (name) => request.headers.get(name),
        method: request.method,
        pathWithQuery: new URL(request.url).pathname,
        body: request.body,
        agentPublicKey: agent.publicKey,
        now: NOW + 1000,
      });
    expect(verify().agent).toBe(fingerprint(agent.publicKey));
    // ...and rejects it once the timestamp is stale.
    expect(() =>
      verifyAgentRequest({
        getHeader: (name) => request.headers.get(name),
        method: request.method,
        pathWithQuery: new URL(request.url).pathname,
        body: request.body,
        agentPublicKey: agent.publicKey,
        now: NOW + 120_000,
      }),
    ).toThrow();
    // ...or when the body was altered.
    expect(() =>
      verifyAgentRequest({
        getHeader: (name) => request.headers.get(name),
        method: request.method,
        pathWithQuery: new URL(request.url).pathname,
        body: request.body.replace("10", "99999"),
        agentPublicKey: agent.publicKey,
        now: NOW,
      }),
    ).toThrow();
  });

  test("maps quota, rate limit, server errors and malformed bodies to stable codes", async () => {
    const agent = generateSigningKeyPair();
    function clientFor(response: () => Response | Promise<Response>) {
      return createAgentApiClient({
        apiUrl: "https://api.tegra.example",
        agentKeyPair: agent,
        now: () => NOW,
        fetch: async () => response(),
      });
    }
    const request = { server_id: "survival", size_bytes: 10 };
    await expect(
      clientFor(() => new Response("", { status: 413 })).requestBackupUploadUrl(request),
    ).rejects.toMatchObject({ code: "quota_exceeded" });
    await expect(
      clientFor(() => new Response("", { status: 429 })).requestBackupUploadUrl(request),
    ).rejects.toMatchObject({ code: "rate_limited" });
    await expect(
      clientFor(() => new Response("", { status: 500 })).requestBackupUploadUrl(request),
    ).rejects.toMatchObject({ code: "http_error" });
    await expect(
      clientFor(() => new Response("not json", { status: 200 })).requestBackupUploadUrl(request),
    ).rejects.toMatchObject({ code: "invalid_response" });
    await expect(
      clientFor(
        () => new Response(JSON.stringify({ put_url: "x" }), { status: 200 }),
      ).requestBackupUploadUrl(request),
    ).rejects.toMatchObject({ code: "invalid_response" });
    await expect(
      clientFor(() => {
        throw new Error("boom");
      }).requestBackupUploadUrl(request),
    ).rejects.toBeInstanceOf(AgentApiError);
    await expect(
      clientFor(() => new Response("x".repeat(70 * 1024), { status: 200 })).requestBackupUploadUrl(
        request,
      ),
    ).rejects.toMatchObject({ code: "response_too_large" });
  });

  test("refuses a non-https api_url", () => {
    expect(() =>
      createAgentApiClient({
        apiUrl: "http://api.tegra.example",
        agentKeyPair: generateSigningKeyPair(),
      }),
    ).toThrow();
  });

  test("signs POST /v1/agents/self/backups/:id/confirm with an empty body and maps errors", async () => {
    const agent = generateSigningKeyPair();
    const seen: { url: string; method: string; body: unknown; headers: Headers }[] = [];
    const client = createAgentApiClient({
      apiUrl: "https://api.tegra.example",
      agentKeyPair: agent,
      now: () => NOW,
      fetch: async (input, init) => {
        seen.push({
          url: String(input),
          method: init?.method ?? "GET",
          body: init?.body,
          headers: new Headers(init?.headers),
        });
        return new Response(
          JSON.stringify({ id: "bkp_cloud_1", size_bytes: 4096, status: "stored" }),
          { status: 200 },
        );
      },
    });

    const confirmed = await client.confirmBackupUpload("bkp_cloud_1");
    expect(confirmed).toEqual({ id: "bkp_cloud_1", size_bytes: 4096, status: "stored" });
    const req = seen[0];
    if (!req) throw new Error("no confirm request");
    expect(req.url).toBe("https://api.tegra.example/v1/agents/self/backups/bkp_cloud_1/confirm");
    expect(req.method).toBe("POST");
    expect(req.body).toBeUndefined();
    expect(req.headers.get("content-type")).toBeNull();
    expect(
      verifyAgentRequest({
        getHeader: (name) => req.headers.get(name),
        method: req.method,
        pathWithQuery: new URL(req.url).pathname,
        body: "",
        agentPublicKey: agent.publicKey,
        now: NOW,
      }).agent,
    ).toBe(fingerprint(agent.publicKey));

    // Rejects invalid backup id locally without issuing a request
    await expect(client.confirmBackupUpload("../bad")).rejects.toMatchObject({
      code: "invalid_response",
    });
    expect(seen).toHaveLength(1);

    function clientFor(status: number, body = "") {
      return createAgentApiClient({
        apiUrl: "https://api.tegra.example",
        agentKeyPair: agent,
        now: () => NOW,
        fetch: async () => new Response(body, { status }),
      });
    }
    await expect(clientFor(413).confirmBackupUpload("b1")).rejects.toMatchObject({
      code: "quota_exceeded",
    });
    await expect(clientFor(429).confirmBackupUpload("b1")).rejects.toMatchObject({
      code: "rate_limited",
    });
    await expect(clientFor(409).confirmBackupUpload("b1")).rejects.toMatchObject({
      code: "http_error",
      status: 409,
    });
    await expect(clientFor(200, "not json").confirmBackupUpload("b1")).rejects.toMatchObject({
      code: "invalid_response",
    });
    await expect(clientFor(204).confirmBackupUpload("b1")).resolves.toEqual({
      id: "b1",
      size_bytes: 0,
      status: "stored",
    });
  });
});

describe("agent.subscribe server.backup topic", () => {
  test("publishes server.backup.upload only to authorized subscribers of server.backup", async () => {
    const h = makeHarness();
    const member = generateSigningKeyPair();
    await h.send(
      "agent.members.set",
      {
        grant: signRoleGrant({
          granter: h.owner,
          accountPublicKey: member.publicKey,
          agent: h.agentId,
          servers: ["alpha"],
          role: "viewer",
          issuedAt: NOW,
        }),
      },
      h.owner,
    );

    const session = makeSession(member);
    await h.send("agent.subscribe", { topics: ["server.backup"] }, session.key, {
      session: session.certificate,
      replyTo: session.key.publicKey,
    });
    expect(lastAck(h.sent).ok).toBe(true);

    h.queue.publish(
      "server.backup",
      "server.backup.upload",
      {
        server_id: "alpha",
        backup_id: "bkp-1",
        destination: "tegra_cloud",
        state: "uploading",
        sent_bytes: 128,
        total_bytes: 256,
      },
      { serverId: "alpha" },
    );
    h.queue.publish(
      "server.backup",
      "server.backup.upload",
      {
        server_id: "beta",
        backup_id: "bkp-2",
        destination: "tegra_cloud",
        state: "uploading",
        sent_bytes: 128,
        total_bytes: 256,
      },
      { serverId: "beta" },
    );

    const backupEvents = eventsFor(h.sent, h.agent, session.key).filter(
      (e) => e.type === "server.backup.upload",
    );
    expect(backupEvents).toHaveLength(1);
    const firstBackupEvent = backupEvents[0];
    if (!firstBackupEvent) throw new Error("Expected server.backup.upload event");
    expect((firstBackupEvent.data as { server_id: string }).server_id).toBe("alpha");
  });
});

describe("server status watcher", () => {
  test("maps systemd states to client states", () => {
    expect(mapUnitState("active")).toBe("running");
    expect(mapUnitState("activating")).toBe("starting");
    expect(mapUnitState("deactivating")).toBe("stopping");
    expect(mapUnitState("inactive")).toBe("stopped");
    expect(mapUnitState("failed")).toBe("crashed");
    expect(mapUnitState("maintenance")).toBeNull();
  });

  test("polling sets a silent baseline and then emits every change once", async () => {
    const states = new Map<string, "stopped" | "starting" | "running" | "stopping" | "crashed">([
      ["a", "stopped"],
      ["b", "running"],
    ]);
    const emitted: { server_id: string; state: string; at: number }[] = [];
    const watcher = createServerStatusWatcher({
      listServerIds: () => [...states.keys()],
      getState: async (id) => states.get(id) ?? null,
      emit: (change) => emitted.push(change),
      now: () => NOW,
    });

    await watcher.pollOnce();
    expect(emitted).toHaveLength(0);

    states.set("a", "starting");
    await watcher.pollOnce();
    await watcher.pollOnce();
    expect(emitted).toEqual([{ server_id: "a", state: "starting", at: NOW }]);

    states.set("a", "running");
    states.set("b", "crashed");
    await watcher.pollOnce();
    expect(emitted.map((e) => `${e.server_id}:${e.state}`)).toEqual([
      "a:starting",
      "a:running",
      "b:crashed",
    ]);
  });

  test("refresh emits even without a baseline, forget clears it, and a failing read is ignored", async () => {
    let state: "running" | "stopped" = "running";
    let fail = false;
    const emitted: string[] = [];
    const watcher = createServerStatusWatcher({
      listServerIds: () => ["a"],
      getState: async () => {
        if (fail) throw new Error("systemctl failed");
        return state;
      },
      emit: (change) => emitted.push(change.state),
      now: () => NOW,
    });
    await watcher.refresh("a");
    await watcher.refresh("a");
    expect(emitted).toEqual(["running"]);
    state = "stopped";
    fail = true;
    await watcher.refresh("a");
    expect(emitted).toEqual(["running"]);
    fail = false;
    await watcher.refresh("a");
    expect(emitted).toEqual(["running", "stopped"]);
    watcher.forget("a");
    await watcher.refresh("a");
    expect(emitted).toEqual(["running", "stopped", "stopped"]);
  });

  test("the timer only polls while shouldPoll says so", async () => {
    const timer: { tick: (() => void) | null } = { tick: null };
    let polls = 0;
    let wanted = false;
    const watcher = createServerStatusWatcher({
      listServerIds: () => {
        polls++;
        return [];
      },
      getState: async () => null,
      emit: () => {},
      shouldPoll: () => wanted,
      timers: {
        setInterval: (fn) => {
          timer.tick = fn;
          return 1;
        },
        clearInterval: () => {
          timer.tick = null;
        },
      },
    });
    watcher.start();
    timer.tick?.();
    await Promise.resolve();
    expect(polls).toBe(0);
    wanted = true;
    timer.tick?.();
    await Promise.resolve();
    expect(polls).toBe(1);
    watcher.stop();
    expect(timer.tick).toBeNull();
  });
});

describe("pairing API client signs its requests", () => {
  test("register, poll and delete carry a signature the API can verify", async () => {
    const agent = generateSigningKeyPair();
    const seen: { url: string; method: string; body: string | undefined; headers: Headers }[] = [];
    const api = createPairingApiClient({
      apiUrl: "https://api.tegra.example",
      agentKeyPair: agent,
      now: () => NOW,
      fetch: async (input, init) => {
        seen.push({
          url: String(input),
          method: init?.method ?? "GET",
          body: typeof init?.body === "string" ? init.body : undefined,
          headers: new Headers(init?.headers),
        });
        return new Response(null, { status: init?.method === "POST" ? 201 : 202 });
      },
    });

    await api.registerPairing("0123456789", toBase64Url(agent.publicKey));
    await api.pollGrant("0123456789");
    await api.deletePairing("0123456789");

    expect(seen.map((r) => `${r.method} ${new URL(r.url).pathname}`)).toEqual([
      "POST /v1/agents/pairing",
      "GET /v1/agents/pairing/0123456789/grant",
      "DELETE /v1/agents/pairing/0123456789",
    ]);
    for (const request of seen) {
      const verified = verifyAgentRequest({
        getHeader: (name) => request.headers.get(name),
        method: request.method,
        pathWithQuery: new URL(request.url).pathname,
        body: request.body,
        agentPublicKey: agent.publicKey,
        now: NOW,
      });
      expect(verified.agent).toBe(fingerprint(agent.publicKey));
    }
  });
});

describe("events that outlive their command", () => {
  test("a held ctx stops delivering once the member's role is revoked or the certificate expires", async () => {
    const h = makeHarness();
    const member = generateSigningKeyPair();
    const session = makeSession(member, NOW + 60_000);
    await h.send(
      "agent.members.set",
      {
        grant: signRoleGrant({
          granter: h.owner,
          accountPublicKey: member.publicKey,
          agent: h.agentId,
          servers: ["alpha"],
          role: "viewer",
          issuedAt: NOW,
        }),
      },
      h.owner,
    );
    const held: { ctx: { sendEvent(type: string, data: unknown): void } | null } = { ctx: null };
    h.queue.registerHandler("server.console.subscribe", (_opened, ctx) => {
      held.ctx = ctx;
    });
    const options = { session: session.certificate, replyTo: session.key.publicKey };
    await h.send("server.console.subscribe", { server_id: "alpha" }, session.key, options);
    expect(lastAck(h.sent).ok).toBe(true);

    held.ctx?.sendEvent("server.console.lines", { n: 1 });
    expect(eventsFor(h.sent, h.agent, session.key)).toHaveLength(1);

    await h.send("agent.members.revoke", { account: fingerprint(member.publicKey) }, h.owner);
    held.ctx?.sendEvent("server.console.lines", { n: 2 });
    expect(eventsFor(h.sent, h.agent, session.key)).toHaveLength(1);
  });

  test("an expired session certificate stops a held stream", async () => {
    const h = makeHarness();
    const session = makeSession(h.owner, NOW + 60_000);
    const held: { ctx: { sendEvent(type: string, data: unknown): void } | null } = { ctx: null };
    h.queue.registerHandler("server.console.subscribe", (_opened, ctx) => {
      held.ctx = ctx;
    });
    await h.send("server.console.subscribe", { server_id: "alpha" }, session.key, {
      session: session.certificate,
      replyTo: session.key.publicKey,
    });
    held.ctx?.sendEvent("server.console.lines", { n: 1 });
    h.clock.now = NOW + 60_000;
    held.ctx?.sendEvent("server.console.lines", { n: 2 });
    expect(eventsFor(h.sent, h.agent, session.key)).toHaveLength(1);
  });
});
