// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { beforeAll, describe, expect, test } from "bun:test";
import { fingerprint, generateSigningKeyPair, ready } from "../crypto";
import {
  createCoreRegistry,
  createInMemoryTrustContext,
  createSignedCommand,
  openAgentMessage,
  PROTOCOL_VERSION,
  type SignedCommand,
  type TransportFrame,
} from "../protocol";
import { createCommandQueue, type TransportCommandFrame } from "./jobs";
import { createLogger } from "./logger";

beforeAll(async () => {
  await ready();
});

function wrapCommand(agentId: string, body: SignedCommand): TransportCommandFrame {
  return {
    v: PROTOCOL_VERSION,
    kind: "command",
    route: { agent: agentId },
    body,
  };
}

function makeSilentLogger(logs: string[] = []) {
  return createLogger({
    level: "debug",
    stdout: (line) => logs.push(line),
    stderr: (line) => logs.push(line),
  });
}

describe("command queue", () => {
  test("executes built-in agent.ping handler, emits sealed agent.pong event, and acks ok", async () => {
    const agent = generateSigningKeyPair();
    const account = generateSigningKeyPair();
    const agentId = fingerprint(agent.publicKey);
    let now = 1_700_000_000_000;

    const trust = createInMemoryTrustContext({
      agentKeyPair: agent,
      trustedAccountKeys: [account.publicKey],
      now: () => now,
    });
    const registry = createCoreRegistry();
    const sent: TransportFrame[] = [];
    const queue = createCommandQueue({
      trust,
      registry,
      sendFrame: (frame) => sent.push(frame),
      logger: makeSilentLogger(),
    });

    const cmd = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now,
      },
      registry,
    );

    await queue.enqueue(wrapCommand(agentId, cmd));

    expect(sent.length).toBe(2);
    const eventFrame = sent[0];
    const ackFrame = sent[1];

    expect(eventFrame?.kind).toBe("event");
    if (eventFrame?.kind === "event") {
      const opened = openAgentMessage(eventFrame.body, agent.publicKey, account);
      expect(opened.header.type).toBe("agent.pong");
      expect(opened.header.seq).toBe(1);
      expect(opened.body).toEqual({ at: now });
    }

    expect(ackFrame).toEqual({
      v: PROTOCOL_VERSION,
      kind: "ack",
      route: { agent: agentId },
      body: { id: cmd.header.id, ok: true },
    });

    // Second ping increments event seq monotonically
    now += 1000;
    const cmd2 = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 2,
        now,
      },
      registry,
    );
    await queue.enqueue(wrapCommand(agentId, cmd2));
    const eventFrame2 = sent[2];
    expect(eventFrame2?.kind).toBe("event");
    if (eventFrame2?.kind === "event") {
      const opened2 = openAgentMessage(eventFrame2.body, agent.publicKey, account);
      expect(opened2.header.seq).toBe(2);
      expect(opened2.body).toEqual({ at: now });
    }
  });

  test("rejects untrusted, expired, tampered, and replayed commands with ProtocolError codes", async () => {
    const agent = generateSigningKeyPair();
    const account = generateSigningKeyPair();
    const stranger = generateSigningKeyPair();
    const agentId = fingerprint(agent.publicKey);
    const now = 1_700_000_000_000;

    const trust = createInMemoryTrustContext({
      agentKeyPair: agent,
      trustedAccountKeys: [account.publicKey],
      now: () => now,
    });
    const registry = createCoreRegistry();
    const sent: TransportFrame[] = [];
    const queue = createCommandQueue({
      trust,
      registry,
      sendFrame: (frame) => sent.push(frame),
      logger: makeSilentLogger(),
    });

    // Untrusted signer
    const untrusted = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: stranger,
        counter: 1,
        now,
      },
      registry,
    );
    await queue.enqueue(wrapCommand(agentId, untrusted));
    expect(sent.pop()).toEqual({
      v: PROTOCOL_VERSION,
      kind: "ack",
      route: { agent: agentId },
      body: { id: untrusted.header.id, ok: false, code: "untrusted_signer" },
    });

    // Expired command
    const expired = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now: now - 10_000,
        ttlMs: 5_000,
      },
      registry,
    );
    await queue.enqueue(wrapCommand(agentId, expired));
    expect(sent.pop()).toEqual({
      v: PROTOCOL_VERSION,
      kind: "ack",
      route: { agent: agentId },
      body: { id: expired.header.id, ok: false, code: "expired" },
    });

    // Tampered command
    const valid = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 2,
        now,
      },
      registry,
    );
    const tampered: SignedCommand = {
      ...valid,
      header: { ...valid.header, counter: 3 },
    };
    await queue.enqueue(wrapCommand(agentId, tampered));
    expect(sent.pop()).toEqual({
      v: PROTOCOL_VERSION,
      kind: "ack",
      route: { agent: agentId },
      body: { id: tampered.header.id, ok: false, code: "bad_signature" },
    });

    // Valid command at counter 2 succeeds
    await queue.enqueue(wrapCommand(agentId, valid));
    sent.length = 0;

    // New command reusing counter 2 -> replayed
    const replayedCounter = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 2,
        now,
      },
      registry,
    );
    await queue.enqueue(wrapCommand(agentId, replayedCounter));
    expect(sent.pop()).toEqual({
      v: PROTOCOL_VERSION,
      kind: "ack",
      route: { agent: agentId },
      body: { id: replayedCounter.header.id, ok: false, code: "replayed" },
    });
  });

  test("redelivery of an already executed command returns cached ack ok without re-running handler", async () => {
    const agent = generateSigningKeyPair();
    const account = generateSigningKeyPair();
    const agentId = fingerprint(agent.publicKey);
    const now = 1_700_000_000_000;

    const trust = createInMemoryTrustContext({
      agentKeyPair: agent,
      trustedAccountKeys: [account.publicKey],
      now: () => now,
    });
    const registry = createCoreRegistry();
    const sent: TransportFrame[] = [];
    const queue = createCommandQueue({
      trust,
      registry,
      sendFrame: (frame) => sent.push(frame),
      logger: makeSilentLogger(),
    });

    let runCount = 0;
    queue.registerHandler("server.start", () => {
      runCount++;
    });

    const cmd = createSignedCommand(
      {
        type: "server.start",
        body: { server_id: "srv_1" },
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now,
      },
      registry,
    );

    await queue.enqueue(wrapCommand(agentId, cmd));
    await queue.enqueue(wrapCommand(agentId, cmd));

    expect(runCount).toBe(1);
    expect(sent).toEqual([
      {
        v: PROTOCOL_VERSION,
        kind: "ack",
        route: { agent: agentId },
        body: { id: cmd.header.id, ok: true },
      },
      {
        v: PROTOCOL_VERSION,
        kind: "ack",
        route: { agent: agentId },
        body: { id: cmd.header.id, ok: true },
      },
    ]);
  });

  test("returns no_handler for unregistered command types and handler_error when handler throws", async () => {
    const agent = generateSigningKeyPair();
    const account = generateSigningKeyPair();
    const agentId = fingerprint(agent.publicKey);
    const now = 1_700_000_000_000;

    const trust = createInMemoryTrustContext({
      agentKeyPair: agent,
      trustedAccountKeys: [account.publicKey],
      now: () => now,
    });
    const registry = createCoreRegistry();
    const sent: TransportFrame[] = [];
    const logs: string[] = [];
    const queue = createCommandQueue({
      trust,
      registry,
      sendFrame: (frame) => sent.push(frame),
      logger: makeSilentLogger(logs),
    });

    // No handler for server.stop
    const noHandlerCmd = createSignedCommand(
      {
        type: "server.stop",
        body: { server_id: "srv_secret_id" },
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now,
      },
      registry,
    );
    await queue.enqueue(wrapCommand(agentId, noHandlerCmd));
    expect(sent.pop()).toEqual({
      v: PROTOCOL_VERSION,
      kind: "ack",
      route: { agent: agentId },
      body: { id: noHandlerCmd.header.id, ok: false, code: "no_handler" },
    });

    // Throwing handler for server.start
    queue.registerHandler("server.start", () => {
      throw new Error("disk exploded");
    });
    const failingCmd = createSignedCommand(
      {
        type: "server.start",
        body: { server_id: "srv_do_not_leak" },
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 2,
        now,
      },
      registry,
    );
    await queue.enqueue(wrapCommand(agentId, failingCmd));
    expect(sent.pop()).toEqual({
      v: PROTOCOL_VERSION,
      kind: "ack",
      route: { agent: agentId },
      body: { id: failingCmd.header.id, ok: false, code: "handler_error" },
    });
    expect(logs.join("\n")).not.toContain("srv_do_not_leak");

    // Queue continues processing subsequent commands cleanly
    const pingCmd = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 3,
        now,
      },
      registry,
    );
    await queue.enqueue(wrapCommand(agentId, pingCmd));
    expect(sent[sent.length - 1]).toEqual({
      v: PROTOCOL_VERSION,
      kind: "ack",
      route: { agent: agentId },
      body: { id: pingCmd.header.id, ok: true },
    });
  });

  test("executes simultaneous commands strictly serially", async () => {
    const agent = generateSigningKeyPair();
    const account = generateSigningKeyPair();
    const agentId = fingerprint(agent.publicKey);
    const now = 1_700_000_000_000;

    const trust = createInMemoryTrustContext({
      agentKeyPair: agent,
      trustedAccountKeys: [account.publicKey],
      now: () => now,
    });
    const registry = createCoreRegistry();
    const sent: TransportFrame[] = [];
    const queue = createCommandQueue({
      trust,
      registry,
      sendFrame: (frame) => sent.push(frame),
      logger: makeSilentLogger(),
    });

    const events: string[] = [];
    let releaseFirst: (() => void) | undefined;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });

    queue.registerHandler("server.start", async (opened) => {
      const body = opened.body as { server_id: string };
      events.push(`start:${body.server_id}`);
      if (body.server_id === "first") {
        await firstGate;
      }
      events.push(`end:${body.server_id}`);
    });

    const cmd1 = createSignedCommand(
      {
        type: "server.start",
        body: { server_id: "first" },
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now,
      },
      registry,
    );
    const cmd2 = createSignedCommand(
      {
        type: "server.start",
        body: { server_id: "second" },
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 2,
        now,
      },
      registry,
    );

    const p1 = queue.enqueue(wrapCommand(agentId, cmd1));
    const p2 = queue.enqueue(wrapCommand(agentId, cmd2));

    // Allow microtasks to run so first command enters handler
    await Promise.resolve();
    await Promise.resolve();
    expect(events).toEqual(["start:first"]);

    releaseFirst?.();
    await Promise.all([p1, p2]);

    expect(events).toEqual(["start:first", "end:first", "start:second", "end:second"]);
  });
});
