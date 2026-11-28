// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { createCommandQueue, createLogger, type TransportCommandFrame } from "../agent";
import { openTestEvent } from "../agent/test-events";
import {
  fingerprint,
  generateSigningKeyPair,
  ready,
  type SigningKeyPair,
  toBase64Url,
} from "../crypto";
import {
  CommandRegistry,
  createCoreRegistry,
  createInMemoryTrustContext,
  createSignedCommand,
  defineCommand,
  PROTOCOL_VERSION,
  ProtocolError,
  serverIdSchema,
  serverStatsBodySchema,
  serverStatsCommand,
  serverStatsResultSchema,
  signSessionCertificate,
  type TransportFrame,
} from "../protocol";
import {
  createServerManager,
  createServerStatsCollector,
  getUnitStats,
  parseActiveEnterTimestampMs,
  parseSystemdStatsOutput,
  type RunFixedLike,
  registerServerHandlers,
  type ServerMetadata,
  writeServerMetadata,
} from "./index";

const NOW = 1_700_000_000_000;
const tempDirs: string[] = [];
const silentLogger = createLogger({ level: "error", stdout: () => {}, stderr: () => {} });

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
  const dir = mkdtempSync(join(tmpdir(), "tegrad-server-stats-"));
  tempDirs.push(dir);
  return dir;
}

function makeSession(account: SigningKeyPair) {
  const key = generateSigningKeyPair();
  const certificate = signSessionCertificate({
    sessionPublicKey: key.publicKey,
    accountKeyPair: account,
    notBefore: NOW - 1000,
    notAfter: NOW + 3_600_000,
  });
  return { key, certificate };
}

function makeMetadata(id = "survival", memoryMb = 4096): ServerMetadata {
  return {
    v: 1,
    id,
    name: "Survival",
    minecraft_version: "1.21.4",
    loader: "vanilla",
    loader_version: null,
    memory_mb: memoryMb,
    jvm_args: [],
    port: 25565,
    created_at: NOW,
  };
}

describe("server.stats schema and command definition", () => {
  test("is registered in the core registry as non-sensitive viewer command", () => {
    const registry = createCoreRegistry();
    const def = registry.get("server.stats");
    expect(def).toBe(serverStatsCommand);
    expect(def?.sensitive).toBe(false);
    expect(def?.minRole).toBe("viewer");
  });

  test("serverStatsBodySchema accepts valid server_id and rejects extra or invalid fields", () => {
    expect(serverStatsBodySchema.safeParse({ server_id: "survival" }).success).toBe(true);
    expect(serverStatsBodySchema.safeParse({ server_id: "survival", extra: true }).success).toBe(
      false,
    );
    expect(serverStatsBodySchema.safeParse({ server_id: "../bad" }).success).toBe(false);
    expect(serverStatsBodySchema.safeParse({}).success).toBe(false);
    expect(serverStatsBodySchema.safeParse(null).success).toBe(false);
  });

  test("serverStatsResultSchema validates fields and rejects extra or out-of-range values", () => {
    const valid = {
      server_id: "survival",
      running: true,
      memory_used_mb: 2048,
      memory_limit_mb: 4096,
      cpu_percent: 175.4,
      cpu_count: 8,
      uptime_seconds: 3600,
    };
    expect(serverStatsResultSchema.safeParse(valid).success).toBe(true);
    expect(serverStatsResultSchema.safeParse({ ...valid, extra: 1 }).success).toBe(false);
    expect(serverStatsResultSchema.safeParse({ ...valid, memory_used_mb: -1 }).success).toBe(false);
    expect(serverStatsResultSchema.safeParse({ ...valid, memory_used_mb: 12.5 }).success).toBe(
      false,
    );
    expect(serverStatsResultSchema.safeParse({ ...valid, cpu_percent: -0.1 }).success).toBe(false);
    expect(serverStatsResultSchema.safeParse({ ...valid, cpu_percent: Number.NaN }).success).toBe(
      false,
    );
    expect(
      serverStatsResultSchema.safeParse({ ...valid, cpu_percent: Number.POSITIVE_INFINITY })
        .success,
    ).toBe(false);
    expect(serverStatsResultSchema.safeParse({ ...valid, cpu_count: 0 }).success).toBe(false);
    expect(serverStatsResultSchema.safeParse({ ...valid, uptime_seconds: -5 }).success).toBe(false);
    expect(serverStatsResultSchema.safeParse({ ...valid, uptime_seconds: 1.5 }).success).toBe(
      false,
    );
  });
});

describe("systemd stats parsing and getUnitStats", () => {
  test("parses active unit output including @unix timestamp and large CPUUsageNSec", () => {
    const parsed = parseSystemdStatsOutput(
      [
        "ActiveState=active",
        "MemoryCurrent=1073741824",
        "CPUUsageNSec=9007199254740999",
        "ActiveEnterTimestamp=@1700000000",
      ].join("\n"),
    );

    expect(parsed).toEqual({
      activeState: "active",
      memoryCurrentBytes: 1_073_741_824,
      cpuUsageNs: 9_007_199_254_740_999n,
      activeEnterTimestampMs: 1_700_000_000_000,
    });
  });

  test("degrades safely when accounting is disabled or values are invalid", () => {
    const disabled = parseSystemdStatsOutput(
      [
        "ActiveState=active",
        "MemoryCurrent=[not set]",
        "CPUUsageNSec=18446744073709551615",
        "ActiveEnterTimestamp=n/a",
      ].join("\n"),
    );
    expect(disabled).toEqual({
      activeState: "active",
      memoryCurrentBytes: null,
      cpuUsageNs: null,
      activeEnterTimestampMs: null,
    });

    const malformed = parseSystemdStatsOutput(
      [
        "ActiveState=inactive",
        "MemoryCurrent=infinity",
        "CPUUsageNSec=-10",
        "ActiveEnterTimestamp=not-a-timestamp",
        "NoEqualsHere",
      ].join("\n"),
    );
    expect(malformed).toEqual({
      activeState: "inactive",
      memoryCurrentBytes: null,
      cpuUsageNs: null,
      activeEnterTimestampMs: null,
    });

    expect(parseActiveEnterTimestampMs("@0")).toBeNull();
    expect(parseActiveEnterTimestampMs("0")).toBeNull();
    expect(parseActiveEnterTimestampMs("")).toBeNull();
    expect(parseActiveEnterTimestampMs("2026-01-01T00:00:00Z")).toBe(
      Date.parse("2026-01-01T00:00:00Z"),
    );
  });

  test("getUnitStats validates server_id before calling systemctl and surfaces errors", async () => {
    const calls: { cmd: string; args: readonly string[] }[] = [];
    const runFixedImpl: RunFixedLike = async (cmd, args) => {
      calls.push({ cmd, args });
      return {
        code: 0,
        stdout: "ActiveState=active\nMemoryCurrent=0\nCPUUsageNSec=0\nActiveEnterTimestamp=@100\n",
        stderr: "",
        timedOut: false,
        truncated: false,
      };
    };

    try {
      await getUnitStats("../bad", runFixedImpl);
      throw new Error("Expected invalid_body");
    } catch (err) {
      expect(err).toBeInstanceOf(ProtocolError);
      expect((err as ProtocolError).code).toBe("invalid_body");
    }
    expect(calls).toHaveLength(0);

    await getUnitStats("survival", runFixedImpl);
    expect(calls).toEqual([
      {
        cmd: "systemctl",
        args: [
          "show",
          "--timestamp=unix",
          "-p",
          "ActiveState,MemoryCurrent,CPUUsageNSec,ActiveEnterTimestamp",
          "tegrad-server@survival.service",
        ],
      },
    ]);

    await expect(
      getUnitStats("survival", async () => ({
        code: 1,
        stdout: "",
        stderr: "boom",
        timedOut: false,
        truncated: false,
      })),
    ).rejects.toThrow(ProtocolError);
  });
});

describe("createServerStatsCollector", () => {
  test("returns zeros when stopped while preserving memory_limit_mb and cpu_count", async () => {
    const dir = makeTempDir();
    writeServerMetadata(dir, makeMetadata("survival", 4096));

    const collector = createServerStatsCollector({
      serversDir: dir,
      availableParallelismImpl: () => 6,
      now: () => NOW,
      runFixedImpl: async () => ({
        code: 0,
        stdout:
          "ActiveState=inactive\nMemoryCurrent=[not set]\nCPUUsageNSec=[not set]\nActiveEnterTimestamp=n/a\n",
        stderr: "",
        timedOut: false,
        truncated: false,
      }),
    });

    const stats = await collector.readStats("survival");
    expect(stats).toEqual({
      server_id: "survival",
      running: false,
      memory_used_mb: 0,
      memory_limit_mb: 4096,
      cpu_percent: 0,
      cpu_count: 6,
      uptime_seconds: 0,
    });
    expect(serverStatsResultSchema.safeParse(stats).success).toBe(true);
  });

  test("computes memory_used_mb, uptime_seconds, and cpu_percent across consecutive samples", async () => {
    const dir = makeTempDir();
    writeServerMetadata(dir, makeMetadata("survival", 4096));

    let currentNow = 1_700_000_120_000;
    let activeEnterSec = 1_700_000_000;
    let memoryBytes = 1536 * 1024 * 1024;
    let cpuNs = 10_000_000_000n;
    let activeState = "active";

    const collector = createServerStatsCollector({
      serversDir: dir,
      availableParallelismImpl: () => 4,
      now: () => currentNow,
      getUnitStatsImpl: async () => ({
        activeState,
        memoryCurrentBytes: memoryBytes,
        cpuUsageNs: cpuNs,
        activeEnterTimestampMs: activeEnterSec * 1000,
      }),
    });

    // First reading has no previous sample -> cpu_percent is 0.
    const first = await collector.readStats("survival");
    expect(first).toEqual({
      server_id: "survival",
      running: true,
      memory_used_mb: 1536,
      memory_limit_mb: 4096,
      cpu_percent: 0,
      cpu_count: 4,
      uptime_seconds: 120,
    });

    // 2 seconds elapsed, 3 seconds of CPU time used across cores -> 150.0% of one core.
    currentNow += 2000;
    cpuNs += 3_000_000_000n;
    memoryBytes = 1600 * 1024 * 1024;
    const second = await collector.readStats("survival");
    expect(second).toEqual({
      server_id: "survival",
      running: true,
      memory_used_mb: 1600,
      memory_limit_mb: 4096,
      cpu_percent: 150,
      cpu_count: 4,
      uptime_seconds: 122,
    });

    // 4 seconds elapsed, 1 second of CPU time -> 25.0%.
    currentNow += 4000;
    cpuNs += 1_000_000_000n;
    const third = await collector.readStats("survival");
    expect(third.cpu_percent).toBe(25);

    // If the unit restarts (ActiveEnterTimestamp changes), cpu_percent resets to 0.
    currentNow += 2000;
    activeEnterSec = 1_700_000_127;
    cpuNs = 200_000_000n;
    const afterRestart = await collector.readStats("survival");
    expect(afterRestart.cpu_percent).toBe(0);

    // Stopping clears the sample so starting again starts fresh at 0%.
    activeState = "inactive";
    const stopped = await collector.readStats("survival");
    expect(stopped.running).toBe(false);
    expect(stopped.cpu_percent).toBe(0);
    expect(stopped.memory_used_mb).toBe(0);
    expect(stopped.uptime_seconds).toBe(0);

    activeState = "active";
    currentNow += 1000;
    cpuNs = 500_000_000n;
    const restarted = await collector.readStats("survival");
    expect(restarted.cpu_percent).toBe(0);
  });

  test("returns 0 for disabled accounting and throws server_not_found for missing server", async () => {
    const dir = makeTempDir();
    writeServerMetadata(dir, makeMetadata("survival", 2048));

    let systemctlCalled = false;
    const collector = createServerStatsCollector({
      serversDir: dir,
      availableParallelismImpl: () => 2,
      now: () => NOW + 5000,
      runFixedImpl: async () => {
        systemctlCalled = true;
        return {
          code: 0,
          stdout:
            "ActiveState=active\nMemoryCurrent=18446744073709551615\nCPUUsageNSec=[not set]\nActiveEnterTimestamp=@1700000000\n",
          stderr: "",
          timedOut: false,
          truncated: false,
        };
      },
    });

    await expect(collector.readStats("missing")).rejects.toThrow(ProtocolError);
    expect(systemctlCalled).toBe(false);

    const stats = await collector.readStats("survival");
    expect(systemctlCalled).toBe(true);
    expect(stats).toEqual({
      server_id: "survival",
      running: true,
      memory_used_mb: 0,
      memory_limit_mb: 2048,
      cpu_percent: 0,
      cpu_count: 2,
      uptime_seconds: 5,
    });
  });
});

describe("server.stats command handler and authorization", () => {
  function setupQueue(options?: {
    readonly serversDir?: string;
    readonly runFixedImpl?: RunFixedLike;
    readonly nowMs?: () => number;
  }) {
    const serversDir = options?.serversDir ?? makeTempDir();
    const runDir = makeTempDir();
    const agent = generateSigningKeyPair();
    const owner = generateSigningKeyPair();
    const viewer = generateSigningKeyPair();
    const viewerSession = makeSession(viewer);
    const registry = createCoreRegistry();
    const trust = createInMemoryTrustContext({
      agentKeyPair: agent,
      trustedAccountKeys: [owner.publicKey],
      members: [
        {
          account_key: toBase64Url(viewer.publicKey),
          account: fingerprint(viewer.publicKey),
          granted_by: fingerprint(owner.publicKey),
          role: "viewer",
          servers: ["survival"],
          issued_at: NOW,
        },
      ],
      now: options?.nowMs ?? (() => NOW),
    });

    const sent: TransportFrame[] = [];
    const queue = createCommandQueue({
      trust,
      registry,
      sendFrame: (frame) => sent.push(frame),
      logger: silentLogger,
    });
    const manager = createServerManager({
      serversDir,
      runDir,
      platform: "linux",
      availableParallelismImpl: () => 4,
      ...(options?.runFixedImpl !== undefined ? { runFixedImpl: options.runFixedImpl } : {}),
      ...(options?.nowMs !== undefined ? { now: options.nowMs } : {}),
    });
    registerServerHandlers(queue, manager);

    return {
      serversDir,
      agent,
      owner,
      viewer,
      viewerSession,
      registry,
      sent,
      queue,
      manager,
    };
  }

  test("viewer session receives encrypted server.stats.result sealed to reply_to", async () => {
    let nowMs = 1_700_000_010_000;
    let callCount = 0;
    const ctx = setupQueue({
      nowMs: () => nowMs,
      runFixedImpl: async () => {
        callCount++;
        const cpuNs = callCount === 1 ? "1000000000" : "2000000000";
        return {
          code: 0,
          stdout: `ActiveState=active\nMemoryCurrent=536870912\nCPUUsageNSec=${cpuNs}\nActiveEnterTimestamp=@1700000000\n`,
          stderr: "",
          timedOut: false,
          truncated: false,
        };
      },
    });
    writeServerMetadata(ctx.serversDir, makeMetadata("survival", 2048));

    const sendAsViewer = async (counter: number) => {
      const cmd = createSignedCommand(
        {
          type: "server.stats",
          body: { server_id: "survival" },
          agentPublicKey: ctx.agent.publicKey,
          signer: ctx.viewerSession.key,
          session: ctx.viewerSession.certificate,
          replyTo: ctx.viewerSession.key.publicKey,
          counter,
          now: nowMs,
        },
        ctx.registry,
      );
      const frame: TransportCommandFrame = {
        v: PROTOCOL_VERSION,
        kind: "command",
        route: { agent: fingerprint(ctx.agent.publicKey) },
        body: cmd,
      };
      await ctx.queue.enqueue(frame);
      return cmd;
    };

    const cmd1 = await sendAsViewer(1);
    nowMs += 2000;
    const cmd2 = await sendAsViewer(2);

    const events = ctx.sent.filter(
      (f): f is Extract<TransportFrame, { kind: "event" }> => f.kind === "event",
    );
    expect(events).toHaveLength(2);
    const [firstEvent, secondEvent] = events;
    if (!firstEvent || !secondEvent) {
      throw new Error("Expected two server.stats.result events");
    }
    expect(firstEvent.route.recipient).toBe(fingerprint(ctx.viewerSession.key.publicKey));

    const firstOpened = openTestEvent(firstEvent.body, ctx.agent.publicKey, ctx.viewerSession.key);
    expect(firstOpened.header.type).toBe("server.stats.result");
    expect(firstOpened.inReplyTo).toBe(cmd1.header.id);
    expect(serverStatsResultSchema.parse(firstOpened.body)).toEqual({
      server_id: "survival",
      running: true,
      memory_used_mb: 512,
      memory_limit_mb: 2048,
      cpu_percent: 0,
      cpu_count: 4,
      uptime_seconds: 10,
    });

    const secondOpened = openTestEvent(
      secondEvent.body,
      ctx.agent.publicKey,
      ctx.viewerSession.key,
    );
    expect(secondOpened.inReplyTo).toBe(cmd2.header.id);
    expect(serverStatsResultSchema.parse(secondOpened.body)).toEqual({
      server_id: "survival",
      running: true,
      memory_used_mb: 512,
      memory_limit_mb: 2048,
      cpu_percent: 50,
      cpu_count: 4,
      uptime_seconds: 12,
    });

    // Account key cannot decrypt a reply sealed to the session key.
    expect(() => openTestEvent(firstEvent.body, ctx.agent.publicKey, ctx.viewer)).toThrow();
    ctx.manager.close();
  });

  test("rejects untrusted accounts and viewers without access to the target server", async () => {
    const ctx = setupQueue();
    writeServerMetadata(ctx.serversDir, makeMetadata("creative", 2048));
    const stranger = generateSigningKeyPair();

    const strangerCmd = createSignedCommand(
      {
        type: "server.stats",
        body: { server_id: "creative" },
        agentPublicKey: ctx.agent.publicKey,
        signer: stranger,
        counter: 1,
        now: NOW,
      },
      ctx.registry,
    );
    await ctx.queue.enqueue({
      v: PROTOCOL_VERSION,
      kind: "command",
      route: { agent: fingerprint(ctx.agent.publicKey) },
      body: strangerCmd,
    });

    const scopedViewerCmd = createSignedCommand(
      {
        type: "server.stats",
        body: { server_id: "creative" },
        agentPublicKey: ctx.agent.publicKey,
        signer: ctx.viewerSession.key,
        session: ctx.viewerSession.certificate,
        replyTo: ctx.viewerSession.key.publicKey,
        counter: 1,
        now: NOW,
      },
      ctx.registry,
    );
    await ctx.queue.enqueue({
      v: PROTOCOL_VERSION,
      kind: "command",
      route: { agent: fingerprint(ctx.agent.publicKey) },
      body: scopedViewerCmd,
    });

    const acks = ctx.sent.filter(
      (f): f is Extract<TransportFrame, { kind: "ack" }> => f.kind === "ack",
    );
    expect(acks[0]?.body).toEqual({
      id: strangerCmd.header.id,
      ok: false,
      code: "untrusted_signer",
    });
    expect(acks[1]?.body).toEqual({
      id: scopedViewerCmd.header.id,
      ok: false,
      code: "insufficient_role",
    });
    expect(ctx.sent.some((f) => f.kind === "event")).toBe(false);
    ctx.manager.close();
  });

  test("rejects extra parameters on server.stats and returns server_not_found for missing server", async () => {
    const ctx = setupQueue();

    expect(() =>
      createSignedCommand(
        {
          type: "server.stats",
          body: { server_id: "survival", unexpected: 1 },
          agentPublicKey: ctx.agent.publicKey,
          signer: ctx.owner,
          counter: 1,
          now: NOW,
        },
        ctx.registry,
      ),
    ).toThrow(ProtocolError);

    const permissiveRegistry = new CommandRegistry().register(
      defineCommand({
        type: "server.stats",
        level: "session",
        minRole: "viewer",
        body: z.object({ server_id: serverIdSchema, unexpected: z.number() }),
      }),
    );
    const extraCmd = createSignedCommand(
      {
        type: "server.stats",
        body: { server_id: "survival", unexpected: 1 },
        agentPublicKey: ctx.agent.publicKey,
        signer: ctx.owner,
        counter: 1,
        now: NOW,
      },
      permissiveRegistry,
    );
    await ctx.queue.enqueue({
      v: PROTOCOL_VERSION,
      kind: "command",
      route: { agent: fingerprint(ctx.agent.publicKey) },
      body: extraCmd,
    });

    const missingCmd = createSignedCommand(
      {
        type: "server.stats",
        body: { server_id: "survival" },
        agentPublicKey: ctx.agent.publicKey,
        signer: ctx.owner,
        counter: 2,
        now: NOW,
      },
      ctx.registry,
    );
    await ctx.queue.enqueue({
      v: PROTOCOL_VERSION,
      kind: "command",
      route: { agent: fingerprint(ctx.agent.publicKey) },
      body: missingCmd,
    });

    const acks = ctx.sent.filter(
      (f): f is Extract<TransportFrame, { kind: "ack" }> => f.kind === "ack",
    );
    expect(acks[0]?.body).toEqual({
      id: extraCmd.header.id,
      ok: false,
      code: "invalid_body",
    });
    expect(acks[1]?.body).toEqual({
      id: missingCmd.header.id,
      ok: false,
      code: "server_not_found",
    });
    expect(ctx.sent.some((f) => f.kind === "event")).toBe(false);
    ctx.manager.close();
  });
});
