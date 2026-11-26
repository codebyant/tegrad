// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { type NetworkInterfaceInfo, tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
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
  hostInfoBodySchema,
  hostInfoCommand,
  hostInfoResultSchema,
  PROTOCOL_VERSION,
  ProtocolError,
  signSessionCertificate,
  type TransportFrame,
} from "../protocol";
import { RESERVED_SYSTEM_MEMORY_MB } from "../server/memory";
import { readAddressesFromFibTrie, readHostAddresses, readHostInfo } from "./host-info";
import { createCommandQueue, type TransportCommandFrame } from "./jobs";
import { createLogger } from "./logger";
import { openTestEvent } from "./test-events";

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
  const dir = mkdtempSync(join(tmpdir(), "tegrad-host-info-"));
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

describe("host.info schema and command definition", () => {
  test("is registered in the core registry as non-sensitive viewer command", () => {
    const registry = createCoreRegistry();
    const def = registry.get("host.info");
    expect(def).toBe(hostInfoCommand);
    expect(def?.sensitive).toBe(false);
    expect(def?.minRole).toBe("viewer");
  });

  test("hostInfoBodySchema accepts empty object and rejects extra parameters", () => {
    expect(hostInfoBodySchema.safeParse({}).success).toBe(true);
    expect(hostInfoBodySchema.safeParse({ extra: true }).success).toBe(false);
    expect(hostInfoBodySchema.safeParse({ server_id: "survival" }).success).toBe(false);
    expect(hostInfoBodySchema.safeParse(null).success).toBe(false);
  });

  test("hostInfoResultSchema validates memory, cpu and reserve fields", () => {
    expect(
      hostInfoResultSchema.safeParse({
        memory_total_mb: 16384,
        memory_available_mb: 12288,
        cpu_count: 8,
        reserved_memory_mb: 1024,
      }).success,
    ).toBe(true);

    expect(
      hostInfoResultSchema.safeParse({
        memory_total_mb: -1,
        memory_available_mb: 1024,
        cpu_count: 4,
        reserved_memory_mb: 1024,
      }).success,
    ).toBe(false);

    expect(
      hostInfoResultSchema.safeParse({
        memory_total_mb: 8192,
        memory_available_mb: 4096,
        cpu_count: 0,
        reserved_memory_mb: 1024,
      }).success,
    ).toBe(false);

    expect(
      hostInfoResultSchema.safeParse({
        memory_total_mb: 8192.5,
        memory_available_mb: 4096,
        cpu_count: 4,
        reserved_memory_mb: 1024,
      }).success,
    ).toBe(false);

    expect(
      hostInfoResultSchema.safeParse({
        memory_total_mb: 8192,
        memory_available_mb: 4096,
        cpu_count: 4,
      }).success,
    ).toBe(false);
  });
});

describe("readHostInfo", () => {
  test("reads simulated /proc/meminfo, cpu_count and default reserved memory", () => {
    const dir = makeTempDir();
    const meminfoPath = join(dir, "meminfo");
    writeFileSync(
      meminfoPath,
      [
        "MemTotal:       16777216 kB", // 16384 MB
        "MemFree:         4194304 kB",
        "MemAvailable:   12582912 kB", // 12288 MB
        "Buffers:          262144 kB",
      ].join("\n"),
    );

    const info = readHostInfo({
      meminfoPath,
      availableParallelismImpl: () => 6,
      networkInterfacesImpl: () => ({}),
      fibTriePath: join(dir, "no-fib-trie"),
    });

    expect(info).toEqual({
      memory_total_mb: 16384,
      memory_available_mb: 12288,
      cpu_count: 6,
      reserved_memory_mb: RESERVED_SYSTEM_MEMORY_MB,
      addresses: [],
    });
    expect(hostInfoResultSchema.safeParse(info).success).toBe(true);
  });

  test("lists only external IPv4 addresses, once each and without link-local ones", () => {
    const iface = (address: string, family: "IPv4" | "IPv6", internal = false) =>
      ({
        address,
        netmask: "255.255.255.0",
        family,
        mac: "00:00:00:00:00:00",
        internal,
        cidr: null,
      }) as NetworkInterfaceInfo;
    const addresses = readHostAddresses({
      lo: [iface("127.0.0.1", "IPv4", true)],
      eth0: [
        iface("192.168.2.201", "IPv4"),
        iface("fe80::1", "IPv6"),
        iface("169.254.10.2", "IPv4"),
      ],
      eth1: [iface("192.168.2.201", "IPv4"), iface("10.0.0.7", "IPv4")],
    });
    expect(addresses).toEqual(["192.168.2.201", "10.0.0.7"]);
  });

  test("falls back to the kernel routing trie when the sandbox hides the interfaces", () => {
    const dir = makeTempDir();
    const meminfoPath = join(dir, "meminfo");
    writeFileSync(meminfoPath, "MemTotal:        8388608 kB\nMemAvailable:    6291456 kB\n");
    const fibTriePath = join(dir, "fib_trie");
    const section = [
      "  +-- 0.0.0.0/0 3 0 5",
      "     |-- 0.0.0.0",
      "        /0 universe UNICAST",
      "     +-- 127.0.0.0/8 2 0 2",
      "        +-- 127.0.0.0/31 1 0 0",
      "           |-- 127.0.0.0",
      "              /8 host LOCAL",
      "           |-- 127.0.0.1",
      "              /32 host LOCAL",
      "        |-- 127.255.255.255",
      "           /32 link BROADCAST",
      "     +-- 192.168.2.0/24 2 1 2",
      "        |-- 192.168.2.0",
      "           /24 link UNICAST",
      "        +-- 192.168.2.192/26 2 0 2",
      "           |-- 192.168.2.201",
      "              /32 host LOCAL",
      "           |-- 192.168.2.255",
      "              /32 link BROADCAST",
    ].join("\n");
    writeFileSync(fibTriePath, `Main:\n${section}\nLocal:\n${section}\n`);

    expect(readAddressesFromFibTrie(fibTriePath)).toEqual(["192.168.2.201"]);
    expect(readAddressesFromFibTrie(join(dir, "missing"))).toEqual([]);

    const info = readHostInfo({
      meminfoPath,
      availableParallelismImpl: () => 2,
      networkInterfacesImpl: () => ({}),
      fibTriePath,
    });
    expect(info.addresses).toEqual(["192.168.2.201"]);
  });

  test("throws ProtocolError when meminfo file cannot be read", () => {
    const dir = makeTempDir();
    expect(() => readHostInfo({ meminfoPath: join(dir, "missing") })).toThrow(ProtocolError);
  });
});

describe("host.info command handler", () => {
  test("viewer session receives encrypted host.info.result sealed to reply_to", async () => {
    const dir = makeTempDir();
    const meminfoPath = join(dir, "meminfo");
    writeFileSync(meminfoPath, "MemTotal:        8388608 kB\nMemAvailable:    6291456 kB\n");

    const agent = generateSigningKeyPair();
    const owner = generateSigningKeyPair();
    const viewer = generateSigningKeyPair();
    const viewerSession = makeSession(viewer);
    const agentId = fingerprint(agent.publicKey);
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
      now: () => NOW,
    });

    const sent: TransportFrame[] = [];
    const queue = createCommandQueue({
      trust,
      registry,
      sendFrame: (frame) => sent.push(frame),
      logger: silentLogger,
      readHostInfo: () =>
        readHostInfo({
          meminfoPath,
          availableParallelismImpl: () => 4,
          networkInterfacesImpl: () => ({}),
          fibTriePath: join(dir, "no-fib-trie"),
        }),
    });

    const command = createSignedCommand(
      {
        type: "host.info",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: viewerSession.key,
        session: viewerSession.certificate,
        replyTo: viewerSession.key.publicKey,
        counter: 1,
        now: NOW,
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

    const ack = sent.find((f) => f.kind === "ack");
    expect(ack?.kind).toBe("ack");
    if (ack?.kind === "ack") {
      expect(ack.body).toEqual({ id: command.header.id, ok: true });
    }

    const event = sent.find((f) => f.kind === "event");
    expect(event?.kind).toBe("event");
    if (event?.kind !== "event") return;

    expect(event.route.recipient).toBe(fingerprint(viewerSession.key.publicKey));
    const opened = openTestEvent(event.body, agent.publicKey, viewerSession.key);
    expect(opened.header.type).toBe("host.info.result");
    expect(opened.inReplyTo).toBe(command.header.id);
    expect(hostInfoResultSchema.parse(opened.body)).toEqual({
      memory_total_mb: 8192,
      memory_available_mb: 6144,
      cpu_count: 4,
      reserved_memory_mb: RESERVED_SYSTEM_MEMORY_MB,
      addresses: [],
    });

    // Account key cannot decrypt a reply sealed to the session key.
    expect(() => openTestEvent(event.body, agent.publicKey, viewer)).toThrow();
  });

  test("rejects untrusted accounts", async () => {
    const agent = generateSigningKeyPair();
    const owner = generateSigningKeyPair();
    const stranger = generateSigningKeyPair();
    const registry = createCoreRegistry();
    const trust = createInMemoryTrustContext({
      agentKeyPair: agent,
      trustedAccountKeys: [owner.publicKey],
      now: () => NOW,
    });

    const sent: TransportFrame[] = [];
    const queue = createCommandQueue({
      trust,
      registry,
      sendFrame: (frame) => sent.push(frame),
      logger: silentLogger,
    });

    const command = createSignedCommand(
      {
        type: "host.info",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: stranger,
        counter: 1,
        now: NOW,
      },
      registry,
    );

    await queue.enqueue({
      v: PROTOCOL_VERSION,
      kind: "command",
      route: { agent: fingerprint(agent.publicKey) },
      body: command,
    });

    const ack = sent.find((f) => f.kind === "ack");
    expect(ack?.kind === "ack" && ack.body).toEqual({
      id: command.header.id,
      ok: false,
      code: "untrusted_signer",
    });
    expect(sent.some((f) => f.kind === "event")).toBe(false);
  });

  test("rejects extra parameters on host.info at openCommand", async () => {
    const agent = generateSigningKeyPair();
    const owner = generateSigningKeyPair();
    const registry = createCoreRegistry();
    const trust = createInMemoryTrustContext({
      agentKeyPair: agent,
      trustedAccountKeys: [owner.publicKey],
      now: () => NOW,
    });

    // Client-side validation rejects extra parameters before signing.
    expect(() =>
      createSignedCommand(
        {
          type: "host.info",
          body: { unexpected: 1 },
          agentPublicKey: agent.publicKey,
          signer: owner,
          counter: 1,
          now: NOW,
        },
        registry,
      ),
    ).toThrow(ProtocolError);

    // Server-side validation also rejects a command signed with extra parameters.
    const permissiveRegistry = new CommandRegistry().register(
      defineCommand({
        type: "host.info",
        sensitive: false,
        minRole: "viewer",
        body: z.object({ unexpected: z.number() }),
      }),
    );
    const command = createSignedCommand(
      {
        type: "host.info",
        body: { unexpected: 1 },
        agentPublicKey: agent.publicKey,
        signer: owner,
        counter: 1,
        now: NOW,
      },
      permissiveRegistry,
    );

    const sent: TransportFrame[] = [];
    const queue = createCommandQueue({
      trust,
      registry,
      sendFrame: (frame) => sent.push(frame),
      logger: silentLogger,
    });

    await queue.enqueue({
      v: PROTOCOL_VERSION,
      kind: "command",
      route: { agent: fingerprint(agent.publicKey) },
      body: command,
    });

    const ack = sent.find((f) => f.kind === "ack");
    expect(ack?.kind === "ack" && ack.body).toEqual({
      id: command.header.id,
      ok: false,
      code: "invalid_body",
    });
    expect(sent.some((f) => f.kind === "event")).toBe(false);
  });
});
