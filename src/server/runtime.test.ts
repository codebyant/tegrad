// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCommandQueue, createLogger, type TransportCommandFrame } from "../agent";
import { fingerprint, generateSigningKeyPair, ready } from "../crypto";
import {
  createCoreRegistry,
  createInMemoryTrustContext,
  createSignedCommand,
  openAgentMessage,
  openCommand,
  PROTOCOL_VERSION,
  ProtocolError,
  signSessionCertificate,
  type TransportFrame,
} from "../protocol";
import {
  createServerManager,
  type FetchLike,
  getJavaBinPath,
  type RunFixedLike,
  registerServerHandlers,
} from "./index";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

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

function makeSilentLogger() {
  return createLogger({ level: "error", stdout: () => {}, stderr: () => {} });
}

function makeFakeVanillaFetch(): FetchLike {
  const jarBytes = new TextEncoder().encode("PK-vanilla-server");
  const sha1 = createHash("sha1").update(jarBytes).digest("hex");

  return async (input) => {
    const url = String(input);
    if (url === "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json") {
      return new Response(
        JSON.stringify({
          versions: [
            { id: "1.21.4", url: "https://piston-meta.mojang.com/v1/packages/1.21.4.json" },
          ],
        }),
        { status: 200 },
      );
    }
    if (url === "https://piston-meta.mojang.com/v1/packages/1.21.4.json") {
      return new Response(
        JSON.stringify({
          downloads: {
            server: {
              sha1,
              size: jarBytes.byteLength,
              url: "https://piston-data.mojang.com/v1/objects/server.jar",
            },
          },
        }),
        { status: 200 },
      );
    }
    if (url === "https://piston-data.mojang.com/v1/objects/server.jar") {
      return new Response(jarBytes, { status: 200 });
    }
    return new Response("not found", { status: 404 });
  };
}

function preinstallFakeJava(serversDir: string, major: 8 | 16 | 17 | 21): string {
  const binPath = getJavaBinPath(serversDir, major, "linux");
  mkdirSync(join(binPath, ".."), { recursive: true });
  writeFileSync(binPath, "#!/bin/sh\n");
  return binPath;
}

function makeSystemdFake() {
  const states = new Map<string, "active" | "inactive">();
  const commands: { cmd: string; args: readonly string[] }[] = [];
  let stuckActiveUnit: string | null = null;

  const runFixedImpl: RunFixedLike = async (cmd, args) => {
    commands.push({ cmd, args });
    if (cmd === "systemctl") {
      const action = args[0];
      if (action === "show") {
        const unit = args[3] ?? "";
        const state = states.get(unit) ?? "inactive";
        return {
          code: 0,
          stdout: `ActiveState=${state}\nSubState=${state === "active" ? "running" : "dead"}\nMainPID=${state === "active" ? 1234 : 0}\nMemoryCurrent=${state === "active" ? 524288000 : "[not set]"}\n`,
          stderr: "",
          timedOut: false,
          truncated: false,
        };
      }
      if (action === "start") {
        const unit = args[1] ?? "";
        states.set(unit, "active");
        return { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
      }
      if (action === "stop") {
        const unit = args[1] ?? "";
        if (unit !== stuckActiveUnit) {
          states.set(unit, "inactive");
        }
        return { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
      }
      if (action === "set-property") {
        return { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
      }
    }
    return { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
  };

  return {
    states,
    commands,
    setStuckActive(unit: string | null) {
      stuckActiveUnit = unit;
    },
    runFixedImpl,
  };
}

describe("ServerManager lifecycle and command integration", () => {
  test("eula_accepted=false creates server with RCON disabled and blocks start until accepted", async () => {
    const serversDir = makeTempDir("tegrad-rt-eula-");
    const runDir = makeTempDir("tegrad-rt-run-");
    preinstallFakeJava(serversDir, 21);

    const sysd = makeSystemdFake();
    const manager = createServerManager({
      serversDir,
      runDir,
      platform: "linux",
      fetchImpl: makeFakeVanillaFetch(),
      runFixedImpl: sysd.runFixedImpl,
      readMeminfoImpl: () => ({ memTotalMb: 16384, memAvailableMb: 12000 }),
      now: () => 1_700_000_000_000,
    });

    const created = await manager.createServer({
      server_id: "smp-1",
      name: "My SMP",
      minecraft_version: "1.21.4",
      loader: "vanilla",
      memory_mb: 2048,
      jvm_args: ["-XX:+UseG1GC"],
      eula_accepted: false,
    });

    expect(created.id).toBe("smp-1");
    expect(created.port).toBe(25565);

    const srvDir = join(serversDir, "smp-1");
    expect(existsSync(join(srvDir, "logs"))).toBe(true);
    expect(existsSync(join(srvDir, "tegrad-server.json"))).toBe(true);
    expect(existsSync(join(srvDir, "start.sh"))).toBe(true);
    expect(readFileSync(join(srvDir, "eula.txt"), "utf8")).toBe("eula=false\n");

    const props = readFileSync(join(srvDir, "server.properties"), "utf8");
    expect(props).toContain("server-port=25565");
    expect(props).toContain("online-mode=true");
    expect(props).toContain("enable-rcon=false");

    // Start must fail with eula_not_accepted
    try {
      await manager.startServer("smp-1");
      throw new Error("Expected eula_not_accepted");
    } catch (err) {
      expect(err).toBeInstanceOf(ProtocolError);
      expect((err as ProtocolError).code).toBe("eula_not_accepted");
    }

    // Even if someone manually enables RCON in server.properties, update_settings forces it back to false
    writeFileSync(
      join(srvDir, "server.properties"),
      "server-port=25565\nenable-rcon=true\nmotd=Hi\n",
    );

    const updated = manager.updateServerSettings({
      server_id: "smp-1",
      memory_mb: 3072,
      port: 25570,
      eula_accepted: true,
    });
    expect(updated.memory_mb).toBe(3072);
    expect(updated.port).toBe(25570);

    const updatedProps = readFileSync(join(srvDir, "server.properties"), "utf8");
    expect(updatedProps).toContain("server-port=25570");
    expect(updatedProps).toContain("enable-rcon=false");
    expect(updatedProps).toContain("motd=Hi");

    const updatedStart = readFileSync(join(srvDir, "start.sh"), "utf8");
    expect(updatedStart).toContain("-Xms3072M -Xmx3072M");

    // Now start succeeds and applies MemoryMax = ceil(3072 * 1.25) = 3840M
    await manager.startServer("smp-1");
    expect(
      sysd.commands.some(
        (c) =>
          c.cmd === "systemctl" && c.args[0] === "set-property" && c.args[3] === "MemoryMax=3840M",
      ),
    ).toBe(true);

    manager.close();
  });

  test("enforces RAM budget across running servers and refuses delete until confirmed stopped", async () => {
    const serversDir = makeTempDir("tegrad-rt-ram-");
    const runDir = makeTempDir("tegrad-rt-ram-run-");
    preinstallFakeJava(serversDir, 21);

    const sysd = makeSystemdFake();
    let fakeNow = 1_700_000_000_000;
    const manager = createServerManager({
      serversDir,
      runDir,
      platform: "linux",
      fetchImpl: makeFakeVanillaFetch(),
      runFixedImpl: sysd.runFixedImpl,
      writeFifoImpl: () => {
        // simulate graceful stop on FIFO write unless unit is stuck
      },
      readMeminfoImpl: () => ({ memTotalMb: 6144, memAvailableMb: 5000 }),
      stopPollIntervalMs: 10,
      stopTimeoutMs: 50,
      now: () => fakeNow,
      sleepImpl: async (ms) => {
        fakeNow += ms;
      },
    });

    await manager.createServer({
      server_id: "srv-a",
      name: "Server A",
      minecraft_version: "1.21.4",
      loader: "vanilla",
      memory_mb: 3072,
      eula_accepted: true,
    });
    await manager.createServer({
      server_id: "srv-b",
      name: "Server B",
      minecraft_version: "1.21.4",
      loader: "vanilla",
      memory_mb: 3072,
      eula_accepted: true,
    });

    await manager.startServer("srv-a");

    // Host total 6144 - 1024 = 5120 MB budget; 3072 + 3072 = 6144 > 5120 -> insufficient_memory
    try {
      await manager.startServer("srv-b");
      throw new Error("Expected insufficient_memory");
    } catch (err) {
      expect(err).toBeInstanceOf(ProtocolError);
      expect((err as ProtocolError).code).toBe("insufficient_memory");
    }

    // Delete refuses to remove directory if unit cannot be confirmed stopped
    sysd.setStuckActive("tegrad-server@srv-a.service");
    try {
      await manager.deleteServer("srv-a");
      throw new Error("Expected server_running");
    } catch (err) {
      expect(err).toBeInstanceOf(ProtocolError);
      expect((err as ProtocolError).code).toBe("server_running");
    }
    expect(existsSync(join(serversDir, "srv-a"))).toBe(true);

    // Once unit stops properly, delete stops and removes the folder
    sysd.setStuckActive(null);
    await manager.deleteServer("srv-a");
    expect(existsSync(join(serversDir, "srv-a"))).toBe(false);

    manager.close();
  });

  test("CommandRegistry + CommandQueue + openCommand end-to-end (including sensitive server.delete)", async () => {
    const serversDir = makeTempDir("tegrad-rt-e2e-");
    const runDir = makeTempDir("tegrad-rt-e2e-run-");
    preinstallFakeJava(serversDir, 21);

    const agent = generateSigningKeyPair();
    const account = generateSigningKeyPair();
    const session = generateSigningKeyPair();
    const agentId = fingerprint(agent.publicKey);
    let now = 1_700_000_000_000;

    const sessionCert = signSessionCertificate({
      sessionPublicKey: session.publicKey,
      accountKeyPair: account,
      notBefore: now - 60_000,
      notAfter: now + 3_600_000,
    });

    const registry = createCoreRegistry();
    const trust = createInMemoryTrustContext({
      agentKeyPair: agent,
      trustedAccountKeys: [account.publicKey],
      now: () => now,
    });

    const frames: TransportFrame[] = [];
    const queue = createCommandQueue({
      trust,
      registry,
      sendFrame: (frame) => frames.push(frame),
      logger: makeSilentLogger(),
    });

    const sysd = makeSystemdFake();
    const fifoWrites: string[] = [];
    const manager = createServerManager({
      serversDir,
      runDir,
      platform: "linux",
      fetchImpl: makeFakeVanillaFetch(),
      runFixedImpl: sysd.runFixedImpl,
      writeFifoImpl: (_path, data) => fifoWrites.push(data),
      readMeminfoImpl: () => ({ memTotalMb: 16384, memAvailableMb: 12000 }),
      stopPollIntervalMs: 5,
      stopTimeoutMs: 20,
      now: () => now,
      sleepImpl: async (ms) => {
        now += ms;
      },
    });
    registerServerHandlers(queue, manager);

    const wrap = (cmd: ReturnType<typeof createSignedCommand>): TransportCommandFrame => ({
      v: PROTOCOL_VERSION,
      kind: "command",
      route: { agent: agentId },
      body: cmd,
    });

    // 1. Session key creates server
    const createCmd = createSignedCommand(
      {
        type: "server.create",
        body: {
          server_id: "alpha-1",
          name: "Alpha Server",
          minecraft_version: "1.21.4",
          loader: "vanilla",
          memory_mb: 2048,
          eula_accepted: true,
        },
        agentPublicKey: agent.publicKey,
        signer: session,
        session: sessionCert,
        counter: 1,
        now,
      },
      registry,
    );
    await queue.enqueue(wrap(createCmd));

    // 2. Session key lists servers
    const listCmd = createSignedCommand(
      {
        type: "server.list",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: session,
        session: sessionCert,
        counter: 2,
        now,
      },
      registry,
    );
    await queue.enqueue(wrap(listCmd));

    // 3. Session key starts server and queries status
    const startCmd = createSignedCommand(
      {
        type: "server.start",
        body: { server_id: "alpha-1" },
        agentPublicKey: agent.publicKey,
        signer: session,
        session: sessionCert,
        counter: 3,
        now,
      },
      registry,
    );
    await queue.enqueue(wrap(startCmd));

    const statusCmd = createSignedCommand(
      {
        type: "server.status",
        body: { server_id: "alpha-1" },
        agentPublicKey: agent.publicKey,
        signer: session,
        session: sessionCert,
        counter: 4,
        now,
      },
      registry,
    );
    await queue.enqueue(wrap(statusCmd));

    // 4. Session key sends console line
    const consoleCmd = createSignedCommand(
      {
        type: "server.console.send",
        body: { server_id: "alpha-1", line: "list" },
        agentPublicKey: agent.publicKey,
        signer: session,
        session: sessionCert,
        counter: 5,
        now,
      },
      registry,
    );
    await queue.enqueue(wrap(consoleCmd));
    expect(fifoWrites).toContain("list\n");

    // 5. Session key CANNOT invoke sensitive server.delete
    const sessionDeleteCmd = createSignedCommand(
      {
        type: "server.delete",
        body: { server_id: "alpha-1" },
        agentPublicKey: agent.publicKey,
        signer: session,
        session: sessionCert,
        counter: 6,
        now,
      },
      registry,
    );
    await expect(openCommand(sessionDeleteCmd, trust, registry)).rejects.toThrow(ProtocolError);

    // 6. Account key CAN invoke sensitive server.delete
    const accountDeleteCmd = createSignedCommand(
      {
        type: "server.delete",
        body: { server_id: "alpha-1" },
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now,
      },
      registry,
    );
    await queue.enqueue(wrap(accountDeleteCmd));
    expect(existsSync(join(serversDir, "alpha-1"))).toBe(false);

    // Verify sealed events emitted
    const events = frames
      .filter((f): f is Extract<TransportFrame, { kind: "event" }> => f.kind === "event")
      .map((f) => openAgentMessage(f.body, agent.publicKey, account));

    const listEvent = events.find((e) => e.header.type === "server.list.result");
    if (!listEvent) {
      throw new Error("Expected server.list.result event");
    }
    expect((listEvent.body as { servers: { id: string }[] }).servers.map((s) => s.id)).toEqual([
      "alpha-1",
    ]);

    const statusEvent = events.find((e) => e.header.type === "server.status.result");
    if (!statusEvent) {
      throw new Error("Expected server.status.result event");
    }
    expect((statusEvent.body as { systemd: { active_state: string } }).systemd.active_state).toBe(
      "active",
    );

    manager.close();
  });
});
