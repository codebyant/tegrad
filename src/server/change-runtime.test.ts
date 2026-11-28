// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCommandQueue, createLogger, type TransportCommandFrame } from "../agent";
import { openTestEvent } from "../agent/test-events";
import { createBackupManager } from "../backup";
import { fingerprint, generateSigningKeyPair, ready, toBase64Url } from "../crypto";
import {
  createCoreRegistry,
  createInMemoryTrustContext,
  createSignedCommand,
  openCommand,
  PROTOCOL_VERSION,
  ProtocolError,
  type ServerChangeRuntimeBody,
  serverChangeRuntimeBodySchema,
  signRoleGrant,
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

function sha256Hex(data: Uint8Array | string): string {
  return createHash("sha256").update(data).digest("hex");
}

function sha1Hex(data: Uint8Array | string): string {
  return createHash("sha1").update(data).digest("hex");
}

function makeSilentLogger() {
  return createLogger({ level: "error", stdout: () => {}, stderr: () => {} });
}

function preinstallFakeJava(serversDir: string, major: 8 | 16 | 17 | 21): string {
  const binPath = getJavaBinPath(serversDir, major, "linux");
  mkdirSync(join(binPath, ".."), { recursive: true });
  writeFileSync(binPath, "#!/bin/sh\n");
  return binPath;
}

function makeFakeLoaderHarness(options?: {
  readonly failFabricInstall?: boolean;
  readonly failVanillaHash?: boolean;
  readonly unitState?: "active" | "activating" | "inactive" | "failed";
}) {
  const vanilla1204Jar = new TextEncoder().encode("PK-vanilla-1.20.4");
  const vanilla1204Sha1 = sha1Hex(vanilla1204Jar);
  const fabricInstallerJar = new TextEncoder().encode("PK-fabric-installer");
  const fabricInstallerSha256 = sha256Hex(fabricInstallerJar);
  const fabricInstallerUrl =
    "https://maven.fabricmc.net/net/fabricmc/fabric-installer/1.0.1/fabric-installer-1.0.1.jar";
  const forgeInstallerJar = new TextEncoder().encode("PK-forge-installer");
  const forgeInstallerSha256 = sha256Hex(forgeInstallerJar);
  const forgeInstallerUrl =
    "https://maven.minecraftforge.net/net/minecraftforge/forge/1.20.1-47.2.0/forge-1.20.1-47.2.0-installer.jar";

  const installerRunDirs: string[] = [];
  const commands: { cmd: string; args: readonly string[] }[] = [];
  const unitState = options?.unitState ?? "inactive";

  const fetchImpl: FetchLike = async (input) => {
    const url = String(input);
    if (url === "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json") {
      return new Response(
        JSON.stringify({
          versions: [
            { id: "1.20.4", url: "https://piston-meta.mojang.com/v1/packages/1.20.4.json" },
          ],
        }),
        { status: 200 },
      );
    }
    if (url === "https://piston-meta.mojang.com/v1/packages/1.20.4.json") {
      return new Response(
        JSON.stringify({
          downloads: {
            server: {
              sha1: options?.failVanillaHash ? "0".repeat(40) : vanilla1204Sha1,
              size: vanilla1204Jar.byteLength,
              url: "https://piston-data.mojang.com/v1/objects/1.20.4/server.jar",
            },
          },
        }),
        { status: 200 },
      );
    }
    if (url === "https://piston-data.mojang.com/v1/objects/1.20.4/server.jar") {
      return new Response(vanilla1204Jar, { status: 200 });
    }
    if (url === "https://meta.fabricmc.net/v2/versions/game") {
      return new Response(JSON.stringify([{ version: "1.21.4", stable: true }]), { status: 200 });
    }
    if (url === "https://meta.fabricmc.net/v2/versions/loader") {
      return new Response(
        JSON.stringify([
          { version: "0.16.10", stable: true },
          { version: "0.16.9", stable: true },
        ]),
        { status: 200 },
      );
    }
    if (url === "https://meta.fabricmc.net/v2/versions/installer") {
      return new Response(
        JSON.stringify([{ version: "1.0.1", url: fabricInstallerUrl, stable: true }]),
        { status: 200 },
      );
    }
    if (url === `${fabricInstallerUrl}.sha256`) {
      return new Response(`${fabricInstallerSha256}\n`, { status: 200 });
    }
    if (url === fabricInstallerUrl) {
      return new Response(fabricInstallerJar, { status: 200 });
    }
    if (url === "https://files.minecraftforge.net/net/minecraftforge/forge/promotions_slim.json") {
      return new Response(JSON.stringify({ promos: { "1.20.1-recommended": "47.2.0" } }), {
        status: 200,
      });
    }
    if (url === `${forgeInstallerUrl}.sha256`) {
      return new Response(forgeInstallerSha256, { status: 200 });
    }
    if (url === forgeInstallerUrl) {
      return new Response(forgeInstallerJar, { status: 200 });
    }
    return new Response("not found", { status: 404 });
  };

  const runFixedImpl: RunFixedLike = async (cmd, args) => {
    commands.push({ cmd, args });
    if (cmd === "systemctl" && args[0] === "show") {
      const sub =
        unitState === "active" ? "running" : unitState === "activating" ? "start" : "dead";
      return {
        code: 0,
        stdout: `ActiveState=${unitState}\nSubState=${sub}\nMainPID=0\nMemoryCurrent=[not set]\n`,
        stderr: "",
        timedOut: false,
        truncated: false,
      };
    }

    if (args.includes("-dir")) {
      const dirIdx = args.indexOf("-dir");
      const targetDir = args[dirIdx + 1] ?? "";
      installerRunDirs.push(targetDir);
      if (options?.failFabricInstall) {
        return { code: 1, stdout: "", stderr: "fabric failed", timedOut: false, truncated: false };
      }
      writeFileSync(join(targetDir, "fabric-server-launch.jar"), "PK-fabric-launch");
      writeFileSync(join(targetDir, "server.jar"), "PK-fabric-mc");
      mkdirSync(join(targetDir, "libraries", "net", "fabricmc"), { recursive: true });
      writeFileSync(join(targetDir, "libraries", "net", "fabricmc", "loader.jar"), "PK-fabric-lib");
      return { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
    }

    if (args.includes("--installServer")) {
      const idx = args.indexOf("--installServer");
      const targetDir = args[idx + 1] ?? "";
      installerRunDirs.push(targetDir);
      const unixDir = join(
        targetDir,
        "libraries",
        "net",
        "minecraftforge",
        "forge",
        "1.20.1-47.2.0",
      );
      mkdirSync(unixDir, { recursive: true });
      writeFileSync(join(unixDir, "unix_args.txt"), "-cp forge.jar\n");
      writeFileSync(join(targetDir, "run.sh"), "#!/bin/sh\n");
      return { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
    }

    return { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
  };

  return { fetchImpl, runFixedImpl, installerRunDirs, commands };
}

describe("server.change_runtime", () => {
  test("schema accepts valid payloads and rejects invalid or extra fields", () => {
    expect(
      serverChangeRuntimeBodySchema.safeParse({
        server_id: "survival-1",
        minecraft_version: "1.21.4",
        loader: "fabric",
        loader_version: "0.16.10",
        backup_before: true,
      }).success,
    ).toBe(true);

    expect(
      serverChangeRuntimeBodySchema.safeParse({
        server_id: "survival-1",
        minecraft_version: "1.21.4",
        loader: "vanilla",
      }).success,
    ).toBe(true);

    expect(
      serverChangeRuntimeBodySchema.safeParse({
        server_id: "../escape",
        minecraft_version: "1.21.4",
        loader: "vanilla",
      }).success,
    ).toBe(false);

    expect(
      serverChangeRuntimeBodySchema.safeParse({
        server_id: "survival-1",
        minecraft_version: "",
        loader: "vanilla",
      }).success,
    ).toBe(false);

    expect(
      serverChangeRuntimeBodySchema.safeParse({
        server_id: "survival-1",
        minecraft_version: "1.21.4",
        loader: "paper",
      }).success,
    ).toBe(false);

    expect(
      serverChangeRuntimeBodySchema.safeParse({
        server_id: "survival-1",
        minecraft_version: "1.21.4",
        loader: "vanilla",
        extra: true,
      }).success,
    ).toBe(false);
  });

  test("switches loader/version via staging dir, cleans old runtime, preserves user data, and updates start.sh + status", async () => {
    const serversDir = makeTempDir("tegrad-chg-rt-");
    const runDir = makeTempDir("tegrad-chg-run-");
    preinstallFakeJava(serversDir, 17);
    preinstallFakeJava(serversDir, 21);

    const harness = makeFakeLoaderHarness();
    const manager = createServerManager({
      serversDir,
      runDir,
      platform: "linux",
      fetchImpl: harness.fetchImpl,
      runFixedImpl: harness.runFixedImpl,
      now: () => 1_700_000_000_000,
    });

    await manager.createServer({
      server_id: "smp",
      name: "SMP",
      minecraft_version: "1.20.4",
      loader: "vanilla",
      memory_mb: 4096,
      jvm_args: ["-XX:+UseG1GC"],
      port: 25577,
      eula_accepted: true,
    });

    const srvDir = join(serversDir, "smp");
    mkdirSync(join(srvDir, "world", "region"), { recursive: true });
    writeFileSync(join(srvDir, "world", "level.dat"), "world-bytes");
    mkdirSync(join(srvDir, "mods"), { recursive: true });
    writeFileSync(join(srvDir, "mods", "keep-mod.jar"), "mod-bytes");
    mkdirSync(join(srvDir, "config"), { recursive: true });
    writeFileSync(join(srvDir, "config", "mod.toml"), "enabled = true\n");
    writeFileSync(join(srvDir, "whitelist.json"), '[{"name":"Alex"}]');
    writeFileSync(join(srvDir, "logs", "latest.log"), "boot ok\n");
    writeFileSync(join(srvDir, "forge-1.20.4-stale.jar"), "stale-jar");

    const beforeStart = readFileSync(join(srvDir, "start.sh"), "utf8");
    expect(beforeStart).toContain(getJavaBinPath(serversDir, 17, "linux"));
    expect(beforeStart).toContain("server.jar");

    const updated = await manager.changeServerRuntime({
      server_id: "smp",
      minecraft_version: "1.21.4",
      loader: "fabric",
      loader_version: "0.16.10",
    });

    expect(updated.minecraft_version).toBe("1.21.4");
    expect(updated.loader).toBe("fabric");
    expect(updated.loader_version).toBe("0.16.10");
    expect(updated.launch_target).toEqual({
      kind: "jar",
      jar_relative_path: "fabric-server-launch.jar",
    });
    expect(updated.memory_mb).toBe(4096);
    expect(updated.jvm_args).toEqual(["-XX:+UseG1GC"]);
    expect(updated.port).toBe(25577);

    // Installer ran in a temporary directory inside serverDir, never directly in serverDir
    expect(harness.installerRunDirs.length).toBe(1);
    expect(harness.installerRunDirs[0]).toContain(".tmp-runtime-");

    // Stale runtime jar removed, new runtime installed, no temp dirs left behind
    expect(existsSync(join(srvDir, "forge-1.20.4-stale.jar"))).toBe(false);
    expect(existsSync(join(srvDir, "fabric-server-launch.jar"))).toBe(true);
    expect(existsSync(join(srvDir, "libraries", "net", "fabricmc", "loader.jar"))).toBe(true);
    expect(readdirSync(srvDir).some((n) => n.startsWith(".tmp-runtime"))).toBe(false);

    // User files untouched
    expect(readFileSync(join(srvDir, "world", "level.dat"), "utf8")).toBe("world-bytes");
    expect(readFileSync(join(srvDir, "mods", "keep-mod.jar"), "utf8")).toBe("mod-bytes");
    expect(readFileSync(join(srvDir, "config", "mod.toml"), "utf8")).toBe("enabled = true\n");
    expect(readFileSync(join(srvDir, "whitelist.json"), "utf8")).toBe('[{"name":"Alex"}]');
    expect(readFileSync(join(srvDir, "logs", "latest.log"), "utf8")).toBe("boot ok\n");
    expect(readFileSync(join(srvDir, "eula.txt"), "utf8")).toBe("eula=true\n");
    expect(readFileSync(join(srvDir, "server.properties"), "utf8")).toContain("server-port=25577");

    // start.sh regenerated with Java 21, preserved RAM/JVM args, new target
    const afterStart = readFileSync(join(srvDir, "start.sh"), "utf8");
    expect(afterStart).toContain(getJavaBinPath(serversDir, 21, "linux"));
    expect(afterStart).toContain("-Xms4096M -Xmx4096M");
    expect(afterStart).toContain("'-XX:+UseG1GC'");
    expect(afterStart).toContain("fabric-server-launch.jar");

    // server.status reflects updated metadata
    const status = await manager.getServerStatus("smp");
    expect(status.server.minecraft_version).toBe("1.21.4");
    expect(status.server.loader).toBe("fabric");
    expect(status.server.loader_version).toBe("0.16.10");

    // Switch again to Forge 1.20.1 (Java 17 + args_file) and confirm old Fabric files are cleaned up
    const forgeMeta = await manager.changeServerRuntime({
      server_id: "smp",
      minecraft_version: "1.20.1",
      loader: "forge",
    });
    expect(forgeMeta.loader).toBe("forge");
    expect(forgeMeta.loader_version).toBe("47.2.0");
    expect(forgeMeta.launch_target).toEqual({
      kind: "args_file",
      args_file_relative_path: "libraries/net/minecraftforge/forge/1.20.1-47.2.0/unix_args.txt",
    });
    expect(existsSync(join(srvDir, "fabric-server-launch.jar"))).toBe(false);
    expect(existsSync(join(srvDir, "libraries", "net", "fabricmc"))).toBe(false);
    expect(
      existsSync(
        join(
          srvDir,
          "libraries",
          "net",
          "minecraftforge",
          "forge",
          "1.20.1-47.2.0",
          "unix_args.txt",
        ),
      ),
    ).toBe(true);
    const forgeStart = readFileSync(join(srvDir, "start.sh"), "utf8");
    expect(forgeStart).toContain(getJavaBinPath(serversDir, 17, "linux"));
    expect(forgeStart).toContain("unix_args.txt");

    manager.close();
  });

  test("failed loader installation leaves existing runtime, start.sh, and metadata completely intact", async () => {
    const serversDir = makeTempDir("tegrad-chg-fail-");
    const runDir = makeTempDir("tegrad-chg-fail-run-");
    preinstallFakeJava(serversDir, 17);
    preinstallFakeJava(serversDir, 21);

    const okHarness = makeFakeLoaderHarness();
    const setupManager = createServerManager({
      serversDir,
      runDir,
      platform: "linux",
      fetchImpl: okHarness.fetchImpl,
      runFixedImpl: okHarness.runFixedImpl,
      now: () => 1_700_000_000_000,
    });
    await setupManager.createServer({
      server_id: "smp",
      name: "SMP",
      minecraft_version: "1.20.4",
      loader: "vanilla",
      memory_mb: 2048,
      eula_accepted: true,
    });
    setupManager.close();

    const srvDir = join(serversDir, "smp");
    const originalJar = readFileSync(join(srvDir, "server.jar"), "utf8");
    const originalStart = readFileSync(join(srvDir, "start.sh"), "utf8");
    const originalMeta = readFileSync(join(srvDir, "tegrad-server.json"), "utf8");

    const failHarness = makeFakeLoaderHarness({ failFabricInstall: true });
    const failingManager = createServerManager({
      serversDir,
      runDir,
      platform: "linux",
      fetchImpl: failHarness.fetchImpl,
      runFixedImpl: failHarness.runFixedImpl,
      now: () => 1_700_000_000_000,
    });

    await expect(
      failingManager.changeServerRuntime({
        server_id: "smp",
        minecraft_version: "1.21.4",
        loader: "fabric",
      }),
    ).rejects.toMatchObject({ code: "download_failed" });

    expect(readFileSync(join(srvDir, "server.jar"), "utf8")).toBe(originalJar);
    expect(readFileSync(join(srvDir, "start.sh"), "utf8")).toBe(originalStart);
    expect(readFileSync(join(srvDir, "tegrad-server.json"), "utf8")).toBe(originalMeta);
    expect(readdirSync(srvDir).some((n) => n.startsWith(".tmp-runtime"))).toBe(false);

    failingManager.close();
  });

  test("refuses running server with server_running before calling backup or downloader", async () => {
    const serversDir = makeTempDir("tegrad-chg-running-");
    const runDir = makeTempDir("tegrad-chg-running-run-");
    preinstallFakeJava(serversDir, 17);
    preinstallFakeJava(serversDir, 21);

    const setupHarness = makeFakeLoaderHarness();
    const setupManager = createServerManager({
      serversDir,
      runDir,
      platform: "linux",
      fetchImpl: setupHarness.fetchImpl,
      runFixedImpl: setupHarness.runFixedImpl,
    });
    await setupManager.createServer({
      server_id: "smp",
      name: "SMP",
      minecraft_version: "1.20.4",
      loader: "vanilla",
      memory_mb: 2048,
      eula_accepted: true,
    });
    setupManager.close();

    let backupCalled = false;
    let fetchCalled = false;
    const runningHarness = makeFakeLoaderHarness({ unitState: "active" });
    const manager = createServerManager({
      serversDir,
      runDir,
      platform: "linux",
      fetchImpl: async (...args) => {
        fetchCalled = true;
        return runningHarness.fetchImpl(...args);
      },
      runFixedImpl: runningHarness.runFixedImpl,
      backupBeforeChange: async () => {
        backupCalled = true;
      },
    });

    await expect(
      manager.changeServerRuntime({
        server_id: "smp",
        minecraft_version: "1.21.4",
        loader: "fabric",
        backup_before: true,
      }),
    ).rejects.toMatchObject({ code: "server_running" });

    expect(backupCalled).toBe(false);
    expect(fetchCalled).toBe(false);
    manager.close();
  });

  test("backup_before=true creates a local before_change backup and aborts runtime change if backup fails", async () => {
    const root = makeTempDir("tegrad-chg-bkp-");
    const serversDir = join(root, "servers");
    const runDir = join(root, "run");
    const stateDir = join(root, "state");
    const backupsDir = join(root, "backups");
    mkdirSync(serversDir, { recursive: true });
    mkdirSync(runDir, { recursive: true });
    preinstallFakeJava(serversDir, 17);
    preinstallFakeJava(serversDir, 21);

    const harness = makeFakeLoaderHarness();
    const backupManager = createBackupManager({
      stateDir,
      serversBaseDir: serversDir,
      localBackupsDir: backupsDir,
      now: () => 1_700_000_000_000,
    });

    const manager = createServerManager({
      serversDir,
      runDir,
      platform: "linux",
      fetchImpl: harness.fetchImpl,
      runFixedImpl: harness.runFixedImpl,
      backupBeforeChange: async (serverId) => {
        await backupManager.createLocalBackup({
          server_id: serverId,
          trigger: "before_change",
          note: "Before runtime change",
        });
      },
    });

    await manager.createServer({
      server_id: "smp",
      name: "SMP",
      minecraft_version: "1.20.4",
      loader: "vanilla",
      memory_mb: 2048,
      eula_accepted: true,
    });

    await manager.changeServerRuntime({
      server_id: "smp",
      minecraft_version: "1.21.4",
      loader: "fabric",
      backup_before: true,
    });

    const listed = await backupManager.listBackups({ server_id: "smp", destination: "local" });
    expect(listed.backups).toHaveLength(1);
    expect(listed.backups[0]?.trigger).toBe("before_change");

    // If backup fails, runtime change is cancelled before touching the server
    const failingManager = createServerManager({
      serversDir,
      runDir,
      platform: "linux",
      fetchImpl: harness.fetchImpl,
      runFixedImpl: harness.runFixedImpl,
      backupBeforeChange: async () => {
        throw new ProtocolError("backup_failed", "Disk full");
      },
    });

    await expect(
      failingManager.changeServerRuntime({
        server_id: "smp",
        minecraft_version: "1.20.4",
        loader: "vanilla",
        backup_before: true,
      }),
    ).rejects.toMatchObject({ code: "backup_failed" });

    expect((await failingManager.getServerStatus("smp")).server.loader).toBe("fabric");

    manager.close();
    failingManager.close();
  });

  test("CommandQueue + RBAC enforces admin role and returns server.change_runtime.result", async () => {
    const serversDir = makeTempDir("tegrad-chg-rbac-");
    const runDir = makeTempDir("tegrad-chg-rbac-run-");
    preinstallFakeJava(serversDir, 17);
    preinstallFakeJava(serversDir, 21);

    const agent = generateSigningKeyPair();
    const owner = generateSigningKeyPair();
    const editor = generateSigningKeyPair();
    const admin = generateSigningKeyPair();
    const adminSession = generateSigningKeyPair();
    const now = 1_700_000_000_000;

    const adminCert = signSessionCertificate({
      sessionPublicKey: adminSession.publicKey,
      accountKeyPair: admin,
      notBefore: now - 1000,
      notAfter: now + 3_600_000,
    });

    const registry = createCoreRegistry();
    const trust = createInMemoryTrustContext({
      agentKeyPair: agent,
      trustedAccountKeys: [owner.publicKey],
      members: [
        {
          account_key: toBase64Url(editor.publicKey),
          account: fingerprint(editor.publicKey),
          granted_by: fingerprint(owner.publicKey),
          role: "editor",
          servers: "*",
          issued_at: now,
        },
        {
          account_key: toBase64Url(admin.publicKey),
          account: fingerprint(admin.publicKey),
          granted_by: fingerprint(owner.publicKey),
          role: "admin",
          servers: ["smp"],
          issued_at: now,
        },
      ],
      now: () => now,
    });

    const frames: TransportFrame[] = [];
    const queue = createCommandQueue({
      trust,
      registry,
      sendFrame: (frame) => frames.push(frame),
      logger: makeSilentLogger(),
    });

    const harness = makeFakeLoaderHarness();
    const manager = createServerManager({
      serversDir,
      runDir,
      platform: "linux",
      fetchImpl: harness.fetchImpl,
      runFixedImpl: harness.runFixedImpl,
      now: () => now,
    });
    registerServerHandlers(queue, manager);

    await manager.createServer({
      server_id: "smp",
      name: "SMP",
      minecraft_version: "1.20.4",
      loader: "vanilla",
      memory_mb: 2048,
      eula_accepted: true,
    });

    const payload: ServerChangeRuntimeBody = {
      server_id: "smp",
      minecraft_version: "1.21.4",
      loader: "fabric",
      loader_version: "0.16.10",
    };

    const editorCmd = createSignedCommand(
      {
        type: "server.change_runtime",
        body: payload,
        agentPublicKey: agent.publicKey,
        signer: editor,
        counter: 1,
        now,
      },
      registry,
    );
    await expect(openCommand(editorCmd, trust, registry)).rejects.toMatchObject({
      code: "insufficient_role",
    });

    const adminCmd = createSignedCommand(
      {
        type: "server.change_runtime",
        body: payload,
        agentPublicKey: agent.publicKey,
        signer: adminSession,
        session: adminCert,
        replyTo: adminSession.publicKey,
        counter: 1,
        now,
      },
      registry,
    );
    const frame: TransportCommandFrame = {
      v: PROTOCOL_VERSION,
      kind: "command",
      route: { agent: fingerprint(agent.publicKey) },
      body: adminCmd,
    };
    await queue.enqueue(frame);

    const ack = frames.find((f) => f.kind === "ack");
    expect(ack?.kind === "ack" && ack.body.ok).toBe(true);

    const events = frames
      .filter((f): f is Extract<TransportFrame, { kind: "event" }> => f.kind === "event")
      .map((f) => openTestEvent(f.body, agent.publicKey, adminSession));
    expect(events).toHaveLength(1);
    const firstEvent = events[0];
    if (firstEvent === undefined) {
      throw new Error("Expected server.change_runtime.result event");
    }
    expect(firstEvent.header.type).toBe("server.change_runtime.result");
    const resultServer = (
      firstEvent.body as { server: { minecraft_version: string; loader: string } }
    ).server;
    expect(resultServer.minecraft_version).toBe("1.21.4");
    expect(resultServer.loader).toBe("fabric");

    // Verify role grant on another server does not grant access here
    const otherGrant = signRoleGrant({
      granter: owner,
      accountPublicKey: editor.publicKey,
      agent: fingerprint(agent.publicKey),
      servers: ["other"],
      role: "admin",
      issuedAt: now,
    });
    expect(otherGrant.role).toBe("admin");

    manager.close();
  });
});
