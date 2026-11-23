// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, describe, expect, test } from "bun:test";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCommandQueue } from "../agent/jobs";
import { createLogger } from "../agent/logger";
import { openTestEvent } from "../agent/test-events";
import { generateSigningKeyPair, ready, toBase64Url } from "../crypto";
import {
  createCoreRegistry,
  createInMemoryTrustContext,
  createSignedCommand,
  openCommand,
  PROTOCOL_VERSION,
  ProtocolError,
  signSessionCertificate,
  type TransportFrame,
} from "../protocol";
import {
  assertPlayitSecretKey,
  buildPlayitSpawnSpec,
  computeSha256Hex,
  createPlayitTunnelManager,
  ensurePlayitBinary,
  getPlayitBinaryPath,
  getPlayitKeyPath,
  type PinnedPlayitAsset,
  PLAYIT_RELEASE_ASSETS,
  PLAYIT_VERSION,
  registerTunnelHandlers,
  resolvePlayitPlatform,
  type SpawnedTunnelProcess,
  savePlayitSecretKey,
  type TunnelSpawnLike,
} from "./index";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

const VALID_HEX_KEY = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir !== undefined) {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe("Playit secret key storage and permissions", () => {
  test("writes playit.key with 0600 permissions, validates format, and rejects permissive mode on POSIX", () => {
    const stateDir = makeTempDir("tegrad-playit-key-");
    const keyPath = savePlayitSecretKey(stateDir, VALID_HEX_KEY);
    expect(keyPath).toBe(getPlayitKeyPath(stateDir));
    expect(readFileSync(keyPath, "utf8").trim()).toBe(VALID_HEX_KEY);
    expect(assertPlayitSecretKey(stateDir)).toBe(keyPath);

    // Invalid keys rejected
    expect(() => savePlayitSecretKey(stateDir, "not-hex-key")).toThrow(ProtocolError);
    expect(() => savePlayitSecretKey(stateDir, "abc")).toThrow(ProtocolError);

    if (process.platform !== "win32") {
      expect(statSync(keyPath).mode & 0o777).toBe(0o600);
      chmodSync(keyPath, 0o644);
      expect(() => assertPlayitSecretKey(stateDir)).toThrow(/0600/);
    }
  });
});

describe("Playit pinned binary download and SHA-256 verification", () => {
  test("pins linux-x64 and linux-arm64 release assets with 64-char SHA-256 hashes", () => {
    expect(PLAYIT_VERSION).toBe("v2.0.2");
    expect(resolvePlayitPlatform("linux", "x64")).toBe("linux-x64");
    expect(resolvePlayitPlatform("linux", "arm64")).toBe("linux-arm64");
    expect(() => resolvePlayitPlatform("win32", "x64")).toThrow(ProtocolError);

    for (const platform of ["linux-x64", "linux-arm64"] as const) {
      const asset = PLAYIT_RELEASE_ASSETS[platform];
      expect(asset.url.startsWith("https://github.com/playit-cloud/playit-agent/")).toBe(true);
      expect(asset.sha256).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  test("downloads binary, verifies SHA-256 before installing, and rejects tampered bytes", async () => {
    const stateDir = makeTempDir("tegrad-playit-bin-");
    const goodBytes = new TextEncoder().encode("#!/bin/sh\necho fake-playitd\n");
    const goodHash = computeSha256Hex(goodBytes);

    const pinnedAsset: PinnedPlayitAsset = {
      version: PLAYIT_VERSION,
      platform: "linux-x64",
      assetName: "playit-linux-amd64",
      url: "https://github.com/playit-cloud/playit-agent/releases/download/v2.0.2/playit-linux-amd64",
      sha256: goodHash,
    };

    // Tampered download must fail with hash_mismatch and leave no binary on disk
    const tamperedDir = makeTempDir("tegrad-playit-bad-");
    await expect(
      ensurePlayitBinary({
        stateDir: tamperedDir,
        asset: pinnedAsset,
        fetchImpl: async () => new Response(new TextEncoder().encode("tampered-binary")),
      }),
    ).rejects.toThrow(/SHA-256 mismatch/);
    expect(existsSync(getPlayitBinaryPath(tamperedDir))).toBe(false);

    // Valid download installs binary and passes subsequent verification without re-downloading
    let fetchCount = 0;
    const binPath = await ensurePlayitBinary({
      stateDir,
      asset: pinnedAsset,
      fetchImpl: async () => {
        fetchCount++;
        return new Response(goodBytes);
      },
    });
    expect(binPath).toBe(getPlayitBinaryPath(stateDir));
    expect(fetchCount).toBe(1);

    const cachedPath = await ensurePlayitBinary({
      stateDir,
      asset: pinnedAsset,
      fetchImpl: async () => {
        fetchCount++;
        return new Response(goodBytes);
      },
    });
    expect(cachedPath).toBe(binPath);
    expect(fetchCount).toBe(1);
  });
});

describe("Playit process supervision, spawn args/env, and secret redaction", () => {
  test("spawns playitd with fixed argv, no shell, minimal env, and never exposes secret key in args/env/logs/status", async () => {
    const stateDir = makeTempDir("tegrad-playit-run-");
    const fakeBinBytes = new TextEncoder().encode("fake-playitd-binary");
    const fakeAsset: PinnedPlayitAsset = {
      version: PLAYIT_VERSION,
      platform: "linux-x64",
      assetName: "playit-linux-amd64",
      url: "https://github.com/playit-cloud/playit-agent/releases/download/v2.0.2/playit-linux-amd64",
      sha256: computeSha256Hex(fakeBinBytes),
    };

    const logLines: string[] = [];
    const logger = createLogger({
      level: "debug",
      stdout: (line) => logLines.push(line),
      stderr: (line) => logLines.push(line),
    });

    let spawnedCmd: readonly string[] | undefined;
    let spawnedEnv: Readonly<Record<string, string>> | undefined;
    let resolveExit: ((code: number) => void) | undefined;
    const killedSignals: (number | NodeJS.Signals | undefined)[] = [];

    const fakeSpawn: TunnelSpawnLike = (cmd, opts): SpawnedTunnelProcess => {
      spawnedCmd = cmd;
      spawnedEnv = opts.env;
      const exited = new Promise<number>((resolve) => {
        resolveExit = resolve;
      });
      return {
        pid: 4242,
        exited,
        kill(signal) {
          killedSignals.push(signal);
          resolveExit?.(0);
        },
      };
    };

    const manager = createPlayitTunnelManager({
      stateDir,
      asset: fakeAsset,
      platform: "linux",
      fetchImpl: async () => new Response(fakeBinBytes),
      spawnImpl: fakeSpawn,
      now: () => 1_700_000_000_000,
      logger,
    });

    // Cannot start before key is set
    await expect(manager.start()).rejects.toThrow(ProtocolError);

    manager.setKey(VALID_HEX_KEY);
    expect(manager.status()).toMatchObject({
      configured: true,
      running: false,
      pid: null,
      version: PLAYIT_VERSION,
    });

    const started = await manager.start();
    expect(started.running).toBe(true);
    expect(started.pid).toBe(4242);

    // Verify fixed argv (no shell, secret passed via --secret-path file, NOT inline)
    expect(spawnedCmd).toEqual([
      getPlayitBinaryPath(stateDir),
      "--secret-path",
      getPlayitKeyPath(stateDir),
      "--socket-path",
      join(stateDir, "playit.sock"),
      "--cert-dir",
      join(stateDir, "playit-certs"),
    ]);
    expect(spawnedCmd?.join(" ")).not.toContain(VALID_HEX_KEY);

    // Verify minimal environment
    expect(spawnedEnv).toEqual({
      PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      LC_ALL: "C",
    });
    expect(JSON.stringify(spawnedEnv)).not.toContain(VALID_HEX_KEY);

    // Starting twice fails
    await expect(manager.start()).rejects.toThrow(ProtocolError);

    const stopped = await manager.stop();
    expect(stopped.running).toBe(false);
    expect(stopped.pid).toBeNull();
    expect(killedSignals).toEqual(["SIGTERM"]);

    // Verify secret key never appears in logs or status
    const allLogs = logLines.join("\n");
    expect(allLogs).not.toContain(VALID_HEX_KEY);
    expect(JSON.stringify(started)).not.toContain(VALID_HEX_KEY);
    expect(JSON.stringify(stopped)).not.toContain(VALID_HEX_KEY);

    // buildPlayitSpawnSpec matches directly
    const spec = buildPlayitSpawnSpec({
      binaryPath: "/var/lib/tegrad/bin/playitd",
      stateDir: "/var/lib/tegrad",
      keyPath: "/var/lib/tegrad/playit.key",
      platform: "linux",
    });
    expect(spec.args).toEqual([
      "--secret-path",
      "/var/lib/tegrad/playit.key",
      "--socket-path",
      join("/var/lib/tegrad", "playit.sock"),
      "--cert-dir",
      join("/var/lib/tegrad", "playit-certs"),
    ]);
  });
});

describe("Tunnel protocol commands and sensitivity enforcement", () => {
  test("tunnel.playit.set_key is rejected with session key and accepted with direct account key", async () => {
    await ready();
    const agentKeyPair = generateSigningKeyPair();
    const accountKeyPair = generateSigningKeyPair();
    const sessionKeyPair = generateSigningKeyPair();
    const registry = createCoreRegistry();
    const nowMs = 1_700_000_000_000;

    const sessionCert = signSessionCertificate({
      accountKeyPair,
      sessionPublicKey: sessionKeyPair.publicKey,
      notBefore: nowMs - 1000,
      notAfter: nowMs + 60_000,
      id: toBase64Url(new Uint8Array(16).fill(7)),
    });

    const trust = createInMemoryTrustContext({
      agentKeyPair,
      trustedAccountKeys: [accountKeyPair.publicKey],
      now: () => nowMs,
    });

    // Session key rejected for tunnel.playit.set_key
    const setKeyWithSession = createSignedCommand(
      {
        type: "tunnel.playit.set_key",
        body: { secret_key: VALID_HEX_KEY },
        agentPublicKey: agentKeyPair.publicKey,
        signer: sessionKeyPair,
        session: sessionCert,
        counter: 1,
        now: nowMs,
      },
      registry,
    );
    try {
      await openCommand(setKeyWithSession, trust, registry);
      expect.unreachable("Expected sensitive_requires_account_key");
    } catch (err) {
      expect(err instanceof ProtocolError && err.code).toBe("sensitive_requires_account_key");
    }

    // Session key accepted for tunnel.playit.status
    const statusWithSession = createSignedCommand(
      {
        type: "tunnel.playit.status",
        body: {},
        agentPublicKey: agentKeyPair.publicKey,
        signer: sessionKeyPair,
        session: sessionCert,
        counter: 2,
        now: nowMs,
      },
      registry,
    );
    const openedStatus = await openCommand(statusWithSession, trust, registry);
    expect(openedStatus.header.type).toBe("tunnel.playit.status");

    // Direct account key accepted for tunnel.playit.set_key
    const setKeyWithAccount = createSignedCommand(
      {
        type: "tunnel.playit.set_key",
        body: { secret_key: VALID_HEX_KEY },
        agentPublicKey: agentKeyPair.publicKey,
        signer: accountKeyPair,
        counter: 1,
        now: nowMs,
      },
      registry,
    );
    const openedSetKey = await openCommand(setKeyWithAccount, trust, registry);
    expect(openedSetKey.header.type).toBe("tunnel.playit.set_key");
  });

  test("registerTunnelHandlers executes set_key, status, start, stop via CommandQueue", async () => {
    await ready();
    const stateDir = makeTempDir("tegrad-playit-queue-");
    const fakeBinBytes = new TextEncoder().encode("fake-playitd");
    const fakeAsset: PinnedPlayitAsset = {
      version: PLAYIT_VERSION,
      platform: "linux-x64",
      assetName: "playit-linux-amd64",
      url: "https://github.com/playit-cloud/playit-agent/releases/download/v2.0.2/playit-linux-amd64",
      sha256: computeSha256Hex(fakeBinBytes),
    };

    const agentKeyPair = generateSigningKeyPair();
    const accountKeyPair = generateSigningKeyPair();
    const nowMs = 1_700_000_000_000;
    const registry = createCoreRegistry();
    const trust = createInMemoryTrustContext({
      agentKeyPair,
      trustedAccountKeys: [accountKeyPair.publicKey],
      now: () => nowMs,
    });

    const frames: TransportFrame[] = [];
    const logger = createLogger({ level: "error", stdout: () => {}, stderr: () => {} });
    const queue = createCommandQueue({
      trust,
      registry,
      sendFrame: (frame) => frames.push(frame),
      logger,
    });

    const manager = createPlayitTunnelManager({
      stateDir,
      asset: fakeAsset,
      platform: "linux",
      fetchImpl: async () => new Response(fakeBinBytes),
      spawnImpl: () => {
        let done: ((code: number) => void) | undefined;
        return {
          pid: 9001,
          exited: new Promise<number>((r) => {
            done = r;
          }),
          kill() {
            done?.(0);
          },
        };
      },
      now: () => nowMs,
    });
    registerTunnelHandlers(queue, manager);

    let counter = 1;
    const sendCmd = async (type: string, body: unknown) => {
      const signed = createSignedCommand(
        {
          type,
          body,
          agentPublicKey: agentKeyPair.publicKey,
          signer: accountKeyPair,
          counter: counter++,
          now: nowMs,
        },
        registry,
      );
      await queue.enqueue({
        v: PROTOCOL_VERSION,
        kind: "command",
        route: { agent: "agent-1" },
        body: signed,
      });
    };

    await sendCmd("tunnel.playit.set_key", { secret_key: VALID_HEX_KEY });
    await sendCmd("tunnel.playit.start", {});
    await sendCmd("tunnel.playit.status", {});
    await sendCmd("tunnel.playit.stop", {});

    const events = frames
      .filter((f): f is Extract<TransportFrame, { kind: "event" }> => f.kind === "event")
      .map((f) => openTestEvent(f.body, agentKeyPair.publicKey, accountKeyPair));

    expect(events.map((e) => e.header.type)).toEqual([
      "tunnel.playit.key_updated",
      "tunnel.playit.started",
      "tunnel.playit.status.result",
      "tunnel.playit.stopped",
    ]);

    const acks = frames.filter(
      (f): f is Extract<TransportFrame, { kind: "ack" }> => f.kind === "ack",
    );
    expect(acks).toHaveLength(4);
    expect(acks.every((a) => a.body.ok)).toBe(true);
  });
});

describe("Adversarial playit security checks", () => {
  test("blocks redirect to disallowed host, HTTP downgrade, non-standard port, redirect loop, and streaming size overflow", async () => {
    const baseAsset: PinnedPlayitAsset = {
      version: PLAYIT_VERSION,
      platform: "linux-x64",
      assetName: "playit-linux-amd64",
      url: "https://github.com/playit-cloud/playit-agent/releases/download/v2.0.2/playit-linux-amd64",
      sha256: "a".repeat(64),
    };

    // Redirect to disallowed host
    await expect(
      ensurePlayitBinary({
        stateDir: makeTempDir("tegrad-playit-adv-1-"),
        asset: baseAsset,
        fetchImpl: async () =>
          new Response(null, {
            status: 302,
            headers: { location: "https://evil.example/playitd" },
          }),
      }),
    ).rejects.toMatchObject({ code: "download_failed" });

    // Redirect HTTP downgrade
    await expect(
      ensurePlayitBinary({
        stateDir: makeTempDir("tegrad-playit-adv-2-"),
        asset: baseAsset,
        fetchImpl: async () =>
          new Response(null, {
            status: 302,
            headers: { location: "http://github.com/playitd" },
          }),
      }),
    ).rejects.toMatchObject({ code: "download_failed" });

    // Redirect to non-standard port on allowed host
    await expect(
      ensurePlayitBinary({
        stateDir: makeTempDir("tegrad-playit-adv-3-"),
        asset: baseAsset,
        fetchImpl: async () =>
          new Response(null, {
            status: 302,
            headers: { location: "https://github.com:8443/playitd" },
          }),
      }),
    ).rejects.toMatchObject({ code: "download_failed" });

    // Infinite redirect loop within allowlist
    await expect(
      ensurePlayitBinary({
        stateDir: makeTempDir("tegrad-playit-adv-4-"),
        asset: baseAsset,
        fetchImpl: async () =>
          new Response(null, {
            status: 302,
            headers: { location: "https://objects.githubusercontent.com/loop" },
          }),
      }),
    ).rejects.toMatchObject({ code: "download_failed" });

    // Streaming overflow without Content-Length
    await expect(
      ensurePlayitBinary({
        stateDir: makeTempDir("tegrad-playit-adv-5-"),
        asset: baseAsset,
        maxBytes: 64,
        fetchImpl: async () =>
          new Response(
            new ReadableStream<Uint8Array>({
              start(controller) {
                controller.enqueue(new Uint8Array(40).fill(0x55));
                controller.enqueue(new Uint8Array(40).fill(0x66));
                controller.close();
              },
            }),
            { status: 200 },
          ),
      }),
    ).rejects.toMatchObject({ code: "download_failed" });
  });

  test("fails closed if existing playitd binary on disk is tampered and prevents concurrent double-start", async () => {
    const stateDir = makeTempDir("tegrad-playit-adv-tamper-");
    const goodBytes = new TextEncoder().encode("valid-playitd");
    const goodAsset: PinnedPlayitAsset = {
      version: PLAYIT_VERSION,
      platform: "linux-x64",
      assetName: "playit-linux-amd64",
      url: "https://github.com/playit-cloud/playit-agent/releases/download/v2.0.2/playit-linux-amd64",
      sha256: computeSha256Hex(goodBytes),
    };

    // Pre-populate a tampered binary at <stateDir>/bin/playitd
    const binPath = getPlayitBinaryPath(stateDir);
    mkdirSync(join(stateDir, "bin"), { recursive: true });
    writeFileSync(binPath, "malicious-replacement");

    let spawnCount = 0;
    const manager = createPlayitTunnelManager({
      stateDir,
      asset: goodAsset,
      platform: "linux",
      spawnImpl: () => {
        spawnCount++;
        return {
          pid: 1234,
          exited: new Promise<number>(() => {}),
          kill() {},
        };
      },
    });
    manager.setKey(VALID_HEX_KEY);

    await expect(manager.start()).rejects.toMatchObject({ code: "hash_mismatch" });
    expect(spawnCount).toBe(0);

    // Concurrent start calls must not spawn two processes
    const raceDir = makeTempDir("tegrad-playit-adv-race-");
    let releaseDownload: (() => void) | undefined;
    let raceSpawns = 0;
    const raceManager = createPlayitTunnelManager({
      stateDir: raceDir,
      asset: goodAsset,
      platform: "linux",
      fetchImpl: async () => {
        await new Promise<void>((resolve) => {
          releaseDownload = resolve;
        });
        return new Response(goodBytes);
      },
      spawnImpl: () => {
        raceSpawns++;
        let done: ((code: number) => void) | undefined;
        return {
          pid: 5678,
          exited: new Promise<number>((resolve) => {
            done = resolve;
          }),
          kill() {
            done?.(0);
          },
        };
      },
    });
    raceManager.setKey(VALID_HEX_KEY);

    const first = raceManager.start();
    const second = raceManager.start();
    await expect(second).rejects.toMatchObject({ code: "tunnel_already_running" });
    releaseDownload?.();
    const started = await first;
    expect(started.running).toBe(true);
    expect(raceSpawns).toBe(1);
    await raceManager.close();
  });

  test("invalid secret key error never echoes the key material", () => {
    const stateDir = makeTempDir("tegrad-playit-adv-key-");
    const leakyInvalidKey = "not-hex-SECRET_PLAYIT_TOKEN_VALUE_12345";
    try {
      savePlayitSecretKey(stateDir, leakyInvalidKey);
      expect.unreachable("Expected invalid_body");
    } catch (err) {
      expect(err).toBeInstanceOf(ProtocolError);
      expect((err as Error).message).not.toContain("SECRET_PLAYIT_TOKEN_VALUE_12345");
    }
  });
});
