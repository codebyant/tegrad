// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getStatePaths, loadConfig, StateError, type TimerProvider } from "../agent";
import { generateSigningKeyPair, ready, signingKeyPairFromSeed } from "../crypto";
import {
  checkForUpdate,
  computeBytesSha256,
  computeNextCheckDelayMs,
  createAutoUpdater,
  DEFAULT_UPDATE_INTERVAL_MS,
  DEFAULT_UPDATE_JITTER_RATIO,
  MANIFEST_SCHEMA_VERSION,
  READY_FILE_NAME,
  readyFileSchema,
  STAGED_BINARY_NAME,
  STAGED_MANIFEST_NAME,
  signManifest,
  type UnsignedReleaseManifest,
  UpdateError,
} from "./index";

const TEST_RELEASE_SEED = new Uint8Array(32).fill(0x42);

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "tegrad-updater-test-"));
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

function buildSignedManifest(
  version: string,
  channel: "stable" | "beta" | "nightly",
  binaryBytes: Uint8Array,
  secretKey: Uint8Array,
  assetUrl: string = `https://github.com/codebyant/tegrad/releases/download/v${version}/tegrad-linux-x64`,
) {
  const sha = computeBytesSha256(binaryBytes);
  const unsigned: UnsignedReleaseManifest = {
    v: MANIFEST_SCHEMA_VERSION,
    channel,
    version,
    tag: `v${version}`,
    published_at: 1_795_300_000_000,
    assets: {
      "linux-x64": {
        url: assetUrl,
        sha256: sha,
        size: binaryBytes.byteLength,
      },
      "linux-arm64": {
        url: assetUrl.replace("linux-x64", "linux-arm64"),
        sha256: sha,
        size: binaryBytes.byteLength,
      },
    },
  };
  return signManifest(unsigned, secretKey);
}

describe("updater (checkForUpdate and createAutoUpdater)", () => {
  test("verifies manifest signature, downloads binary, checks SHA-256, and stages files with ready.json written last", async () => {
    const stateDir = makeTempDir();
    const keyPair = signingKeyPairFromSeed(TEST_RELEASE_SEED);
    const binBytes = new TextEncoder().encode("#!/bin/sh\n# never executed by agent\n");
    const manifest = buildSignedManifest("0.2.0", "stable", binBytes, keyPair.secretKey);
    const fetchedUrls: string[] = [];

    const result = await checkForUpdate({
      stateDir,
      channel: "stable",
      currentVersion: "0.1.0",
      arch: "linux-x64",
      publicKey: keyPair.publicKey,
      now: () => 1_795_300_123_000,
      fetch: async (input) => {
        const url = String(input);
        fetchedUrls.push(url);
        if (url.endsWith("/stable.json")) {
          return new Response(JSON.stringify(manifest), { status: 200 });
        }
        if (url === manifest.assets["linux-x64"].url) {
          return new Response(binBytes, {
            status: 200,
            headers: { "content-length": String(binBytes.byteLength) },
          });
        }
        return new Response("Not found", { status: 404 });
      },
    });

    expect(result.status).toBe("staged");
    if (result.status !== "staged") return;

    expect(result.targetVersion).toBe("0.2.0");
    expect(result.sha256).toBe(computeBytesSha256(binBytes));
    expect(fetchedUrls.length).toBe(2);

    const { updateDir } = getStatePaths(stateDir);
    expect(existsSync(join(updateDir, STAGED_BINARY_NAME))).toBe(true);
    expect(existsSync(join(updateDir, STAGED_MANIFEST_NAME))).toBe(true);
    expect(existsSync(join(updateDir, READY_FILE_NAME))).toBe(true);

    const stagedBin = readFileSync(join(updateDir, STAGED_BINARY_NAME));
    expect(Buffer.compare(stagedBin, Buffer.from(binBytes))).toBe(0);

    const readyData = readyFileSchema.parse(
      JSON.parse(readFileSync(join(updateDir, READY_FILE_NAME), "utf8")),
    );
    expect(readyData.version).toBe("0.2.0");
    expect(readyData.sha256).toBe(computeBytesSha256(binBytes));

    if (process.platform !== "win32") {
      expect(statSync(updateDir).mode & 0o777).toBe(0o700);
      expect(statSync(join(updateDir, STAGED_BINARY_NAME)).mode & 0o777).toBe(0o600);
      expect(statSync(join(updateDir, STAGED_MANIFEST_NAME)).mode & 0o777).toBe(0o600);
      expect(statSync(join(updateDir, READY_FILE_NAME)).mode & 0o777).toBe(0o600);
    }
  });

  test("verifies manifest signature BEFORE attempting to download binary", async () => {
    const stateDir = makeTempDir();
    const attacker = generateSigningKeyPair();
    const binBytes = new TextEncoder().encode("malicious-binary");
    const forged = buildSignedManifest("9.9.9", "stable", binBytes, attacker.secretKey);
    const fetchedUrls: string[] = [];

    try {
      await checkForUpdate({
        stateDir,
        channel: "stable",
        currentVersion: "0.1.0",
        arch: "linux-x64",
        fetch: async (input) => {
          const url = String(input);
          fetchedUrls.push(url);
          if (url.endsWith("/stable.json")) {
            return new Response(JSON.stringify(forged), { status: 200 });
          }
          throw new Error("Binary download should never be attempted for an untrusted manifest");
        },
      });
      throw new Error("Expected bad_manifest_signature");
    } catch (err) {
      expect(err).toBeInstanceOf(UpdateError);
      expect((err as UpdateError).code).toBe("bad_manifest_signature");
    }

    expect(fetchedUrls.length).toBe(1);
    const { updateDir } = getStatePaths(stateDir);
    expect(existsSync(join(updateDir, READY_FILE_NAME))).toBe(false);
  });

  test("deletes temp file and never creates ready.json when downloaded binary SHA-256 mismatches", async () => {
    const stateDir = makeTempDir();
    const keyPair = signingKeyPairFromSeed(TEST_RELEASE_SEED);
    const expectedBytes = new TextEncoder().encode("legitimate-binary-bytes");
    const tamperedBytes = new TextEncoder().encode("tampered-binary-byteXXX");
    const manifest = buildSignedManifest("0.2.0", "stable", expectedBytes, keyPair.secretKey);

    try {
      await checkForUpdate({
        stateDir,
        channel: "stable",
        currentVersion: "0.1.0",
        arch: "linux-x64",
        publicKey: keyPair.publicKey,
        fetch: async (input) => {
          const url = String(input);
          if (url.endsWith("/stable.json")) {
            return new Response(JSON.stringify(manifest), { status: 200 });
          }
          return new Response(tamperedBytes, { status: 200 });
        },
      });
      throw new Error("Expected hash_mismatch");
    } catch (err) {
      expect(err).toBeInstanceOf(UpdateError);
      expect((err as UpdateError).code).toBe("hash_mismatch");
    }

    const { updateDir } = getStatePaths(stateDir);
    expect(readdirSync(updateDir)).toEqual([]);
    expect(existsSync(join(updateDir, READY_FILE_NAME))).toBe(false);
  });

  test("refuses non-https manifest URLs, non-https asset URLs, and disallowed asset hosts", async () => {
    const stateDir = makeTempDir();
    const keyPair = signingKeyPairFromSeed(TEST_RELEASE_SEED);
    const binBytes = new TextEncoder().encode("binary");

    // Non-https manifest base URL
    await expect(
      checkForUpdate({
        stateDir,
        manifestBaseUrl: "http://github.com/codebyant/tegrad/releases/latest/download",
        currentVersion: "0.1.0",
        arch: "linux-x64",
        fetch: async () => new Response("{}", { status: 200 }),
      }),
    ).rejects.toMatchObject({ code: "invalid_url" });

    // Signed manifest pointing to an untrusted host
    const badHostManifest = buildSignedManifest(
      "0.2.0",
      "stable",
      binBytes,
      keyPair.secretKey,
      "https://evil.attacker.example/tegrad-linux-x64",
    );

    let binaryFetched = false;
    await expect(
      checkForUpdate({
        stateDir,
        channel: "stable",
        currentVersion: "0.1.0",
        arch: "linux-x64",
        publicKey: keyPair.publicKey,
        fetch: async (input) => {
          if (String(input).endsWith("/stable.json")) {
            return new Response(JSON.stringify(badHostManifest), { status: 200 });
          }
          binaryFetched = true;
          return new Response(binBytes, { status: 200 });
        },
      }),
    ).rejects.toMatchObject({ code: "host_not_allowed" });

    expect(binaryFetched).toBe(false);
  });

  test("returns up_to_date on equal or older version unless allowDowngrade is true", async () => {
    const stateDir = makeTempDir();
    const keyPair = signingKeyPairFromSeed(TEST_RELEASE_SEED);
    const binBytes = new TextEncoder().encode("older-binary");
    const manifest = buildSignedManifest("0.1.0", "stable", binBytes, keyPair.secretKey);
    let binaryDownloads = 0;

    const fakeFetch = async (input: string | URL | Request) => {
      if (String(input).endsWith("/stable.json")) {
        return new Response(JSON.stringify(manifest), { status: 200 });
      }
      binaryDownloads++;
      return new Response(binBytes, { status: 200 });
    };

    const resBlocked = await checkForUpdate({
      stateDir,
      channel: "stable",
      currentVersion: "0.2.0",
      arch: "linux-x64",
      publicKey: keyPair.publicKey,
      fetch: fakeFetch,
    });
    expect(resBlocked.status).toBe("up_to_date");
    expect(binaryDownloads).toBe(0);

    const resAllowed = await checkForUpdate({
      stateDir,
      channel: "stable",
      currentVersion: "0.2.0",
      allowDowngrade: true,
      arch: "linux-x64",
      publicKey: keyPair.publicKey,
      fetch: fakeFetch,
    });
    expect(resAllowed.status).toBe("staged");
    expect(binaryDownloads).toBe(1);
  });

  test("auto-updater schedules 6h checks with ±10% jitter and respects auto: false", async () => {
    expect(
      computeNextCheckDelayMs(DEFAULT_UPDATE_INTERVAL_MS, DEFAULT_UPDATE_JITTER_RATIO, () => 0),
    ).toBe(Math.round(DEFAULT_UPDATE_INTERVAL_MS * 0.9));
    expect(
      computeNextCheckDelayMs(DEFAULT_UPDATE_INTERVAL_MS, DEFAULT_UPDATE_JITTER_RATIO, () => 1),
    ).toBe(Math.round(DEFAULT_UPDATE_INTERVAL_MS * 1.1));

    const stateDir = makeTempDir();
    const scheduled: { fn: () => void; ms: number }[] = [];
    const fakeTimers: TimerProvider = {
      setTimeout(fn, ms) {
        const entry = { fn, ms };
        scheduled.push(entry);
        return entry;
      },
      clearTimeout() {},
      setInterval() {
        return 0;
      },
      clearInterval() {},
      now: () => 0,
    };

    const disabled = createAutoUpdater({
      stateDir,
      auto: false,
      timers: fakeTimers,
      fetch: async () => new Response("{}", { status: 404 }),
    });
    disabled.start();
    expect(disabled.isRunning()).toBe(false);
    expect(scheduled.length).toBe(0);

    const enabled = createAutoUpdater({
      stateDir,
      auto: true,
      timers: fakeTimers,
      random: () => 0.5,
      fetch: async () => new Response("{}", { status: 404 }),
    });
    enabled.start();
    expect(enabled.isRunning()).toBe(true);
    expect(scheduled.length).toBe(1);
    expect(scheduled[0]?.ms).toBe(DEFAULT_UPDATE_INTERVAL_MS);
    enabled.stop();
    expect(enabled.isRunning()).toBe(false);
  });

  test("loadConfig parses optional update configuration and rejects insecure manifest_base_url", () => {
    const stateDir = makeTempDir();
    const { configPath } = getStatePaths(stateDir);

    writeFileSync(
      configPath,
      JSON.stringify({
        api_url: "https://api.tegramc.com",
        update: {
          channel: "beta",
          auto: false,
          manifest_base_url: "https://releases.tegramc.com",
        },
      }),
      "utf8",
    );

    const cfg = loadConfig(stateDir);
    expect(cfg.update).toEqual({
      channel: "beta",
      auto: false,
      manifestBaseUrl: "https://releases.tegramc.com/",
    });

    writeFileSync(
      configPath,
      JSON.stringify({
        api_url: "https://api.tegramc.com",
        update: {
          manifest_base_url: "http://releases.tegramc.com",
        },
      }),
      "utf8",
    );
    expect(() => loadConfig(stateDir)).toThrow(StateError);
  });

  test("updater.ts never invokes child_process, Bun.spawn, or runFixed (never executes downloaded binary)", () => {
    const updaterSource = readFileSync(join(import.meta.dir, "updater.ts"), "utf8");
    expect(updaterSource).not.toMatch(/\bBun\.spawn\b/);
    expect(updaterSource).not.toMatch(/\bchild_process\b/);
    expect(updaterSource).not.toMatch(/\brunFixed\b/);
    expect(updaterSource).not.toMatch(/\bexecFile\b/);
    expect(updaterSource).not.toMatch(/\bspawnSync\b/);
  });

  test("blocks redirected asset downloads to disallowed hosts or non-https URLs", async () => {
    const stateDir = makeTempDir();
    const keyPair = signingKeyPairFromSeed(TEST_RELEASE_SEED);
    const binBytes = new TextEncoder().encode("binary-payload");
    const manifest = buildSignedManifest("0.2.0", "stable", binBytes, keyPair.secretKey);

    await expect(
      checkForUpdate({
        stateDir,
        channel: "stable",
        currentVersion: "0.1.0",
        arch: "linux-x64",
        publicKey: keyPair.publicKey,
        fetch: async (input) => {
          const url = String(input);
          if (url.endsWith("/stable.json")) {
            return new Response(JSON.stringify(manifest), { status: 200 });
          }
          const redirected = new Response(binBytes, { status: 200 });
          Object.defineProperty(redirected, "url", {
            value: "https://evil-redirect.attacker.example/tegrad-linux-x64",
          });
          return redirected;
        },
      }),
    ).rejects.toMatchObject({ code: "host_not_allowed" });

    const { updateDir } = getStatePaths(stateDir);
    expect(existsSync(join(updateDir, READY_FILE_NAME))).toBe(false);
  });
});
