// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runCli } from "../cli/main";
import { generateSigningKeyPair, ready, signingKeyPairFromSeed } from "../crypto";
import {
  applyStagedUpdate,
  computeBytesSha256,
  MANIFEST_SCHEMA_VERSION,
  MAX_BINARY_BYTES,
  MAX_MANIFEST_BYTES,
  READY_FILE_NAME,
  type ReleaseChannel,
  STAGED_BINARY_NAME,
  STAGED_MANIFEST_NAME,
  signManifest,
  type UnsignedReleaseManifest,
  UpdateError,
} from "./index";

const TEST_RELEASE_SEED = new Uint8Array(32).fill(0x42);

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "tegrad-apply-test-"));
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

function stageFixture(params: {
  readonly rootDir: string;
  readonly currentBinaryBytes: Uint8Array;
  readonly stagedBinaryBytes: Uint8Array;
  readonly manifestVersion: string;
  readonly channel?: ReleaseChannel;
  readonly signingSecretKey: Uint8Array;
  readonly hashOverride?: string;
  readonly readyVersionOverride?: string;
}): {
  readonly binDir: string;
  readonly binPath: string;
  readonly prevBinPath: string;
  readonly updateDir: string;
} {
  const binDir = join(params.rootDir, "opt-bin");
  const updateDir = join(params.rootDir, "state-update");
  mkdirSync(binDir, { recursive: true });
  mkdirSync(updateDir, { recursive: true });

  const binPath = join(binDir, "tegrad");
  const prevBinPath = join(binDir, "tegrad.prev");
  writeFileSync(binPath, params.currentBinaryBytes);

  const channel = params.channel ?? "stable";
  const sha = params.hashOverride ?? computeBytesSha256(params.stagedBinaryBytes);
  const unsigned: UnsignedReleaseManifest = {
    v: MANIFEST_SCHEMA_VERSION,
    channel,
    version: params.manifestVersion,
    tag: `v${params.manifestVersion}`,
    published_at: 1_795_300_000_000,
    assets: {
      "linux-x64": {
        url: `https://github.com/codebyant/tegrad/releases/download/v${params.manifestVersion}/tegrad-linux-x64`,
        sha256: sha,
        size: params.stagedBinaryBytes.byteLength,
      },
      "linux-arm64": {
        url: `https://github.com/codebyant/tegrad/releases/download/v${params.manifestVersion}/tegrad-linux-arm64`,
        sha256: sha,
        size: params.stagedBinaryBytes.byteLength,
      },
    },
  };
  const signed = signManifest(unsigned, params.signingSecretKey);

  writeFileSync(join(updateDir, STAGED_BINARY_NAME), params.stagedBinaryBytes);
  writeFileSync(join(updateDir, STAGED_MANIFEST_NAME), JSON.stringify(signed, null, 2), "utf8");
  const readyVer = params.readyVersionOverride ?? params.manifestVersion;
  writeFileSync(
    join(updateDir, READY_FILE_NAME),
    JSON.stringify({
      v: 1,
      channel,
      version: readyVer,
      tag: `v${readyVer}`,
      arch: "linux-x64",
      sha256: sha,
      size: params.stagedBinaryBytes.byteLength,
      staged_at: 1_795_300_000_000,
    }),
    "utf8",
  );

  return { binDir, binPath, prevBinPath, updateDir };
}

describe("applyStagedUpdate (TOCTOU defense, verification, atomic install, rollback)", () => {
  test("copies into root staging dir BEFORE verification, resists TOCTOU swap, installs atomically with tegrad.prev, and cleans staging", async () => {
    const rootDir = makeTempDir();
    const keyPair = signingKeyPairFromSeed(TEST_RELEASE_SEED);
    const oldBytes = new TextEncoder().encode("old-tegrad-v0.1.0");
    const newBytes = new TextEncoder().encode("new-tegrad-v0.2.0-verified");
    const evilSwapBytes = new TextEncoder().encode("EVIL-TOCTOU-SWAP-PAYLOAD!");

    const fx = stageFixture({
      rootDir,
      currentBinaryBytes: oldBytes,
      stagedBinaryBytes: newBytes,
      manifestVersion: "0.2.0",
      signingSecretKey: keyPair.secretKey,
    });

    let verifiedRootBinaryPath = "";
    const calls: string[] = [];

    const result = await applyStagedUpdate({
      updateDir: fx.updateDir,
      binPath: fx.binPath,
      currentVersion: "0.1.0",
      arch: "linux-x64",
      publicKey: keyPair.publicKey,
      stabilizeMs: 0,
      sleep: async () => {},
      afterCopyBeforeVerifyHook: ({ updateDir, rootBinaryPath }) => {
        // Simulate compromised unprivileged 'tegrad' user swapping staged-tegrad
        // right after the root applicator copied it into /opt/tegrad/bin/.staging-tmp-*
        expect(rootBinaryPath.startsWith(fx.binDir)).toBe(true);
        writeFileSync(join(updateDir, STAGED_BINARY_NAME), evilSwapBytes);
      },
      verifyHook: (rootBinaryPath) => {
        verifiedRootBinaryPath = rootBinaryPath;
      },
      runCommand: async (command, args) => {
        calls.push(`${command} ${args.join(" ")}`);
        if (args[0] === "restart") {
          return { code: 0, stdout: "", stderr: "" };
        }
        if (args[0] === "is-active") {
          return { code: 0, stdout: "active\n", stderr: "" };
        }
        return { code: 1, stdout: "", stderr: "unexpected" };
      },
    });

    expect(result.applied).toBe(true);
    expect(result.version).toBe("0.2.0");
    expect(verifiedRootBinaryPath.startsWith(fx.binDir)).toBe(true);

    // Installed binary MUST be the verified newBytes, NEVER the TOCTOU-swapped evil payload
    expect(Buffer.compare(readFileSync(fx.binPath), Buffer.from(newBytes))).toBe(0);
    // Backup tegrad.prev contains old binary
    expect(Buffer.compare(readFileSync(fx.prevBinPath), Buffer.from(oldBytes))).toBe(0);
    // Staging files removed
    expect(existsSync(join(fx.updateDir, READY_FILE_NAME))).toBe(false);
    expect(existsSync(join(fx.updateDir, STAGED_BINARY_NAME))).toBe(false);
    expect(existsSync(join(fx.updateDir, STAGED_MANIFEST_NAME))).toBe(false);
    expect(calls).toEqual([
      "systemctl restart tegrad.service",
      "systemctl is-active tegrad.service",
    ]);
  });

  test("rejects tampered binary or untrusted signature without modifying installed binary and cleans up ready.json", async () => {
    const rootDir = makeTempDir();
    const keyPair = signingKeyPairFromSeed(TEST_RELEASE_SEED);
    const attacker = generateSigningKeyPair();
    const oldBytes = new TextEncoder().encode("old-tegrad-v0.1.0");
    const newBytes = new TextEncoder().encode("new-tegrad-v0.2.0");

    // Case 1: attacker signature
    const fx1 = stageFixture({
      rootDir,
      currentBinaryBytes: oldBytes,
      stagedBinaryBytes: newBytes,
      manifestVersion: "0.2.0",
      signingSecretKey: attacker.secretKey,
    });

    let restartCalled = false;
    await expect(
      applyStagedUpdate({
        updateDir: fx1.updateDir,
        binPath: fx1.binPath,
        currentVersion: "0.1.0",
        arch: "linux-x64",
        publicKey: keyPair.publicKey,
        runCommand: async () => {
          restartCalled = true;
          return { code: 0, stdout: "active\n", stderr: "" };
        },
      }),
    ).rejects.toMatchObject({ code: "bad_manifest_signature" });

    expect(restartCalled).toBe(false);
    expect(Buffer.compare(readFileSync(fx1.binPath), Buffer.from(oldBytes))).toBe(0);
    expect(existsSync(join(fx1.updateDir, READY_FILE_NAME))).toBe(false);

    // Case 2: valid signature, tampered staged binary bytes
    const rootDir2 = makeTempDir();
    const fx2 = stageFixture({
      rootDir: rootDir2,
      currentBinaryBytes: oldBytes,
      stagedBinaryBytes: newBytes,
      manifestVersion: "0.2.0",
      signingSecretKey: keyPair.secretKey,
    });
    writeFileSync(
      join(fx2.updateDir, STAGED_BINARY_NAME),
      new TextEncoder().encode("new-tegrad-v0.2.X"),
    );

    await expect(
      applyStagedUpdate({
        updateDir: fx2.updateDir,
        binPath: fx2.binPath,
        currentVersion: "0.1.0",
        arch: "linux-x64",
        publicKey: keyPair.publicKey,
        runCommand: async () => ({ code: 0, stdout: "active\n", stderr: "" }),
      }),
    ).rejects.toMatchObject({ code: "hash_mismatch" });

    expect(Buffer.compare(readFileSync(fx2.binPath), Buffer.from(oldBytes))).toBe(0);
    expect(existsSync(join(fx2.updateDir, READY_FILE_NAME))).toBe(false);
  });

  test("rejects downgrade unless explicitly authorized via allowDowngrade", async () => {
    const rootDir = makeTempDir();
    const keyPair = signingKeyPairFromSeed(TEST_RELEASE_SEED);
    const oldBytes = new TextEncoder().encode("current-v0.3.0");
    const olderBytes = new TextEncoder().encode("older-v0.2.0");

    const fx = stageFixture({
      rootDir,
      currentBinaryBytes: oldBytes,
      stagedBinaryBytes: olderBytes,
      manifestVersion: "0.2.0",
      signingSecretKey: keyPair.secretKey,
    });

    await expect(
      applyStagedUpdate({
        updateDir: fx.updateDir,
        binPath: fx.binPath,
        currentVersion: "0.3.0",
        arch: "linux-x64",
        publicKey: keyPair.publicKey,
        runCommand: async () => ({ code: 0, stdout: "active\n", stderr: "" }),
      }),
    ).rejects.toMatchObject({ code: "downgrade_blocked" });

    expect(Buffer.compare(readFileSync(fx.binPath), Buffer.from(oldBytes))).toBe(0);
  });

  test("rolls back automatically to tegrad.prev when systemctl restart fails or service fails health check", async () => {
    const rootDir = makeTempDir();
    const keyPair = signingKeyPairFromSeed(TEST_RELEASE_SEED);
    const oldBytes = new TextEncoder().encode("healthy-v0.1.0");
    const brokenBytes = new TextEncoder().encode("crashing-v0.2.0");

    // Case 1: systemctl restart fails
    const fx1 = stageFixture({
      rootDir,
      currentBinaryBytes: oldBytes,
      stagedBinaryBytes: brokenBytes,
      manifestVersion: "0.2.0",
      signingSecretKey: keyPair.secretKey,
    });

    const restartLog1: string[] = [];
    let restartAttempts1 = 0;
    await expect(
      applyStagedUpdate({
        updateDir: fx1.updateDir,
        binPath: fx1.binPath,
        currentVersion: "0.1.0",
        arch: "linux-x64",
        publicKey: keyPair.publicKey,
        sleep: async () => {},
        runCommand: async (cmd, args) => {
          restartLog1.push(`${cmd} ${args.join(" ")}`);
          if (args[0] === "restart") {
            restartAttempts1++;
            if (restartAttempts1 === 1) {
              return { code: 1, stdout: "", stderr: "Job failed" };
            }
            return { code: 0, stdout: "", stderr: "" };
          }
          return { code: 0, stdout: "active\n", stderr: "" };
        },
      }),
    ).rejects.toMatchObject({ code: "health_check_failed" });

    // Binary was restored to oldBytes and service restarted again
    expect(Buffer.compare(readFileSync(fx1.binPath), Buffer.from(oldBytes))).toBe(0);
    expect(restartLog1).toEqual([
      "systemctl restart tegrad.service",
      "systemctl restart tegrad.service",
    ]);

    // Case 2: restart succeeds, first is-active is active, then crashes during stabilization check
    const rootDir2 = makeTempDir();
    const fx2 = stageFixture({
      rootDir: rootDir2,
      currentBinaryBytes: oldBytes,
      stagedBinaryBytes: brokenBytes,
      manifestVersion: "0.2.0",
      signingSecretKey: keyPair.secretKey,
    });

    let isActiveChecks = 0;
    let restarts2 = 0;
    await expect(
      applyStagedUpdate({
        updateDir: fx2.updateDir,
        binPath: fx2.binPath,
        currentVersion: "0.1.0",
        arch: "linux-x64",
        publicKey: keyPair.publicKey,
        stabilizeMs: 10,
        sleep: async () => {},
        runCommand: async (_cmd, args) => {
          if (args[0] === "restart") {
            restarts2++;
            return { code: 0, stdout: "", stderr: "" };
          }
          isActiveChecks++;
          if (isActiveChecks === 1) {
            return { code: 0, stdout: "active\n", stderr: "" };
          }
          return { code: 3, stdout: "failed\n", stderr: "" };
        },
      }),
    ).rejects.toMatchObject({ code: "health_check_failed" });

    expect(restarts2).toBe(2);
    expect(Buffer.compare(readFileSync(fx2.binPath), Buffer.from(oldBytes))).toBe(0);
  });

  test("rejects symlinks in staged-tegrad or staged-manifest.json", async () => {
    const rootDir = makeTempDir();
    const keyPair = signingKeyPairFromSeed(TEST_RELEASE_SEED);
    const oldBytes = new TextEncoder().encode("old-v0.1.0");
    const newBytes = new TextEncoder().encode("new-v0.2.0");

    const fx = stageFixture({
      rootDir,
      currentBinaryBytes: oldBytes,
      stagedBinaryBytes: newBytes,
      manifestVersion: "0.2.0",
      signingSecretKey: keyPair.secretKey,
    });

    const externalTarget = join(rootDir, "outside-secret");
    writeFileSync(externalTarget, newBytes);
    rmSync(join(fx.updateDir, STAGED_BINARY_NAME));

    let symlinkCreated = false;
    try {
      symlinkSync(externalTarget, join(fx.updateDir, STAGED_BINARY_NAME));
      symlinkCreated = true;
    } catch {
      // Unprivileged Windows without Developer Mode may disallow file symlinks
      symlinkCreated = false;
    }

    if (!symlinkCreated) {
      return;
    }

    try {
      await applyStagedUpdate({
        updateDir: fx.updateDir,
        binPath: fx.binPath,
        currentVersion: "0.1.0",
        arch: "linux-x64",
        publicKey: keyPair.publicKey,
        runCommand: async () => ({ code: 0, stdout: "active\n", stderr: "" }),
      });
      throw new Error("Expected unsafe_path");
    } catch (err) {
      expect(err).toBeInstanceOf(UpdateError);
      expect((err as UpdateError).code).toBe("unsafe_path");
    }

    // Installed binary untouched and external target untouched
    expect(Buffer.compare(readFileSync(fx.binPath), Buffer.from(oldBytes))).toBe(0);
    expect(existsSync(externalTarget)).toBe(true);
  });

  test("CLI apply-update dispatches cleanly and returns exit 0 on success", async () => {
    const rootDir = makeTempDir();
    const keyPair = signingKeyPairFromSeed(TEST_RELEASE_SEED);
    const oldBytes = new TextEncoder().encode("old-v0.1.0");
    const newBytes = new TextEncoder().encode("new-v0.2.0");

    const fx = stageFixture({
      rootDir,
      currentBinaryBytes: oldBytes,
      stagedBinaryBytes: newBytes,
      manifestVersion: "0.2.0",
      signingSecretKey: keyPair.secretKey,
    });

    let stdout = "";
    let stderr = "";
    const code = await runCli(["apply-update"], {
      applyUpdateOptions: {
        updateDir: fx.updateDir,
        binPath: fx.binPath,
        currentVersion: "0.1.0",
        arch: "linux-x64",
        publicKey: keyPair.publicKey,
        stabilizeMs: 0,
        sleep: async () => {},
        runCommand: async (_cmd, args) =>
          args[0] === "is-active"
            ? { code: 0, stdout: "active\n", stderr: "" }
            : { code: 0, stdout: "", stderr: "" },
      },
      stdout: (t) => {
        stdout += t;
      },
      stderr: (t) => {
        stderr += t;
      },
    });

    expect(code).toBe(0);
    expect(stderr).toBe("");
    expect(stdout).toContain("Applied v0.2.0");
  });

  test("adversarial: blocks replay/downgrade of older signed manifests even when ready.json claims a higher version", async () => {
    const keyPair = signingKeyPairFromSeed(TEST_RELEASE_SEED);
    const currentBytes = new TextEncoder().encode("current-v0.3.0-binary");
    const vulnerableOldBytes = new TextEncoder().encode("old-vulnerable-v0.0.1-binary");

    const downgradeCases: readonly {
      readonly currentVersion: string;
      readonly manifestVersion: string;
      readonly channel: ReleaseChannel;
    }[] = [
      { currentVersion: "0.3.0", manifestVersion: "0.0.1", channel: "stable" },
      { currentVersion: "0.3.0", manifestVersion: "0.3.0", channel: "stable" },
      {
        currentVersion: "0.3.0",
        manifestVersion: "0.3.0-nightly.202611220600",
        channel: "nightly",
      },
      {
        currentVersion: "0.3.0-nightly.202611220600",
        manifestVersion: "0.3.0-beta.99",
        channel: "beta",
      },
      {
        currentVersion: "0.3.0-nightly.202611230600",
        manifestVersion: "0.3.0-nightly.202611220600",
        channel: "nightly",
      },
      { currentVersion: "0.3.0-beta.10", manifestVersion: "0.3.0-beta.2", channel: "beta" },
    ];

    for (const tc of downgradeCases) {
      const rootDir = makeTempDir();
      // Compromised tegrad user lies in ready.json claiming version 9.9.9,
      // while staging a genuinely signed older manifest (tc.manifestVersion).
      const fx = stageFixture({
        rootDir,
        currentBinaryBytes: currentBytes,
        stagedBinaryBytes: vulnerableOldBytes,
        manifestVersion: tc.manifestVersion,
        channel: tc.channel,
        signingSecretKey: keyPair.secretKey,
        readyVersionOverride: "9.9.9",
      });

      let systemctlCalled = false;
      await expect(
        applyStagedUpdate({
          updateDir: fx.updateDir,
          binPath: fx.binPath,
          currentVersion: tc.currentVersion,
          arch: "linux-x64",
          publicKey: keyPair.publicKey,
          runCommand: async () => {
            systemctlCalled = true;
            return { code: 0, stdout: "active\n", stderr: "" };
          },
        }),
      ).rejects.toMatchObject({ code: "downgrade_blocked" });

      expect(systemctlCalled).toBe(false);
      expect(Buffer.compare(readFileSync(fx.binPath), Buffer.from(currentBytes))).toBe(0);
      expect(existsSync(fx.prevBinPath)).toBe(false);
      // Staged files and ready.json must be cleaned up so systemd path unit cannot loop
      expect(readdirSync(fx.updateDir)).toEqual([]);
      expect(readdirSync(fx.binDir)).toEqual(["tegrad"]);
    }
  });

  test("adversarial: rejects oversized (10 GB sparse / > MAX_BINARY_BYTES / > MAX_MANIFEST_BYTES) and empty staged files before filling binDir", async () => {
    const keyPair = signingKeyPairFromSeed(TEST_RELEASE_SEED);
    const currentBytes = new TextEncoder().encode("current-v0.1.0");
    const validBytes = new TextEncoder().encode("new-v0.2.0");

    // Case 1: 10 GB sparse staged-tegrad file (> MAX_BINARY_BYTES = 200 MiB)
    const rootDir1 = makeTempDir();
    const fx1 = stageFixture({
      rootDir: rootDir1,
      currentBinaryBytes: currentBytes,
      stagedBinaryBytes: validBytes,
      manifestVersion: "0.2.0",
      signingSecretKey: keyPair.secretKey,
    });
    const tenGiB = 10 * 1024 * 1024 * 1024;
    truncateSync(join(fx1.updateDir, STAGED_BINARY_NAME), tenGiB);

    await expect(
      applyStagedUpdate({
        updateDir: fx1.updateDir,
        binPath: fx1.binPath,
        currentVersion: "0.1.0",
        arch: "linux-x64",
        publicKey: keyPair.publicKey,
        runCommand: async () => ({ code: 0, stdout: "active\n", stderr: "" }),
      }),
    ).rejects.toMatchObject({ code: "size_limit_exceeded" });

    expect(Buffer.compare(readFileSync(fx1.binPath), Buffer.from(currentBytes))).toBe(0);
    // No temporary staging dirs left behind in binDir and staged files cleaned up
    expect(readdirSync(fx1.binDir)).toEqual(["tegrad"]);
    expect(readdirSync(fx1.updateDir)).toEqual([]);

    // Case 2: staged-manifest.json exceeds MAX_MANIFEST_BYTES (64 KiB)
    const rootDir2 = makeTempDir();
    const fx2 = stageFixture({
      rootDir: rootDir2,
      currentBinaryBytes: currentBytes,
      stagedBinaryBytes: validBytes,
      manifestVersion: "0.2.0",
      signingSecretKey: keyPair.secretKey,
    });
    truncateSync(join(fx2.updateDir, STAGED_MANIFEST_NAME), MAX_MANIFEST_BYTES + 1);

    await expect(
      applyStagedUpdate({
        updateDir: fx2.updateDir,
        binPath: fx2.binPath,
        currentVersion: "0.1.0",
        arch: "linux-x64",
        publicKey: keyPair.publicKey,
        runCommand: async () => ({ code: 0, stdout: "active\n", stderr: "" }),
      }),
    ).rejects.toMatchObject({ code: "size_limit_exceeded" });

    expect(readdirSync(fx2.binDir)).toEqual(["tegrad"]);
    expect(readdirSync(fx2.updateDir)).toEqual([]);

    // Case 3: empty (0-byte) staged-tegrad
    const rootDir3 = makeTempDir();
    const fx3 = stageFixture({
      rootDir: rootDir3,
      currentBinaryBytes: currentBytes,
      stagedBinaryBytes: validBytes,
      manifestVersion: "0.2.0",
      signingSecretKey: keyPair.secretKey,
    });
    truncateSync(join(fx3.updateDir, STAGED_BINARY_NAME), 0);

    await expect(
      applyStagedUpdate({
        updateDir: fx3.updateDir,
        binPath: fx3.binPath,
        currentVersion: "0.1.0",
        arch: "linux-x64",
        publicKey: keyPair.publicKey,
        runCommand: async () => ({ code: 0, stdout: "active\n", stderr: "" }),
      }),
    ).rejects.toMatchObject({ code: "apply_failed" });

    expect(MAX_BINARY_BYTES).toBe(200 * 1024 * 1024);
    expect(readdirSync(fx3.binDir)).toEqual(["tegrad"]);
    expect(readdirSync(fx3.updateDir)).toEqual([]);
  });

  test("adversarial: rejects symlinks, dangling symlinks, and directory replacements for ready.json, staged-manifest.json, staged-tegrad, and updateDir", async () => {
    const keyPair = signingKeyPairFromSeed(TEST_RELEASE_SEED);
    const currentBytes = new TextEncoder().encode("current-v0.1.0");
    const newBytes = new TextEncoder().encode("new-v0.2.0");

    // 1. Directory planted where ready.json or staged-tegrad is expected
    for (const targetName of [READY_FILE_NAME, STAGED_BINARY_NAME, STAGED_MANIFEST_NAME]) {
      const rootDir = makeTempDir();
      const fx = stageFixture({
        rootDir,
        currentBinaryBytes: currentBytes,
        stagedBinaryBytes: newBytes,
        manifestVersion: "0.2.0",
        signingSecretKey: keyPair.secretKey,
      });
      const targetPath = join(fx.updateDir, targetName);
      rmSync(targetPath, { force: true });
      mkdirSync(targetPath);

      await expect(
        applyStagedUpdate({
          updateDir: fx.updateDir,
          binPath: fx.binPath,
          currentVersion: "0.1.0",
          arch: "linux-x64",
          publicKey: keyPair.publicKey,
          runCommand: async () => ({ code: 0, stdout: "active\n", stderr: "" }),
        }),
      ).rejects.toMatchObject({ code: "unsafe_path" });

      expect(Buffer.compare(readFileSync(fx.binPath), Buffer.from(currentBytes))).toBe(0);
    }

    // 2. Live and dangling symlinks for ready.json, staged-manifest.json, staged-tegrad, and updateDir
    const probeDir = makeTempDir();
    let symlinksSupported = false;
    try {
      const probeTarget = join(probeDir, "target");
      writeFileSync(probeTarget, "ok");
      symlinkSync(probeTarget, join(probeDir, "link"));
      symlinksSupported = true;
    } catch {
      symlinksSupported = false;
    }

    if (!symlinksSupported) {
      return;
    }

    for (const targetName of [READY_FILE_NAME, STAGED_MANIFEST_NAME, STAGED_BINARY_NAME]) {
      for (const dangling of [false, true]) {
        const rootDir = makeTempDir();
        const fx = stageFixture({
          rootDir,
          currentBinaryBytes: currentBytes,
          stagedBinaryBytes: newBytes,
          manifestVersion: "0.2.0",
          signingSecretKey: keyPair.secretKey,
        });

        const externalFile = join(rootDir, "protected-system-file");
        if (!dangling) {
          writeFileSync(externalFile, "sensitive-root-content");
        }
        const stagedTarget = join(fx.updateDir, targetName);
        rmSync(stagedTarget, { force: true });
        symlinkSync(externalFile, stagedTarget);

        await expect(
          applyStagedUpdate({
            updateDir: fx.updateDir,
            binPath: fx.binPath,
            currentVersion: "0.1.0",
            arch: "linux-x64",
            publicKey: keyPair.publicKey,
            runCommand: async () => ({ code: 0, stdout: "active\n", stderr: "" }),
          }),
        ).rejects.toMatchObject({ code: "unsafe_path" });

        // External target file must NEVER be deleted or modified
        if (!dangling) {
          expect(existsSync(externalFile)).toBe(true);
          expect(readFileSync(externalFile, "utf8")).toBe("sensitive-root-content");
        }
        expect(Buffer.compare(readFileSync(fx.binPath), Buffer.from(currentBytes))).toBe(0);
      }
    }

    // 3. updateDir itself is a symlink to another directory
    const rootDirSym = makeTempDir();
    const fxSym = stageFixture({
      rootDir: rootDirSym,
      currentBinaryBytes: currentBytes,
      stagedBinaryBytes: newBytes,
      manifestVersion: "0.2.0",
      signingSecretKey: keyPair.secretKey,
    });
    const symlinkUpdateDir = join(rootDirSym, "symlink-update-dir");
    symlinkSync(fxSym.updateDir, symlinkUpdateDir, "dir");

    await expect(
      applyStagedUpdate({
        updateDir: symlinkUpdateDir,
        binPath: fxSym.binPath,
        currentVersion: "0.1.0",
        arch: "linux-x64",
        publicKey: keyPair.publicKey,
        runCommand: async () => ({ code: 0, stdout: "active\n", stderr: "" }),
      }),
    ).rejects.toMatchObject({ code: "unsafe_path" });

    // Files inside the target directory must not have been deleted by finally cleanup
    expect(existsSync(join(fxSym.updateDir, READY_FILE_NAME))).toBe(true);
  });

  test("reports rollback_failed if both update restart and rollback restart fail", async () => {
    const rootDir = makeTempDir();
    const keyPair = signingKeyPairFromSeed(TEST_RELEASE_SEED);
    const oldBytes = new TextEncoder().encode("old-v0.1.0");
    const newBytes = new TextEncoder().encode("new-v0.2.0");

    const fx = stageFixture({
      rootDir,
      currentBinaryBytes: oldBytes,
      stagedBinaryBytes: newBytes,
      manifestVersion: "0.2.0",
      signingSecretKey: keyPair.secretKey,
    });

    await expect(
      applyStagedUpdate({
        updateDir: fx.updateDir,
        binPath: fx.binPath,
        currentVersion: "0.1.0",
        arch: "linux-x64",
        publicKey: keyPair.publicKey,
        runCommand: async () => ({ code: 1, stdout: "", stderr: "systemd bus error" }),
      }),
    ).rejects.toMatchObject({ code: "rollback_failed" });

    // Even when systemctl restart failed during rollback, the previous binary was restored on disk
    expect(Buffer.compare(readFileSync(fx.binPath), Buffer.from(oldBytes))).toBe(0);
  });
});
