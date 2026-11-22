// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { randomBytes as nodeRandomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  constants as fsConstants,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  renameSync,
  rmSync,
  type Stats,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { type RunFixedResult, runFixed } from "../agent";
import { type PublicKey, ready } from "../crypto";
import { VERSION } from "../version";
import { shouldUpdate } from "./channels";
import { UpdateError } from "./errors";
import { type ReleaseArch, type ReleaseManifest, verifyReleaseBinary } from "./manifest";
import {
  MAX_BINARY_BYTES,
  MAX_MANIFEST_BYTES,
  READY_FILE_NAME,
  STAGED_BINARY_NAME,
  STAGED_MANIFEST_NAME,
} from "./updater";

export const DEFAULT_BIN_PATH = "/opt/tegrad/bin/tegrad";
export const DEFAULT_UPDATE_DIR = "/var/lib/tegrad/update";
export const DEFAULT_SERVICE_NAME = "tegrad.service";
export const DEFAULT_HEALTH_TIMEOUT_MS = 15_000;
export const DEFAULT_HEALTH_POLL_INTERVAL_MS = 500;
export const DEFAULT_STABILIZE_MS = 1_500;

const COPY_CHUNK_BYTES = 64 * 1024;
const ROOT_STAGING_DIR_MODE = 0o700;
const ROOT_STAGING_FILE_MODE = 0o600;
const INSTALLED_BINARY_MODE = 0o755;

function isPosix(platform: NodeJS.Platform = process.platform): boolean {
  return platform !== "win32";
}

function getNoFollowReadFlags(platform: NodeJS.Platform): number {
  if (!isPosix(platform)) {
    return fsConstants.O_RDONLY;
  }
  const noFollow = typeof fsConstants.O_NOFOLLOW === "number" ? fsConstants.O_NOFOLLOW : 0;
  const nonBlock = typeof fsConstants.O_NONBLOCK === "number" ? fsConstants.O_NONBLOCK : 0;
  return fsConstants.O_RDONLY | noFollow | nonBlock;
}

function lstatOrNull(filePath: string): Stats | null {
  try {
    return lstatSync(filePath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }
    throw err;
  }
}

function isRealDirectory(dirPath: string): boolean {
  const stat = lstatOrNull(dirPath);
  return stat !== null && !stat.isSymbolicLink() && stat.isDirectory();
}

function assertNotSymlinkDir(dirPath: string): void {
  const stat = lstatOrNull(dirPath);
  if (stat === null) {
    throw new UpdateError("unsafe_path", `Directory does not exist: ${dirPath}`);
  }
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new UpdateError("unsafe_path", `Refusing to use symlink or non-directory: ${dirPath}`);
  }
}

function assertRegularNonSymlinkFile(filePath: string, maxBytes: number): Stats {
  const stat = lstatOrNull(filePath);
  if (stat === null) {
    throw new UpdateError("apply_failed", `Required staged file is missing: ${filePath}`);
  }
  if (stat.isSymbolicLink()) {
    throw new UpdateError("unsafe_path", `Refusing to read symlink: ${filePath}`);
  }
  if (!stat.isFile()) {
    throw new UpdateError("unsafe_path", `Refusing to read non-regular file: ${filePath}`);
  }
  if (stat.size <= 0) {
    throw new UpdateError("apply_failed", `Staged file is empty: ${filePath}`);
  }
  if (stat.size > maxBytes) {
    throw new UpdateError(
      "size_limit_exceeded",
      `Staged file ${filePath} exceeds maximum size of ${maxBytes} bytes`,
    );
  }
  return stat;
}

function copyRegularFileNoFollow(
  srcPath: string,
  dstPath: string,
  maxBytes: number,
  dstMode: number,
  platform: NodeJS.Platform,
): number {
  const initialStat = assertRegularNonSymlinkFile(srcPath, maxBytes);

  let srcFd: number | undefined;
  let dstFd: number | undefined;
  let total = 0;

  try {
    try {
      srcFd = openSync(srcPath, getNoFollowReadFlags(platform));
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ELOOP") {
        throw new UpdateError("unsafe_path", `Refusing to open symlink: ${srcPath}`);
      }
      throw err;
    }
    const fdStat = fstatSync(srcFd);
    if (!fdStat.isFile()) {
      throw new UpdateError("unsafe_path", `Opened source is not a regular file: ${srcPath}`);
    }
    if (isPosix(platform) && (fdStat.ino !== initialStat.ino || fdStat.dev !== initialStat.dev)) {
      throw new UpdateError(
        "unsafe_path",
        `Source file inode changed during open (TOCTOU detected): ${srcPath}`,
      );
    }
    if (fdStat.size <= 0) {
      throw new UpdateError("apply_failed", `Staged file is empty: ${srcPath}`);
    }
    if (fdStat.size > maxBytes) {
      throw new UpdateError(
        "size_limit_exceeded",
        `Staged file ${srcPath} exceeds maximum size of ${maxBytes} bytes`,
      );
    }

    dstFd = openSync(dstPath, "wx", dstMode);
    const buffer = Buffer.allocUnsafe(COPY_CHUNK_BYTES);

    while (true) {
      const bytesRead = readSync(srcFd, buffer, 0, buffer.length, null);
      if (bytesRead === 0) {
        break;
      }
      total += bytesRead;
      if (total > maxBytes) {
        throw new UpdateError(
          "size_limit_exceeded",
          `File ${srcPath} exceeded maximum size of ${maxBytes} bytes during copy`,
        );
      }
      writeSync(dstFd, buffer, 0, bytesRead);
    }

    if (total <= 0) {
      throw new UpdateError("apply_failed", `Staged file is empty: ${srcPath}`);
    }

    fsyncSync(dstFd);
    closeSync(dstFd);
    dstFd = undefined;

    if (isPosix(platform)) {
      chmodSync(dstPath, dstMode);
    }

    return total;
  } catch (err) {
    if (dstFd !== undefined) {
      try {
        closeSync(dstFd);
      } catch {
        // ignore
      }
    }
    try {
      if (existsSync(dstPath)) {
        unlinkSync(dstPath);
      }
    } catch {
      // ignore
    }
    throw err;
  } finally {
    if (srcFd !== undefined) {
      try {
        closeSync(srcFd);
      } catch {
        // ignore
      }
    }
  }
}

function atomicCopyFile(
  srcPath: string,
  dstPath: string,
  mode: number,
  maxBytes: number,
  platform: NodeJS.Platform,
): void {
  const dir = dirname(dstPath);
  const suffix = nodeRandomBytes(8).toString("hex");
  const tmpPath = join(dir, `.tmp-copy-${process.pid}-${suffix}`);
  try {
    copyRegularFileNoFollow(srcPath, tmpPath, maxBytes, mode, platform);
    if (isPosix(platform)) {
      chmodSync(tmpPath, mode);
    }
    renameSync(tmpPath, dstPath);
  } catch (err) {
    try {
      if (existsSync(tmpPath)) {
        unlinkSync(tmpPath);
      }
    } catch {
      // ignore
    }
    throw err;
  }
}

function safeUnlinkIfPresent(filePath: string): void {
  try {
    const stat = lstatSync(filePath);
    if (!stat.isDirectory()) {
      unlinkSync(filePath);
    }
  } catch {
    // file does not exist or already removed
  }
}

export type ApplyCommandRunner = (
  command: string,
  args: readonly string[],
) => Promise<Pick<RunFixedResult, "code" | "stdout" | "stderr">>;

export interface ApplyUpdateOptions {
  readonly updateDir?: string;
  readonly binPath?: string;
  readonly prevBinPath?: string;
  readonly currentVersion?: string;
  readonly arch?: ReleaseArch;
  readonly publicKey?: PublicKey;
  readonly allowDowngrade?: boolean;
  readonly maxManifestBytes?: number;
  readonly maxBinaryBytes?: number;
  readonly serviceName?: string;
  readonly healthTimeoutMs?: number;
  readonly healthPollIntervalMs?: number;
  readonly stabilizeMs?: number;
  readonly platform?: NodeJS.Platform;
  readonly runCommand?: ApplyCommandRunner;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly now?: () => number;
  readonly afterCopyBeforeVerifyHook?: (context: {
    readonly updateDir: string;
    readonly rootStagingDir: string;
    readonly rootBinaryPath: string;
    readonly rootManifestPath: string;
  }) => void | Promise<void>;
  readonly verifyHook?: (rootBinaryPath: string, rootManifestPath: string) => void | Promise<void>;
}

export interface ApplyUpdateResult {
  readonly applied: true;
  readonly previousVersion: string;
  readonly version: string;
  readonly tag: string;
  readonly channel: ReleaseManifest["channel"];
  readonly arch: ReleaseArch;
  readonly sha256: string;
  readonly binPath: string;
  readonly prevBinPath: string;
}

async function waitForServiceActive(
  runCommand: ApplyCommandRunner,
  serviceName: string,
  healthTimeoutMs: number,
  healthPollIntervalMs: number,
  stabilizeMs: number,
  sleep: (ms: number) => Promise<void>,
  now: () => number,
): Promise<{ readonly healthy: boolean; readonly lastStatus: string }> {
  const deadline = now() + healthTimeoutMs;
  let lastStatus = "unknown";

  while (true) {
    const res = await runCommand("systemctl", ["is-active", serviceName]);
    const status = res.stdout.trim() || res.stderr.trim() || `exit-${res.code}`;
    lastStatus = status;

    if (res.code === 0 && status === "active") {
      if (stabilizeMs <= 0) {
        return { healthy: true, lastStatus: "active" };
      }
      await sleep(stabilizeMs);
      const confirm = await runCommand("systemctl", ["is-active", serviceName]);
      const confirmStatus =
        confirm.stdout.trim() || confirm.stderr.trim() || `exit-${confirm.code}`;
      if (confirm.code === 0 && confirmStatus === "active") {
        return { healthy: true, lastStatus: "active" };
      }
      return { healthy: false, lastStatus: confirmStatus };
    }

    if (status === "failed") {
      return { healthy: false, lastStatus: status };
    }

    const remaining = deadline - now();
    if (remaining <= 0) {
      return { healthy: false, lastStatus };
    }

    await sleep(Math.min(healthPollIntervalMs, remaining));
  }
}

export async function applyStagedUpdate(
  options: ApplyUpdateOptions = {},
): Promise<ApplyUpdateResult> {
  await ready();

  const updateDir = options.updateDir ?? DEFAULT_UPDATE_DIR;
  const binPath = options.binPath ?? DEFAULT_BIN_PATH;
  const binDir = dirname(binPath);
  const prevBinPath = options.prevBinPath ?? `${binPath}.prev`;
  const currentVersion = options.currentVersion ?? VERSION;
  const maxManifestBytes = options.maxManifestBytes ?? MAX_MANIFEST_BYTES;
  const maxBinaryBytes = options.maxBinaryBytes ?? MAX_BINARY_BYTES;
  const serviceName = options.serviceName ?? DEFAULT_SERVICE_NAME;
  const healthTimeoutMs = options.healthTimeoutMs ?? DEFAULT_HEALTH_TIMEOUT_MS;
  const healthPollIntervalMs = options.healthPollIntervalMs ?? DEFAULT_HEALTH_POLL_INTERVAL_MS;
  const stabilizeMs = options.stabilizeMs ?? DEFAULT_STABILIZE_MS;
  const platform = options.platform ?? process.platform;
  const sleep =
    options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const now = options.now ?? (() => Date.now());
  const runCommand: ApplyCommandRunner =
    options.runCommand ??
    ((command, args) => runFixed(command, args, { timeoutMs: 30_000, maxOutputBytes: 8192 }));

  // Verify updateDir (and its parent) and binDir are real directories (never symlinks)
  assertNotSymlinkDir(dirname(updateDir));
  assertNotSymlinkDir(updateDir);
  assertNotSymlinkDir(binDir);

  const readyPath = join(updateDir, READY_FILE_NAME);
  const stagedBinaryPath = join(updateDir, STAGED_BINARY_NAME);
  const stagedManifestPath = join(updateDir, STAGED_MANIFEST_NAME);

  let rootStagingDir: string | null = null;

  try {
    // Validate ready.json if present (including dangling symlinks via lstat) and remove trigger immediately
    const readyStat = lstatOrNull(readyPath);
    if (readyStat !== null) {
      if (readyStat.isSymbolicLink() || !readyStat.isFile()) {
        throw new UpdateError("unsafe_path", `Refusing to process unsafe ready file: ${readyPath}`);
      }
      safeUnlinkIfPresent(readyPath);
    }

    // 1. TOCTOU defense: copy staged files into a root-owned private directory under binDir
    //    BEFORE verifying signature and SHA-256. The unprivileged 'tegrad' user cannot write
    //    inside binDir (/opt/tegrad/bin), eliminating any swap window between verify and install.
    const suffix = nodeRandomBytes(8).toString("hex");
    rootStagingDir = join(binDir, `.staging-tmp-${process.pid}-${suffix}`);
    mkdirSync(rootStagingDir, { mode: ROOT_STAGING_DIR_MODE });
    if (isPosix(platform)) {
      chmodSync(rootStagingDir, ROOT_STAGING_DIR_MODE);
    }

    const rootManifestPath = join(rootStagingDir, "manifest.json");
    const rootBinaryPath = join(rootStagingDir, "tegrad.new");

    copyRegularFileNoFollow(
      stagedManifestPath,
      rootManifestPath,
      maxManifestBytes,
      ROOT_STAGING_FILE_MODE,
      platform,
    );
    copyRegularFileNoFollow(
      stagedBinaryPath,
      rootBinaryPath,
      maxBinaryBytes,
      ROOT_STAGING_FILE_MODE,
      platform,
    );

    if (options.afterCopyBeforeVerifyHook !== undefined) {
      await options.afterCopyBeforeVerifyHook({
        updateDir,
        rootStagingDir,
        rootBinaryPath,
        rootManifestPath,
      });
    }

    // 2. Verify Ed25519 signature of manifest and SHA-256 of binary strictly on root-owned copies
    const manifestContent = readFileSync(rootManifestPath, "utf8");
    const verified = await verifyReleaseBinary({
      binaryPath: rootBinaryPath,
      manifestContent,
      ...(options.arch !== undefined ? { arch: options.arch } : {}),
      ...(options.publicKey !== undefined ? { publicKey: options.publicKey } : {}),
    });

    if (verified.mode !== "manifest") {
      throw new UpdateError("invalid_manifest", "Expected manifest verification mode");
    }

    if (options.verifyHook !== undefined) {
      await options.verifyHook(rootBinaryPath, rootManifestPath);
    }

    // 3. Enforce version progression (never trust unprivileged ready.json to enable downgrades)
    const allowed = shouldUpdate(currentVersion, verified.manifest.version, {
      allowDowngrade: options.allowDowngrade === true,
    });
    if (!allowed) {
      throw new UpdateError(
        "downgrade_blocked",
        `Refusing update from ${currentVersion} to ${verified.manifest.version} without explicit downgrade authorization`,
      );
    }

    // 4. Backup current binary atomically to tegrad.prev
    const hadPrevious = existsSync(binPath);
    if (hadPrevious) {
      atomicCopyFile(binPath, prevBinPath, INSTALLED_BINARY_MODE, maxBinaryBytes, platform);
    }

    // 5. Atomically install verified binary from root-owned staging dir to binPath
    if (isPosix(platform)) {
      chmodSync(rootBinaryPath, INSTALLED_BINARY_MODE);
    }
    renameSync(rootBinaryPath, binPath);

    // 6. Restart tegrad.service and verify health; roll back automatically on failure
    const rollback = async (reason: string): Promise<never> => {
      if (hadPrevious && existsSync(prevBinPath)) {
        try {
          atomicCopyFile(prevBinPath, binPath, INSTALLED_BINARY_MODE, maxBinaryBytes, platform);
          const rollbackRestart = await runCommand("systemctl", ["restart", serviceName]);
          if (rollbackRestart.code !== 0) {
            throw new Error(
              `systemctl restart ${serviceName} exited with code ${rollbackRestart.code}${
                rollbackRestart.stderr.trim() ? `: ${rollbackRestart.stderr.trim()}` : ""
              }`,
            );
          }
        } catch (rollbackErr) {
          throw new UpdateError(
            "rollback_failed",
            `Update failed (${reason}) and automatic rollback failed: ${
              rollbackErr instanceof Error ? rollbackErr.message : String(rollbackErr)
            }`,
          );
        }
      }
      throw new UpdateError("health_check_failed", `Update failed and was rolled back: ${reason}`);
    };

    const restartRes = await runCommand("systemctl", ["restart", serviceName]);
    if (restartRes.code !== 0) {
      await rollback(
        `systemctl restart ${serviceName} exited with code ${restartRes.code}${
          restartRes.stderr.trim() ? `: ${restartRes.stderr.trim()}` : ""
        }`,
      );
    }

    const health = await waitForServiceActive(
      runCommand,
      serviceName,
      healthTimeoutMs,
      healthPollIntervalMs,
      stabilizeMs,
      sleep,
      now,
    );
    if (!health.healthy) {
      await rollback(`${serviceName} did not stabilize as active (status: ${health.lastStatus})`);
    }

    return {
      applied: true,
      previousVersion: currentVersion,
      version: verified.manifest.version,
      tag: verified.manifest.tag,
      channel: verified.manifest.channel,
      arch: verified.arch,
      sha256: verified.sha256,
      binPath,
      prevBinPath,
    };
  } finally {
    if (rootStagingDir !== null && existsSync(rootStagingDir)) {
      try {
        rmSync(rootStagingDir, { recursive: true, force: true });
      } catch {
        // ignore cleanup errors
      }
    }
    // Always clean up staged files so tegrad-update.path cannot loop on corrupt staging data,
    // after re-verifying updateDir and its parent are still real directories (never symlinks).
    if (isRealDirectory(dirname(updateDir)) && isRealDirectory(updateDir)) {
      safeUnlinkIfPresent(readyPath);
      safeUnlinkIfPresent(stagedBinaryPath);
      safeUnlinkIfPresent(stagedManifestPath);
    }
  }
}
