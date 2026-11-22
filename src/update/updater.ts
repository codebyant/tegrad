// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { createHash, randomBytes as nodeRandomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  renameSync,
  type Stats,
  unlinkSync,
  writeSync,
} from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import {
  defaultTimers,
  type FetchLike,
  getStatePaths,
  type Logger,
  type TimerHandle,
  type TimerProvider,
  writeFileAtomic,
} from "../agent";
import { type PublicKey, ready } from "../crypto";
import { VERSION } from "../version";
import { type ReleaseChannel, releaseChannelSchema, shouldUpdate } from "./channels";
import { UpdateError } from "./errors";
import {
  type ReleaseArch,
  type ReleaseManifest,
  resolveReleaseArch,
  verifyManifest,
} from "./manifest";

export const DEFAULT_UPDATE_CHANNEL: ReleaseChannel = "stable";
export const DEFAULT_UPDATE_INTERVAL_MS = 6 * 60 * 60 * 1000;
export const DEFAULT_UPDATE_JITTER_RATIO = 0.1;
export const DEFAULT_MANIFEST_BASE_URL =
  "https://github.com/codebyant/tegrad/releases/latest/download";

export const DEFAULT_ALLOWED_ASSET_HOSTS: readonly string[] = [
  "github.com",
  "objects.githubusercontent.com",
  "release-assets.githubusercontent.com",
];

export const MAX_MANIFEST_BYTES = 64 * 1024;
export const MAX_BINARY_BYTES = 200 * 1024 * 1024;
export const DEFAULT_MANIFEST_TIMEOUT_MS = 30_000;
export const DEFAULT_BINARY_TIMEOUT_MS = 120_000;

export const STAGED_BINARY_NAME = "staged-tegrad";
export const STAGED_MANIFEST_NAME = "staged-manifest.json";
export const READY_FILE_NAME = "ready.json";

const UPDATE_DIR_MODE = 0o700;
const STAGED_FILE_MODE = 0o600;

export const readyFileSchema = z
  .object({
    v: z.literal(1),
    channel: releaseChannelSchema,
    version: z.string().min(1),
    tag: z.string().min(1),
    arch: z.enum(["linux-x64", "linux-arm64"]),
    sha256: z.string().regex(/^[0-9a-f]{64}$/),
    size: z.number().int().positive(),
    staged_at: z.number().int().nonnegative(),
  })
  .strict();

export type ReadyFile = z.infer<typeof readyFileSchema>;

function isPosix(platform: NodeJS.Platform = process.platform): boolean {
  return platform !== "win32";
}

function parseStrictHttpsUrl(rawUrl: string, label: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new UpdateError("invalid_url", `Invalid ${label}: "${rawUrl}"`);
  }

  if (parsed.protocol !== "https:") {
    throw new UpdateError(
      "invalid_url",
      `${label} must use https:// (got ${parsed.protocol}//${parsed.host})`,
    );
  }

  if (parsed.username.length > 0 || parsed.password.length > 0) {
    throw new UpdateError("invalid_url", `${label} must not contain embedded credentials`);
  }

  if (parsed.hostname.length === 0) {
    throw new UpdateError("invalid_url", `${label} must include a hostname`);
  }

  return parsed;
}

export function validateAssetUrl(rawUrl: string, allowedHosts: ReadonlySet<string>): URL {
  const parsed = parseStrictHttpsUrl(rawUrl, "asset URL");
  const host = parsed.hostname.toLowerCase();
  if (!allowedHosts.has(host)) {
    throw new UpdateError(
      "host_not_allowed",
      `Asset URL host "${host}" is not in the allowed host list`,
    );
  }
  return parsed;
}

export function buildManifestUrl(manifestBaseUrl: string, channel: ReleaseChannel): string {
  const parsed = parseStrictHttpsUrl(manifestBaseUrl, "manifest_base_url");
  const normalized = parsed.toString().replace(/\/+$/, "");
  return `${normalized}/${channel}.json`;
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

export function ensureSafeUpdateDir(
  stateDir: string,
  platform: NodeJS.Platform = process.platform,
): string {
  const stateStat = lstatOrNull(stateDir);
  if (stateStat !== null) {
    if (stateStat.isSymbolicLink() || !stateStat.isDirectory()) {
      throw new UpdateError("unsafe_path", `State directory ${stateDir} must be a real directory`);
    }
  } else {
    mkdirSync(stateDir, { recursive: true, mode: UPDATE_DIR_MODE });
    if (isPosix(platform)) {
      chmodSync(stateDir, UPDATE_DIR_MODE);
    }
  }

  const { updateDir } = getStatePaths(stateDir);
  const stat = lstatOrNull(updateDir);
  if (stat !== null) {
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new UpdateError("unsafe_path", `Update directory ${updateDir} must not be a symlink`);
    }
    if (isPosix(platform)) {
      chmodSync(updateDir, UPDATE_DIR_MODE);
    }
  } else {
    mkdirSync(updateDir, { recursive: true, mode: UPDATE_DIR_MODE });
    if (isPosix(platform)) {
      chmodSync(updateDir, UPDATE_DIR_MODE);
    }
  }

  return updateDir;
}

async function fetchWithTimeout(
  fetchImpl: FetchLike,
  url: string,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, timeoutMs);

  try {
    return await fetchImpl(url, {
      method: "GET",
      signal: controller.signal,
      headers: {
        accept: "application/octet-stream, application/json",
      },
    });
  } catch (err) {
    throw new UpdateError(
      "download_failed",
      `Failed to fetch ${url}: ${err instanceof Error ? err.message : String(err)}`,
    );
  } finally {
    clearTimeout(timer);
  }
}

async function readResponseBytesCapped(response: Response, maxBytes: number): Promise<Uint8Array> {
  const contentLengthHeader = response.headers.get("content-length");
  if (contentLengthHeader !== null) {
    const declared = Number(contentLengthHeader);
    if (Number.isFinite(declared) && declared > maxBytes) {
      throw new UpdateError(
        "size_limit_exceeded",
        `Response exceeds maximum allowed size of ${maxBytes} bytes`,
      );
    }
  }

  if (response.body === null) {
    const arr = new Uint8Array(await response.arrayBuffer());
    if (arr.byteLength > maxBytes) {
      throw new UpdateError(
        "size_limit_exceeded",
        `Response exceeds maximum allowed size of ${maxBytes} bytes`,
      );
    }
    return arr;
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value === undefined || value.byteLength === 0) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new UpdateError(
          "size_limit_exceeded",
          `Response exceeds maximum allowed size of ${maxBytes} bytes`,
        );
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return combined;
}

async function downloadAndHashToTempFile(
  response: Response,
  tmpPath: string,
  expectedSize: number,
  maxBytes: number,
): Promise<{ readonly sha256: string; readonly size: number }> {
  const effectiveCap = Math.min(expectedSize, maxBytes);
  const contentLengthHeader = response.headers.get("content-length");
  if (contentLengthHeader !== null) {
    const declared = Number(contentLengthHeader);
    if (Number.isFinite(declared) && declared > maxBytes) {
      throw new UpdateError(
        "size_limit_exceeded",
        `Binary exceeds maximum allowed size of ${maxBytes} bytes`,
      );
    }
    if (Number.isFinite(declared) && declared !== expectedSize) {
      throw new UpdateError(
        "size_mismatch",
        `Binary Content-Length (${declared}) does not match manifest size (${expectedSize})`,
      );
    }
  }

  const hasher = createHash("sha256");
  let total = 0;
  let fd: number | undefined;

  try {
    fd = openSync(tmpPath, "wx", STAGED_FILE_MODE);

    if (response.body === null) {
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (bytes.byteLength > maxBytes) {
        throw new UpdateError(
          "size_limit_exceeded",
          `Binary exceeds maximum allowed size of ${maxBytes} bytes`,
        );
      }
      if (bytes.byteLength !== expectedSize) {
        throw new UpdateError(
          "size_mismatch",
          `Downloaded binary size (${bytes.byteLength}) does not match manifest size (${expectedSize})`,
        );
      }
      writeSync(fd, bytes);
      hasher.update(bytes);
      total = bytes.byteLength;
    } else {
      const reader = response.body.getReader();
      try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          if (value === undefined || value.byteLength === 0) continue;
          total += value.byteLength;
          if (total > maxBytes) {
            await reader.cancel();
            throw new UpdateError(
              "size_limit_exceeded",
              `Binary exceeds maximum allowed size of ${maxBytes} bytes`,
            );
          }
          if (total > effectiveCap) {
            await reader.cancel();
            throw new UpdateError(
              "size_mismatch",
              `Downloaded binary exceeded manifest size of ${expectedSize} bytes`,
            );
          }
          writeSync(fd, value);
          hasher.update(value);
        }
      } finally {
        reader.releaseLock();
      }
    }

    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;

    if (total !== expectedSize) {
      throw new UpdateError(
        "size_mismatch",
        `Downloaded binary size (${total}) does not match manifest size (${expectedSize})`,
      );
    }

    return { sha256: hasher.digest("hex"), size: total };
  } catch (err) {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        // ignore close error during cleanup
      }
    }
    try {
      if (existsSync(tmpPath)) {
        unlinkSync(tmpPath);
      }
    } catch {
      // ignore cleanup error
    }
    throw err;
  }
}

export interface CheckForUpdateOptions {
  readonly stateDir: string;
  readonly channel?: ReleaseChannel;
  readonly currentVersion?: string;
  readonly manifestBaseUrl?: string;
  readonly allowDowngrade?: boolean;
  readonly arch?: ReleaseArch;
  readonly publicKey?: PublicKey;
  readonly allowedHosts?: readonly string[];
  readonly maxManifestBytes?: number;
  readonly maxBinaryBytes?: number;
  readonly manifestTimeoutMs?: number;
  readonly binaryTimeoutMs?: number;
  readonly fetch?: FetchLike;
  readonly now?: () => number;
  readonly platform?: NodeJS.Platform;
}

export type CheckForUpdateResult =
  | {
      readonly status: "up_to_date";
      readonly channel: ReleaseChannel;
      readonly currentVersion: string;
      readonly latestVersion: string;
    }
  | {
      readonly status: "staged";
      readonly channel: ReleaseChannel;
      readonly currentVersion: string;
      readonly targetVersion: string;
      readonly tag: string;
      readonly arch: ReleaseArch;
      readonly sha256: string;
      readonly size: number;
      readonly stagedBinaryPath: string;
      readonly stagedManifestPath: string;
      readonly readyPath: string;
    };

export async function checkForUpdate(
  options: CheckForUpdateOptions,
): Promise<CheckForUpdateResult> {
  await ready();

  const channel = options.channel ?? DEFAULT_UPDATE_CHANNEL;
  const currentVersion = options.currentVersion ?? VERSION;
  const manifestBaseUrl = options.manifestBaseUrl ?? DEFAULT_MANIFEST_BASE_URL;
  const maxManifestBytes = options.maxManifestBytes ?? MAX_MANIFEST_BYTES;
  const maxBinaryBytes = options.maxBinaryBytes ?? MAX_BINARY_BYTES;
  const manifestTimeoutMs = options.manifestTimeoutMs ?? DEFAULT_MANIFEST_TIMEOUT_MS;
  const binaryTimeoutMs = options.binaryTimeoutMs ?? DEFAULT_BINARY_TIMEOUT_MS;
  const fetchImpl = options.fetch ?? fetch;
  const now = options.now ?? (() => Date.now());
  const platform = options.platform ?? process.platform;

  const manifestUrl = buildManifestUrl(manifestBaseUrl, channel);
  const manifestHost = new URL(manifestUrl).hostname.toLowerCase();

  const allowedHosts = new Set<string>(
    options.allowedHosts !== undefined
      ? options.allowedHosts.map((h) => h.toLowerCase())
      : [...DEFAULT_ALLOWED_ASSET_HOSTS, manifestHost],
  );

  // 1. Download manifest with strict size cap and timeout
  const manifestResponse = await fetchWithTimeout(fetchImpl, manifestUrl, manifestTimeoutMs);
  if (!manifestResponse.ok) {
    throw new UpdateError(
      "download_failed",
      `Failed to download manifest ${manifestUrl}: HTTP ${manifestResponse.status}`,
    );
  }
  if (manifestResponse.url && manifestResponse.url.length > 0) {
    parseStrictHttpsUrl(manifestResponse.url, "redirected manifest URL");
  }
  const manifestBytes = await readResponseBytesCapped(manifestResponse, maxManifestBytes);

  let rawManifest: unknown;
  try {
    rawManifest = JSON.parse(new TextDecoder().decode(manifestBytes)) as unknown;
  } catch {
    throw new UpdateError("invalid_manifest", "Downloaded release manifest is not valid JSON");
  }

  // 2. Verify Ed25519 signature BEFORE trusting any field in the manifest
  const manifest: ReleaseManifest = verifyManifest(rawManifest, {
    expectedChannel: channel,
    ...(options.publicKey !== undefined ? { publicKey: options.publicKey } : {}),
  });

  // 3. Compare versions
  const needsUpdate = shouldUpdate(currentVersion, manifest.version, {
    allowDowngrade: options.allowDowngrade === true,
  });
  if (!needsUpdate) {
    return {
      status: "up_to_date",
      channel,
      currentVersion,
      latestVersion: manifest.version,
    };
  }

  // 4. Select architecture asset and validate HTTPS + allowed host + size cap
  const arch = options.arch ?? resolveReleaseArch(platform);
  const asset = manifest.assets[arch];
  validateAssetUrl(asset.url, allowedHosts);

  if (asset.size > maxBinaryBytes) {
    throw new UpdateError(
      "size_limit_exceeded",
      `Manifest asset size (${asset.size}) exceeds maximum allowed size (${maxBinaryBytes})`,
    );
  }

  // 5. Ensure /var/lib/tegrad/update exists with mode 0700 and no symlinks
  const updateDir = ensureSafeUpdateDir(options.stateDir, platform);

  // 6. Download binary into temporary file inside updateDir
  const suffix = nodeRandomBytes(8).toString("hex");
  const tmpBinaryPath = join(updateDir, `.tmp-${STAGED_BINARY_NAME}-${process.pid}-${suffix}`);
  const binResponse = await fetchWithTimeout(fetchImpl, asset.url, binaryTimeoutMs);
  if (!binResponse.ok) {
    throw new UpdateError(
      "download_failed",
      `Failed to download update binary ${asset.url}: HTTP ${binResponse.status}`,
    );
  }
  if (binResponse.url && binResponse.url.length > 0) {
    validateAssetUrl(binResponse.url, allowedHosts);
  }

  const { sha256, size } = await downloadAndHashToTempFile(
    binResponse,
    tmpBinaryPath,
    asset.size,
    maxBinaryBytes,
  );

  // 7. Verify SHA-256 against signed manifest; delete temp file immediately on mismatch
  if (sha256 !== asset.sha256) {
    try {
      if (existsSync(tmpBinaryPath)) {
        unlinkSync(tmpBinaryPath);
      }
    } catch {
      // ignore cleanup error
    }
    throw new UpdateError(
      "hash_mismatch",
      `Downloaded binary SHA-256 mismatch (expected ${asset.sha256}, got ${sha256})`,
    );
  }

  // 8. Atomically promote staged-tegrad, staged-manifest.json, and LAST ready.json
  const stagedBinaryPath = join(updateDir, STAGED_BINARY_NAME);
  const stagedManifestPath = join(updateDir, STAGED_MANIFEST_NAME);
  const readyPath = join(updateDir, READY_FILE_NAME);

  // Remove any stale ready.json before updating staged-tegrad and staged-manifest.json
  const existingReadyStat = lstatOrNull(readyPath);
  if (existingReadyStat !== null) {
    if (existingReadyStat.isSymbolicLink() || existingReadyStat.isDirectory()) {
      throw new UpdateError(
        "unsafe_path",
        `Refusing to overwrite non-regular ready file: ${readyPath}`,
      );
    }
    unlinkSync(readyPath);
  }
  for (const targetPath of [stagedBinaryPath, stagedManifestPath]) {
    const targetStat = lstatOrNull(targetPath);
    if (targetStat !== null && (targetStat.isSymbolicLink() || targetStat.isDirectory())) {
      throw new UpdateError(
        "unsafe_path",
        `Refusing to overwrite symlink or directory: ${targetPath}`,
      );
    }
  }

  try {
    if (isPosix(platform)) {
      chmodSync(tmpBinaryPath, STAGED_FILE_MODE);
    }
    renameSync(tmpBinaryPath, stagedBinaryPath);
  } catch (err) {
    try {
      if (existsSync(tmpBinaryPath)) {
        unlinkSync(tmpBinaryPath);
      }
    } catch {
      // ignore cleanup error
    }
    throw err;
  }

  writeFileAtomic(stagedManifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {
    mode: STAGED_FILE_MODE,
    dirMode: UPDATE_DIR_MODE,
  });

  const readyPayload: ReadyFile = {
    v: 1,
    channel,
    version: manifest.version,
    tag: manifest.tag,
    arch,
    sha256,
    size,
    staged_at: now(),
  };

  writeFileAtomic(readyPath, `${JSON.stringify(readyPayload, null, 2)}\n`, {
    mode: STAGED_FILE_MODE,
    dirMode: UPDATE_DIR_MODE,
  });

  return {
    status: "staged",
    channel,
    currentVersion,
    targetVersion: manifest.version,
    tag: manifest.tag,
    arch,
    sha256,
    size,
    stagedBinaryPath,
    stagedManifestPath,
    readyPath,
  };
}

export function computeNextCheckDelayMs(
  intervalMs: number = DEFAULT_UPDATE_INTERVAL_MS,
  jitterRatio: number = DEFAULT_UPDATE_JITTER_RATIO,
  random: () => number = Math.random,
): number {
  const clampedRandom = Math.min(1, Math.max(0, random()));
  const clampedJitter = Math.min(0.5, Math.max(0, jitterRatio));
  const factor = 1 - clampedJitter + 2 * clampedJitter * clampedRandom;
  return Math.max(1, Math.round(intervalMs * factor));
}

export interface AutoUpdaterOptions extends CheckForUpdateOptions {
  readonly auto?: boolean;
  readonly intervalMs?: number;
  readonly jitterRatio?: number;
  readonly timers?: TimerProvider;
  readonly random?: () => number;
  readonly logger?: Logger;
  readonly onStaged?: (result: Extract<CheckForUpdateResult, { status: "staged" }>) => void;
}

export interface AutoUpdater {
  start(): void;
  stop(): void;
  checkNow(): Promise<CheckForUpdateResult | null>;
  isRunning(): boolean;
}

export function createAutoUpdater(options: AutoUpdaterOptions): AutoUpdater {
  const auto = options.auto ?? true;
  const intervalMs = options.intervalMs ?? DEFAULT_UPDATE_INTERVAL_MS;
  const jitterRatio = options.jitterRatio ?? DEFAULT_UPDATE_JITTER_RATIO;
  const timers = options.timers ?? defaultTimers;
  const random = options.random ?? Math.random;

  let running = false;
  let timerHandle: TimerHandle | null = null;
  let inFlight: Promise<CheckForUpdateResult | null> | null = null;

  function clearTimer(): void {
    if (timerHandle !== null) {
      timers.clearTimeout(timerHandle);
      timerHandle = null;
    }
  }

  function scheduleNext(): void {
    if (!running || !auto) {
      return;
    }
    clearTimer();
    const delayMs = computeNextCheckDelayMs(intervalMs, jitterRatio, random);
    timerHandle = timers.setTimeout(() => {
      timerHandle = null;
      if (!running) return;
      void runCheck().finally(() => {
        if (running) {
          scheduleNext();
        }
      });
    }, delayMs);
  }

  async function runCheck(): Promise<CheckForUpdateResult | null> {
    if (inFlight !== null) {
      return inFlight;
    }
    inFlight = (async () => {
      try {
        const result = await checkForUpdate(options);
        if (result.status === "staged") {
          options.logger?.info("Staged verified update", {
            channel: result.channel,
            version: result.targetVersion,
            arch: result.arch,
          });
          options.onStaged?.(result);
        } else {
          options.logger?.debug("Agent is up to date", {
            channel: result.channel,
            version: result.currentVersion,
          });
        }
        return result;
      } catch (err) {
        options.logger?.warn("Update check failed", {
          code: err instanceof UpdateError ? err.code : "unknown",
          message: err instanceof Error ? err.message : String(err),
        });
        return null;
      } finally {
        inFlight = null;
      }
    })();
    return inFlight;
  }

  return {
    start(): void {
      if (running || !auto) {
        return;
      }
      running = true;
      scheduleNext();
    },

    stop(): void {
      running = false;
      clearTimer();
    },

    checkNow(): Promise<CheckForUpdateResult | null> {
      return runCheck();
    },

    isRunning(): boolean {
      return running;
    },
  };
}
