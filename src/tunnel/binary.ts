// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import { ProtocolError } from "../protocol";

export const PLAYIT_VERSION = "v2.0.2";
export const DEFAULT_PLAYIT_DOWNLOAD_TIMEOUT_MS = 60_000;
export const DEFAULT_PLAYIT_MAX_BINARY_BYTES = 64 * 1024 * 1024; // 64 MiB

const ALLOWED_DOWNLOAD_HOSTS = new Set([
  "github.com",
  "objects.githubusercontent.com",
  "release-assets.githubusercontent.com",
]);

const MAX_REDIRECTS = 5;
const BIN_DIR_MODE = 0o700;
const BIN_FILE_MODE = 0o700;

export type PlayitPlatform = "linux-x64" | "linux-arm64";

export interface PinnedPlayitAsset {
  readonly version: string;
  readonly platform: PlayitPlatform;
  readonly assetName: string;
  readonly url: string;
  readonly sha256: string;
}

export const PLAYIT_RELEASE_ASSETS: Readonly<Record<PlayitPlatform, PinnedPlayitAsset>> = {
  "linux-x64": {
    version: PLAYIT_VERSION,
    platform: "linux-x64",
    assetName: "playit-linux-amd64",
    url: `https://github.com/playit-cloud/playit-agent/releases/download/${PLAYIT_VERSION}/playit-linux-amd64`,
    sha256: "9d27a8dbb4d2d8a7107fcabfa33028c789a30a64c97a36447fe4afb94e08dde9",
  },
  "linux-arm64": {
    version: PLAYIT_VERSION,
    platform: "linux-arm64",
    assetName: "playit-linux-aarch64",
    url: `https://github.com/playit-cloud/playit-agent/releases/download/${PLAYIT_VERSION}/playit-linux-aarch64`,
    sha256: "aed86fc2b82a772ca0e1d5cddec6c3123f96e12a099f7ae45aaa59a9a430a2cd",
  },
};

export type TunnelFetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

function isPosix(platform: NodeJS.Platform = process.platform): boolean {
  return platform !== "win32";
}

export function resolvePlayitPlatform(
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch,
): PlayitPlatform {
  if (platform !== "linux") {
    throw new ProtocolError(
      "tunnel_failed",
      `Unsupported platform for playit binary: ${platform} (only linux is supported)`,
    );
  }
  if (arch === "x64") {
    return "linux-x64";
  }
  if (arch === "arm64") {
    return "linux-arm64";
  }
  throw new ProtocolError(
    "tunnel_failed",
    `Unsupported architecture for playit binary: ${arch} (supported: x64, arm64)`,
  );
}

export function getPlayitBinaryPath(stateDir: string): string {
  return join(stateDir, "bin", "playitd");
}

export function computeSha256Hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

function sha256Equal(actualHex: string, expectedHex: string): boolean {
  const a = Buffer.from(actualHex.toLowerCase(), "hex");
  const b = Buffer.from(expectedHex.toLowerCase(), "hex");
  if (a.byteLength === 0 || a.byteLength !== b.byteLength) {
    return false;
  }
  return timingSafeEqual(a, b);
}

export function verifyFileSha256(filePath: string, expectedSha256: string): boolean {
  const stat = lstatSync(filePath, { throwIfNoEntry: false });
  if (stat === undefined || stat.isSymbolicLink() || !stat.isFile()) {
    return false;
  }
  const bytes = readFileSync(filePath);
  const actual = computeSha256Hex(new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength));
  return sha256Equal(actual, expectedSha256);
}

function validateDownloadUrl(rawUrl: string, allowInsecure: boolean): URL {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new ProtocolError("download_failed", "Invalid playit download URL");
  }
  if (parsed.username.length > 0 || parsed.password.length > 0) {
    throw new ProtocolError("download_failed", "Playit download URL must not contain credentials");
  }
  if (parsed.hash.length > 0) {
    throw new ProtocolError("download_failed", "Playit download URL must not contain a fragment");
  }
  const host = parsed.hostname.toLowerCase();
  if (parsed.protocol === "https:") {
    if (parsed.port !== "") {
      throw new ProtocolError(
        "download_failed",
        "Playit download URL must not specify a non-standard port",
      );
    }
    if (!ALLOWED_DOWNLOAD_HOSTS.has(host)) {
      throw new ProtocolError("download_failed", `Disallowed playit download host: ${host}`);
    }
    return parsed;
  }
  const isLoopback =
    host === "127.0.0.1" || host === "localhost" || host === "[::1]" || host === "::1";
  if (allowInsecure && parsed.protocol === "http:" && isLoopback) {
    return parsed;
  }
  throw new ProtocolError("download_failed", "Playit download URL must use https://");
}

async function fetchWithValidatedRedirects(
  initialUrl: string,
  fetchImpl: TunnelFetchLike,
  timeoutMs: number,
  maxBytes: number,
  allowInsecure: boolean,
): Promise<Uint8Array> {
  let currentUrl = validateDownloadUrl(initialUrl, allowInsecure).toString();

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      let response: Response;
      try {
        response = await fetchImpl(currentUrl, {
          method: "GET",
          redirect: "manual",
          signal: controller.signal,
        });
      } catch {
        throw new ProtocolError("download_failed", "Failed to download playit binary");
      }

      if (response.status >= 300 && response.status < 400) {
        void response.body?.cancel().catch(() => {});
        const location = response.headers.get("location");
        if (!location) {
          throw new ProtocolError("download_failed", "Playit download redirect missing Location");
        }
        if (hop === MAX_REDIRECTS) {
          throw new ProtocolError(
            "download_failed",
            "Too many redirects while downloading playit binary",
          );
        }
        let nextUrl: string;
        try {
          nextUrl = new URL(location, currentUrl).toString();
        } catch {
          throw new ProtocolError("download_failed", "Malformed playit redirect Location URL");
        }
        currentUrl = validateDownloadUrl(nextUrl, allowInsecure).toString();
        continue;
      }

      if (!response.ok) {
        void response.body?.cancel().catch(() => {});
        throw new ProtocolError(
          "download_failed",
          `Failed to download playit binary (HTTP ${response.status})`,
        );
      }

      const declaredLength = response.headers.get("content-length");
      if (declaredLength !== null) {
        const parsedLen = Number(declaredLength);
        if (Number.isFinite(parsedLen) && parsedLen > maxBytes) {
          void response.body?.cancel().catch(() => {});
          throw new ProtocolError("download_failed", "Playit binary exceeds maximum size limit");
        }
      }

      if (response.body === null) {
        const buf = new Uint8Array(await response.arrayBuffer());
        if (buf.byteLength > maxBytes) {
          throw new ProtocolError("download_failed", "Playit binary exceeds maximum size limit");
        }
        return buf;
      }

      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let total = 0;

      try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) {
            break;
          }
          if (value === undefined || value.byteLength === 0) {
            continue;
          }
          total += value.byteLength;
          if (total > maxBytes) {
            await reader.cancel();
            throw new ProtocolError("download_failed", "Playit binary exceeds maximum size limit");
          }
          chunks.push(value);
        }
      } catch (err) {
        if (err instanceof ProtocolError) {
          throw err;
        }
        throw new ProtocolError("download_failed", "Failed while reading playit binary stream");
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
    } finally {
      clearTimeout(timer);
    }
  }

  throw new ProtocolError("download_failed", "Too many redirects while downloading playit binary");
}

function writeExecutableAtomic(filePath: string, data: Uint8Array): void {
  const dir = dirname(filePath);
  mkdirSync(dir, { recursive: true, mode: BIN_DIR_MODE });
  if (isPosix()) {
    chmodSync(dir, BIN_DIR_MODE);
  }

  const suffix = randomBytes(8).toString("hex");
  const tmpPath = join(dir, `.tmp-${basename(filePath)}-${process.pid}-${suffix}`);
  let fd: number | undefined;
  try {
    fd = openSync(tmpPath, "wx", BIN_FILE_MODE);
    writeFileSync(fd, data);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    if (isPosix()) {
      chmodSync(tmpPath, BIN_FILE_MODE);
    }
    renameSync(tmpPath, filePath);
  } catch (err) {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        // ignore close failure
      }
    }
    try {
      if (existsSync(tmpPath)) {
        unlinkSync(tmpPath);
      }
    } catch {
      // ignore cleanup failure
    }
    throw err;
  }
}

export interface EnsurePlayitBinaryOptions {
  readonly stateDir: string;
  readonly asset?: PinnedPlayitAsset;
  readonly platform?: NodeJS.Platform;
  readonly arch?: string;
  readonly fetchImpl?: TunnelFetchLike;
  readonly timeoutMs?: number;
  readonly maxBytes?: number;
  readonly allowInsecure?: boolean;
}

/**
 * Ensures the pinned playitd binary exists at `<stateDir>/bin/playitd` and
 * matches its pinned SHA-256 digest before returning its path.
 */
export async function ensurePlayitBinary(options: EnsurePlayitBinaryOptions): Promise<string> {
  const asset =
    options.asset ?? PLAYIT_RELEASE_ASSETS[resolvePlayitPlatform(options.platform, options.arch)];
  const binaryPath = getPlayitBinaryPath(options.stateDir);

  const existingStat = lstatSync(binaryPath, { throwIfNoEntry: false });
  if (existingStat !== undefined) {
    if (verifyFileSha256(binaryPath, asset.sha256)) {
      return binaryPath;
    }
    throw new ProtocolError(
      "hash_mismatch",
      `Existing playit binary at ${binaryPath} failed SHA-256 verification`,
    );
  }

  const fetchImpl = options.fetchImpl ?? ((input, init) => fetch(input, init));
  const bytes = await fetchWithValidatedRedirects(
    asset.url,
    fetchImpl,
    options.timeoutMs ?? DEFAULT_PLAYIT_DOWNLOAD_TIMEOUT_MS,
    options.maxBytes ?? DEFAULT_PLAYIT_MAX_BINARY_BYTES,
    options.allowInsecure ?? false,
  );

  const actualHash = computeSha256Hex(bytes);
  if (!sha256Equal(actualHash, asset.sha256)) {
    throw new ProtocolError(
      "hash_mismatch",
      `Downloaded playit binary SHA-256 mismatch (expected ${asset.sha256}, got ${actualHash})`,
    );
  }

  writeExecutableAtomic(binaryPath, bytes);
  return binaryPath;
}
