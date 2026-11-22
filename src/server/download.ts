// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import type { z } from "zod";
import { ProtocolError } from "../protocol";

export type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;
export type HashAlgorithm = "sha256" | "sha1";

export const DEFAULT_MAX_JSON_BYTES = 2 * 1024 * 1024;
export const DEFAULT_MAX_TEXT_BYTES = 256 * 1024;
export const DEFAULT_MAX_BINARY_BYTES = 300 * 1024 * 1024;
export const DEFAULT_MAX_REDIRECTS = 5;
export const DEFAULT_DOWNLOAD_TIMEOUT_MS = 60_000;

const SHA256_HEX_REGEX = /^[0-9a-f]{64}$/i;
const SHA1_HEX_REGEX = /^[0-9a-f]{40}$/i;

function isPosix(platform: NodeJS.Platform = process.platform): boolean {
  return platform !== "win32";
}

export function validateDownloadUrl(rawUrl: string, allowedHosts: ReadonlySet<string>): URL {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new ProtocolError("download_failed", "Invalid download URL");
  }

  if (parsed.protocol !== "https:") {
    throw new ProtocolError(
      "download_failed",
      `Download URL must use https:// (got ${parsed.protocol})`,
    );
  }

  if (parsed.username || parsed.password) {
    throw new ProtocolError("download_failed", "Download URL must not contain credentials");
  }

  const host = parsed.hostname.toLowerCase();
  if (!allowedHosts.has(host)) {
    throw new ProtocolError("download_failed", `Download host is not allowed: ${host}`);
  }

  return parsed;
}

export interface FetchAllowlistOptions {
  readonly allowedHosts: ReadonlySet<string>;
  readonly fetchImpl?: FetchLike;
  readonly maxRedirects?: number;
  readonly timeoutMs?: number;
  readonly accept?: string;
}

export async function fetchWithAllowlist(
  rawUrl: string,
  options: FetchAllowlistOptions,
): Promise<Response> {
  const fetchFn: FetchLike = options.fetchImpl ?? ((input, init) => globalThis.fetch(input, init));
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  const timeoutMs = options.timeoutMs ?? DEFAULT_DOWNLOAD_TIMEOUT_MS;

  let currentUrl = validateDownloadUrl(rawUrl, options.allowedHosts);

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let response: Response;

    try {
      const headers: Record<string, string> = {};
      if (options.accept !== undefined) {
        headers.Accept = options.accept;
      }
      response = await fetchFn(currentUrl.toString(), {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers,
      });
    } catch {
      throw new ProtocolError("download_failed", `Failed to fetch ${currentUrl.hostname}`);
    } finally {
      clearTimeout(timer);
    }

    if (
      response.status === 301 ||
      response.status === 302 ||
      response.status === 303 ||
      response.status === 307 ||
      response.status === 308
    ) {
      const location = response.headers.get("location");
      if (!location) {
        throw new ProtocolError("download_failed", "Redirect response missing Location header");
      }
      if (hop === maxRedirects) {
        throw new ProtocolError("download_failed", "Exceeded maximum redirect hops");
      }
      let nextUrlStr: string;
      try {
        nextUrlStr = new URL(location, currentUrl).toString();
      } catch {
        throw new ProtocolError("download_failed", "Malformed redirect Location URL");
      }
      currentUrl = validateDownloadUrl(nextUrlStr, options.allowedHosts);
      continue;
    }

    if (!response.ok) {
      throw new ProtocolError(
        "download_failed",
        `Download request to ${currentUrl.hostname} failed with HTTP ${response.status}`,
      );
    }

    return response;
  }

  throw new ProtocolError("download_failed", "Exceeded maximum redirect hops");
}

async function readResponseBytesCapped(response: Response, maxBytes: number): Promise<Uint8Array> {
  const contentLengthHeader = response.headers.get("content-length");
  if (contentLengthHeader !== null) {
    const declared = Number(contentLengthHeader);
    if (Number.isFinite(declared) && declared > maxBytes) {
      throw new ProtocolError("download_failed", "Response exceeds maximum allowed size");
    }
  }

  if (response.body === null) {
    const buf = new Uint8Array(await response.arrayBuffer());
    if (buf.byteLength > maxBytes) {
      throw new ProtocolError("download_failed", "Response exceeds maximum allowed size");
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
        throw new ProtocolError("download_failed", "Response exceeds maximum allowed size");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

export async function fetchTextWithAllowlist(
  rawUrl: string,
  options: FetchAllowlistOptions & { readonly maxBytes?: number },
): Promise<string> {
  const response = await fetchWithAllowlist(rawUrl, options);
  const bytes = await readResponseBytesCapped(response, options.maxBytes ?? DEFAULT_MAX_TEXT_BYTES);
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

export async function fetchJsonWithAllowlist<T>(
  rawUrl: string,
  schema: z.ZodType<T>,
  options: FetchAllowlistOptions & { readonly maxBytes?: number },
): Promise<T> {
  const response = await fetchWithAllowlist(rawUrl, {
    ...options,
    accept: options.accept ?? "application/json",
  });
  const bytes = await readResponseBytesCapped(response, options.maxBytes ?? DEFAULT_MAX_JSON_BYTES);

  let rawJson: unknown;
  try {
    rawJson = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } catch {
    throw new ProtocolError("download_failed", "Invalid JSON payload from remote endpoint");
  }

  const parsed = schema.safeParse(rawJson);
  if (!parsed.success) {
    throw new ProtocolError("download_failed", "Remote JSON failed schema validation");
  }

  return parsed.data;
}

export function normalizeExpectedHash(algorithm: HashAlgorithm, rawHex: string): string {
  const trimmed = rawHex.trim().toLowerCase();
  const regex = algorithm === "sha256" ? SHA256_HEX_REGEX : SHA1_HEX_REGEX;
  if (!regex.test(trimmed)) {
    throw new ProtocolError("hash_mismatch", `Invalid expected ${algorithm} checksum format`);
  }
  return trimmed;
}

export function compareHexDigests(actualHex: string, expectedHex: string): boolean {
  const a = Buffer.from(actualHex.toLowerCase(), "hex");
  const b = Buffer.from(expectedHex.toLowerCase(), "hex");
  if (a.byteLength === 0 || a.byteLength !== b.byteLength) {
    return false;
  }
  return timingSafeEqual(a, b);
}

export async function fetchSidecarHash(
  rawUrl: string,
  algorithm: HashAlgorithm,
  options: FetchAllowlistOptions,
): Promise<string> {
  const text = await fetchTextWithAllowlist(rawUrl, {
    ...options,
    maxBytes: 4096,
  });
  const token = text.trim().split(/\s+/)[0] ?? "";
  return normalizeExpectedHash(algorithm, token);
}

export interface DownloadVerifiedFileOptions extends FetchAllowlistOptions {
  readonly url: string;
  readonly destPath: string;
  readonly expectedHash: {
    readonly algorithm: HashAlgorithm;
    readonly hex: string;
  };
  readonly maxBytes?: number;
  readonly fileMode?: number;
  readonly dirMode?: number;
}

export async function downloadVerifiedFile(
  options: DownloadVerifiedFileOptions,
): Promise<{ readonly bytes: number; readonly hash: string }> {
  const expectedHex = normalizeExpectedHash(
    options.expectedHash.algorithm,
    options.expectedHash.hex,
  );
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BINARY_BYTES;
  const fileMode = options.fileMode ?? 0o640;
  const dirMode = options.dirMode ?? 0o750;

  const response = await fetchWithAllowlist(options.url, options);

  const contentLengthHeader = response.headers.get("content-length");
  if (contentLengthHeader !== null) {
    const declared = Number(contentLengthHeader);
    if (Number.isFinite(declared) && declared > maxBytes) {
      throw new ProtocolError("download_failed", "Download exceeds maximum allowed size");
    }
  }

  const dir = dirname(options.destPath);
  mkdirSync(dir, { recursive: true, mode: dirMode });
  if (isPosix()) {
    chmodSync(dir, dirMode);
  }

  const suffix = randomBytes(8).toString("hex");
  const tmpPath = join(dir, `.tmp-${basename(options.destPath)}-${process.pid}-${suffix}`);
  const hasher = createHash(options.expectedHash.algorithm);
  let fd: number | undefined;
  let totalBytes = 0;

  try {
    fd = openSync(tmpPath, "wx", fileMode);

    if (response.body === null) {
      const buf = new Uint8Array(await response.arrayBuffer());
      if (buf.byteLength > maxBytes) {
        throw new ProtocolError("download_failed", "Download exceeds maximum allowed size");
      }
      if (buf.byteLength > 0) {
        hasher.update(buf);
        writeSync(fd, buf, 0, buf.byteLength);
        totalBytes = buf.byteLength;
      }
    } else {
      const reader = response.body.getReader();
      try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) {
            break;
          }
          if (value === undefined || value.byteLength === 0) {
            continue;
          }
          totalBytes += value.byteLength;
          if (totalBytes > maxBytes) {
            await reader.cancel();
            throw new ProtocolError("download_failed", "Download exceeds maximum allowed size");
          }
          hasher.update(value);
          writeSync(fd, value, 0, value.byteLength);
        }
      } finally {
        reader.releaseLock();
      }
    }

    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;

    const actualHex = hasher.digest("hex");
    if (!compareHexDigests(actualHex, expectedHex)) {
      throw new ProtocolError(
        "hash_mismatch",
        `Checksum mismatch (${options.expectedHash.algorithm}) for downloaded artifact`,
      );
    }

    if (isPosix()) {
      chmodSync(tmpPath, fileMode);
    }

    renameSync(tmpPath, options.destPath);
    return { bytes: totalBytes, hash: actualHex };
  } catch (err) {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        // ignore close cleanup failure
      }
    }
    try {
      if (existsSync(tmpPath)) {
        unlinkSync(tmpPath);
      }
    } catch {
      // ignore unlink cleanup failure
    }
    throw err;
  }
}
