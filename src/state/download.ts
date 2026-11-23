// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { createHash, timingSafeEqual } from "node:crypto";
import { validateCdnHost } from "../agent/state";
import { ProtocolError } from "../protocol";
import type { FetchLike } from "../server/download";

export const DEFAULT_MOD_ALLOWED_HOSTS: ReadonlySet<string> = new Set([
  "cdn.modrinth.com",
  "edge.forgecdn.net",
  "mediafilez.forgecdn.net",
]);

export const DEFAULT_MAX_MOD_BYTES = 256 * 1024 * 1024; // 256 MiB
export const DEFAULT_MAX_SERVERPACK_BYTES = 512 * 1024 * 1024; // 512 MiB
export const DEFAULT_STATE_MAX_REDIRECTS = 5;
export const DEFAULT_STATE_DOWNLOAD_TIMEOUT_MS = 60_000;

const SHA1_REGEX = /^[0-9a-f]{40}$/i;
const SHA256_REGEX = /^[0-9a-f]{64}$/i;
const SHA512_REGEX = /^[0-9a-f]{128}$/i;

export interface ExpectedHashes {
  readonly sha1?: string | undefined;
  readonly sha256?: string | undefined;
  readonly sha512?: string | undefined;
}

export interface VerifiedDownloadResult {
  readonly data: Uint8Array;
  readonly bytes: number;
  readonly sha1: string;
  readonly sha256: string;
  readonly sha512: string;
}

export interface DownloadVerifiedBufferOptions {
  readonly url: string;
  readonly allowedHosts: ReadonlySet<string>;
  readonly expectedHashes?: ExpectedHashes;
  readonly maxBytes?: number;
  readonly maxRedirects?: number;
  readonly timeoutMs?: number;
  readonly fetchImpl?: FetchLike;
}

export function buildAllowedDownloadHosts(
  extraHosts: readonly (string | undefined)[] = [],
): ReadonlySet<string> {
  const hosts = new Set<string>(DEFAULT_MOD_ALLOWED_HOSTS);
  for (const raw of extraHosts) {
    if (raw !== undefined && raw.trim().length > 0) {
      hosts.add(validateCdnHost(raw));
    }
  }
  return hosts;
}

export function validateStateDownloadUrl(rawUrl: string, allowedHosts: ReadonlySet<string>): URL {
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

  if (parsed.port !== "") {
    throw new ProtocolError("download_failed", "Download URL must not specify a non-standard port");
  }

  if (parsed.hash.length > 0) {
    throw new ProtocolError("download_failed", "Download URL must not contain a URL fragment");
  }

  const host = parsed.hostname.toLowerCase();
  if (!allowedHosts.has(host)) {
    throw new ProtocolError("download_failed", `Download host is not allowed: ${host}`);
  }

  return parsed;
}

function normalizeHash(algorithm: "sha1" | "sha256" | "sha512", raw: string): string {
  const trimmed = raw.trim().toLowerCase();
  const regex =
    algorithm === "sha1" ? SHA1_REGEX : algorithm === "sha256" ? SHA256_REGEX : SHA512_REGEX;
  if (!regex.test(trimmed)) {
    throw new ProtocolError("hash_mismatch", `Invalid expected ${algorithm} checksum format`);
  }
  return trimmed;
}

function digestsEqual(actualHex: string, expectedHex: string): boolean {
  const a = Buffer.from(actualHex.toLowerCase(), "hex");
  const b = Buffer.from(expectedHex.toLowerCase(), "hex");
  if (a.byteLength === 0 || a.byteLength !== b.byteLength) {
    return false;
  }
  return timingSafeEqual(a, b);
}

async function readCappedBytes(response: Response, maxBytes: number): Promise<Uint8Array> {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null) {
    const declared = Number(contentLength);
    if (Number.isFinite(declared) && declared > maxBytes) {
      throw new ProtocolError("download_failed", "Download exceeds maximum allowed size");
    }
  }

  if (response.body === null) {
    const buf = new Uint8Array(await response.arrayBuffer());
    if (buf.byteLength > maxBytes) {
      throw new ProtocolError("download_failed", "Download exceeds maximum allowed size");
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
        throw new ProtocolError("download_failed", "Download exceeds maximum allowed size");
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

export async function downloadVerifiedBuffer(
  options: DownloadVerifiedBufferOptions,
): Promise<VerifiedDownloadResult> {
  const expectedSha1 =
    options.expectedHashes?.sha1 !== undefined
      ? normalizeHash("sha1", options.expectedHashes.sha1)
      : undefined;
  const expectedSha256 =
    options.expectedHashes?.sha256 !== undefined
      ? normalizeHash("sha256", options.expectedHashes.sha256)
      : undefined;
  const expectedSha512 =
    options.expectedHashes?.sha512 !== undefined
      ? normalizeHash("sha512", options.expectedHashes.sha512)
      : undefined;

  const fetchFn: FetchLike = options.fetchImpl ?? ((input, init) => globalThis.fetch(input, init));
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_MOD_BYTES;
  const maxRedirects = options.maxRedirects ?? DEFAULT_STATE_MAX_REDIRECTS;
  const timeoutMs = options.timeoutMs ?? DEFAULT_STATE_DOWNLOAD_TIMEOUT_MS;

  let currentUrl = validateStateDownloadUrl(options.url, options.allowedHosts);
  let data: Uint8Array | null = null;

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      let response: Response;
      try {
        response = await fetchFn(currentUrl.toString(), {
          method: "GET",
          redirect: "manual",
          signal: controller.signal,
        });
      } catch {
        throw new ProtocolError("download_failed", `Failed to fetch ${currentUrl.hostname}`);
      }

      if (
        response.status === 301 ||
        response.status === 302 ||
        response.status === 303 ||
        response.status === 307 ||
        response.status === 308
      ) {
        void response.body?.cancel().catch(() => {});
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
        currentUrl = validateStateDownloadUrl(nextUrlStr, options.allowedHosts);
        continue;
      }

      if (!response.ok) {
        void response.body?.cancel().catch(() => {});
        throw new ProtocolError(
          "download_failed",
          `Download request to ${currentUrl.hostname} failed with HTTP ${response.status}`,
        );
      }

      try {
        data = await readCappedBytes(response, maxBytes);
      } catch (err) {
        if (err instanceof ProtocolError) {
          throw err;
        }
        throw new ProtocolError(
          "download_failed",
          `Failed while reading response from ${currentUrl.hostname}`,
        );
      }
      break;
    } finally {
      clearTimeout(timer);
    }
  }

  if (data === null) {
    throw new ProtocolError("download_failed", "Exceeded maximum redirect hops");
  }
  const sha1 = createHash("sha1").update(data).digest("hex");
  const sha256 = createHash("sha256").update(data).digest("hex");
  const sha512 = createHash("sha512").update(data).digest("hex");

  if (expectedSha1 !== undefined && !digestsEqual(sha1, expectedSha1)) {
    throw new ProtocolError("hash_mismatch", "Downloaded artifact SHA-1 checksum mismatch");
  }
  if (expectedSha256 !== undefined && !digestsEqual(sha256, expectedSha256)) {
    throw new ProtocolError("hash_mismatch", "Downloaded artifact SHA-256 checksum mismatch");
  }
  if (expectedSha512 !== undefined && !digestsEqual(sha512, expectedSha512)) {
    throw new ProtocolError("hash_mismatch", "Downloaded artifact SHA-512 checksum mismatch");
  }

  return {
    data,
    bytes: data.byteLength,
    sha1,
    sha256,
    sha512,
  };
}
