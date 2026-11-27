// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { createHash, timingSafeEqual } from "node:crypto";
import { closeSync, openSync, unlinkSync, writeSync } from "node:fs";
import { validateCdnHost } from "../agent/state";
import { ProtocolError } from "../protocol";
import type { FetchLike } from "../server/download";

export const DEFAULT_MOD_ALLOWED_HOSTS: ReadonlySet<string> = new Set([
  "cdn.modrinth.com",
  "edge.forgecdn.net",
  "mediafilez.forgecdn.net",
  // Tegra's own CDN, where Tegra modpack archives, manifests and server packs live.
  "cdn2.seijin.com.br",
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
  readonly signal?: AbortSignal;
}

export function isUrlHostAllowed(
  rawUrl: string,
  allowedHosts: ReadonlySet<string>,
):
  | { readonly ok: true; readonly url: URL }
  | { readonly ok: false; readonly reason: "host_not_allowed" | "invalid_url" } {
  try {
    const url = validateStateDownloadUrl(rawUrl, allowedHosts);
    return { ok: true, url };
  } catch (err) {
    if (err instanceof ProtocolError && err.message.includes("not allowed")) {
      return { ok: false, reason: "host_not_allowed" };
    }
    return { ok: false, reason: "invalid_url" };
  }
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

async function fetchFollowingRedirects<T>(
  options: DownloadVerifiedBufferOptions,
  readBody: (response: Response, maxBytes: number) => Promise<T>,
): Promise<{ readonly body: T; readonly expected: ExpectedHashDigests }> {
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
  let data: T | null = null;

  for (let hop = 0; hop <= maxRedirects; hop++) {
    if (options.signal?.aborted) {
      throw new ProtocolError("cancelled", "Download aborted");
    }
    const controller = new AbortController();
    const onAbort = (): void => controller.abort();
    options.signal?.addEventListener("abort", onAbort, { once: true });
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
        if (options.signal?.aborted) {
          throw new ProtocolError("cancelled", "Download aborted");
        }
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
        data = await readBody(response, maxBytes);
      } catch (err) {
        if (options.signal?.aborted) {
          throw new ProtocolError("cancelled", "Download aborted");
        }
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
      options.signal?.removeEventListener("abort", onAbort);
    }
  }

  if (data === null) {
    throw new ProtocolError("download_failed", "Exceeded maximum redirect hops");
  }
  return {
    body: data,
    expected: { sha1: expectedSha1, sha256: expectedSha256, sha512: expectedSha512 },
  };
}

interface ExpectedHashDigests {
  readonly sha1: string | undefined;
  readonly sha256: string | undefined;
  readonly sha512: string | undefined;
}

function assertDigests(
  actual: { readonly sha1: string; readonly sha256: string; readonly sha512: string },
  expected: ExpectedHashDigests,
): void {
  if (expected.sha1 !== undefined && !digestsEqual(actual.sha1, expected.sha1)) {
    throw new ProtocolError("hash_mismatch", "Downloaded artifact SHA-1 checksum mismatch");
  }
  if (expected.sha256 !== undefined && !digestsEqual(actual.sha256, expected.sha256)) {
    throw new ProtocolError("hash_mismatch", "Downloaded artifact SHA-256 checksum mismatch");
  }
  if (expected.sha512 !== undefined && !digestsEqual(actual.sha512, expected.sha512)) {
    throw new ProtocolError("hash_mismatch", "Downloaded artifact SHA-512 checksum mismatch");
  }
}

export async function downloadVerifiedBuffer(
  options: DownloadVerifiedBufferOptions,
): Promise<VerifiedDownloadResult> {
  const { body: data, expected } = await fetchFollowingRedirects(options, readCappedBytes);
  const sha1 = createHash("sha1").update(data).digest("hex");
  const sha256 = createHash("sha256").update(data).digest("hex");
  const sha512 = createHash("sha512").update(data).digest("hex");
  assertDigests({ sha1, sha256, sha512 }, expected);
  return { data, bytes: data.byteLength, sha1, sha256, sha512 };
}

export interface VerifiedFileDownloadResult {
  readonly path: string;
  readonly bytes: number;
  readonly sha1: string;
  readonly sha256: string;
  readonly sha512: string;
}

/**
 * Streams a download straight to `destPath`, hashing as it goes, so archives of hundreds of
 * megabytes never sit in memory. The file is removed when the download or the hash check fails.
 */
export async function downloadVerifiedToFile(
  options: DownloadVerifiedBufferOptions & { readonly destPath: string },
): Promise<VerifiedFileDownloadResult> {
  const writeBody = async (response: Response, maxBytes: number) => {
    const declared = Number(response.headers.get("content-length"));
    if (Number.isFinite(declared) && declared > maxBytes) {
      throw new ProtocolError("download_failed", "Download exceeds maximum allowed size");
    }
    const hashes = {
      sha1: createHash("sha1"),
      sha256: createHash("sha256"),
      sha512: createHash("sha512"),
    };
    const fd = openSync(options.destPath, "w", 0o600);
    let total = 0;
    try {
      const write = (chunk: Uint8Array): void => {
        total += chunk.byteLength;
        if (total > maxBytes) {
          throw new ProtocolError("download_failed", "Download exceeds maximum allowed size");
        }
        hashes.sha1.update(chunk);
        hashes.sha256.update(chunk);
        hashes.sha512.update(chunk);
        let offset = 0;
        while (offset < chunk.byteLength) {
          offset += writeSync(fd, chunk, offset, chunk.byteLength - offset);
        }
      };
      if (response.body === null) {
        write(new Uint8Array(await response.arrayBuffer()));
      } else {
        const reader = response.body.getReader();
        try {
          while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            if (value !== undefined && value.byteLength > 0) write(value);
          }
        } catch (err) {
          await reader.cancel().catch(() => {});
          throw err;
        } finally {
          reader.releaseLock();
        }
      }
    } finally {
      closeSync(fd);
    }
    return {
      bytes: total,
      sha1: hashes.sha1.digest("hex"),
      sha256: hashes.sha256.digest("hex"),
      sha512: hashes.sha512.digest("hex"),
    };
  };

  try {
    const { body, expected } = await fetchFollowingRedirects(options, writeBody);
    assertDigests(body, expected);
    return { path: options.destPath, ...body };
  } catch (err) {
    try {
      unlinkSync(options.destPath);
    } catch {
      // Nothing was written or it is already gone.
    }
    throw err;
  }
}
