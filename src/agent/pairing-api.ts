// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
import type { SigningKeyPair } from "../crypto";
import { buildApiUrl, type FetchLike, signedRequestHeaders } from "./api-client";
import { validateApiUrl } from "./state";

export type { FetchLike };

export const PAIRING_API_TIMEOUT_MS = 10_000;
export const PAIRING_API_MAX_RESPONSE_BYTES = 64 * 1024;

export type PairingApiErrorCode =
  | "network_error"
  | "http_error"
  | "response_too_large"
  | "invalid_response"
  | "aborted";

export class PairingApiError extends Error {
  readonly code: PairingApiErrorCode;

  constructor(code: PairingApiErrorCode, message: string) {
    super(message);
    this.name = "PairingApiError";
    this.code = code;
  }
}

export type PollGrantResult =
  | { readonly status: "pending" }
  | { readonly status: "expired" }
  | { readonly status: "ready"; readonly grant: unknown };

export interface PairingApiClient {
  registerPairing(
    code: string,
    agentPublicKeyB64: string,
    signal?: AbortSignal,
  ): Promise<"created" | "conflict">;
  pollGrant(code: string, signal?: AbortSignal): Promise<PollGrantResult>;
  deletePairing(code: string): Promise<void>;
}

export interface PairingApiClientOptions {
  readonly apiUrl: string;
  /** Signs every request; the control API checks it against the key sent at registration. */
  readonly agentKeyPair: SigningKeyPair;
  readonly now?: () => number;
  readonly allowInsecure?: boolean;
  readonly fetch?: FetchLike;
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
}

const grantResponseSchema = z.object({
  grant: z.unknown(),
});

async function readBoundedText(response: Response, maxBytes: number): Promise<string> {
  const contentLengthHeader = response.headers.get("content-length");
  if (contentLengthHeader !== null) {
    const declared = Number(contentLengthHeader);
    if (Number.isFinite(declared) && declared > maxBytes) {
      throw new PairingApiError("response_too_large", "Pairing API response exceeds size limit");
    }
  }

  if (response.body === null) {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > maxBytes) {
      throw new PairingApiError("response_too_large", "Pairing API response exceeds size limit");
    }
    return text;
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (value !== undefined) {
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel();
          throw new PairingApiError(
            "response_too_large",
            "Pairing API response exceeds size limit",
          );
        }
        chunks.push(value);
      }
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
  return new TextDecoder("utf-8", { fatal: true }).decode(combined);
}

async function fetchWithTimeout(
  fetchFn: FetchLike,
  url: string,
  init: RequestInit,
  timeoutMs: number,
  externalSignal?: AbortSignal,
): Promise<Response> {
  if (externalSignal?.aborted) {
    throw new PairingApiError("aborted", "Pairing request aborted");
  }

  const controller = new AbortController();
  let timedOut = false;

  const onExternalAbort = (): void => {
    controller.abort();
  };
  externalSignal?.addEventListener("abort", onExternalAbort, { once: true });

  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  try {
    return await fetchFn(url, {
      ...init,
      signal: controller.signal,
    });
  } catch {
    if (externalSignal?.aborted) {
      throw new PairingApiError("aborted", "Pairing request aborted");
    }
    if (timedOut) {
      throw new PairingApiError("network_error", "Pairing API request timed out");
    }
    throw new PairingApiError("network_error", "Pairing API network request failed");
  } finally {
    clearTimeout(timer);
    externalSignal?.removeEventListener("abort", onExternalAbort);
  }
}

export function createPairingApiClient(options: PairingApiClientOptions): PairingApiClient {
  const validatedUrl = validateApiUrl(options.apiUrl, options.allowInsecure ?? false);
  const fetchFn: FetchLike = options.fetch ?? ((input, init) => fetch(input, init));
  const timeoutMs = options.timeoutMs ?? PAIRING_API_TIMEOUT_MS;
  const maxResponseBytes = options.maxResponseBytes ?? PAIRING_API_MAX_RESPONSE_BYTES;
  const now = options.now ?? (() => Date.now());

  function signed(method: string, url: string, body?: string): Record<string, string> {
    return signedRequestHeaders({ agentKeyPair: options.agentKeyPair, now }, method, url, body);
  }

  return {
    async registerPairing(
      code: string,
      agentPublicKeyB64: string,
      signal?: AbortSignal,
    ): Promise<"created" | "conflict"> {
      const url = buildApiUrl(validatedUrl, "/agents/pairing");
      const requestBody = JSON.stringify({
        code,
        agent_public_key: agentPublicKeyB64,
      });
      const response = await fetchWithTimeout(
        fetchFn,
        url,
        {
          method: "POST",
          headers: { "content-type": "application/json", ...signed("POST", url, requestBody) },
          body: requestBody,
        },
        timeoutMs,
        signal,
      );

      if (response.status === 201) {
        return "created";
      }
      if (response.status === 409) {
        return "conflict";
      }
      throw new PairingApiError(
        "http_error",
        `Pairing registration failed with HTTP ${response.status}`,
      );
    },

    async pollGrant(code: string, signal?: AbortSignal): Promise<PollGrantResult> {
      const url = buildApiUrl(validatedUrl, `/agents/pairing/${encodeURIComponent(code)}/grant`);
      const response = await fetchWithTimeout(
        fetchFn,
        url,
        {
          method: "GET",
          headers: { accept: "application/json", ...signed("GET", url) },
        },
        timeoutMs,
        signal,
      );

      if (response.status === 202) {
        return { status: "pending" };
      }
      if (response.status === 404 || response.status === 410) {
        return { status: "expired" };
      }
      if (response.status !== 200) {
        throw new PairingApiError("http_error", `Pairing poll failed with HTTP ${response.status}`);
      }

      const text = await readBoundedText(response, maxResponseBytes);
      let raw: unknown;
      try {
        raw = JSON.parse(text) as unknown;
      } catch {
        throw new PairingApiError("invalid_response", "Pairing API returned invalid JSON");
      }

      const parsed = grantResponseSchema.safeParse(raw);
      if (!parsed.success || parsed.data.grant === undefined) {
        throw new PairingApiError("invalid_response", "Pairing API returned malformed grant body");
      }

      return { status: "ready", grant: parsed.data.grant };
    },

    async deletePairing(code: string): Promise<void> {
      const url = buildApiUrl(validatedUrl, `/agents/pairing/${encodeURIComponent(code)}`);
      try {
        await fetchWithTimeout(
          fetchFn,
          url,
          { method: "DELETE", headers: signed("DELETE", url) },
          timeoutMs,
        );
      } catch {
        // Best-effort cleanup
      }
    },
  };
}
