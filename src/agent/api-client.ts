// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
import type { SigningKeyPair } from "../crypto";
import { signAgentRequest } from "../protocol";
import { validateApiUrl } from "./state";

export const AGENT_API_TIMEOUT_MS = 10_000;
export const AGENT_API_MAX_RESPONSE_BYTES = 64 * 1024;
/** Path prefix of the control API, appended to the configured `api_url`. */
export const AGENT_API_PREFIX = "/v1";

export type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

export type AgentApiErrorCode =
  | "network_error"
  | "http_error"
  | "quota_exceeded"
  | "rate_limited"
  | "response_too_large"
  | "invalid_response"
  | "aborted";

export class AgentApiError extends Error {
  readonly code: AgentApiErrorCode;
  readonly status: number | undefined;

  constructor(code: AgentApiErrorCode, message: string, status?: number) {
    super(message);
    this.name = "AgentApiError";
    this.code = code;
    this.status = status;
  }
}

export interface SignedRequestOptions {
  readonly agentKeyPair: SigningKeyPair;
  readonly now: () => number;
}

/**
 * Headers that authenticate one request as coming from this agent. The
 * signature covers the method, the path with query, the body and a timestamp,
 * so the exact URL that is sent must be the one passed here.
 */
export function signedRequestHeaders(
  options: SignedRequestOptions,
  method: string,
  url: string,
  body: string | undefined,
): Record<string, string> {
  const parsed = new URL(url);
  return signAgentRequest({
    agentKeyPair: options.agentKeyPair,
    method,
    pathWithQuery: `${parsed.pathname}${parsed.search}`,
    ...(body !== undefined ? { body } : {}),
    ts: options.now(),
  });
}

export function buildApiUrl(baseApiUrl: string, pathSuffix: string): string {
  const url = new URL(baseApiUrl);
  const basePath = url.pathname.replace(/\/+$/, "");
  url.pathname = `${basePath}${AGENT_API_PREFIX}${pathSuffix}`;
  url.search = "";
  url.hash = "";
  return url.toString();
}

export interface BackupUploadTarget {
  readonly put_url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly expires_at: number;
  readonly max_bytes: number;
}

export interface BackupUploadUrlRequest {
  readonly server_id: string;
  readonly size_bytes: number;
}

export interface AgentApiClient {
  /** `POST /v1/agents/self/backup-upload-url`: where to `PUT` a backup of `size_bytes`. */
  requestBackupUploadUrl(
    request: BackupUploadUrlRequest,
    signal?: AbortSignal,
  ): Promise<BackupUploadTarget>;
}

export interface AgentApiClientOptions {
  readonly apiUrl: string;
  readonly agentKeyPair: SigningKeyPair;
  readonly allowInsecure?: boolean;
  readonly fetch?: FetchLike;
  readonly now?: () => number;
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
}

const backupUploadTargetSchema = z.object({
  put_url: z.string().min(1).max(4096),
  headers: z.record(z.string(), z.string()).default({}),
  expires_at: z.number().int().nonnegative(),
  max_bytes: z.number().int().positive(),
});

async function readBoundedText(response: Response, maxBytes: number): Promise<string> {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    void response.body?.cancel().catch(() => {});
    throw new AgentApiError("response_too_large", "API response exceeds size limit");
  }

  if (response.body === null) {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > maxBytes) {
      throw new AgentApiError("response_too_large", "API response exceeds size limit");
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
          throw new AgentApiError("response_too_large", "API response exceeds size limit");
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

export function createAgentApiClient(options: AgentApiClientOptions): AgentApiClient {
  const validatedUrl = validateApiUrl(options.apiUrl, options.allowInsecure ?? false);
  const fetchFn: FetchLike = options.fetch ?? ((input, init) => fetch(input, init));
  const now = options.now ?? (() => Date.now());
  const timeoutMs = options.timeoutMs ?? AGENT_API_TIMEOUT_MS;
  const maxResponseBytes = options.maxResponseBytes ?? AGENT_API_MAX_RESPONSE_BYTES;

  async function signedJson(
    method: string,
    pathSuffix: string,
    payload: unknown,
    externalSignal?: AbortSignal,
  ): Promise<Response> {
    if (externalSignal?.aborted) {
      throw new AgentApiError("aborted", "API request aborted");
    }
    const url = buildApiUrl(validatedUrl, pathSuffix);
    const body = JSON.stringify(payload);
    const headers = {
      "content-type": "application/json",
      accept: "application/json",
      ...signedRequestHeaders({ agentKeyPair: options.agentKeyPair, now }, method, url, body),
    };

    const controller = new AbortController();
    let timedOut = false;
    const onAbort = (): void => controller.abort();
    externalSignal?.addEventListener("abort", onAbort, { once: true });
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);

    try {
      return await fetchFn(url, {
        method,
        headers,
        body,
        redirect: "error",
        signal: controller.signal,
      });
    } catch {
      if (externalSignal?.aborted) {
        throw new AgentApiError("aborted", "API request aborted");
      }
      throw new AgentApiError(
        "network_error",
        timedOut ? "API request timed out" : "API network request failed",
      );
    } finally {
      clearTimeout(timer);
      externalSignal?.removeEventListener("abort", onAbort);
    }
  }

  return {
    async requestBackupUploadUrl(
      request: BackupUploadUrlRequest,
      signal?: AbortSignal,
    ): Promise<BackupUploadTarget> {
      const response = await signedJson(
        "POST",
        "/agents/self/backup-upload-url",
        { server_id: request.server_id, size_bytes: request.size_bytes },
        signal,
      );

      if (response.status === 413) {
        void response.body?.cancel().catch(() => {});
        throw new AgentApiError("quota_exceeded", "Backup storage quota exceeded", 413);
      }
      if (response.status === 429) {
        void response.body?.cancel().catch(() => {});
        throw new AgentApiError("rate_limited", "Backup upload URL request was rate limited", 429);
      }
      if (response.status !== 200 && response.status !== 201) {
        void response.body?.cancel().catch(() => {});
        throw new AgentApiError(
          "http_error",
          `Backup upload URL request failed with HTTP ${response.status}`,
          response.status,
        );
      }

      let raw: unknown;
      try {
        raw = JSON.parse(await readBoundedText(response, maxResponseBytes)) as unknown;
      } catch (err) {
        if (err instanceof AgentApiError) {
          throw err;
        }
        throw new AgentApiError("invalid_response", "API returned invalid JSON");
      }
      const parsed = backupUploadTargetSchema.safeParse(raw);
      if (!parsed.success) {
        throw new AgentApiError("invalid_response", "API returned a malformed upload target");
      }
      return parsed.data;
    },
  };
}
