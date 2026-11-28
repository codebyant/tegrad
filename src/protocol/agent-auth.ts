// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import {
  canonicalize,
  fingerprint,
  fromBase64Url,
  type PublicKey,
  randomBytes,
  type SigningKeyPair,
  sha256,
  sign,
  toBase64Url,
  verify,
} from "../crypto";
import { concatBytes, DOMAIN_AGENT_AUTH, DOMAIN_AGENT_HTTP, PROTOCOL_VERSION } from "./domains";
import { ProtocolError } from "./errors";
import {
  AGENT_NONCE_BYTES,
  agentNonceSchema,
  type KeyId,
  keyIdSchema,
  type TransportFrame,
  transportAuthFrameSchema,
  transportHelloFrameSchema,
} from "./schemas";

export const AGENT_AUTH_MAX_SKEW_MS = 60_000;
export const AGENT_HTTP_MAX_SKEW_MS = 60_000;

export const AGENT_HTTP_HEADER_AGENT = "X-Tegra-Agent";
export const AGENT_HTTP_HEADER_TS = "X-Tegra-Ts";
export const AGENT_HTTP_HEADER_SIG = "X-Tegra-Sig";

export type HelloFrame = Extract<TransportFrame, { kind: "hello" }>;
export type AuthFrame = Extract<TransportFrame, { kind: "auth" }>;

const utf8Encoder = new TextEncoder();

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, "0");
  }
  return out;
}

/** Fresh nonce for a `hello` frame. */
export function generateAgentNonce(): string {
  return toBase64Url(randomBytes(AGENT_NONCE_BYTES));
}

export function createHelloFrame(params: {
  readonly agent: KeyId;
  readonly serverTime: number;
  readonly nonce?: string;
}): HelloFrame {
  return transportHelloFrameSchema.parse({
    v: PROTOCOL_VERSION,
    kind: "hello",
    route: { agent: params.agent },
    body: { nonce: params.nonce ?? generateAgentNonce(), server_time: params.serverTime },
  });
}

function authSigningInput(agent: KeyId, nonce: string, ts: number): Uint8Array {
  return concatBytes(DOMAIN_AGENT_AUTH, canonicalize({ agent, nonce, ts }));
}

/** Agent side: answers the API's `hello` challenge. */
export function signAgentAuth(params: {
  readonly agentKeyPair: SigningKeyPair;
  readonly hello: unknown;
  readonly ts: number;
}): AuthFrame {
  const parsed = transportHelloFrameSchema.safeParse(params.hello);
  if (!parsed.success) {
    throw new ProtocolError("invalid_format", "Malformed hello frame");
  }
  const agent = fingerprint(params.agentKeyPair.publicKey);
  if (parsed.data.route.agent !== agent) {
    throw new ProtocolError("wrong_agent", "Hello frame is addressed to a different agent");
  }
  const nonce = parsed.data.body.nonce;
  const signature = sign(authSigningInput(agent, nonce, params.ts), params.agentKeyPair.secretKey);
  return transportAuthFrameSchema.parse({
    v: PROTOCOL_VERSION,
    kind: "auth",
    route: { agent },
    body: { nonce, ts: params.ts, sig: toBase64Url(signature) },
  });
}

export interface VerifyAgentAuthOptions {
  readonly agentPublicKey: PublicKey;
  /** The nonce the API sent in `hello` for this connection. */
  readonly expectedNonce: string;
  readonly now: number;
  readonly maxSkewMs?: number;
  /** Nonces already accepted; a repeated nonce is refused and a new one is recorded. */
  readonly usedNonces?: Set<string>;
}

/** API side: checks an `auth` frame against the challenge that was issued. */
export function verifyAgentAuth(frame: unknown, options: VerifyAgentAuthOptions): AuthFrame {
  const parsed = transportAuthFrameSchema.safeParse(frame);
  if (!parsed.success) {
    throw new ProtocolError("invalid_format", "Malformed auth frame");
  }
  const { route, body } = parsed.data;
  const agent = fingerprint(options.agentPublicKey);
  if (route.agent !== agent) {
    throw new ProtocolError("wrong_agent", "Auth frame is addressed to a different agent");
  }
  if (!agentNonceSchema.safeParse(options.expectedNonce).success) {
    throw new ProtocolError("auth_invalid", "Invalid challenge nonce");
  }
  if (body.nonce !== options.expectedNonce) {
    throw new ProtocolError("auth_invalid", "Auth nonce does not match the challenge");
  }
  if (options.usedNonces?.has(body.nonce)) {
    throw new ProtocolError("replayed", "Auth nonce was already used");
  }
  const maxSkew = options.maxSkewMs ?? AGENT_AUTH_MAX_SKEW_MS;
  if (Math.abs(options.now - body.ts) > maxSkew) {
    throw new ProtocolError("auth_invalid", "Auth timestamp is outside the allowed window");
  }

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = fromBase64Url(body.sig);
  } catch {
    throw new ProtocolError("bad_signature", "Invalid auth signature encoding");
  }
  if (
    !verify(authSigningInput(agent, body.nonce, body.ts), signatureBytes, options.agentPublicKey)
  ) {
    throw new ProtocolError("bad_signature", "Invalid auth signature");
  }

  options.usedNonces?.add(body.nonce);
  return parsed.data;
}

export type AgentRequestBody = Uint8Array | string | null | undefined;

function bodyBytes(body: AgentRequestBody): Uint8Array {
  if (body === null || body === undefined) {
    return new Uint8Array(0);
  }
  return typeof body === "string" ? utf8Encoder.encode(body) : body;
}

function httpSigningInput(
  method: string,
  pathWithQuery: string,
  body: AgentRequestBody,
  ts: number,
): Uint8Array {
  const bodyHash = toHex(sha256(bodyBytes(body)));
  return concatBytes(
    DOMAIN_AGENT_HTTP,
    utf8Encoder.encode(`${method.toUpperCase()}\n${pathWithQuery}\n${bodyHash}\n${ts}`),
  );
}

export interface SignAgentRequestParams {
  readonly agentKeyPair: SigningKeyPair;
  readonly method: string;
  /** Request path including the query string, exactly as sent on the wire. */
  readonly pathWithQuery: string;
  readonly body?: AgentRequestBody;
  readonly ts: number;
}

/** Returns the `X-Tegra-Agent`, `X-Tegra-Ts` and `X-Tegra-Sig` headers. */
export function signAgentRequest(params: SignAgentRequestParams): Record<string, string> {
  if (!params.pathWithQuery.startsWith("/")) {
    throw new RangeError("pathWithQuery must start with /");
  }
  const signature = sign(
    httpSigningInput(params.method, params.pathWithQuery, params.body, params.ts),
    params.agentKeyPair.secretKey,
  );
  return {
    [AGENT_HTTP_HEADER_AGENT]: fingerprint(params.agentKeyPair.publicKey),
    [AGENT_HTTP_HEADER_TS]: String(params.ts),
    [AGENT_HTTP_HEADER_SIG]: toBase64Url(signature),
  };
}

export interface VerifyAgentRequestParams {
  /** Case-insensitive header lookup (e.g. `(name) => request.headers.get(name)`). */
  readonly getHeader: (name: string) => string | null | undefined;
  readonly method: string;
  readonly pathWithQuery: string;
  readonly body?: AgentRequestBody;
  readonly agentPublicKey: PublicKey;
  readonly now: number;
  readonly maxSkewMs?: number;
}

export function verifyAgentRequest(params: VerifyAgentRequestParams): { readonly agent: KeyId } {
  const agentHeader = params.getHeader(AGENT_HTTP_HEADER_AGENT);
  const tsHeader = params.getHeader(AGENT_HTTP_HEADER_TS);
  const sigHeader = params.getHeader(AGENT_HTTP_HEADER_SIG);
  if (!agentHeader || !tsHeader || !sigHeader) {
    throw new ProtocolError("request_invalid", "Missing agent signature headers");
  }
  const agent = keyIdSchema.safeParse(agentHeader);
  if (!agent.success || agent.data !== fingerprint(params.agentPublicKey)) {
    throw new ProtocolError("wrong_agent", "Request signed by a different agent");
  }
  if (!/^\d{1,16}$/.test(tsHeader)) {
    throw new ProtocolError("request_invalid", "Invalid request timestamp");
  }
  const ts = Number(tsHeader);
  const maxSkew = params.maxSkewMs ?? AGENT_HTTP_MAX_SKEW_MS;
  if (ts < params.now - maxSkew) {
    throw new ProtocolError("expired", "Request timestamp is too old");
  }
  if (ts > params.now + maxSkew) {
    throw new ProtocolError("not_yet_valid", "Request timestamp is in the future");
  }

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = fromBase64Url(sigHeader);
  } catch {
    throw new ProtocolError("bad_signature", "Invalid request signature encoding");
  }
  const input = httpSigningInput(params.method, params.pathWithQuery, params.body, ts);
  if (!verify(input, signatureBytes, params.agentPublicKey)) {
    throw new ProtocolError("bad_signature", "Invalid request signature");
  }
  return { agent: agent.data };
}
