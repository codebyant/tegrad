// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { ProtocolError } from "./errors";

export const PROTOCOL_VERSION = 1 as const;

const utf8Encoder = new TextEncoder();

export const DOMAIN_COMMAND = utf8Encoder.encode("tegrad/command/v1\0");
export const DOMAIN_SESSION = utf8Encoder.encode("tegrad/session/v1\0");
export const DOMAIN_AGENT_MESSAGE = utf8Encoder.encode("tegrad/agent-message/v1\0");
export const DOMAIN_REVOCATION = utf8Encoder.encode("tegrad/revocation/v1\0");
export const DOMAIN_TRUST_GRANT = utf8Encoder.encode("tegrad/trust-grant/v1\0");
export const DOMAIN_PAIRING_PROOF = utf8Encoder.encode("tegrad/pairing-proof/v1\0");

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) {
    total += part.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function assertSupportedVersion(value: unknown): void {
  if (typeof value === "object" && value !== null && "v" in value) {
    const version = (value as { v: unknown }).v;
    if (version !== PROTOCOL_VERSION) {
      throw new ProtocolError("unsupported_version", "Unsupported protocol version");
    }
  }
}
