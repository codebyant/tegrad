// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

export type ProtocolErrorCode =
  | "invalid_format"
  | "unsupported_version"
  | "wrong_agent"
  | "wrong_recipient"
  | "expired"
  | "not_yet_valid"
  | "ttl_too_long"
  | "untrusted_signer"
  | "bad_signature"
  | "session_invalid"
  | "session_revoked"
  | "replayed"
  | "unknown_command"
  | "invalid_body"
  | "sensitive_requires_account_key"
  | "decrypt_failed";

export class ProtocolError extends Error {
  readonly code: ProtocolErrorCode;

  constructor(code: ProtocolErrorCode, message: string) {
    super(message);
    this.name = "ProtocolError";
    this.code = code;
  }
}
