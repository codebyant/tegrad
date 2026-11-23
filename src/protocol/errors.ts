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
  | "decrypt_failed"
  | "insufficient_role"
  | "too_many_subscribers"
  | "role_grant_invalid"
  | "auth_invalid"
  | "request_invalid"
  | "grant_invalid"
  | "grant_wrong_agent"
  | "grant_expired"
  | "grant_bad_signature"
  | "grant_proof_required"
  | "grant_bad_proof"
  | "revocation_stale"
  | "revocation_not_superset"
  | "insufficient_memory"
  | "eula_not_accepted"
  | "server_not_found"
  | "server_already_exists"
  | "server_running"
  | "server_stopped"
  | "invalid_jvm_args"
  | "download_failed"
  | "hash_mismatch"
  | "systemd_error"
  | "perms_unavailable"
  | "origin_locked"
  | "plan_not_found"
  | "plan_expired"
  | "plan_stale"
  | "mod_not_found"
  | "mod_already_exists"
  | "backup_not_found"
  | "backup_failed"
  | "backup_config_invalid"
  | "tunnel_not_configured"
  | "tunnel_already_running"
  | "tunnel_not_running"
  | "tunnel_failed";

export class ProtocolError extends Error {
  readonly code: ProtocolErrorCode;

  constructor(code: ProtocolErrorCode, message: string) {
    super(message);
    this.name = "ProtocolError";
    this.code = code;
  }
}
