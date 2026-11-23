// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

export type UpdateErrorCode =
  | "invalid_version"
  | "invalid_manifest"
  | "bad_manifest_signature"
  | "bad_sums_signature"
  | "placeholder_release_key"
  | "channel_mismatch"
  | "unsupported_arch"
  | "invalid_url"
  | "host_not_allowed"
  | "download_failed"
  | "size_mismatch"
  | "size_limit_exceeded"
  | "hash_mismatch"
  | "checksum_not_found"
  | "downgrade_blocked"
  | "unsafe_path"
  | "apply_failed"
  | "health_check_failed"
  | "rollback_failed";

export class UpdateError extends Error {
  readonly code: UpdateErrorCode;

  constructor(code: UpdateErrorCode, message: string) {
    super(message);
    this.name = "UpdateError";
    this.code = code;
  }
}
