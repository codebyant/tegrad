// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

export type VaultErrorCode =
  | "weak_password"
  | "wrong_password"
  | "unlock_failed"
  | "invalid_blob"
  | "invalid_recovery_code"
  | "locked"
  | "invalid_session";

export class VaultError extends Error {
  readonly code: VaultErrorCode;

  constructor(code: VaultErrorCode, message: string) {
    super(message);
    this.name = "VaultError";
    this.code = code;
  }
}
