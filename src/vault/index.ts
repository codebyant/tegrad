// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

export {
  buildPasswordAad,
  buildRecoveryAad,
  type ParsedVaultBlob,
  parseVaultBlob,
  VAULT_VERSION,
  type VaultBlob,
  type VaultKdf,
  vaultBlobSchema,
  vaultKdfSchema,
} from "./blob";
export { type CounterStore, createMemoryCounterStore } from "./counter";
export { VaultError, type VaultErrorCode } from "./errors";
export {
  MIN_PASSWORD_LENGTH,
  MIN_PASSWORD_SCORE,
  type PasswordValidationResult,
  type ValidatePasswordOptions,
  validatePassword,
} from "./password";
export {
  deriveRecoveryKey,
  formatRecoveryCode,
  generateRecoveryCodeBytes,
  parseRecoveryCode,
  RECOVERY_CODE_BYTES,
} from "./recovery-code";
export {
  createCommandFromSession,
  createSensitiveCommand,
  type IssueSessionOptions,
  isSessionExpired,
  issueSession,
  parseSession,
  SESSION_DURATION_MS,
  type Session,
  type SessionDuration,
  type SignRevocationParams,
  serializeSession,
  sessionExpiresAt,
  signRevocation,
  type VaultCommandParams,
} from "./session";
export {
  type ChangePasswordOptions,
  type CreateVaultParams,
  type CreateVaultResult,
  changePassword,
  createVault,
  type RotateRecoveryCodeResult,
  resetPasswordWithRecovery,
  rotateRecoveryCode,
  type UnlockedVault,
  unlockVault,
  unlockVaultWithRecovery,
  withUnlockedVault,
} from "./vault";
