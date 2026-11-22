// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import {
  aeadDecrypt,
  aeadEncrypt,
  assertKdfParams,
  deriveKeyFromPassword,
  fingerprint,
  generateSalt,
  generateSigningKeyPair,
  KDF_MODERATE,
  type KdfPreset,
  memzero,
  type PublicKey,
  SIGNING_SECRET_KEY_BYTES,
  SIGNING_SEED_BYTES,
  type SigningKeyPair,
  signingKeyPairFromSeed,
  toBase64Url,
} from "../crypto";
import type { KeyId } from "../protocol";
import {
  buildPasswordAad,
  buildRecoveryAad,
  parseVaultBlob,
  VAULT_VERSION,
  type VaultBlob,
  type VaultKdf,
} from "./blob";
import { VaultError } from "./errors";
import { validatePassword } from "./password";
import {
  deriveRecoveryKey,
  formatRecoveryCode,
  generateRecoveryCodeBytes,
  parseRecoveryCode,
} from "./recovery-code";

export interface UnlockedVault {
  readonly account: KeyId;
  readonly publicKey: PublicKey;
  readonly keyPair: SigningKeyPair;
  lock(): void;
}

export interface CreateVaultParams {
  readonly password: string;
  readonly now?: number;
  readonly kdf?: KdfPreset;
  readonly userInputs?: readonly string[];
}

export interface CreateVaultResult {
  readonly blob: VaultBlob;
  readonly recoveryCode: string;
  readonly unlocked: UnlockedVault;
}

export interface ChangePasswordOptions {
  readonly now?: number;
  readonly kdf?: KdfPreset;
  readonly userInputs?: readonly string[];
}

export interface RotateRecoveryCodeResult {
  readonly blob: VaultBlob;
  readonly recoveryCode: string;
}

class UnlockedVaultHandle implements UnlockedVault {
  readonly #account: KeyId;
  readonly #keyPair: SigningKeyPair;
  #locked = false;

  constructor(account: KeyId, keyPair: SigningKeyPair) {
    this.#account = account;
    this.#keyPair = keyPair;
  }

  #assertOpen(): void {
    if (this.#locked) {
      throw new VaultError("locked", "Vault is locked");
    }
  }

  get account(): KeyId {
    this.#assertOpen();
    return this.#account;
  }

  get publicKey(): PublicKey {
    this.#assertOpen();
    return this.#keyPair.publicKey;
  }

  get keyPair(): SigningKeyPair {
    this.#assertOpen();
    return this.#keyPair;
  }

  lock(): void {
    if (this.#locked) return;
    memzero(this.#keyPair.secretKey);
    this.#locked = true;
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

function assertValidTimestamp(now: number): void {
  if (!Number.isSafeInteger(now) || now < 0) {
    throw new RangeError("Timestamp must be a non-negative safe integer");
  }
}

function assertValidPassword(password: string, userInputs?: readonly string[]): void {
  const result = validatePassword(password, userInputs !== undefined ? { userInputs } : undefined);
  if (!result.ok) {
    throw new VaultError("weak_password", "Password does not meet strength requirements");
  }
}

function wrapWithPassword(
  secretKey: Uint8Array,
  password: string,
  meta: { readonly v: typeof VAULT_VERSION; readonly account: KeyId; readonly public_key: string },
  preset: KdfPreset,
): { readonly kdf: VaultKdf; readonly wrapped_secret: string } {
  const salt = generateSalt();
  const kdfParams = {
    alg: preset.alg,
    opslimit: preset.opslimit,
    memlimit: preset.memlimit,
    salt,
  };
  assertKdfParams(kdfParams);

  const kdf: VaultKdf = {
    alg: kdfParams.alg,
    opslimit: kdfParams.opslimit,
    memlimit: kdfParams.memlimit,
    salt: toBase64Url(salt),
  };

  const aad = buildPasswordAad({
    v: meta.v,
    account: meta.account,
    public_key: meta.public_key,
    kdf,
  });

  const derivedKey = deriveKeyFromPassword(password, kdfParams);
  try {
    const wrapped = aeadEncrypt(secretKey, derivedKey, aad);
    return {
      kdf,
      wrapped_secret: toBase64Url(wrapped),
    };
  } finally {
    memzero(derivedKey);
  }
}

function wrapWithRecovery(
  secretKey: Uint8Array,
  meta: { readonly v: typeof VAULT_VERSION; readonly account: KeyId; readonly public_key: string },
): { readonly wrapped_secret: string; readonly recoveryCode: string } {
  const codeBytes = generateRecoveryCodeBytes();
  try {
    const recoveryCode = formatRecoveryCode(codeBytes);
    const recoveryKey = deriveRecoveryKey(codeBytes);
    try {
      const aad = buildRecoveryAad(meta);
      const wrapped = aeadEncrypt(secretKey, recoveryKey, aad);
      return {
        wrapped_secret: toBase64Url(wrapped),
        recoveryCode,
      };
    } finally {
      memzero(recoveryKey);
    }
  } finally {
    memzero(codeBytes);
  }
}

function verifyDecryptedSecretKey(
  rawSecretKey: Uint8Array,
  expectedPublicKey: Uint8Array,
  expectedAccount: KeyId,
): UnlockedVault {
  if (rawSecretKey.length !== SIGNING_SECRET_KEY_BYTES) {
    memzero(rawSecretKey);
    throw new VaultError("invalid_blob", "Decrypted key has invalid length");
  }

  const seed = rawSecretKey.slice(0, SIGNING_SEED_BYTES);
  let derived: SigningKeyPair;
  try {
    derived = signingKeyPairFromSeed(seed);
  } finally {
    memzero(seed);
  }

  const valid =
    bytesEqual(derived.publicKey, expectedPublicKey) &&
    bytesEqual(derived.secretKey, rawSecretKey) &&
    fingerprint(derived.publicKey) === expectedAccount;

  memzero(rawSecretKey);

  if (!valid) {
    memzero(derived.secretKey);
    throw new VaultError("invalid_blob", "Decrypted key does not match vault metadata");
  }

  return new UnlockedVaultHandle(expectedAccount, derived);
}

export function createVault(params: CreateVaultParams): CreateVaultResult {
  const now = params.now ?? Date.now();
  assertValidTimestamp(now);
  assertValidPassword(params.password, params.userInputs);

  const keyPair = generateSigningKeyPair();
  const account = fingerprint(keyPair.publicKey);
  const publicKeyB64 = toBase64Url(keyPair.publicKey);
  const meta = {
    v: VAULT_VERSION,
    account,
    public_key: publicKeyB64,
  };

  try {
    const passwordSection = wrapWithPassword(
      keyPair.secretKey,
      params.password,
      meta,
      params.kdf ?? KDF_MODERATE,
    );
    const { wrapped_secret: recoveryWrappedSecret, recoveryCode } = wrapWithRecovery(
      keyPair.secretKey,
      meta,
    );

    const blob: VaultBlob = {
      v: VAULT_VERSION,
      account,
      public_key: publicKeyB64,
      created_at: now,
      password: passwordSection,
      recovery: {
        wrapped_secret: recoveryWrappedSecret,
      },
    };

    const unlocked = new UnlockedVaultHandle(account, keyPair);
    return { blob, recoveryCode, unlocked };
  } catch (err) {
    memzero(keyPair.secretKey);
    throw err;
  }
}

export function unlockVault(blob: unknown, password: string): UnlockedVault {
  const parsed = parseVaultBlob(blob);
  const aad = buildPasswordAad({
    v: parsed.blob.v,
    account: parsed.blob.account,
    public_key: parsed.blob.public_key,
    kdf: parsed.blob.password.kdf,
  });

  const derivedKey = deriveKeyFromPassword(password, parsed.kdfParams);
  let rawSecretKey: Uint8Array;
  try {
    rawSecretKey = aeadDecrypt(parsed.passwordWrapped, derivedKey, aad);
  } catch {
    throw new VaultError("unlock_failed", "Failed to unlock vault");
  } finally {
    memzero(derivedKey);
  }

  return verifyDecryptedSecretKey(rawSecretKey, parsed.publicKeyBytes, parsed.blob.account);
}

export function unlockVaultWithRecovery(blob: unknown, recoveryCode: string): UnlockedVault {
  const parsed = parseVaultBlob(blob);
  const codeBytes = parseRecoveryCode(recoveryCode);

  let recoveryKey: Uint8Array;
  try {
    recoveryKey = deriveRecoveryKey(codeBytes);
  } finally {
    memzero(codeBytes);
  }

  const aad = buildRecoveryAad({
    v: parsed.blob.v,
    account: parsed.blob.account,
    public_key: parsed.blob.public_key,
  });

  let rawSecretKey: Uint8Array;
  try {
    rawSecretKey = aeadDecrypt(parsed.recoveryWrapped, recoveryKey, aad);
  } catch {
    throw new VaultError("unlock_failed", "Failed to unlock vault with recovery code");
  } finally {
    memzero(recoveryKey);
  }

  return verifyDecryptedSecretKey(rawSecretKey, parsed.publicKeyBytes, parsed.blob.account);
}

export async function withUnlockedVault<T>(
  blob: unknown,
  password: string,
  fn: (unlocked: UnlockedVault) => T | Promise<T>,
): Promise<T> {
  const unlocked = unlockVault(blob, password);
  try {
    return await fn(unlocked);
  } finally {
    unlocked.lock();
  }
}

export function changePassword(
  blob: unknown,
  oldPassword: string,
  newPassword: string,
  options?: ChangePasswordOptions,
): VaultBlob {
  if (options?.now !== undefined) {
    assertValidTimestamp(options.now);
  }
  assertValidPassword(newPassword, options?.userInputs);

  const parsed = parseVaultBlob(blob);
  const unlocked = unlockVault(parsed.blob, oldPassword);
  try {
    const passwordSection = wrapWithPassword(
      unlocked.keyPair.secretKey,
      newPassword,
      {
        v: parsed.blob.v,
        account: parsed.blob.account,
        public_key: parsed.blob.public_key,
      },
      options?.kdf ?? KDF_MODERATE,
    );

    return {
      v: parsed.blob.v,
      account: parsed.blob.account,
      public_key: parsed.blob.public_key,
      created_at: parsed.blob.created_at,
      password: passwordSection,
      recovery: {
        wrapped_secret: parsed.blob.recovery.wrapped_secret,
      },
    };
  } finally {
    unlocked.lock();
  }
}

export function rotateRecoveryCode(blob: unknown, password: string): RotateRecoveryCodeResult {
  const parsed = parseVaultBlob(blob);
  const unlocked = unlockVault(parsed.blob, password);
  try {
    const { wrapped_secret, recoveryCode } = wrapWithRecovery(unlocked.keyPair.secretKey, {
      v: parsed.blob.v,
      account: parsed.blob.account,
      public_key: parsed.blob.public_key,
    });

    const nextBlob: VaultBlob = {
      v: parsed.blob.v,
      account: parsed.blob.account,
      public_key: parsed.blob.public_key,
      created_at: parsed.blob.created_at,
      password: {
        kdf: { ...parsed.blob.password.kdf },
        wrapped_secret: parsed.blob.password.wrapped_secret,
      },
      recovery: {
        wrapped_secret,
      },
    };

    return { blob: nextBlob, recoveryCode };
  } finally {
    unlocked.lock();
  }
}

export function resetPasswordWithRecovery(
  blob: unknown,
  recoveryCode: string,
  newPassword: string,
  options?: ChangePasswordOptions,
): VaultBlob {
  if (options?.now !== undefined) {
    assertValidTimestamp(options.now);
  }
  assertValidPassword(newPassword, options?.userInputs);

  const parsed = parseVaultBlob(blob);
  const unlocked = unlockVaultWithRecovery(parsed.blob, recoveryCode);
  try {
    const passwordSection = wrapWithPassword(
      unlocked.keyPair.secretKey,
      newPassword,
      {
        v: parsed.blob.v,
        account: parsed.blob.account,
        public_key: parsed.blob.public_key,
      },
      options?.kdf ?? KDF_MODERATE,
    );

    return {
      v: parsed.blob.v,
      account: parsed.blob.account,
      public_key: parsed.blob.public_key,
      created_at: parsed.blob.created_at,
      password: passwordSection,
      recovery: {
        wrapped_secret: parsed.blob.recovery.wrapped_secret,
      },
    };
  } finally {
    unlocked.lock();
  }
}
