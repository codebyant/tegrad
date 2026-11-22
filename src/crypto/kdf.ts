// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { getSodium } from "./sodium";

export const KDF_ALG_ARGON2ID13 = "argon2id13" as const;
export const KDF_SALT_BYTES = 16;
export const KDF_KEY_BYTES = 32;

export interface KdfPreset {
  readonly alg: typeof KDF_ALG_ARGON2ID13;
  readonly opslimit: number;
  readonly memlimit: number;
}

export interface KdfParams extends KdfPreset {
  readonly salt: Uint8Array;
}

export const KDF_FLOOR: KdfPreset = {
  alg: KDF_ALG_ARGON2ID13,
  opslimit: 3,
  memlimit: 128 * 1024 * 1024,
};

export const KDF_MODERATE: KdfPreset = {
  alg: KDF_ALG_ARGON2ID13,
  opslimit: 3,
  memlimit: 256 * 1024 * 1024,
};

const utf8Encoder = new TextEncoder();

export function generateSalt(): Uint8Array {
  return getSodium().randombytes_buf(KDF_SALT_BYTES);
}

export function assertKdfParams(params: unknown): asserts params is KdfParams {
  if (typeof params !== "object" || params === null) {
    throw new Error("KDF parameters must be an object");
  }

  const record = params as Record<string, unknown>;

  if (record.alg !== KDF_ALG_ARGON2ID13) {
    throw new Error(`Unsupported KDF algorithm: expected ${KDF_ALG_ARGON2ID13}`);
  }

  if (
    typeof record.opslimit !== "number" ||
    !Number.isSafeInteger(record.opslimit) ||
    record.opslimit < KDF_FLOOR.opslimit
  ) {
    throw new Error(`KDF opslimit must be an integer >= ${KDF_FLOOR.opslimit}`);
  }

  if (
    typeof record.memlimit !== "number" ||
    !Number.isSafeInteger(record.memlimit) ||
    record.memlimit < KDF_FLOOR.memlimit
  ) {
    throw new Error(`KDF memlimit must be an integer >= ${KDF_FLOOR.memlimit}`);
  }

  if (!(record.salt instanceof Uint8Array) || record.salt.length !== KDF_SALT_BYTES) {
    throw new Error(`KDF salt must be a Uint8Array of ${KDF_SALT_BYTES} bytes`);
  }
}

export function deriveKeyFromPassword(
  password: string | Uint8Array,
  params: KdfParams,
  keyLength: number = KDF_KEY_BYTES,
): Uint8Array {
  const s = getSodium();
  assertKdfParams(params);
  if (!Number.isSafeInteger(keyLength) || keyLength < 16) {
    throw new RangeError("Derived key length must be an integer >= 16");
  }

  const isString = typeof password === "string";
  const pwBytes = isString ? utf8Encoder.encode(password) : password;
  try {
    return s.crypto_pwhash(
      keyLength,
      pwBytes,
      params.salt,
      params.opslimit,
      params.memlimit,
      s.crypto_pwhash_ALG_ARGON2ID13,
    );
  } finally {
    if (isString) {
      s.memzero(pwBytes);
    }
  }
}
