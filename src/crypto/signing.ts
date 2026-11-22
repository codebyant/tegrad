// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { toBase32 } from "./encoding";
import { getSodium } from "./sodium";

export const SIGNING_PUBLIC_KEY_BYTES = 32;
export const SIGNING_SECRET_KEY_BYTES = 64;
export const SIGNING_SEED_BYTES = 32;
export const SIGNATURE_BYTES = 64;
export const FINGERPRINT_HASH_BYTES = 32;
export const FINGERPRINT_TRUNCATED_BYTES = 20;

export type PublicKey = Uint8Array;
export type SecretKey = Uint8Array;

export interface SigningKeyPair {
  readonly publicKey: PublicKey;
  readonly secretKey: SecretKey;
}

export function generateSigningKeyPair(): SigningKeyPair {
  const s = getSodium();
  const kp = s.crypto_sign_keypair();
  return {
    publicKey: kp.publicKey,
    secretKey: kp.privateKey,
  };
}

export function signingKeyPairFromSeed(seed: Uint8Array): SigningKeyPair {
  const s = getSodium();
  if (seed.length !== SIGNING_SEED_BYTES) {
    throw new RangeError(`Signing seed must be ${SIGNING_SEED_BYTES} bytes`);
  }
  const kp = s.crypto_sign_seed_keypair(seed);
  return {
    publicKey: kp.publicKey,
    secretKey: kp.privateKey,
  };
}

export function sign(message: Uint8Array, secretKey: SecretKey): Uint8Array {
  const s = getSodium();
  if (secretKey.length !== SIGNING_SECRET_KEY_BYTES) {
    throw new RangeError(`Signing secret key must be ${SIGNING_SECRET_KEY_BYTES} bytes`);
  }
  return s.crypto_sign_detached(message, secretKey);
}

export function verify(message: Uint8Array, signature: Uint8Array, publicKey: PublicKey): boolean {
  const s = getSodium();
  if (signature.length !== SIGNATURE_BYTES || publicKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
    return false;
  }
  try {
    return s.crypto_sign_verify_detached(signature, message, publicKey);
  } catch {
    return false;
  }
}

export function fingerprint(publicKey: PublicKey): string {
  const s = getSodium();
  if (publicKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new RangeError(`Public key must be ${SIGNING_PUBLIC_KEY_BYTES} bytes`);
  }
  const digest = s.crypto_generichash(FINGERPRINT_HASH_BYTES, publicKey, null);
  return toBase32(digest.subarray(0, FINGERPRINT_TRUNCATED_BYTES));
}
