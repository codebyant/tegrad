// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { getSodium } from "./sodium";

export const SYMMETRIC_KEY_BYTES = 32;
export const AEAD_NONCE_BYTES = 24;
export const AEAD_TAG_BYTES = 16;

export function generateSymmetricKey(): Uint8Array {
  return getSodium().randombytes_buf(SYMMETRIC_KEY_BYTES);
}

export function aeadEncrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  associatedData?: Uint8Array,
): Uint8Array {
  const s = getSodium();
  if (key.length !== SYMMETRIC_KEY_BYTES) {
    throw new RangeError(`Symmetric key must be ${SYMMETRIC_KEY_BYTES} bytes`);
  }
  const nonce = s.randombytes_buf(AEAD_NONCE_BYTES);
  const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    associatedData ?? null,
    null,
    nonce,
    key,
  );
  const out = new Uint8Array(AEAD_NONCE_BYTES + ciphertext.length);
  out.set(nonce, 0);
  out.set(ciphertext, AEAD_NONCE_BYTES);
  return out;
}

export function aeadDecrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  associatedData?: Uint8Array,
): Uint8Array {
  const s = getSodium();
  if (key.length !== SYMMETRIC_KEY_BYTES) {
    throw new RangeError(`Symmetric key must be ${SYMMETRIC_KEY_BYTES} bytes`);
  }
  if (ciphertext.length < AEAD_NONCE_BYTES + AEAD_TAG_BYTES) {
    throw new Error("Ciphertext is too short");
  }
  const nonce = ciphertext.subarray(0, AEAD_NONCE_BYTES);
  const body = ciphertext.subarray(AEAD_NONCE_BYTES);
  return s.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    body,
    associatedData ?? null,
    nonce,
    key,
  );
}
