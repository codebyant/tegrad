// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import {
  type PublicKey,
  SIGNING_PUBLIC_KEY_BYTES,
  SIGNING_SECRET_KEY_BYTES,
  type SigningKeyPair,
} from "./signing";
import { getSodium } from "./sodium";

export function sealTo(plaintext: Uint8Array, recipientSigningPublicKey: PublicKey): Uint8Array {
  const s = getSodium();
  if (recipientSigningPublicKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new RangeError(`Recipient public key must be ${SIGNING_PUBLIC_KEY_BYTES} bytes`);
  }
  const curvePk = s.crypto_sign_ed25519_pk_to_curve25519(recipientSigningPublicKey);
  return s.crypto_box_seal(plaintext, curvePk);
}

export function openSealed(
  ciphertext: Uint8Array,
  recipientSigningKeyPair: SigningKeyPair,
): Uint8Array {
  const s = getSodium();
  if (
    recipientSigningKeyPair.publicKey.length !== SIGNING_PUBLIC_KEY_BYTES ||
    recipientSigningKeyPair.secretKey.length !== SIGNING_SECRET_KEY_BYTES
  ) {
    throw new RangeError("Invalid recipient signing key pair length");
  }
  const curvePk = s.crypto_sign_ed25519_pk_to_curve25519(recipientSigningKeyPair.publicKey);
  const curveSk = s.crypto_sign_ed25519_sk_to_curve25519(recipientSigningKeyPair.secretKey);
  try {
    return s.crypto_box_seal_open(ciphertext, curvePk, curveSk);
  } finally {
    s.memzero(curveSk);
  }
}
