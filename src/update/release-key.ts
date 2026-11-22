// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { fromBase64Url, type PublicKey, SIGNING_PUBLIC_KEY_BYTES } from "../crypto";
import { UpdateError } from "./errors";

// TODO(release-key): replace placeholder test public key with production offline Ed25519 release signing public key before first public release.
export const RELEASE_PUBLIC_KEY_BASE64URL = "IVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI";

/**
 * Fixed 12-byte ASN.1 DER SubjectPublicKeyInfo prefix for Ed25519 (OID 1.3.101.112).
 * Followed directly by the 32-byte raw Ed25519 public key.
 */
const ED25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

export function getReleasePublicKey(): PublicKey {
  const key = fromBase64Url(RELEASE_PUBLIC_KEY_BASE64URL);
  if (key.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new UpdateError(
      "bad_manifest_signature",
      `Embedded release public key must be ${SIGNING_PUBLIC_KEY_BYTES} bytes`,
    );
  }
  return key;
}

export function ed25519PublicKeyToPem(publicKey: PublicKey): string {
  if (publicKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new RangeError(`Ed25519 public key must be ${SIGNING_PUBLIC_KEY_BYTES} bytes`);
  }
  const der = new Uint8Array(ED25519_SPKI_PREFIX.length + publicKey.length);
  der.set(ED25519_SPKI_PREFIX, 0);
  der.set(publicKey, ED25519_SPKI_PREFIX.length);
  const b64 = Buffer.from(der).toString("base64");
  return `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----\n`;
}

export function ed25519PublicKeyFromPem(pem: string): PublicKey {
  const stripped = pem
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");
  const der = new Uint8Array(Buffer.from(stripped, "base64"));
  if (der.length !== ED25519_SPKI_PREFIX.length + SIGNING_PUBLIC_KEY_BYTES) {
    throw new UpdateError("bad_manifest_signature", "Invalid Ed25519 SPKI PEM length");
  }
  for (let i = 0; i < ED25519_SPKI_PREFIX.length; i++) {
    if (der[i] !== ED25519_SPKI_PREFIX[i]) {
      throw new UpdateError("bad_manifest_signature", "Invalid Ed25519 SPKI DER header");
    }
  }
  return der.subarray(ED25519_SPKI_PREFIX.length);
}
