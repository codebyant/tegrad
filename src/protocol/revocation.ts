// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import {
  canonicalize,
  fingerprint,
  fromBase64Url,
  type PublicKey,
  type SigningKeyPair,
  sign,
  toBase64Url,
  verify,
} from "../crypto";
import {
  assertSupportedVersion,
  concatBytes,
  DOMAIN_REVOCATION,
  PROTOCOL_VERSION,
} from "./domains";
import { ProtocolError } from "./errors";
import { type RevocationList, revocationListSchema } from "./schemas";

export interface SignRevocationListParams {
  readonly accountKeyPair: SigningKeyPair;
  readonly issuedAt: number;
  readonly revoked: readonly string[];
}

export function signRevocationList(params: SignRevocationListParams): RevocationList {
  if (!Number.isSafeInteger(params.issuedAt) || params.issuedAt < 0) {
    throw new RangeError("issuedAt must be a non-negative safe integer");
  }

  const unsigned = {
    v: PROTOCOL_VERSION,
    account: fingerprint(params.accountKeyPair.publicKey),
    issued_at: params.issuedAt,
    revoked: [...params.revoked],
  };

  const signingInput = concatBytes(DOMAIN_REVOCATION, canonicalize(unsigned));
  const signature = sign(signingInput, params.accountKeyPair.secretKey);

  return {
    ...unsigned,
    sig: toBase64Url(signature),
  };
}

export function verifyRevocationList(list: unknown, accountPublicKey: PublicKey): RevocationList {
  assertSupportedVersion(list);

  const parsed = revocationListSchema.safeParse(list);
  if (!parsed.success) {
    throw new ProtocolError("invalid_format", "Malformed revocation list");
  }

  const data = parsed.data;
  if (data.account !== fingerprint(accountPublicKey)) {
    throw new ProtocolError("untrusted_signer", "Revocation list account mismatch");
  }

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = fromBase64Url(data.sig);
  } catch {
    throw new ProtocolError("bad_signature", "Invalid revocation list signature encoding");
  }

  const { sig: _sig, ...unsigned } = data;
  const signingInput = concatBytes(DOMAIN_REVOCATION, canonicalize(unsigned));
  if (!verify(signingInput, signatureBytes, accountPublicKey)) {
    throw new ProtocolError("bad_signature", "Invalid revocation list signature");
  }

  return data;
}
