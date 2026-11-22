// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import {
  canonicalize,
  fingerprint,
  fromBase64Url,
  type PublicKey,
  randomBytes,
  SIGNING_PUBLIC_KEY_BYTES,
  type SigningKeyPair,
  sign,
  toBase64Url,
  verify,
} from "../crypto";
import { assertSupportedVersion, concatBytes, DOMAIN_SESSION, PROTOCOL_VERSION } from "./domains";
import { ProtocolError } from "./errors";
import { type SessionCertificate, sessionCertificateSchema } from "./schemas";

export interface SignSessionCertificateParams {
  readonly sessionPublicKey: PublicKey;
  readonly accountKeyPair: SigningKeyPair;
  readonly notBefore: number;
  readonly notAfter: number;
  readonly id?: string;
}

export interface VerifiedSessionCertificate {
  readonly certificate: SessionCertificate;
  readonly sessionPublicKey: PublicKey;
}

export function signSessionCertificate(params: SignSessionCertificateParams): SessionCertificate {
  if (params.sessionPublicKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new RangeError(`Session public key must be ${SIGNING_PUBLIC_KEY_BYTES} bytes`);
  }
  if (!Number.isSafeInteger(params.notBefore) || !Number.isSafeInteger(params.notAfter)) {
    throw new RangeError("Session validity timestamps must be safe integers");
  }
  if (params.notBefore < 0 || params.notAfter <= params.notBefore) {
    throw new RangeError("Invalid session certificate validity window");
  }

  const unsigned = {
    v: PROTOCOL_VERSION,
    session_key: toBase64Url(params.sessionPublicKey),
    account: fingerprint(params.accountKeyPair.publicKey),
    not_before: params.notBefore,
    not_after: params.notAfter,
    id: params.id ?? toBase64Url(randomBytes(16)),
  };

  const signingInput = concatBytes(DOMAIN_SESSION, canonicalize(unsigned));
  const signature = sign(signingInput, params.accountKeyPair.secretKey);

  return {
    ...unsigned,
    sig: toBase64Url(signature),
  };
}

export function verifySessionCertificate(
  certificate: unknown,
  accountPublicKey: PublicKey,
  atTime?: number,
): VerifiedSessionCertificate {
  assertSupportedVersion(certificate);

  const parsed = sessionCertificateSchema.safeParse(certificate);
  if (!parsed.success) {
    throw new ProtocolError("session_invalid", "Malformed session certificate");
  }

  const cert = parsed.data;
  if (cert.account !== fingerprint(accountPublicKey)) {
    throw new ProtocolError("session_invalid", "Session certificate account mismatch");
  }

  if (cert.not_after <= cert.not_before) {
    throw new ProtocolError("session_invalid", "Session certificate has invalid validity window");
  }

  if (atTime !== undefined && (atTime < cert.not_before || atTime >= cert.not_after)) {
    throw new ProtocolError("session_invalid", "Session certificate is not valid at this time");
  }

  let sessionPublicKey: Uint8Array;
  let signatureBytes: Uint8Array;
  try {
    sessionPublicKey = fromBase64Url(cert.session_key);
    signatureBytes = fromBase64Url(cert.sig);
  } catch {
    throw new ProtocolError("session_invalid", "Invalid base64url encoding in session certificate");
  }

  if (sessionPublicKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new ProtocolError("session_invalid", "Invalid session public key length");
  }

  const { sig: _sig, ...unsigned } = cert;
  const signingInput = concatBytes(DOMAIN_SESSION, canonicalize(unsigned));
  if (!verify(signingInput, signatureBytes, accountPublicKey)) {
    throw new ProtocolError("session_invalid", "Invalid session certificate signature");
  }

  return {
    certificate: cert,
    sessionPublicKey,
  };
}
