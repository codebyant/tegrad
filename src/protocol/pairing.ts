// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
import {
  canonicalize,
  fingerprint,
  fromBase64Url,
  HASH_BYTES,
  hash,
  type PublicKey,
  randomBytes,
  SIGNING_PUBLIC_KEY_BYTES,
  type SigningKeyPair,
  sign,
  toBase64Url,
  verify,
} from "../crypto";
import { MAX_CLOCK_SKEW_MS } from "./command";
import {
  assertSupportedVersion,
  concatBytes,
  DOMAIN_PAIRING_PROOF,
  DOMAIN_TRUST_GRANT,
  PROTOCOL_VERSION,
} from "./domains";
import { ProtocolError } from "./errors";
import { base64UrlSchema, type KeyId, keyIdSchema } from "./schemas";

export const PAIRING_CODE_LENGTH = 10;
export const PAIRING_SECRET_BYTES = 16;
export const DEFAULT_TRUST_GRANT_TTL_MS = 10 * 60 * 1000;
export const MAX_TRUST_GRANT_TTL_MS = 15 * 60 * 1000;

const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const PAIRING_CODE_REGEX = /^[0-9A-HJKMNP-TV-Z]{10}$/;

export const pairingCodeSchema = z.string().regex(PAIRING_CODE_REGEX, "Invalid pairing code");

export const trustGrantSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  kind: z.literal("agent-pairing"),
  account_key: base64UrlSchema,
  agent: keyIdSchema,
  issued_at: z.number().int().nonnegative(),
  expires_at: z.number().int().nonnegative(),
  proof: base64UrlSchema.optional(),
  sig: base64UrlSchema,
});
export type TrustGrant = z.infer<typeof trustGrantSchema>;

export interface PairingFragment {
  readonly code: string;
  readonly secret?: string;
  readonly agentFingerprint?: KeyId;
}

export interface BuildPairingFragmentParams {
  readonly code: string;
  readonly secret: string;
  readonly agentFingerprint: KeyId;
}

export interface SignTrustGrantParams {
  readonly accountKeyPair: SigningKeyPair;
  readonly agentPublicKey: PublicKey;
  readonly secret?: string | Uint8Array;
  readonly issuedAt: number;
  readonly ttlMs?: number;
}

export interface VerifyTrustGrantOptions {
  readonly agentPublicKey: PublicKey;
  readonly secret?: string | Uint8Array;
  readonly now: number;
  readonly requireProof: boolean;
}

export interface VerifiedTrustGrant {
  readonly accountPublicKey: PublicKey;
  readonly accountId: KeyId;
  readonly proven: boolean;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

function decodeSecretBytes(secret: string | Uint8Array): Uint8Array | null {
  let bytes: Uint8Array;
  if (typeof secret === "string") {
    if (!base64UrlSchema.safeParse(secret).success) {
      return null;
    }
    try {
      bytes = fromBase64Url(secret);
    } catch {
      return null;
    }
  } else {
    bytes = secret;
  }
  if (bytes.length !== PAIRING_SECRET_BYTES) {
    return null;
  }
  return bytes;
}

export function generatePairingCode(): string {
  const bytes = randomBytes(PAIRING_CODE_LENGTH);
  let out = "";
  for (let i = 0; i < PAIRING_CODE_LENGTH; i++) {
    const idx = (bytes[i] ?? 0) & 0x1f;
    out += CROCKFORD_ALPHABET[idx] ?? "";
  }
  return out;
}

export function generatePairingSecret(): string {
  return toBase64Url(randomBytes(PAIRING_SECRET_BYTES));
}

export function buildPairingFragment(params: BuildPairingFragmentParams): string {
  if (!pairingCodeSchema.safeParse(params.code).success) {
    throw new ProtocolError("invalid_format", "Invalid pairing code");
  }
  if (decodeSecretBytes(params.secret) === null) {
    throw new ProtocolError("invalid_format", "Invalid pairing secret");
  }
  if (!keyIdSchema.safeParse(params.agentFingerprint).success) {
    throw new ProtocolError("invalid_format", "Invalid agent fingerprint");
  }
  return `${params.code}.${params.secret}.${params.agentFingerprint}`;
}

export function parsePairingFragment(text: string): PairingFragment {
  const raw = text.startsWith("#") ? text.slice(1) : text;
  if (raw.length === 0) {
    throw new ProtocolError("invalid_format", "Empty pairing fragment");
  }

  const parts = raw.split(".");
  if (parts.length === 1) {
    const code = parts[0] ?? "";
    if (!pairingCodeSchema.safeParse(code).success) {
      throw new ProtocolError("invalid_format", "Invalid pairing code");
    }
    return { code };
  }

  if (parts.length === 3) {
    const code = parts[0] ?? "";
    const secret = parts[1] ?? "";
    const agentFingerprint = parts[2] ?? "";

    if (!pairingCodeSchema.safeParse(code).success) {
      throw new ProtocolError("invalid_format", "Invalid pairing code");
    }
    if (decodeSecretBytes(secret) === null) {
      throw new ProtocolError("invalid_format", "Invalid pairing secret");
    }
    const parsedFp = keyIdSchema.safeParse(agentFingerprint);
    if (!parsedFp.success) {
      throw new ProtocolError("invalid_format", "Invalid agent fingerprint");
    }

    return {
      code,
      secret,
      agentFingerprint: parsedFp.data,
    };
  }

  throw new ProtocolError("invalid_format", "Malformed pairing fragment");
}

function computePairingProof(
  base: {
    readonly v: typeof PROTOCOL_VERSION;
    readonly kind: "agent-pairing";
    readonly account_key: string;
    readonly agent: KeyId;
    readonly issued_at: number;
    readonly expires_at: number;
  },
  secretBytes: Uint8Array,
): Uint8Array {
  const input = concatBytes(DOMAIN_PAIRING_PROOF, canonicalize(base));
  return hash(input, secretBytes);
}

export function signTrustGrant(params: SignTrustGrantParams): TrustGrant {
  if (!Number.isSafeInteger(params.issuedAt) || params.issuedAt < 0) {
    throw new RangeError("issuedAt must be a non-negative safe integer");
  }
  if (params.agentPublicKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new RangeError(`Agent public key must be ${SIGNING_PUBLIC_KEY_BYTES} bytes`);
  }

  const ttlMs = params.ttlMs ?? DEFAULT_TRUST_GRANT_TTL_MS;
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0 || ttlMs > MAX_TRUST_GRANT_TTL_MS) {
    throw new RangeError(
      `ttlMs must be a positive safe integer at most ${MAX_TRUST_GRANT_TTL_MS} ms`,
    );
  }

  const base = {
    v: PROTOCOL_VERSION,
    kind: "agent-pairing" as const,
    account_key: toBase64Url(params.accountKeyPair.publicKey),
    agent: fingerprint(params.agentPublicKey),
    issued_at: params.issuedAt,
    expires_at: params.issuedAt + ttlMs,
  };

  let proof: string | undefined;
  if (params.secret !== undefined) {
    const secretBytes = decodeSecretBytes(params.secret);
    if (secretBytes === null) {
      throw new RangeError(`Pairing secret must be ${PAIRING_SECRET_BYTES} bytes`);
    }
    proof = toBase64Url(computePairingProof(base, secretBytes));
  }

  const unsigned = proof !== undefined ? { ...base, proof } : base;
  const signingInput = concatBytes(DOMAIN_TRUST_GRANT, canonicalize(unsigned));
  const signature = sign(signingInput, params.accountKeyPair.secretKey);

  return {
    ...unsigned,
    sig: toBase64Url(signature),
  };
}

export function verifyTrustGrant(
  grant: unknown,
  options: VerifyTrustGrantOptions,
): VerifiedTrustGrant {
  assertSupportedVersion(grant);

  const parsed = trustGrantSchema.safeParse(grant);
  if (!parsed.success) {
    throw new ProtocolError("grant_invalid", "Malformed trust grant");
  }

  const data = parsed.data;
  if (data.expires_at <= data.issued_at) {
    throw new ProtocolError("grant_invalid", "Trust grant expiration is not after issuance");
  }
  if (data.expires_at - data.issued_at > MAX_TRUST_GRANT_TTL_MS) {
    throw new ProtocolError("grant_invalid", "Trust grant lifetime exceeds maximum allowed window");
  }

  let accountPublicKey: Uint8Array;
  try {
    accountPublicKey = fromBase64Url(data.account_key);
  } catch {
    throw new ProtocolError("grant_invalid", "Invalid account_key encoding in trust grant");
  }
  if (accountPublicKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new ProtocolError("grant_invalid", "Invalid account_key length in trust grant");
  }

  const expectedAgent = fingerprint(options.agentPublicKey);
  if (data.agent !== expectedAgent) {
    throw new ProtocolError("grant_wrong_agent", "Trust grant is addressed to a different agent");
  }

  if (data.issued_at > options.now + MAX_CLOCK_SKEW_MS) {
    throw new ProtocolError("not_yet_valid", "Trust grant issued_at is in the future");
  }
  if (options.now >= data.expires_at) {
    throw new ProtocolError("grant_expired", "Trust grant has expired");
  }

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = fromBase64Url(data.sig);
  } catch {
    throw new ProtocolError("grant_bad_signature", "Invalid trust grant signature encoding");
  }

  const base = {
    v: data.v,
    kind: data.kind,
    account_key: data.account_key,
    agent: data.agent,
    issued_at: data.issued_at,
    expires_at: data.expires_at,
  };
  const unsigned = data.proof !== undefined ? { ...base, proof: data.proof } : base;
  const signingInput = concatBytes(DOMAIN_TRUST_GRANT, canonicalize(unsigned));
  if (!verify(signingInput, signatureBytes, accountPublicKey)) {
    throw new ProtocolError("grant_bad_signature", "Invalid trust grant signature");
  }

  let proven = false;
  if (data.proof === undefined) {
    if (options.requireProof) {
      throw new ProtocolError("grant_proof_required", "Trust grant is missing pairing proof");
    }
  } else {
    if (options.secret === undefined) {
      throw new ProtocolError("grant_bad_proof", "Pairing secret unavailable to verify proof");
    }
    const secretBytes = decodeSecretBytes(options.secret);
    if (secretBytes === null) {
      throw new ProtocolError("grant_bad_proof", "Invalid pairing secret");
    }
    let proofBytes: Uint8Array;
    try {
      proofBytes = fromBase64Url(data.proof);
    } catch {
      throw new ProtocolError("grant_bad_proof", "Invalid proof encoding");
    }
    if (proofBytes.length !== HASH_BYTES) {
      throw new ProtocolError("grant_bad_proof", "Invalid proof length");
    }
    const expectedProof = computePairingProof(base, secretBytes);
    if (!bytesEqual(proofBytes, expectedProof)) {
      throw new ProtocolError("grant_bad_proof", "Pairing proof does not match secret");
    }
    proven = true;
  }

  return {
    accountPublicKey,
    accountId: fingerprint(accountPublicKey),
    proven,
  };
}
