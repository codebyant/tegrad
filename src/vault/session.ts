// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
import {
  fromBase64Url,
  generateSigningKeyPair,
  memzero,
  type PublicKey,
  SIGNING_PUBLIC_KEY_BYTES,
  SIGNING_SECRET_KEY_BYTES,
  SIGNING_SEED_BYTES,
  type SigningKeyPair,
  signingKeyPairFromSeed,
  toBase64Url,
} from "../crypto";
import {
  base64UrlSchema,
  type CommandRegistry,
  createSignedCommand,
  type RevocationList,
  type SessionCertificate,
  type SignedCommand,
  sessionCertificateSchema,
  signRevocationList,
  signSessionCertificate,
} from "../protocol";
import { VaultError } from "./errors";
import type { UnlockedVault } from "./vault";

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

export const SESSION_DURATION_MS = {
  "24h": DAY_MS,
  "7d": 7 * DAY_MS,
  "30d": 30 * DAY_MS,
  remember: 180 * DAY_MS,
} as const;

export type SessionDuration = keyof typeof SESSION_DURATION_MS;

export interface Session {
  readonly keyPair: SigningKeyPair;
  readonly certificate: SessionCertificate;
}

export interface IssueSessionOptions {
  readonly duration: SessionDuration;
  readonly now?: number;
  readonly id?: string;
}

export interface VaultCommandParams {
  /** Public key that receives the replies. Sessions default to their own key. */
  readonly replyTo?: PublicKey;
  readonly type: string;
  readonly body: unknown;
  readonly agentPublicKey: PublicKey;
  readonly counter: number;
  readonly now: number;
  readonly registry: CommandRegistry;
  readonly ttlMs?: number;
  readonly id?: string;
}

export interface SignRevocationParams {
  readonly revoked: readonly string[];
  readonly now: number;
}

const serializedSessionSchema = z.object({
  v: z.literal(1),
  public_key: base64UrlSchema,
  secret_key: base64UrlSchema,
  certificate: sessionCertificateSchema,
});

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

export function issueSession(unlocked: UnlockedVault, options: IssueSessionOptions): Session {
  const accountKeyPair = unlocked.keyPair;
  const now = options.now ?? Date.now();
  if (!Number.isSafeInteger(now) || now < 0) {
    throw new RangeError("Timestamp must be a non-negative safe integer");
  }

  const durationMs = SESSION_DURATION_MS[options.duration];
  const keyPair = generateSigningKeyPair();
  try {
    const certificate = signSessionCertificate({
      sessionPublicKey: keyPair.publicKey,
      accountKeyPair,
      notBefore: now,
      notAfter: now + durationMs,
      ...(options.id !== undefined ? { id: options.id } : {}),
    });

    return { keyPair, certificate };
  } catch (err) {
    memzero(keyPair.secretKey);
    throw err;
  }
}

export function serializeSession(session: Session): string {
  return JSON.stringify({
    v: 1,
    public_key: toBase64Url(session.keyPair.publicKey),
    secret_key: toBase64Url(session.keyPair.secretKey),
    certificate: session.certificate,
  });
}

export function parseSession(text: string): Session {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new VaultError("invalid_session", "Malformed session JSON");
  }

  const parsed = serializedSessionSchema.safeParse(raw);
  if (!parsed.success) {
    throw new VaultError("invalid_session", "Malformed serialized session");
  }

  const { public_key, secret_key, certificate } = parsed.data;
  if (certificate.not_after <= certificate.not_before) {
    throw new VaultError("invalid_session", "Session certificate has invalid validity window");
  }

  let publicKey: Uint8Array;
  let secretKey: Uint8Array;
  let certPublicKey: Uint8Array;
  try {
    publicKey = fromBase64Url(public_key);
    secretKey = fromBase64Url(secret_key);
    certPublicKey = fromBase64Url(certificate.session_key);
  } catch {
    throw new VaultError("invalid_session", "Invalid base64url encoding in serialized session");
  }

  if (
    publicKey.length !== SIGNING_PUBLIC_KEY_BYTES ||
    secretKey.length !== SIGNING_SECRET_KEY_BYTES ||
    certPublicKey.length !== SIGNING_PUBLIC_KEY_BYTES
  ) {
    memzero(secretKey);
    throw new VaultError("invalid_session", "Invalid session key length");
  }

  const seed = secretKey.slice(0, SIGNING_SEED_BYTES);
  let derived: SigningKeyPair;
  try {
    derived = signingKeyPairFromSeed(seed);
  } finally {
    memzero(seed);
  }

  const valid =
    bytesEqual(derived.publicKey, publicKey) &&
    bytesEqual(derived.secretKey, secretKey) &&
    bytesEqual(publicKey, certPublicKey);

  memzero(secretKey);

  if (!valid) {
    memzero(derived.secretKey);
    throw new VaultError("invalid_session", "Session keys do not match certificate");
  }

  return {
    keyPair: derived,
    certificate,
  };
}

export function sessionExpiresAt(session: Session): number {
  return session.certificate.not_after;
}

export function isSessionExpired(session: Session, now: number = Date.now()): boolean {
  return now >= session.certificate.not_after;
}

export function createCommandFromSession(
  session: Session,
  params: VaultCommandParams,
): SignedCommand {
  return createSignedCommand(
    {
      type: params.type,
      body: params.body,
      agentPublicKey: params.agentPublicKey,
      signer: session.keyPair,
      session: session.certificate,
      replyTo: params.replyTo ?? session.keyPair.publicKey,
      counter: params.counter,
      now: params.now,
      ...(params.ttlMs !== undefined ? { ttlMs: params.ttlMs } : {}),
      ...(params.id !== undefined ? { id: params.id } : {}),
    },
    params.registry,
  );
}

export function createSensitiveCommand(
  unlocked: UnlockedVault,
  params: VaultCommandParams,
): SignedCommand {
  const accountKeyPair = unlocked.keyPair;
  return createSignedCommand(
    {
      type: params.type,
      body: params.body,
      agentPublicKey: params.agentPublicKey,
      signer: accountKeyPair,
      ...(params.replyTo !== undefined ? { replyTo: params.replyTo } : {}),
      counter: params.counter,
      now: params.now,
      ...(params.ttlMs !== undefined ? { ttlMs: params.ttlMs } : {}),
      ...(params.id !== undefined ? { id: params.id } : {}),
    },
    params.registry,
  );
}

export function signRevocation(
  unlocked: UnlockedVault,
  params: SignRevocationParams,
): RevocationList {
  const accountKeyPair = unlocked.keyPair;
  return signRevocationList({
    accountKeyPair,
    issuedAt: params.now,
    revoked: params.revoked,
  });
}
