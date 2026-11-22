// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import {
  canonicalize,
  fingerprint,
  fromBase64Url,
  openSealed,
  type PublicKey,
  randomBytes,
  type SigningKeyPair,
  sealTo,
  sign,
  toBase64Url,
  verify,
} from "../crypto";
import { assertSupportedVersion, concatBytes, DOMAIN_COMMAND, PROTOCOL_VERSION } from "./domains";
import { ProtocolError } from "./errors";
import type { CommandRegistry } from "./registry";
import {
  type CommandHeader,
  type KeyId,
  type SessionCertificate,
  type SignedCommand,
  signedCommandSchema,
} from "./schemas";
import { verifySessionCertificate } from "./session";
import type { TrustContext } from "./trust";

export const COMMAND_ID_BYTES = 16;
export const DEFAULT_COMMAND_TTL_MS = 5 * 60 * 1000;
export const MAX_COMMAND_TTL_MS = 10 * 60 * 1000;
export const MAX_CLOCK_SKEW_MS = 30 * 1000;

const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

export interface CreateSignedCommandParams {
  readonly type: string;
  readonly body: unknown;
  readonly agentPublicKey: PublicKey;
  readonly signer: SigningKeyPair;
  readonly session?: SessionCertificate;
  readonly counter: number;
  readonly now: number;
  readonly ttlMs?: number;
  readonly id?: string;
}

export interface OpenedCommand<TBody = unknown> {
  readonly header: CommandHeader;
  readonly body: TBody;
  readonly signerType: "account" | "session";
  readonly accountId: KeyId;
  readonly sessionId?: string;
}

export function createSignedCommand(
  params: CreateSignedCommandParams,
  registry: CommandRegistry,
): SignedCommand {
  const definition = registry.get(params.type);
  if (!definition) {
    throw new ProtocolError("unknown_command", "Unknown command type");
  }

  const parsedBody = definition.body.safeParse(params.body);
  if (!parsedBody.success) {
    throw new ProtocolError("invalid_body", "Command body failed schema validation");
  }

  const ttlMs = params.ttlMs ?? DEFAULT_COMMAND_TTL_MS;
  const header: CommandHeader = {
    v: PROTOCOL_VERSION,
    id: params.id ?? toBase64Url(randomBytes(COMMAND_ID_BYTES)),
    type: params.type,
    agent: fingerprint(params.agentPublicKey),
    signer: fingerprint(params.signer.publicKey),
    issued_at: params.now,
    expires_at: params.now + ttlMs,
    counter: params.counter,
  };

  const payloadBytes = sealTo(canonicalize(parsedBody.data), params.agentPublicKey);
  const signingInput = concatBytes(DOMAIN_COMMAND, canonicalize(header), payloadBytes);
  const signature = sign(signingInput, params.signer.secretKey);

  const command: SignedCommand = {
    header,
    payload: toBase64Url(payloadBytes),
    ...(params.session !== undefined ? { session: params.session } : {}),
    sig: toBase64Url(signature),
  };

  return command;
}

export async function openCommand(
  command: unknown,
  trust: TrustContext,
  registry: CommandRegistry,
): Promise<OpenedCommand> {
  // 1. Validate version and format
  if (typeof command === "object" && command !== null) {
    if ("header" in command) {
      assertSupportedVersion((command as { header: unknown }).header);
    }
    if ("session" in command && (command as { session: unknown }).session !== undefined) {
      assertSupportedVersion((command as { session: unknown }).session);
    }
  }

  const parsed = signedCommandSchema.safeParse(command);
  if (!parsed.success) {
    throw new ProtocolError("invalid_format", "Malformed signed command");
  }

  const { header, payload, session, sig } = parsed.data;

  let idBytes: Uint8Array;
  try {
    idBytes = fromBase64Url(header.id);
  } catch {
    throw new ProtocolError("invalid_format", "Invalid command id encoding");
  }
  if (idBytes.length !== COMMAND_ID_BYTES) {
    throw new ProtocolError("invalid_format", "Invalid command id length");
  }

  // 2. Verify target agent
  const localAgentId = fingerprint(trust.agentKeyPair.publicKey);
  if (header.agent !== localAgentId) {
    throw new ProtocolError("wrong_agent", "Command is addressed to a different agent");
  }

  // 3. Verify time window
  const now = trust.now();
  if (header.expires_at <= header.issued_at) {
    throw new ProtocolError("expired", "Command expiration is not after issuance");
  }
  if (header.expires_at - header.issued_at > MAX_COMMAND_TTL_MS) {
    throw new ProtocolError("ttl_too_long", "Command lifetime exceeds maximum allowed window");
  }
  if (header.issued_at > now + MAX_CLOCK_SKEW_MS) {
    throw new ProtocolError("not_yet_valid", "Command issued_at is in the future");
  }
  if (now >= header.expires_at) {
    throw new ProtocolError("expired", "Command has expired");
  }

  // 4. Resolve and trust signer
  let signerPublicKey: PublicKey;
  let signerType: "account" | "session";
  let accountId: KeyId;
  let sessionId: string | undefined;

  if (session !== undefined) {
    const accountPublicKey = trust.isTrustedAccountKey(session.account);
    if (accountPublicKey === null) {
      throw new ProtocolError("untrusted_signer", "Session certificate account key is not trusted");
    }
    if (trust.isSessionRevoked(session.id)) {
      throw new ProtocolError("session_revoked", "Session certificate has been revoked");
    }
    const verifiedSession = verifySessionCertificate(session, accountPublicKey, header.issued_at);
    if (fingerprint(verifiedSession.sessionPublicKey) !== header.signer) {
      throw new ProtocolError(
        "session_invalid",
        "Session certificate key does not match command signer",
      );
    }
    signerPublicKey = verifiedSession.sessionPublicKey;
    signerType = "session";
    accountId = session.account;
    sessionId = session.id;
  } else {
    const accountPublicKey = trust.isTrustedAccountKey(header.signer);
    if (accountPublicKey === null) {
      throw new ProtocolError("untrusted_signer", "Command signer is not a trusted account key");
    }
    signerPublicKey = accountPublicKey;
    signerType = "account";
    accountId = header.signer;
  }

  // 5. Verify command signature
  let payloadBytes: Uint8Array;
  try {
    payloadBytes = fromBase64Url(payload);
  } catch {
    throw new ProtocolError("invalid_format", "Invalid payload encoding");
  }

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = fromBase64Url(sig);
  } catch {
    throw new ProtocolError("bad_signature", "Invalid signature encoding");
  }

  const signingInput = concatBytes(DOMAIN_COMMAND, canonicalize(header), payloadBytes);
  if (!verify(signingInput, signatureBytes, signerPublicKey)) {
    throw new ProtocolError("bad_signature", "Invalid command signature");
  }

  // 6. Anti-replay (only after valid signature)
  if (!trust.claimCommand(header.signer, header.id, header.counter)) {
    throw new ProtocolError("replayed", "Command replay or non-increasing counter detected");
  }

  // 7. Decrypt payload
  let plaintext: Uint8Array;
  try {
    plaintext = openSealed(payloadBytes, trust.agentKeyPair);
  } catch {
    throw new ProtocolError("decrypt_failed", "Failed to decrypt command payload");
  }

  // 8. Look up command type and validate body
  const definition = registry.get(header.type);
  if (!definition) {
    throw new ProtocolError("unknown_command", "Unknown command type");
  }

  let rawBody: unknown;
  try {
    rawBody = JSON.parse(utf8Decoder.decode(plaintext));
  } catch {
    throw new ProtocolError("invalid_body", "Decrypted command payload is not valid JSON");
  }

  const bodyResult = definition.body.safeParse(rawBody);
  if (!bodyResult.success) {
    throw new ProtocolError("invalid_body", "Command body failed schema validation");
  }

  // 9. Enforce sensitive command policy
  if (definition.sensitive && signerType !== "account") {
    throw new ProtocolError(
      "sensitive_requires_account_key",
      "Sensitive command must be signed directly by an account key",
    );
  }

  return {
    header,
    body: bodyResult.data,
    signerType,
    accountId,
    ...(sessionId !== undefined ? { sessionId } : {}),
  };
}
