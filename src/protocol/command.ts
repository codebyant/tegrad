// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import {
  canonicalize,
  fingerprint,
  fromBase64Url,
  openSealed,
  type PublicKey,
  randomBytes,
  SIGNING_PUBLIC_KEY_BYTES,
  type SigningKeyPair,
  sealTo,
  sign,
  toBase64Url,
  verify,
} from "../crypto";
import { assertSupportedVersion, concatBytes, DOMAIN_COMMAND, PROTOCOL_VERSION } from "./domains";
import { ProtocolError } from "./errors";
import type { CommandRegistry } from "./registry";
import { type Role, roleAtLeast } from "./roles";
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
  /**
   * Ed25519 public key that the agent's replies and events are sealed to.
   * Defaults to the account key. A session signer must use its own key.
   */
  readonly replyTo?: PublicKey;
}

export interface OpenedCommand<TBody = unknown> {
  readonly header: CommandHeader;
  readonly body: TBody;
  readonly signerType: "account" | "session";
  /** True when the signer is a session with an elevated certificate. */
  readonly elevated: boolean;
  readonly accountId: KeyId;
  readonly sessionId?: string;
  /** `not_after` of the signing session certificate, when the signer is a session. */
  readonly sessionNotAfter?: number;
  /** Key from the command's `reply_to`, when present. Replies go here instead of the account key. */
  readonly replyTo?: PublicKey;
  /** Role of the signing account on the command's server (`"*"` for agent commands). */
  readonly role: Role;
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

  if (params.replyTo !== undefined && params.replyTo.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new RangeError(`replyTo must be ${SIGNING_PUBLIC_KEY_BYTES} bytes`);
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
    ...(params.replyTo !== undefined ? { reply_to: toBase64Url(params.replyTo) } : {}),
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

  let replyToKey: PublicKey | undefined;
  if (header.reply_to !== undefined) {
    try {
      replyToKey = fromBase64Url(header.reply_to);
    } catch {
      throw new ProtocolError("invalid_format", "Invalid reply_to encoding");
    }
    if (replyToKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
      throw new ProtocolError("invalid_format", "Invalid reply_to length");
    }
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
  let sessionNotAfter: number | undefined;
  let elevated = false;

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
    if (replyToKey !== undefined && fingerprint(replyToKey) !== header.signer) {
      throw new ProtocolError("wrong_recipient", "reply_to must equal the session key");
    }
    signerPublicKey = verifiedSession.sessionPublicKey;
    signerType = "session";
    accountId = session.account;
    sessionId = session.id;
    sessionNotAfter = verifiedSession.certificate.not_after;
    elevated = verifiedSession.elevated;
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

  // 9. Enforce the signer level the command needs
  if (definition.level === "account" && signerType !== "account") {
    throw new ProtocolError(
      "account_key_required",
      "This command must be signed directly by the account key",
    );
  }
  if (definition.level === "sudo" && signerType !== "account" && !elevated) {
    throw new ProtocolError(
      "elevation_required",
      "This command needs an elevated session or the account key",
    );
  }

  // 10. Enforce the role the command needs on its server
  const scope =
    typeof bodyResult.data === "object" &&
    bodyResult.data !== null &&
    "server_id" in bodyResult.data &&
    typeof (bodyResult.data as { server_id: unknown }).server_id === "string"
      ? (bodyResult.data as { server_id: string }).server_id
      : "*";
  const role = trust.roleFor(accountId, scope);
  if (role === null || !roleAtLeast(role, definition.minRole)) {
    throw new ProtocolError("insufficient_role", "Account role is below the command's minimum");
  }

  return {
    header,
    body: bodyResult.data,
    signerType,
    elevated,
    accountId,
    role,
    ...(sessionId !== undefined ? { sessionId } : {}),
    ...(sessionNotAfter !== undefined ? { sessionNotAfter } : {}),
    ...(replyToKey !== undefined ? { replyTo: replyToKey } : {}),
  };
}
