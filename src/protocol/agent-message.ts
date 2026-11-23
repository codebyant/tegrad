// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
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
import {
  assertSupportedVersion,
  concatBytes,
  DOMAIN_AGENT_MESSAGE,
  PROTOCOL_VERSION,
} from "./domains";
import { ProtocolError } from "./errors";
import {
  type AgentMessage,
  type AgentMessageHeader,
  agentMessageSchema,
  base64UrlSchema,
} from "./schemas";

const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

export interface SealAgentMessageParams {
  readonly type: string;
  readonly body: unknown;
  readonly agentKeyPair: SigningKeyPair;
  readonly recipientPublicKey: PublicKey;
  readonly sentAt: number;
  readonly seq: number;
  readonly id?: string;
}

export interface OpenedAgentMessage {
  readonly header: AgentMessageHeader;
  readonly body: unknown;
}

export function sealAgentMessage(params: SealAgentMessageParams): AgentMessage {
  const header: AgentMessageHeader = {
    v: PROTOCOL_VERSION,
    id: params.id ?? toBase64Url(randomBytes(16)),
    type: params.type,
    agent: fingerprint(params.agentKeyPair.publicKey),
    recipient: fingerprint(params.recipientPublicKey),
    sent_at: params.sentAt,
    seq: params.seq,
  };

  const payloadBytes = sealTo(canonicalize(params.body), params.recipientPublicKey);
  const signingInput = concatBytes(DOMAIN_AGENT_MESSAGE, canonicalize(header), payloadBytes);
  const signature = sign(signingInput, params.agentKeyPair.secretKey);

  return {
    header,
    payload: toBase64Url(payloadBytes),
    sig: toBase64Url(signature),
  };
}

export function openAgentMessage(
  message: unknown,
  agentPublicKey: PublicKey,
  recipientKeyPair: SigningKeyPair,
): OpenedAgentMessage {
  if (typeof message === "object" && message !== null && "header" in message) {
    assertSupportedVersion((message as { header: unknown }).header);
  }

  const parsed = agentMessageSchema.safeParse(message);
  if (!parsed.success) {
    throw new ProtocolError("invalid_format", "Malformed agent message");
  }

  const { header, payload, sig } = parsed.data;

  if (header.agent !== fingerprint(agentPublicKey)) {
    throw new ProtocolError("wrong_agent", "Agent message sender mismatch");
  }

  if (header.recipient !== fingerprint(recipientKeyPair.publicKey)) {
    throw new ProtocolError("wrong_recipient", "Agent message recipient mismatch");
  }

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

  const signingInput = concatBytes(DOMAIN_AGENT_MESSAGE, canonicalize(header), payloadBytes);
  if (!verify(signingInput, signatureBytes, agentPublicKey)) {
    throw new ProtocolError("bad_signature", "Invalid agent message signature");
  }

  let plaintext: Uint8Array;
  try {
    plaintext = openSealed(payloadBytes, recipientKeyPair);
  } catch {
    throw new ProtocolError("decrypt_failed", "Failed to decrypt agent message payload");
  }

  let body: unknown;
  try {
    body = JSON.parse(utf8Decoder.decode(plaintext));
  } catch {
    throw new ProtocolError("invalid_body", "Agent message payload is not valid JSON");
  }

  return { header, body };
}

export interface AgentEventBody {
  readonly in_reply_to?: string;
  readonly data: unknown;
}

export const agentEventBodySchema = z.object({
  in_reply_to: base64UrlSchema.optional(),
  data: z.unknown(),
});

/** Builds the decrypted body every agent event carries: `{ in_reply_to?, data }`. */
export function wrapEventBody(inReplyTo: string | undefined, data: unknown): AgentEventBody {
  return {
    ...(inReplyTo !== undefined ? { in_reply_to: inReplyTo } : {}),
    data,
  };
}

export interface OpenedAgentEvent {
  readonly header: AgentMessageHeader;
  readonly inReplyTo: string | null;
  readonly data: unknown;
}

/** Opens an agent message and unwraps the `{ in_reply_to?, data }` event body. */
export function openAgentEvent(
  message: unknown,
  agentPublicKey: PublicKey,
  recipientKeyPair: SigningKeyPair,
): OpenedAgentEvent {
  const opened = openAgentMessage(message, agentPublicKey, recipientKeyPair);
  const parsed = agentEventBodySchema.safeParse(opened.body);
  if (!parsed.success || typeof opened.body !== "object" || opened.body === null) {
    throw new ProtocolError("invalid_body", "Agent event body is malformed");
  }
  if (!("data" in opened.body)) {
    throw new ProtocolError("invalid_body", "Agent event body has no data");
  }
  return {
    header: opened.header,
    inReplyTo: parsed.data.in_reply_to ?? null,
    data: parsed.data.data,
  };
}
