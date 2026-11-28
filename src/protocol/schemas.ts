// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
import { PROTOCOL_VERSION } from "./domains";

export const keyIdSchema = z.string().regex(/^[a-z2-7]{32}$/, "Invalid KeyId");
export type KeyId = z.infer<typeof keyIdSchema>;

export const base64UrlSchema = z
  .string()
  .min(1)
  .regex(/^[A-Za-z0-9_-]+$/, "Invalid base64url");

export const sessionCertificateSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  session_key: base64UrlSchema,
  account: keyIdSchema,
  not_before: z.number().int().nonnegative(),
  not_after: z.number().int().nonnegative(),
  id: base64UrlSchema,
  /**
   * `"elevated"` marks a short-lived certificate that may sign `sudo` commands. It is
   * inside the signed part, so an agent that does not know the field fails to verify
   * the signature and refuses the certificate.
   */
  scope: z.literal("elevated").optional(),
  sig: base64UrlSchema,
});
export type SessionCertificate = z.infer<typeof sessionCertificateSchema>;

export const commandHeaderSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  id: base64UrlSchema,
  type: z.string().min(1),
  agent: keyIdSchema,
  signer: keyIdSchema,
  issued_at: z.number().int().nonnegative(),
  expires_at: z.number().int().nonnegative(),
  counter: z.number().int().nonnegative(),
  reply_to: base64UrlSchema.optional(),
});
export type CommandHeader = z.infer<typeof commandHeaderSchema>;

export const signedCommandSchema = z.object({
  header: commandHeaderSchema,
  payload: base64UrlSchema,
  session: sessionCertificateSchema.optional(),
  sig: base64UrlSchema,
});
export type SignedCommand = z.infer<typeof signedCommandSchema>;

export const agentMessageHeaderSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  id: base64UrlSchema,
  type: z.string().min(1),
  agent: keyIdSchema,
  recipient: keyIdSchema,
  sent_at: z.number().int().nonnegative(),
  seq: z.number().int().nonnegative(),
});
export type AgentMessageHeader = z.infer<typeof agentMessageHeaderSchema>;

export const agentMessageSchema = z.object({
  header: agentMessageHeaderSchema,
  payload: base64UrlSchema,
  sig: base64UrlSchema,
});
export type AgentMessage = z.infer<typeof agentMessageSchema>;

export const revocationListSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  account: keyIdSchema,
  issued_at: z.number().int().nonnegative(),
  revoked: z.array(base64UrlSchema),
  sig: base64UrlSchema,
});
export type RevocationList = z.infer<typeof revocationListSchema>;

export const transportCommandFrameSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  kind: z.literal("command"),
  route: z.object({
    agent: keyIdSchema,
  }),
  body: signedCommandSchema,
});

export const transportEventFrameSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  kind: z.literal("event"),
  route: z.object({
    agent: keyIdSchema,
    recipient: keyIdSchema,
  }),
  body: agentMessageSchema,
});

export const transportAckFrameSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  kind: z.literal("ack"),
  route: z.object({
    agent: keyIdSchema,
  }),
  body: z.object({
    id: base64UrlSchema,
    ok: z.boolean(),
    code: z.string().optional(),
  }),
});

export const transportPingFrameSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  kind: z.literal("ping"),
  route: z.object({
    agent: keyIdSchema,
  }),
  body: z.object({
    ts: z.number().int().nonnegative(),
  }),
});

export const AGENT_NONCE_BYTES = 32;

export const agentNonceSchema = z
  .string()
  .regex(/^[A-Za-z0-9_-]{43}$/, "Invalid nonce (expected 32 bytes in base64url)");

export const transportHelloFrameSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  kind: z.literal("hello"),
  route: z.object({
    agent: keyIdSchema,
  }),
  body: z.object({
    nonce: agentNonceSchema,
    server_time: z.number().int().nonnegative(),
  }),
});

export const transportAuthFrameSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  kind: z.literal("auth"),
  route: z.object({
    agent: keyIdSchema,
  }),
  body: z.object({
    nonce: agentNonceSchema,
    ts: z.number().int().nonnegative(),
    sig: base64UrlSchema,
  }),
});

export const transportFrameSchema = z.discriminatedUnion("kind", [
  transportHelloFrameSchema,
  transportAuthFrameSchema,
  transportCommandFrameSchema,
  transportEventFrameSchema,
  transportAckFrameSchema,
  transportPingFrameSchema,
]);
export type TransportFrame = z.infer<typeof transportFrameSchema>;
