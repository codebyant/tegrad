// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

export {
  type OpenedAgentMessage,
  openAgentMessage,
  type SealAgentMessageParams,
  sealAgentMessage,
} from "./agent-message";
export {
  COMMAND_ID_BYTES,
  type CreateSignedCommandParams,
  createSignedCommand,
  DEFAULT_COMMAND_TTL_MS,
  MAX_CLOCK_SKEW_MS,
  MAX_COMMAND_TTL_MS,
  type OpenedCommand,
  openCommand,
} from "./command";
export {
  agentPingCommand,
  CORE_COMMANDS,
  createCoreRegistry,
  registerCoreCommands,
  serverDeleteCommand,
  serverStartCommand,
  serverStopCommand,
} from "./commands/core";
export {
  DOMAIN_AGENT_MESSAGE,
  DOMAIN_COMMAND,
  DOMAIN_REVOCATION,
  DOMAIN_SESSION,
  PROTOCOL_VERSION,
} from "./domains";
export { ProtocolError, type ProtocolErrorCode } from "./errors";
export { type CommandDefinition, CommandRegistry, defineCommand } from "./registry";
export {
  type SignRevocationListParams,
  signRevocationList,
  verifyRevocationList,
} from "./revocation";
export {
  type AgentMessage,
  type AgentMessageHeader,
  agentMessageHeaderSchema,
  agentMessageSchema,
  base64UrlSchema,
  type CommandHeader,
  commandHeaderSchema,
  type KeyId,
  keyIdSchema,
  type RevocationList,
  revocationListSchema,
  type SessionCertificate,
  type SignedCommand,
  sessionCertificateSchema,
  signedCommandSchema,
  type TransportFrame,
  transportAckFrameSchema,
  transportCommandFrameSchema,
  transportEventFrameSchema,
  transportFrameSchema,
  transportPingFrameSchema,
} from "./schemas";
export {
  type SignSessionCertificateParams,
  signSessionCertificate,
  type VerifiedSessionCertificate,
  verifySessionCertificate,
} from "./session";
export {
  createInMemoryTrustContext,
  type InMemoryTrustContext,
  type InMemoryTrustContextOptions,
  type TrustContext,
} from "./trust";
