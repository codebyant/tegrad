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
  agentRevocationsSetCommand,
  PAIRING_COMMANDS,
  registerPairingCommands,
} from "./commands/pairing";
export {
  DOMAIN_AGENT_MESSAGE,
  DOMAIN_COMMAND,
  DOMAIN_PAIRING_PROOF,
  DOMAIN_REVOCATION,
  DOMAIN_SESSION,
  DOMAIN_TRUST_GRANT,
  PROTOCOL_VERSION,
} from "./domains";
export { ProtocolError, type ProtocolErrorCode } from "./errors";
export {
  type BuildPairingFragmentParams,
  buildPairingFragment,
  DEFAULT_TRUST_GRANT_TTL_MS,
  generatePairingCode,
  generatePairingSecret,
  MAX_TRUST_GRANT_TTL_MS,
  PAIRING_CODE_LENGTH,
  PAIRING_SECRET_BYTES,
  type PairingFragment,
  pairingCodeSchema,
  parsePairingFragment,
  type SignTrustGrantParams,
  signTrustGrant,
  type TrustGrant,
  trustGrantSchema,
  type VerifiedTrustGrant,
  type VerifyTrustGrantOptions,
  verifyTrustGrant,
} from "./pairing";
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
