// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
import { type CommandRegistry, defineCommand } from "../registry";
import { roleGrantSchema } from "../roles";
import { keyIdSchema } from "../schemas";
import { serverIdSchema } from "./server";

export const SUBSCRIPTION_TOPICS = ["server.status", "server.backup", "server.modpack"] as const;
export const subscriptionTopicSchema = z.enum(SUBSCRIPTION_TOPICS);
export type SubscriptionTopic = z.infer<typeof subscriptionTopicSchema>;

export const SERVER_STATES = ["stopped", "starting", "running", "stopping", "crashed"] as const;
export const serverStateSchema = z.enum(SERVER_STATES);
export type ServerState = z.infer<typeof serverStateSchema>;

export const serverStatusChangedSchema = z.object({
  server_id: serverIdSchema,
  state: serverStateSchema,
  at: z.number().int().nonnegative(),
});
export type ServerStatusChanged = z.infer<typeof serverStatusChangedSchema>;

export const agentSubscribeBodySchema = z
  .object({
    topics: z.array(subscriptionTopicSchema).min(1).max(SUBSCRIPTION_TOPICS.length),
  })
  .strict();
export type AgentSubscribeBody = z.infer<typeof agentSubscribeBodySchema>;

export const agentMembersSetBodySchema = z
  .object({
    grant: roleGrantSchema,
  })
  .strict();
export type AgentMembersSetBody = z.infer<typeof agentMembersSetBodySchema>;

export const agentMembersRevokeBodySchema = z
  .object({
    account: keyIdSchema,
    servers: z.array(serverIdSchema).min(1).max(256).optional(),
  })
  .strict();
export type AgentMembersRevokeBody = z.infer<typeof agentMembersRevokeBodySchema>;

export const agentSubscribeCommand = defineCommand({
  type: "agent.subscribe",
  sensitive: false,
  minRole: "viewer",
  body: agentSubscribeBodySchema,
});

export const agentUnsubscribeCommand = defineCommand({
  type: "agent.unsubscribe",
  sensitive: false,
  minRole: "viewer",
  body: agentSubscribeBodySchema,
});

export const agentMembersSetCommand = defineCommand({
  type: "agent.members.set",
  sensitive: true,
  minRole: "admin",
  body: agentMembersSetBodySchema,
});

export const agentMembersRevokeCommand = defineCommand({
  type: "agent.members.revoke",
  sensitive: true,
  minRole: "admin",
  body: agentMembersRevokeBodySchema,
});

export const AGENT_COMMANDS = [
  agentSubscribeCommand,
  agentUnsubscribeCommand,
  agentMembersSetCommand,
  agentMembersRevokeCommand,
] as const;

export function registerAgentCommands(registry: CommandRegistry): CommandRegistry {
  return registry.registerAll(AGENT_COMMANDS);
}
