// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
import { type CommandRegistry, defineCommand } from "../registry";

export const hostInfoBodySchema = z.object({}).strict();
export type HostInfoBody = z.infer<typeof hostInfoBodySchema>;

export const hostInfoResultSchema = z.object({
  memory_total_mb: z.number().int().nonnegative(),
  memory_available_mb: z.number().int().nonnegative(),
  cpu_count: z.number().int().positive(),
  reserved_memory_mb: z.number().int().nonnegative(),
  /** Non-internal IPv4 addresses of the host, so a player can find the server on the network. */
  addresses: z.array(z.string().min(1).max(45)).max(16).optional(),
});
export type HostInfoResult = z.infer<typeof hostInfoResultSchema>;

export const hostInfoCommand = defineCommand({
  type: "host.info",
  sensitive: false,
  minRole: "viewer",
  body: hostInfoBodySchema,
});

export const HOST_COMMANDS = [hostInfoCommand] as const;

export function registerHostCommands(registry: CommandRegistry): CommandRegistry {
  return registry.registerAll(HOST_COMMANDS);
}
