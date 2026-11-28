// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
import { type CommandRegistry, defineCommand } from "../registry";
import { revocationListSchema } from "../schemas";

export const agentRevocationsSetCommand = defineCommand({
  type: "agent.revocations.set",
  level: "session",
  minRole: "admin",
  body: z.object({
    list: revocationListSchema,
  }),
});

export const PAIRING_COMMANDS = [agentRevocationsSetCommand] as const;

export function registerPairingCommands(registry: CommandRegistry): CommandRegistry {
  return registry.registerAll(PAIRING_COMMANDS);
}
