// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
import { CommandRegistry, defineCommand } from "../registry";
import { registerAgentCommands } from "./agent";
import { registerBackupCommands } from "./backup";
import { registerFilesCommands } from "./files";
import { registerPairingCommands } from "./pairing";
import { registerServerCommands, serverIdSchema } from "./server";
import { registerStateCommands } from "./state";
import { registerTunnelCommands } from "./tunnel";

const serverIdBodySchema = z.object({
  server_id: z.string().min(1),
});

const strictServerDeleteBodySchema = z
  .object({
    server_id: serverIdSchema,
  })
  .strict();

export const agentPingCommand = defineCommand({
  type: "agent.ping",
  sensitive: false,
  minRole: "viewer",
  body: z.object({}).strict(),
});

export const serverStartCommand = defineCommand({
  type: "server.start",
  sensitive: false,
  minRole: "operator",
  body: serverIdBodySchema,
});

export const serverStopCommand = defineCommand({
  type: "server.stop",
  sensitive: false,
  minRole: "operator",
  body: serverIdBodySchema,
});

export const serverDeleteCommand = defineCommand({
  type: "server.delete",
  sensitive: true,
  minRole: "admin",
  body: strictServerDeleteBodySchema,
});

export const CORE_COMMANDS = [
  agentPingCommand,
  serverStartCommand,
  serverStopCommand,
  serverDeleteCommand,
] as const;

export function registerCoreCommands(registry: CommandRegistry): CommandRegistry {
  return registry.registerAll(CORE_COMMANDS);
}

export function createCoreRegistry(): CommandRegistry {
  return registerAgentCommands(
    registerTunnelCommands(
      registerBackupCommands(
        registerStateCommands(
          registerServerCommands(
            registerFilesCommands(
              registerPairingCommands(registerCoreCommands(new CommandRegistry())),
            ),
          ),
        ),
      ),
    ),
  );
}
