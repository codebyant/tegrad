// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
import { type CommandRegistry, defineCommand } from "../registry";

export const SERVER_ID_REGEX = /^[a-z0-9][a-z0-9-]{0,62}$/;
export const DEFAULT_SERVER_PORT = 25565;
export const MAX_CONSOLE_LINE_LENGTH = 1024;
export const MIN_SERVER_MEMORY_MB = 512;
export const MAX_SERVER_MEMORY_MB = 1_048_576;
export const MAX_JVM_ARGS = 64;

export const serverIdSchema = z
  .string()
  .regex(SERVER_ID_REGEX, "server_id must match ^[a-z0-9][a-z0-9-]{0,62}$");

export const serverLoaderSchema = z.enum(["vanilla", "fabric", "forge", "neoforge", "quilt"]);
export type ServerLoader = z.infer<typeof serverLoaderSchema>;

export const serverPortSchema = z.number().int().min(1024).max(65535);
export const serverMemoryMbSchema = z
  .number()
  .int()
  .min(MIN_SERVER_MEMORY_MB)
  .max(MAX_SERVER_MEMORY_MB);

export const consoleLineSchema = z
  .string()
  .min(1)
  .max(MAX_CONSOLE_LINE_LENGTH)
  .refine((value) => !/[\r\n\0]/.test(value), {
    message: "Console line must not contain newline, carriage return, or NUL characters",
  });

const strictServerIdBodySchema = z
  .object({
    server_id: serverIdSchema,
  })
  .strict();

export const serverCreateBodySchema = z
  .object({
    server_id: serverIdSchema,
    name: z.string().trim().min(1).max(128),
    minecraft_version: z.string().min(1).max(64),
    loader: serverLoaderSchema,
    loader_version: z.string().min(1).max(64).optional(),
    memory_mb: serverMemoryMbSchema,
    jvm_args: z.array(z.string()).max(MAX_JVM_ARGS).optional(),
    port: serverPortSchema.optional(),
    eula_accepted: z.boolean(),
  })
  .strict();

export const serverUpdateSettingsBodySchema = z
  .object({
    server_id: serverIdSchema,
    memory_mb: serverMemoryMbSchema.optional(),
    jvm_args: z.array(z.string()).max(MAX_JVM_ARGS).optional(),
    port: serverPortSchema.optional(),
    eula_accepted: z.boolean().optional(),
  })
  .strict();

export const serverConsoleSendBodySchema = z
  .object({
    server_id: serverIdSchema,
    line: consoleLineSchema,
  })
  .strict();

export const serverConsoleSubscribeBodySchema = z
  .object({
    server_id: serverIdSchema,
    from_offset: z.number().int().nonnegative().optional(),
  })
  .strict();

export type ServerCreateBody = z.infer<typeof serverCreateBodySchema>;
export type ServerUpdateSettingsBody = z.infer<typeof serverUpdateSettingsBodySchema>;
export type ServerConsoleSendBody = z.infer<typeof serverConsoleSendBodySchema>;
export type ServerConsoleSubscribeBody = z.infer<typeof serverConsoleSubscribeBodySchema>;

export const serverCreateCommand = defineCommand({
  type: "server.create",
  sensitive: false,
  body: serverCreateBodySchema,
});

export const serverRestartCommand = defineCommand({
  type: "server.restart",
  sensitive: false,
  body: strictServerIdBodySchema,
});

export const serverStatusCommand = defineCommand({
  type: "server.status",
  sensitive: false,
  body: strictServerIdBodySchema,
});

export const serverListCommand = defineCommand({
  type: "server.list",
  sensitive: false,
  body: z.object({}).strict(),
});

export const serverUpdateSettingsCommand = defineCommand({
  type: "server.update_settings",
  sensitive: false,
  body: serverUpdateSettingsBodySchema,
});

export const serverConsoleSendCommand = defineCommand({
  type: "server.console.send",
  sensitive: false,
  body: serverConsoleSendBodySchema,
});

export const serverConsoleSubscribeCommand = defineCommand({
  type: "server.console.subscribe",
  sensitive: false,
  body: serverConsoleSubscribeBodySchema,
});

export const serverConsoleUnsubscribeCommand = defineCommand({
  type: "server.console.unsubscribe",
  sensitive: false,
  body: strictServerIdBodySchema,
});

export const SERVER_COMMANDS = [
  serverCreateCommand,
  serverRestartCommand,
  serverStatusCommand,
  serverListCommand,
  serverUpdateSettingsCommand,
  serverConsoleSendCommand,
  serverConsoleSubscribeCommand,
  serverConsoleUnsubscribeCommand,
] as const;

export function registerServerCommands(registry: CommandRegistry): CommandRegistry {
  return registry.registerAll(SERVER_COMMANDS);
}
