// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
import { type CommandRegistry, defineCommand } from "../registry";

export const PLAYIT_SECRET_KEY_REGEX = /^[0-9a-fA-F]{16,256}$/;

export const playitSecretKeySchema = z
  .string()
  .trim()
  .regex(PLAYIT_SECRET_KEY_REGEX, "secret_key must be a 16-256 character hexadecimal string")
  .refine((value) => value.length % 2 === 0, {
    message: "secret_key must have an even number of hexadecimal characters",
  });

export const tunnelPlayitSetKeyBodySchema = z
  .object({
    secret_key: playitSecretKeySchema,
  })
  .strict();

export type TunnelPlayitSetKeyBody = z.infer<typeof tunnelPlayitSetKeyBodySchema>;

export const tunnelPlayitSetKeyCommand = defineCommand({
  type: "tunnel.playit.set_key",
  level: "sudo",
  minRole: "admin",
  body: tunnelPlayitSetKeyBodySchema,
});

export const tunnelPlayitStartCommand = defineCommand({
  type: "tunnel.playit.start",
  level: "session",
  minRole: "admin",
  body: z.object({}).strict(),
});

export const tunnelPlayitStopCommand = defineCommand({
  type: "tunnel.playit.stop",
  level: "session",
  minRole: "admin",
  body: z.object({}).strict(),
});

export const tunnelPlayitStatusCommand = defineCommand({
  type: "tunnel.playit.status",
  level: "session",
  minRole: "viewer",
  body: z.object({}).strict(),
});

export const TUNNEL_COMMANDS = [
  tunnelPlayitSetKeyCommand,
  tunnelPlayitStartCommand,
  tunnelPlayitStopCommand,
  tunnelPlayitStatusCommand,
] as const;

export function registerTunnelCommands(registry: CommandRegistry): CommandRegistry {
  return registry.registerAll(TUNNEL_COMMANDS);
}
