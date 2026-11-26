// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
import { type CommandRegistry, defineCommand } from "../registry";
import { serverIdSchema } from "./server";

export const MODPACK_SOURCES = ["tegra", "modrinth", "curseforge"] as const;
export const modpackSourceSchema = z.enum(MODPACK_SOURCES);
export type ModpackSource = z.infer<typeof modpackSourceSchema>;

export const MODPACK_INSTALL_PHASES = [
  "resolving",
  "downloading",
  "extracting",
  "overrides",
  "finalizing",
] as const;
export const modpackInstallPhaseSchema = z.enum(MODPACK_INSTALL_PHASES);
export type ModpackInstallPhase = z.infer<typeof modpackInstallPhaseSchema>;

export const MODPACK_INSTALL_JOB_STATES = ["running", "completed", "failed", "cancelled"] as const;
export const modpackInstallJobStateSchema = z.enum(MODPACK_INSTALL_JOB_STATES);
export type ModpackInstallJobState = z.infer<typeof modpackInstallJobStateSchema>;

export const MODPACK_INSTALL_ERROR_CODES = [
  "pack_unavailable",
  "host_not_allowed",
  "hash_mismatch",
  "too_large",
  "install_in_progress",
  "server_running",
  "api_unavailable",
  "io_error",
  "cancelled",
] as const;
export const modpackInstallErrorCodeSchema = z.enum(MODPACK_INSTALL_ERROR_CODES);
export type ModpackInstallErrorCode = z.infer<typeof modpackInstallErrorCodeSchema>;

export const modpackInstallSkippedItemSchema = z
  .object({
    name: z.string().min(1).max(256),
    reason: z.string().min(1).max(128),
  })
  .strict();
export type ModpackInstallSkippedItem = z.infer<typeof modpackInstallSkippedItemSchema>;

export const serverInstallModpackBodySchema = z
  .object({
    server_id: serverIdSchema,
    source: modpackSourceSchema,
    modpack_id: z.string().min(1).max(128),
    version_id: z.string().min(1).max(128),
    modpack_name: z.string().min(1).max(256).optional(),
    version_label: z.string().min(1).max(128).optional(),
  })
  .strict();
export type ServerInstallModpackBody = z.infer<typeof serverInstallModpackBodySchema>;

export const serverInstallModpackStatusBodySchema = z
  .object({
    server_id: serverIdSchema,
  })
  .strict();
export type ServerInstallModpackStatusBody = z.infer<typeof serverInstallModpackStatusBodySchema>;

export const serverInstallModpackCancelBodySchema = z
  .object({
    server_id: serverIdSchema,
    job_id: z.string().min(1).max(128).optional(),
  })
  .strict();
export type ServerInstallModpackCancelBody = z.infer<typeof serverInstallModpackCancelBodySchema>;

export const serverInstallModpackAcceptedEventSchema = z
  .object({
    job_id: z.string().min(1).max(128),
    server_id: serverIdSchema,
  })
  .strict();
export type ServerInstallModpackAcceptedEvent = z.infer<
  typeof serverInstallModpackAcceptedEventSchema
>;

export const serverInstallModpackProgressEventSchema = z
  .object({
    job_id: z.string().min(1).max(128),
    server_id: serverIdSchema,
    phase: modpackInstallPhaseSchema,
    done: z.number().int().nonnegative(),
    total: z.number().int().nonnegative(),
    current: z.string().min(1).max(256).optional(),
  })
  .strict();
export type ServerInstallModpackProgressEvent = z.infer<
  typeof serverInstallModpackProgressEventSchema
>;

export const serverInstallModpackResultEventSchema = z
  .object({
    job_id: z.string().min(1).max(128),
    server_id: serverIdSchema,
    ok: z.boolean(),
    installed: z.number().int().nonnegative(),
    skipped: z.array(modpackInstallSkippedItemSchema).max(4000),
    error_code: modpackInstallErrorCodeSchema.optional(),
  })
  .strict();
export type ServerInstallModpackResultEvent = z.infer<typeof serverInstallModpackResultEventSchema>;

export const modpackInstallJobStatusSchema = z
  .object({
    job_id: z.string().min(1).max(128),
    server_id: serverIdSchema,
    source: modpackSourceSchema,
    modpack_id: z.string().min(1).max(128),
    version_id: z.string().min(1).max(128),
    modpack_name: z.string().min(1).max(256).optional(),
    version_label: z.string().min(1).max(128).optional(),
    status: modpackInstallJobStateSchema,
    phase: modpackInstallPhaseSchema,
    done: z.number().int().nonnegative(),
    total: z.number().int().nonnegative(),
    current: z.string().min(1).max(256).optional(),
    installed: z.number().int().nonnegative(),
    skipped: z.array(modpackInstallSkippedItemSchema).max(4000),
    error_code: modpackInstallErrorCodeSchema.optional(),
    started_at: z.number().int().nonnegative(),
    updated_at: z.number().int().nonnegative(),
    finished_at: z.number().int().nonnegative().optional(),
  })
  .strict();
export type ModpackInstallJobStatus = z.infer<typeof modpackInstallJobStatusSchema>;

export const serverInstallModpackStatusResultSchema = z
  .object({
    server_id: serverIdSchema,
    job: modpackInstallJobStatusSchema.nullable(),
  })
  .strict();
export type ServerInstallModpackStatusResult = z.infer<
  typeof serverInstallModpackStatusResultSchema
>;

export const serverInstallModpackCommand = defineCommand({
  type: "server.install_modpack",
  sensitive: true,
  minRole: "editor",
  body: serverInstallModpackBodySchema,
});

export const serverInstallModpackStatusCommand = defineCommand({
  type: "server.install_modpack.status",
  sensitive: false,
  minRole: "viewer",
  body: serverInstallModpackStatusBodySchema,
});

export const serverInstallModpackCancelCommand = defineCommand({
  type: "server.install_modpack.cancel",
  sensitive: false,
  minRole: "editor",
  body: serverInstallModpackCancelBodySchema,
});

export const MODPACK_COMMANDS = [
  serverInstallModpackCommand,
  serverInstallModpackStatusCommand,
  serverInstallModpackCancelCommand,
] as const;

export function registerModpackCommands(registry: CommandRegistry): CommandRegistry {
  return registry.registerAll(MODPACK_COMMANDS);
}
