// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
import { type CommandRegistry, defineCommand } from "../registry";
import { serverIdSchema } from "./server";

export const BACKUP_ID_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/;
export const MIN_BACKUP_INTERVAL_MINUTES = 5;
export const MAX_BACKUP_INTERVAL_MINUTES = 43_200; // 30 days
export const MIN_BACKUP_RETENTION_COUNT = 1;
export const MAX_BACKUP_RETENTION_COUNT = 1000;

export const backupIdSchema = z
  .string()
  .regex(BACKUP_ID_REGEX, "backup_id must match ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$");

export const backupDestinationKindSchema = z.enum(["local", "s3", "tegra_cloud"]);
export type BackupDestinationKind = z.infer<typeof backupDestinationKindSchema>;

export const backupScheduleConfigSchema = z
  .object({
    enabled: z.boolean(),
    interval_minutes: z
      .number()
      .int()
      .min(MIN_BACKUP_INTERVAL_MINUTES)
      .max(MAX_BACKUP_INTERVAL_MINUTES),
    retention_count: z
      .number()
      .int()
      .min(MIN_BACKUP_RETENTION_COUNT)
      .max(MAX_BACKUP_RETENTION_COUNT),
  })
  .strict();

export const backupLocalConfigSchema = z
  .object({
    enabled: z.boolean(),
    retention_count: z
      .number()
      .int()
      .min(MIN_BACKUP_RETENTION_COUNT)
      .max(MAX_BACKUP_RETENTION_COUNT)
      .optional(),
  })
  .strict();

export const backupS3ConfigSchema = z
  .object({
    enabled: z.boolean(),
    bucket: z.string().min(1).max(255).optional(),
    region: z.string().min(1).max(64).optional(),
    endpoint: z.string().min(1).max(512).optional(),
    prefix: z.string().max(256).optional(),
    retention_count: z
      .number()
      .int()
      .min(MIN_BACKUP_RETENTION_COUNT)
      .max(MAX_BACKUP_RETENTION_COUNT)
      .optional(),
    access_key_id: z.string().min(1).max(256).optional(),
    secret_access_key: z.string().min(1).max(256).optional(),
    session_token: z.string().min(1).max(2048).optional(),
  })
  .strict();

export const backupTegraCloudConfigSchema = z
  .object({
    enabled: z.boolean(),
    retention_count: z
      .number()
      .int()
      .min(MIN_BACKUP_RETENTION_COUNT)
      .max(MAX_BACKUP_RETENTION_COUNT)
      .optional(),
  })
  .strict();

export const serverBackupConfigSetBodySchema = z
  .object({
    server_id: serverIdSchema,
    auto_before_change: z.boolean().optional(),
    schedule: backupScheduleConfigSchema.optional(),
    local: backupLocalConfigSchema.optional(),
    s3: backupS3ConfigSchema.optional(),
    tegra_cloud: backupTegraCloudConfigSchema.optional(),
  })
  .strict();

export const serverBackupCreateBodySchema = z
  .object({
    server_id: serverIdSchema,
    note: z.string().max(256).optional(),
    tegra_cloud_upload_url: z.string().min(1).max(4096).optional(),
  })
  .strict();

export const serverBackupListBodySchema = z
  .object({
    server_id: serverIdSchema,
    destination: backupDestinationKindSchema.optional(),
  })
  .strict();

export const serverBackupDeleteBodySchema = z
  .object({
    server_id: serverIdSchema,
    backup_id: backupIdSchema,
    destination: backupDestinationKindSchema.optional(),
  })
  .strict();

export const serverBackupRestoreBodySchema = z
  .object({
    server_id: serverIdSchema,
    backup_id: backupIdSchema,
    destination: backupDestinationKindSchema.optional(),
    tegra_cloud_download_url: z.string().min(1).max(4096).optional(),
  })
  .strict();

export type BackupScheduleConfig = z.infer<typeof backupScheduleConfigSchema>;
export type BackupLocalConfig = z.infer<typeof backupLocalConfigSchema>;
export type BackupS3ConfigInput = z.infer<typeof backupS3ConfigSchema>;
export type BackupTegraCloudConfig = z.infer<typeof backupTegraCloudConfigSchema>;
export type ServerBackupConfigSetBody = z.infer<typeof serverBackupConfigSetBodySchema>;
export type ServerBackupCreateBody = z.infer<typeof serverBackupCreateBodySchema>;
export type ServerBackupListBody = z.infer<typeof serverBackupListBodySchema>;
export type ServerBackupDeleteBody = z.infer<typeof serverBackupDeleteBodySchema>;
export type ServerBackupRestoreBody = z.infer<typeof serverBackupRestoreBodySchema>;

export const serverBackupConfigSetCommand = defineCommand({
  type: "server.backup.config.set",
  sensitive: false,
  body: serverBackupConfigSetBodySchema,
});

export const serverBackupCreateCommand = defineCommand({
  type: "server.backup.create",
  sensitive: false,
  body: serverBackupCreateBodySchema,
});

export const serverBackupListCommand = defineCommand({
  type: "server.backup.list",
  sensitive: false,
  body: serverBackupListBodySchema,
});

export const serverBackupDeleteCommand = defineCommand({
  type: "server.backup.delete",
  sensitive: true,
  body: serverBackupDeleteBodySchema,
});

export const serverBackupRestoreCommand = defineCommand({
  type: "server.backup.restore",
  sensitive: true,
  body: serverBackupRestoreBodySchema,
});

export const BACKUP_COMMANDS = [
  serverBackupConfigSetCommand,
  serverBackupCreateCommand,
  serverBackupListCommand,
  serverBackupDeleteCommand,
  serverBackupRestoreCommand,
] as const;

export function registerBackupCommands(registry: CommandRegistry): CommandRegistry {
  return registry.registerAll(BACKUP_COMMANDS);
}
