import { z } from "zod";
import { type CommandRegistry } from "../registry";
export declare const BACKUP_ID_REGEX: RegExp;
export declare const MIN_BACKUP_INTERVAL_MINUTES = 5;
export declare const MAX_BACKUP_INTERVAL_MINUTES = 43200;
export declare const MIN_BACKUP_RETENTION_COUNT = 1;
export declare const MAX_BACKUP_RETENTION_COUNT = 1000;
export declare const backupIdSchema: z.ZodString;
export declare const backupDestinationKindSchema: z.ZodEnum<{
    local: "local";
    s3: "s3";
    tegra_cloud: "tegra_cloud";
}>;
export type BackupDestinationKind = z.infer<typeof backupDestinationKindSchema>;
export declare const BACKUP_UPLOAD_STATES: readonly ["queued", "uploading", "done", "failed"];
export declare const backupUploadStateSchema: z.ZodEnum<{
    done: "done";
    failed: "failed";
    queued: "queued";
    uploading: "uploading";
}>;
export type BackupUploadState = z.infer<typeof backupUploadStateSchema>;
export declare const serverBackupUploadEventSchema: z.ZodObject<{
    server_id: z.ZodString;
    backup_id: z.ZodString;
    destination: z.ZodEnum<{
        local: "local";
        s3: "s3";
        tegra_cloud: "tegra_cloud";
    }>;
    state: z.ZodEnum<{
        done: "done";
        failed: "failed";
        queued: "queued";
        uploading: "uploading";
    }>;
    sent_bytes: z.ZodNumber;
    total_bytes: z.ZodNumber;
    error: z.ZodOptional<z.ZodString>;
}, z.core.$strict>;
export type ServerBackupUploadEvent = z.infer<typeof serverBackupUploadEventSchema>;
export declare const pendingBackupUploadSchema: z.ZodObject<{
    destination: z.ZodEnum<{
        local: "local";
        s3: "s3";
        tegra_cloud: "tegra_cloud";
    }>;
    state: z.ZodEnum<{
        done: "done";
        failed: "failed";
        queued: "queued";
        uploading: "uploading";
    }>;
    sent_bytes: z.ZodNumber;
    total_bytes: z.ZodNumber;
    error: z.ZodOptional<z.ZodString>;
}, z.core.$strict>;
export type PendingBackupUpload = z.infer<typeof pendingBackupUploadSchema>;
export declare const backupScheduleConfigSchema: z.ZodObject<{
    enabled: z.ZodBoolean;
    interval_minutes: z.ZodNumber;
    retention_count: z.ZodNumber;
}, z.core.$strict>;
export declare const backupLocalConfigSchema: z.ZodObject<{
    enabled: z.ZodBoolean;
    retention_count: z.ZodOptional<z.ZodNumber>;
}, z.core.$strict>;
export declare const s3BucketSchema: z.ZodString;
export declare const s3RegionSchema: z.ZodString;
export declare const s3PrefixSchema: z.ZodString;
export declare const backupS3ConfigSchema: z.ZodObject<{
    enabled: z.ZodBoolean;
    bucket: z.ZodOptional<z.ZodString>;
    region: z.ZodOptional<z.ZodString>;
    endpoint: z.ZodOptional<z.ZodString>;
    prefix: z.ZodOptional<z.ZodString>;
    retention_count: z.ZodOptional<z.ZodNumber>;
    access_key_id: z.ZodOptional<z.ZodString>;
    secret_access_key: z.ZodOptional<z.ZodString>;
    session_token: z.ZodOptional<z.ZodString>;
}, z.core.$strict>;
export declare const backupTegraCloudConfigSchema: z.ZodObject<{
    enabled: z.ZodBoolean;
    retention_count: z.ZodOptional<z.ZodNumber>;
}, z.core.$strict>;
export declare const serverBackupConfigSetBodySchema: z.ZodObject<{
    server_id: z.ZodString;
    auto_before_change: z.ZodOptional<z.ZodBoolean>;
    schedule: z.ZodOptional<z.ZodObject<{
        enabled: z.ZodBoolean;
        interval_minutes: z.ZodNumber;
        retention_count: z.ZodNumber;
    }, z.core.$strict>>;
    local: z.ZodOptional<z.ZodObject<{
        enabled: z.ZodBoolean;
        retention_count: z.ZodOptional<z.ZodNumber>;
    }, z.core.$strict>>;
    s3: z.ZodOptional<z.ZodObject<{
        enabled: z.ZodBoolean;
        bucket: z.ZodOptional<z.ZodString>;
        region: z.ZodOptional<z.ZodString>;
        endpoint: z.ZodOptional<z.ZodString>;
        prefix: z.ZodOptional<z.ZodString>;
        retention_count: z.ZodOptional<z.ZodNumber>;
        access_key_id: z.ZodOptional<z.ZodString>;
        secret_access_key: z.ZodOptional<z.ZodString>;
        session_token: z.ZodOptional<z.ZodString>;
    }, z.core.$strict>>;
    tegra_cloud: z.ZodOptional<z.ZodObject<{
        enabled: z.ZodBoolean;
        retention_count: z.ZodOptional<z.ZodNumber>;
    }, z.core.$strict>>;
}, z.core.$strict>;
export declare const serverBackupCreateBodySchema: z.ZodObject<{
    server_id: z.ZodString;
    note: z.ZodOptional<z.ZodString>;
    tegra_cloud_upload_url: z.ZodOptional<z.ZodString>;
}, z.core.$strict>;
export declare const serverBackupListBodySchema: z.ZodObject<{
    server_id: z.ZodString;
    destination: z.ZodOptional<z.ZodEnum<{
        local: "local";
        s3: "s3";
        tegra_cloud: "tegra_cloud";
    }>>;
}, z.core.$strict>;
export declare const serverBackupDeleteBodySchema: z.ZodObject<{
    server_id: z.ZodString;
    backup_id: z.ZodString;
    destination: z.ZodOptional<z.ZodEnum<{
        local: "local";
        s3: "s3";
        tegra_cloud: "tegra_cloud";
    }>>;
}, z.core.$strict>;
export declare const serverBackupRestoreBodySchema: z.ZodObject<{
    server_id: z.ZodString;
    backup_id: z.ZodString;
    destination: z.ZodOptional<z.ZodEnum<{
        local: "local";
        s3: "s3";
        tegra_cloud: "tegra_cloud";
    }>>;
    tegra_cloud_download_url: z.ZodOptional<z.ZodString>;
}, z.core.$strict>;
export type BackupScheduleConfig = z.infer<typeof backupScheduleConfigSchema>;
export type BackupLocalConfig = z.infer<typeof backupLocalConfigSchema>;
export type BackupS3ConfigInput = z.infer<typeof backupS3ConfigSchema>;
export type BackupTegraCloudConfig = z.infer<typeof backupTegraCloudConfigSchema>;
export type ServerBackupConfigSetBody = z.infer<typeof serverBackupConfigSetBodySchema>;
export type ServerBackupCreateBody = z.infer<typeof serverBackupCreateBodySchema>;
export type ServerBackupListBody = z.infer<typeof serverBackupListBodySchema>;
export type ServerBackupDeleteBody = z.infer<typeof serverBackupDeleteBodySchema>;
export type ServerBackupRestoreBody = z.infer<typeof serverBackupRestoreBodySchema>;
export declare const serverBackupConfigSetCommand: import("..").CommandDefinition<"server.backup.config.set", {
    server_id: string;
    auto_before_change?: boolean | undefined;
    schedule?: {
        enabled: boolean;
        interval_minutes: number;
        retention_count: number;
    } | undefined;
    local?: {
        enabled: boolean;
        retention_count?: number | undefined;
    } | undefined;
    s3?: {
        enabled: boolean;
        bucket?: string | undefined;
        region?: string | undefined;
        endpoint?: string | undefined;
        prefix?: string | undefined;
        retention_count?: number | undefined;
        access_key_id?: string | undefined;
        secret_access_key?: string | undefined;
        session_token?: string | undefined;
    } | undefined;
    tegra_cloud?: {
        enabled: boolean;
        retention_count?: number | undefined;
    } | undefined;
}>;
export declare const serverBackupConfigGetCommand: import("..").CommandDefinition<"server.backup.config.get", {
    server_id: string;
}>;
export declare const serverBackupCreateCommand: import("..").CommandDefinition<"server.backup.create", {
    server_id: string;
    note?: string | undefined;
    tegra_cloud_upload_url?: string | undefined;
}>;
export declare const serverBackupListCommand: import("..").CommandDefinition<"server.backup.list", {
    server_id: string;
    destination?: "local" | "s3" | "tegra_cloud" | undefined;
}>;
export declare const serverBackupDeleteCommand: import("..").CommandDefinition<"server.backup.delete", {
    server_id: string;
    backup_id: string;
    destination?: "local" | "s3" | "tegra_cloud" | undefined;
}>;
export declare const serverBackupRestoreCommand: import("..").CommandDefinition<"server.backup.restore", {
    server_id: string;
    backup_id: string;
    destination?: "local" | "s3" | "tegra_cloud" | undefined;
    tegra_cloud_download_url?: string | undefined;
}>;
export declare const BACKUP_COMMANDS: readonly [import("..").CommandDefinition<"server.backup.config.set", {
    server_id: string;
    auto_before_change?: boolean | undefined;
    schedule?: {
        enabled: boolean;
        interval_minutes: number;
        retention_count: number;
    } | undefined;
    local?: {
        enabled: boolean;
        retention_count?: number | undefined;
    } | undefined;
    s3?: {
        enabled: boolean;
        bucket?: string | undefined;
        region?: string | undefined;
        endpoint?: string | undefined;
        prefix?: string | undefined;
        retention_count?: number | undefined;
        access_key_id?: string | undefined;
        secret_access_key?: string | undefined;
        session_token?: string | undefined;
    } | undefined;
    tegra_cloud?: {
        enabled: boolean;
        retention_count?: number | undefined;
    } | undefined;
}>, import("..").CommandDefinition<"server.backup.config.get", {
    server_id: string;
}>, import("..").CommandDefinition<"server.backup.create", {
    server_id: string;
    note?: string | undefined;
    tegra_cloud_upload_url?: string | undefined;
}>, import("..").CommandDefinition<"server.backup.list", {
    server_id: string;
    destination?: "local" | "s3" | "tegra_cloud" | undefined;
}>, import("..").CommandDefinition<"server.backup.delete", {
    server_id: string;
    backup_id: string;
    destination?: "local" | "s3" | "tegra_cloud" | undefined;
}>, import("..").CommandDefinition<"server.backup.restore", {
    server_id: string;
    backup_id: string;
    destination?: "local" | "s3" | "tegra_cloud" | undefined;
    tegra_cloud_download_url?: string | undefined;
}>];
export declare function registerBackupCommands(registry: CommandRegistry): CommandRegistry;
