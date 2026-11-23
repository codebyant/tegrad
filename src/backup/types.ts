// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import type { BackupDestinationKind, BackupScheduleConfig } from "../protocol";

export type BackupTrigger = "manual" | "scheduled" | "before_change" | "pre_restore";

export interface BackupMetadata {
  readonly id: string;
  readonly server_id: string;
  readonly created_at: number;
  readonly size_bytes: number;
  readonly sha256: string;
  readonly trigger: BackupTrigger;
  readonly destination: BackupDestinationKind;
  readonly note?: string | undefined;
}

export interface BackupUploadContext {
  readonly serverId: string;
  readonly backupId: string;
  readonly createdAt: number;
  readonly sha256: string;
  readonly trigger: BackupTrigger;
  readonly note?: string;
  readonly retentionCount?: number;
  readonly presignedUploadUrl?: string;
  /** Extra headers the upload URL was issued for (e.g. a signed content type). */
  readonly presignedUploadHeaders?: Readonly<Record<string, string>>;
}

export interface BackupDownloadOptions {
  readonly presignedDownloadUrl?: string;
}

export interface BackupDestination {
  readonly kind: BackupDestinationKind;
  isEnabled(serverId: string): boolean;
  upload(archive: Uint8Array, ctx: BackupUploadContext): Promise<BackupMetadata>;
  list(serverId: string): Promise<readonly BackupMetadata[]>;
  download(
    serverId: string,
    backupId: string,
    options?: BackupDownloadOptions,
  ): Promise<Uint8Array>;
  delete(serverId: string, backupId: string): Promise<void>;
}

export interface BackupDestinationOutcome {
  readonly destination: BackupDestinationKind;
  readonly ok: boolean;
  readonly backup?: BackupMetadata;
  readonly error?: string;
}

export interface BackupCreateResult {
  readonly backup_id: string;
  readonly server_id: string;
  readonly created_at: number;
  readonly size_bytes: number;
  readonly sha256: string;
  readonly trigger: BackupTrigger;
  readonly destinations: readonly BackupDestinationOutcome[];
}

export interface BackupDestinationError {
  readonly destination: BackupDestinationKind;
  readonly error: string;
}

export interface BackupListResult {
  readonly server_id: string;
  readonly backups: readonly BackupMetadata[];
  readonly errors: readonly BackupDestinationError[];
}

export interface BackupDeleteDestinationResult {
  readonly destination: BackupDestinationKind;
  readonly ok: boolean;
  readonly error?: string;
}

export interface BackupDeleteResult {
  readonly server_id: string;
  readonly backup_id: string;
  readonly results: readonly BackupDeleteDestinationResult[];
}

export interface BackupRestoreResult {
  readonly server_id: string;
  readonly backup_id: string;
  readonly destination: BackupDestinationKind;
  readonly safety_backup?: BackupCreateResult;
  readonly restored_files: number;
  readonly restored_bytes: number;
}

/**
 * Structural hook invoked before server state changes (e.g. deploy/sync).
 */
export interface BackupHook {
  beforeChange(serverId: string): Promise<void>;
}

/**
 * Minimal runtime surface needed by the backup subsystem to coordinate
 * world consistency on running Minecraft servers.
 */
export interface ServerRuntimeProvider {
  isRunning(serverId: string): Promise<boolean>;
  sendConsole(serverId: string, line: string): void | Promise<void>;
}

export interface S3Credentials {
  readonly access_key_id: string;
  readonly secret_access_key: string;
  readonly session_token?: string | undefined;
}

export interface ServerBackupS3PublicConfig {
  readonly enabled: boolean;
  readonly bucket?: string | undefined;
  readonly region?: string | undefined;
  readonly endpoint?: string | undefined;
  readonly prefix?: string | undefined;
  readonly retention_count: number;
  readonly credentials_configured: boolean;
}

export interface ServerBackupConfig {
  readonly server_id: string;
  readonly auto_before_change: boolean;
  readonly schedule?: BackupScheduleConfig | undefined;
  readonly local: {
    readonly enabled: boolean;
    readonly retention_count: number;
  };
  readonly s3: ServerBackupS3PublicConfig;
  readonly tegra_cloud: {
    readonly enabled: boolean;
    readonly retention_count: number;
  };
}
