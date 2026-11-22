// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

export {
  type ArchiveServerDirectoryOptions,
  archiveServerDirectory,
  type CreateConsistentArchiveOptions,
  createConsistentServerArchive,
  DEFAULT_SAVE_POLL_INTERVAL_MS,
  DEFAULT_SAVE_TIMEOUT_MS,
  type RestoreServerArchiveOptions,
  restoreServerArchive,
  type ServerArchiveResult,
  type WaitForSaveOptions,
  waitForSaveConfirmation,
} from "./archive";
export {
  BackupConfigStore,
  type BackupConfigStoreOptions,
  DEFAULT_LOCAL_RETENTION_COUNT,
  DEFAULT_S3_RETENTION_COUNT,
  DEFAULT_TEGRA_CLOUD_RETENTION_COUNT,
  validateRemoteHttpsUrl,
} from "./config";
export {
  DEFAULT_LOCAL_BACKUPS_DIR,
  LocalBackupDestination,
  type LocalBackupDestinationOptions,
} from "./destinations/local";
export {
  S3BackupDestination,
  type S3BackupDestinationOptions,
} from "./destinations/s3";
export {
  type CloudFetchLike,
  DEFAULT_TEGRA_CLOUD_MAX_BYTES,
  DEFAULT_TEGRA_CLOUD_TIMEOUT_MS,
  TegraCloudBackupDestination,
  type TegraCloudBackupDestinationOptions,
} from "./destinations/tegra-cloud";
export {
  type BackupManager,
  type BackupManagerOptions,
  type CreateBackupOptions,
  createBackupHook,
  createBackupManager,
  registerBackupHandlers,
} from "./manager";
export {
  type BackupScheduler,
  type BackupSchedulerOptions,
  type BackupTimerHandle,
  type BackupTimerProvider,
  createBackupScheduler,
  defaultBackupTimers,
} from "./scheduler";
export type {
  BackupCreateResult,
  BackupDeleteDestinationResult,
  BackupDeleteResult,
  BackupDestination,
  BackupDestinationError,
  BackupDestinationOutcome,
  BackupDownloadOptions,
  BackupHook,
  BackupListResult,
  BackupMetadata,
  BackupRestoreResult,
  BackupTrigger,
  BackupUploadContext,
  S3Credentials,
  ServerBackupConfig,
  ServerBackupS3PublicConfig,
  ServerRuntimeProvider,
} from "./types";
