// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { randomBytes } from "node:crypto";
import { AgentApiError } from "../agent/api-client";
import type { CommandQueue } from "../agent/jobs";
import type { Logger } from "../agent/logger";
import { DEFAULT_SERVERS_BASE_DIR } from "../files";
import {
  type BackupDestinationKind,
  type BackupUploadState,
  backupIdSchema,
  type PendingBackupUpload,
  ProtocolError,
  type ServerBackupConfigSetBody,
  type ServerBackupCreateBody,
  type ServerBackupDeleteBody,
  type ServerBackupListBody,
  type ServerBackupRestoreBody,
  type ServerBackupUploadEvent,
  serverIdSchema,
} from "../protocol";
import { createServerPermissionContext, type PermissionContext } from "../server/permissions";
import type { MakeServerReadableLike } from "../server/readable";
import {
  type ArchiveServerDirectoryOptions,
  createConsistentServerArchive,
  restoreServerArchive,
  type ServerArchiveResult,
} from "./archive";
import { BackupConfigStore, redactUrlQueryStrings } from "./config";
import { DEFAULT_LOCAL_BACKUPS_DIR, LocalBackupDestination } from "./destinations/local";
import { S3BackupDestination } from "./destinations/s3";
import { type CloudFetchLike, TegraCloudBackupDestination } from "./destinations/tegra-cloud";
import { type BackupScheduler, type BackupTimerProvider, createBackupScheduler } from "./scheduler";
import type {
  BackupCreateResult,
  BackupDeleteDestinationResult,
  BackupDeleteResult,
  BackupDestination,
  BackupDestinationError,
  BackupDestinationOutcome,
  BackupHook,
  BackupMetadata,
  BackupRestoreResult,
  BackupTrigger,
  ServerBackupConfig,
  ServerRuntimeProvider,
} from "./types";

function formatBackupId(timestampMs: number): string {
  const date = new Date(timestampMs);
  const pad = (n: number, width = 2) => String(n).padStart(width, "0");
  const stamp = [
    date.getUTCFullYear(),
    pad(date.getUTCMonth() + 1),
    pad(date.getUTCDate()),
    "-",
    pad(date.getUTCHours()),
    pad(date.getUTCMinutes()),
    pad(date.getUTCSeconds()),
  ].join("");
  const rand = randomBytes(4).toString("hex");
  return `bkp-${stamp}-${rand}`;
}

export interface CreateBackupOptions {
  readonly server_id: string;
  readonly trigger?: BackupTrigger;
  readonly note?: string;
  readonly retention_count?: number;
  readonly tegra_cloud_upload_url?: string;
}

export interface CloudUploadTarget {
  readonly id?: string | undefined;
  readonly put_url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly expires_at: number;
  readonly max_bytes: number;
}

export type CloudUploadUrlProvider = (request: {
  readonly server_id: string;
  readonly size_bytes: number;
}) => Promise<CloudUploadTarget>;

export interface BackupManagerOptions {
  readonly stateDir: string;
  readonly serversBaseDir?: string;
  readonly localBackupsDir?: string;
  readonly runtime?: ServerRuntimeProvider;
  readonly destinations?: readonly BackupDestination[];
  readonly allowInsecure?: boolean;
  readonly saveTimeoutMs?: number;
  readonly savePollIntervalMs?: number;
  readonly cloudTimeoutMs?: number;
  readonly cloudMaxBytes?: number;
  readonly cloudAllowedHosts?: ReadonlySet<string>;
  readonly cloudFetchImpl?: CloudFetchLike;
  /**
   * Asks the control API where to upload a Tegra Cloud backup. When set it is
   * used for every Tegra Cloud upload (manual and scheduled) and a URL sent
   * inside a command is ignored.
   */
  readonly cloudUploadUrlProvider?: CloudUploadUrlProvider;
  /** Confirms a completed Tegra Cloud backup upload with the control API. */
  readonly cloudUploadConfirmer?: (cloudBackupId: string) => Promise<void>;
  /** Emits throttled progress and terminal events for background uploads. */
  readonly onUploadProgress?: (event: ServerBackupUploadEvent) => void;
  /** Minimum interval between `uploading` progress events per upload (default 500 ms). */
  readonly uploadProgressThrottleMs?: number;
  readonly s3MaxBytes?: number;
  readonly maxArchiveFiles?: number;
  readonly maxArchiveBytes?: number;
  readonly timers?: BackupTimerProvider;
  readonly now?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly logger?: Logger;
  readonly serverGroupId?: number | null;
  readonly archiveImpl?: (options: ArchiveServerDirectoryOptions) => ServerArchiveResult;
  readonly makeServerReadableImpl?: MakeServerReadableLike;
}

export interface CreateLocalBackupOptions {
  readonly server_id: string;
  readonly trigger: BackupTrigger;
  readonly note?: string;
}

export interface BackupManager {
  readonly configStore: BackupConfigStore;
  readonly scheduler: BackupScheduler;
  getConfig(serverId: string): ServerBackupConfig;
  setConfig(params: ServerBackupConfigSetBody): ServerBackupConfig;
  createBackup(params: CreateBackupOptions): Promise<BackupCreateResult>;
  createLocalBackup(params: CreateLocalBackupOptions): Promise<BackupCreateResult>;
  listBackups(params: ServerBackupListBody): Promise<{
    readonly server_id: string;
    readonly backups: readonly BackupMetadata[];
    readonly errors: readonly BackupDestinationError[];
  }>;
  deleteBackup(params: ServerBackupDeleteBody): Promise<BackupDeleteResult>;
  restoreBackup(params: ServerBackupRestoreBody): Promise<BackupRestoreResult>;
  waitForPendingUploads(): Promise<void>;
  createBackupHook(): BackupHook;
  start(): void;
  close(): void;
}

const DEFAULT_UPLOAD_PROGRESS_THROTTLE_MS = 500;
const MAX_FAILED_UPLOAD_RECORDS = 128;

interface PendingUploadRecord {
  readonly server_id: string;
  readonly backup_id: string;
  readonly destination: BackupDestinationKind;
  state: BackupUploadState;
  sent_bytes: number;
  readonly total_bytes: number;
  error?: string;
}

function toStableBackupUploadErrorCode(err: unknown): string {
  if (err instanceof AgentApiError) {
    if (err.code === "http_error") {
      if (err.status === 413) return "quota_exceeded";
      if (err.status === 409) return "backup_not_ready";
      if (err.status === 404) return "backup_not_found";
      return "http_error";
    }
    return err.code;
  }
  if (err instanceof ProtocolError) {
    return err.code;
  }
  return "backup_failed";
}

export function createBackupManager(options: BackupManagerOptions): BackupManager {
  const serversBaseDir = options.serversBaseDir ?? DEFAULT_SERVERS_BASE_DIR;
  const allowInsecure = options.allowInsecure ?? false;
  const now = options.now ?? (() => Date.now());
  const permissionContext: PermissionContext = createServerPermissionContext({
    serversRoot: serversBaseDir,
    ...(options.serverGroupId !== undefined ? { serverGroupId: options.serverGroupId } : {}),
    ...(options.logger !== undefined ? { logger: options.logger } : {}),
  });

  const configStore = new BackupConfigStore({
    stateDir: options.stateDir,
    allowInsecure,
  });

  const destinations: readonly BackupDestination[] = options.destinations ?? [
    new LocalBackupDestination({
      backupsDir: options.localBackupsDir ?? DEFAULT_LOCAL_BACKUPS_DIR,
      configStore,
    }),
    new S3BackupDestination({
      configStore,
      allowInsecure,
      ...(options.s3MaxBytes !== undefined ? { maxBytes: options.s3MaxBytes } : {}),
    }),
    new TegraCloudBackupDestination({
      stateDir: options.stateDir,
      configStore,
      allowInsecure,
      ...(options.cloudAllowedHosts !== undefined
        ? { allowedHosts: options.cloudAllowedHosts }
        : {}),
      ...(options.cloudTimeoutMs !== undefined ? { timeoutMs: options.cloudTimeoutMs } : {}),
      ...(options.cloudMaxBytes !== undefined ? { maxBytes: options.cloudMaxBytes } : {}),
      ...(options.cloudFetchImpl !== undefined ? { fetchImpl: options.cloudFetchImpl } : {}),
    }),
  ];

  const destinationMap = new Map<BackupDestinationKind, BackupDestination>();
  for (const dest of destinations) {
    destinationMap.set(dest.kind, dest);
  }

  const uploadProgressThrottleMs =
    options.uploadProgressThrottleMs ?? DEFAULT_UPLOAD_PROGRESS_THROTTLE_MS;
  const pendingUploads = new Map<string, PendingUploadRecord>();
  const activeBackgroundUploads = new Set<Promise<void>>();

  function uploadRecordKey(
    serverId: string,
    backupId: string,
    destination: BackupDestinationKind,
  ): string {
    return `${serverId}\0${backupId}\0${destination}`;
  }

  function emitUploadProgress(record: PendingUploadRecord): void {
    if (options.onUploadProgress === undefined) {
      return;
    }
    const event: ServerBackupUploadEvent = {
      server_id: record.server_id,
      backup_id: record.backup_id,
      destination: record.destination,
      state: record.state,
      sent_bytes: record.sent_bytes,
      total_bytes: record.total_bytes,
      ...(record.error !== undefined ? { error: record.error } : {}),
    };
    try {
      options.onUploadProgress(event);
    } catch {
      // Progress listener failures must never interrupt background uploads.
    }
  }

  function pruneFailedUploadRecords(): void {
    let failedCount = 0;
    for (const record of pendingUploads.values()) {
      if (record.state === "failed") {
        failedCount++;
      }
    }
    if (failedCount <= MAX_FAILED_UPLOAD_RECORDS) {
      return;
    }
    let toRemove = failedCount - MAX_FAILED_UPLOAD_RECORDS;
    for (const [key, record] of pendingUploads.entries()) {
      if (toRemove <= 0) {
        break;
      }
      if (record.state === "failed") {
        pendingUploads.delete(key);
        toRemove--;
      }
    }
  }

  async function executeDestinationUpload(
    dest: BackupDestination,
    buffer: Uint8Array,
    ctxParams: {
      readonly serverId: string;
      readonly backupId: string;
      readonly createdAt: number;
      readonly sha256: string;
      readonly trigger: BackupTrigger;
      readonly note?: string;
      readonly retentionCount?: number;
      readonly tegraCloudUploadUrl?: string;
      readonly onProgress?: (sentBytes: number, totalBytes: number) => void;
    },
  ): Promise<BackupMetadata> {
    let cloudTarget: CloudUploadTarget | undefined;
    if (dest.kind === "tegra_cloud" && options.cloudUploadUrlProvider !== undefined) {
      cloudTarget = await options.cloudUploadUrlProvider({
        server_id: ctxParams.serverId,
        size_bytes: buffer.byteLength,
      });
      if (buffer.byteLength > cloudTarget.max_bytes) {
        throw new ProtocolError(
          "backup_failed",
          `Backup archive size (${buffer.byteLength}) exceeds the allowed upload size (${cloudTarget.max_bytes})`,
        );
      }
    }
    const cloudId = cloudTarget?.id;
    const confirmer = options.cloudUploadConfirmer;
    const confirmUpload =
      dest.kind === "tegra_cloud" && cloudId !== undefined && confirmer !== undefined
        ? () => confirmer(cloudId)
        : undefined;

    return await dest.upload(buffer, {
      serverId: ctxParams.serverId,
      backupId: ctxParams.backupId,
      createdAt: ctxParams.createdAt,
      sha256: ctxParams.sha256,
      trigger: ctxParams.trigger,
      ...(ctxParams.note !== undefined ? { note: ctxParams.note } : {}),
      ...(ctxParams.retentionCount !== undefined
        ? { retentionCount: ctxParams.retentionCount }
        : {}),
      ...(ctxParams.onProgress !== undefined ? { onProgress: ctxParams.onProgress } : {}),
      ...(confirmUpload !== undefined ? { confirmUpload } : {}),
      ...(cloudTarget !== undefined
        ? {
            presignedUploadUrl: cloudTarget.put_url,
            presignedUploadHeaders: cloudTarget.headers,
          }
        : dest.kind === "tegra_cloud" && ctxParams.tegraCloudUploadUrl !== undefined
          ? { presignedUploadUrl: ctxParams.tegraCloudUploadUrl }
          : {}),
    });
  }

  async function runInlineDestinationUpload(
    dest: BackupDestination,
    buffer: Uint8Array,
    ctxParams: {
      readonly serverId: string;
      readonly backupId: string;
      readonly createdAt: number;
      readonly sha256: string;
      readonly trigger: BackupTrigger;
      readonly note?: string;
      readonly retentionCount?: number;
      readonly tegraCloudUploadUrl?: string;
    },
  ): Promise<BackupDestinationOutcome> {
    try {
      const meta = await executeDestinationUpload(dest, buffer, ctxParams);
      return {
        destination: dest.kind,
        ok: true,
        backup: meta,
      };
    } catch (err) {
      const message = redactUrlQueryStrings(err instanceof Error ? err.message : String(err));
      options.logger?.error("Backup destination upload failed", {
        serverId: ctxParams.serverId,
        backupId: ctxParams.backupId,
        destination: dest.kind,
        errName: err instanceof Error ? err.name : "Error",
      });
      return {
        destination: dest.kind,
        ok: false,
        error: message,
      };
    }
  }

  function startBackgroundUpload(
    dest: BackupDestination,
    buffer: Uint8Array,
    record: PendingUploadRecord,
    ctxParams: {
      readonly serverId: string;
      readonly backupId: string;
      readonly createdAt: number;
      readonly sha256: string;
      readonly trigger: BackupTrigger;
      readonly note?: string;
      readonly retentionCount?: number;
      readonly tegraCloudUploadUrl?: string;
    },
  ): void {
    const key = uploadRecordKey(record.server_id, record.backup_id, record.destination);
    const task = (async () => {
      // Yield a microtask so the caller receives the initial queued result before uploading starts.
      await Promise.resolve();
      record.state = "uploading";
      record.sent_bytes = 0;
      let lastEmitAt = now();
      emitUploadProgress(record);

      try {
        await executeDestinationUpload(dest, buffer, {
          ...ctxParams,
          onProgress: (sentBytes, totalBytes) => {
            const clamped = Math.max(0, Math.min(Math.trunc(sentBytes), totalBytes));
            record.sent_bytes = clamped;
            const current = now();
            if (current - lastEmitAt >= uploadProgressThrottleMs) {
              lastEmitAt = current;
              emitUploadProgress(record);
            }
          },
        });
        pendingUploads.delete(key);
        record.state = "done";
        record.sent_bytes = record.total_bytes;
        delete record.error;
        emitUploadProgress(record);
      } catch (err) {
        const errorCode = toStableBackupUploadErrorCode(err);
        record.state = "failed";
        record.error = errorCode;
        pruneFailedUploadRecords();
        options.logger?.error("Background backup destination upload failed", {
          serverId: ctxParams.serverId,
          backupId: ctxParams.backupId,
          destination: dest.kind,
          code: errorCode,
          errName: err instanceof Error ? err.name : "Error",
        });
        emitUploadProgress(record);
      }
    })().finally(() => {
      activeBackgroundUploads.delete(task);
    });
    activeBackgroundUploads.add(task);
  }

  function getConfig(serverId: string): ServerBackupConfig {
    return configStore.getServerConfig(serverId);
  }

  async function createBackup(params: CreateBackupOptions): Promise<BackupCreateResult> {
    const validServerId = serverIdSchema.parse(params.server_id);
    const trigger: BackupTrigger = params.trigger ?? "manual";
    const createdAt = now();
    const backupId = formatBackupId(createdAt);

    const enabledDestinations = destinations.filter((d) => d.isEnabled(validServerId));
    if (enabledDestinations.length === 0) {
      return {
        backup_id: backupId,
        server_id: validServerId,
        created_at: createdAt,
        size_bytes: 0,
        sha256: "",
        trigger,
        destinations: [],
      };
    }

    const orderedDestinations = [...enabledDestinations].sort((a, b) => {
      if (a.kind === "local" && b.kind !== "local") return -1;
      if (b.kind === "local" && a.kind !== "local") return 1;
      return 0;
    });

    const archiveResult = await createConsistentServerArchive({
      serversBaseDir,
      serverId: validServerId,
      ...(options.runtime !== undefined ? { runtime: options.runtime } : {}),
      ...(options.saveTimeoutMs !== undefined ? { saveTimeoutMs: options.saveTimeoutMs } : {}),
      ...(options.savePollIntervalMs !== undefined
        ? { savePollIntervalMs: options.savePollIntervalMs }
        : {}),
      ...(options.maxArchiveFiles !== undefined ? { maxFiles: options.maxArchiveFiles } : {}),
      ...(options.maxArchiveBytes !== undefined ? { maxTotalBytes: options.maxArchiveBytes } : {}),
      now,
      ...(options.sleep !== undefined ? { sleep: options.sleep } : {}),
      ...(options.logger !== undefined ? { logger: options.logger } : {}),
      ...(options.archiveImpl !== undefined ? { archiveImpl: options.archiveImpl } : {}),
      ...(options.makeServerReadableImpl !== undefined
        ? { makeServerReadableImpl: options.makeServerReadableImpl }
        : {}),
    });

    const baseCtx = {
      serverId: validServerId,
      backupId,
      createdAt,
      sha256: archiveResult.sha256,
      trigger,
      ...(params.note !== undefined ? { note: params.note } : {}),
      ...(params.retention_count !== undefined ? { retentionCount: params.retention_count } : {}),
      ...(params.tegra_cloud_upload_url !== undefined
        ? { tegraCloudUploadUrl: params.tegra_cloud_upload_url }
        : {}),
    };

    const [primary, ...secondary] = orderedDestinations;
    if (primary === undefined) {
      return {
        backup_id: backupId,
        server_id: validServerId,
        created_at: createdAt,
        size_bytes: archiveResult.buffer.byteLength,
        sha256: archiveResult.sha256,
        trigger,
        destinations: [],
      };
    }

    const primaryOutcome = await runInlineDestinationUpload(primary, archiveResult.buffer, baseCtx);

    if (secondary.length === 0) {
      return {
        backup_id: backupId,
        server_id: validServerId,
        created_at: createdAt,
        size_bytes: archiveResult.buffer.byteLength,
        sha256: archiveResult.sha256,
        trigger,
        destinations: [primaryOutcome],
      };
    }

    const initialPending: PendingBackupUpload[] = [];
    for (const dest of secondary) {
      const record: PendingUploadRecord = {
        server_id: validServerId,
        backup_id: backupId,
        destination: dest.kind,
        state: "queued",
        sent_bytes: 0,
        total_bytes: archiveResult.buffer.byteLength,
      };
      pendingUploads.set(uploadRecordKey(validServerId, backupId, dest.kind), record);
      emitUploadProgress(record);
      initialPending.push({
        destination: dest.kind,
        state: "queued",
        sent_bytes: 0,
        total_bytes: archiveResult.buffer.byteLength,
      });
      startBackgroundUpload(dest, archiveResult.buffer, record, baseCtx);
    }

    return {
      backup_id: backupId,
      server_id: validServerId,
      created_at: createdAt,
      size_bytes: archiveResult.buffer.byteLength,
      sha256: archiveResult.sha256,
      trigger,
      destinations: [primaryOutcome],
      pending_uploads: initialPending,
    };
  }

  async function createLocalBackup(params: CreateLocalBackupOptions): Promise<BackupCreateResult> {
    const validServerId = serverIdSchema.parse(params.server_id);
    const localDest = destinationMap.get("local");
    if (localDest === undefined) {
      throw new ProtocolError("backup_failed", "Local backup destination is not available");
    }

    const createdAt = now();
    const backupId = formatBackupId(createdAt);
    const archiveResult = await createConsistentServerArchive({
      serversBaseDir,
      serverId: validServerId,
      ...(options.runtime !== undefined ? { runtime: options.runtime } : {}),
      ...(options.saveTimeoutMs !== undefined ? { saveTimeoutMs: options.saveTimeoutMs } : {}),
      ...(options.savePollIntervalMs !== undefined
        ? { savePollIntervalMs: options.savePollIntervalMs }
        : {}),
      ...(options.maxArchiveFiles !== undefined ? { maxFiles: options.maxArchiveFiles } : {}),
      ...(options.maxArchiveBytes !== undefined ? { maxTotalBytes: options.maxArchiveBytes } : {}),
      now,
      ...(options.sleep !== undefined ? { sleep: options.sleep } : {}),
      ...(options.logger !== undefined ? { logger: options.logger } : {}),
      ...(options.archiveImpl !== undefined ? { archiveImpl: options.archiveImpl } : {}),
      ...(options.makeServerReadableImpl !== undefined
        ? { makeServerReadableImpl: options.makeServerReadableImpl }
        : {}),
    });

    const meta = await localDest.upload(archiveResult.buffer, {
      serverId: validServerId,
      backupId,
      createdAt,
      sha256: archiveResult.sha256,
      trigger: params.trigger,
      ...(params.note !== undefined ? { note: params.note } : {}),
    });

    return {
      backup_id: backupId,
      server_id: validServerId,
      created_at: createdAt,
      size_bytes: archiveResult.buffer.byteLength,
      sha256: archiveResult.sha256,
      trigger: params.trigger,
      destinations: [{ destination: "local", ok: true, backup: meta }],
    };
  }

  async function listBackups(params: ServerBackupListBody): Promise<{
    readonly server_id: string;
    readonly backups: readonly BackupMetadata[];
    readonly errors: readonly BackupDestinationError[];
  }> {
    const validServerId = serverIdSchema.parse(params.server_id);
    const targets =
      params.destination !== undefined
        ? ([destinationMap.get(params.destination)].filter(
            (d): d is BackupDestination => d !== undefined,
          ) as BackupDestination[])
        : destinations.filter((d) => d.isEnabled(validServerId));

    const allBackups: BackupMetadata[] = [];
    const errors: BackupDestinationError[] = [];

    for (const dest of targets) {
      try {
        const list = await dest.list(validServerId);
        allBackups.push(...list);
      } catch (err) {
        errors.push({
          destination: dest.kind,
          error: redactUrlQueryStrings(err instanceof Error ? err.message : String(err)),
        });
      }
    }

    allBackups.sort((a, b) => b.created_at - a.created_at || b.id.localeCompare(a.id));

    const pendingByBackupId = new Map<string, PendingBackupUpload[]>();
    for (const record of pendingUploads.values()) {
      if (record.server_id !== validServerId) {
        continue;
      }
      if (params.destination !== undefined && record.destination !== params.destination) {
        continue;
      }
      const list = pendingByBackupId.get(record.backup_id) ?? [];
      list.push({
        destination: record.destination,
        state: record.state,
        sent_bytes: record.sent_bytes,
        total_bytes: record.total_bytes,
        ...(record.error !== undefined ? { error: record.error } : {}),
      });
      pendingByBackupId.set(record.backup_id, list);
    }

    const enrichedBackups = allBackups.map((backup) => {
      const pending = (pendingByBackupId.get(backup.id) ?? []).filter(
        (entry) => entry.destination !== backup.destination,
      );
      return pending.length > 0 ? { ...backup, pending_uploads: pending } : backup;
    });

    return {
      server_id: validServerId,
      backups: enrichedBackups,
      errors,
    };
  }

  async function deleteBackup(params: ServerBackupDeleteBody): Promise<BackupDeleteResult> {
    const validServerId = serverIdSchema.parse(params.server_id);
    const validBackupId = backupIdSchema.parse(params.backup_id);

    if (params.destination !== undefined) {
      const dest = destinationMap.get(params.destination);
      if (dest === undefined) {
        throw new ProtocolError(
          "backup_config_invalid",
          `Unknown backup destination: ${params.destination}`,
        );
      }
      await dest.delete(validServerId, validBackupId);
      pendingUploads.delete(uploadRecordKey(validServerId, validBackupId, dest.kind));
      return {
        server_id: validServerId,
        backup_id: validBackupId,
        results: [{ destination: dest.kind, ok: true }],
      };
    }

    for (const dest of destinations) {
      pendingUploads.delete(uploadRecordKey(validServerId, validBackupId, dest.kind));
    }

    const targets = destinations.filter((d) => d.isEnabled(validServerId));
    const results: BackupDeleteDestinationResult[] = [];
    let allNotFound = targets.length > 0;

    for (const dest of targets) {
      try {
        await dest.delete(validServerId, validBackupId);
        results.push({ destination: dest.kind, ok: true });
        allNotFound = false;
      } catch (err) {
        if (!(err instanceof ProtocolError && err.code === "backup_not_found")) {
          allNotFound = false;
        }
        results.push({
          destination: dest.kind,
          ok: false,
          error: redactUrlQueryStrings(err instanceof Error ? err.message : String(err)),
        });
      }
    }

    if (allNotFound) {
      throw new ProtocolError("backup_not_found", `Backup not found: ${validBackupId}`);
    }

    return {
      server_id: validServerId,
      backup_id: validBackupId,
      results,
    };
  }

  async function resolveRestoreDestination(
    serverId: string,
    backupId: string,
    explicit?: BackupDestinationKind,
  ): Promise<BackupDestination> {
    if (explicit !== undefined) {
      const dest = destinationMap.get(explicit);
      if (dest === undefined) {
        throw new ProtocolError("backup_config_invalid", `Unknown backup destination: ${explicit}`);
      }
      return dest;
    }

    for (const dest of destinations) {
      if (!dest.isEnabled(serverId)) {
        continue;
      }
      try {
        const items = await dest.list(serverId);
        if (items.some((item) => item.id === backupId)) {
          return dest;
        }
      } catch {
        // Continue checking other destinations
      }
    }

    const localDest = destinationMap.get("local");
    if (localDest !== undefined) {
      return localDest;
    }

    throw new ProtocolError("backup_not_found", `Backup not found: ${backupId}`);
  }

  async function restoreBackup(params: ServerBackupRestoreBody): Promise<BackupRestoreResult> {
    const validServerId = serverIdSchema.parse(params.server_id);
    const validBackupId = backupIdSchema.parse(params.backup_id);

    const sourceDest = await resolveRestoreDestination(
      validServerId,
      validBackupId,
      params.destination,
    );

    const archive = await sourceDest.download(validServerId, validBackupId, {
      ...(params.tegra_cloud_download_url !== undefined
        ? { presignedDownloadUrl: params.tegra_cloud_download_url }
        : {}),
    });

    // Always take a safety backup of the current server state before restoring.
    let safetyBackup: BackupCreateResult | undefined;
    const enabled = destinations.filter((d) => d.isEnabled(validServerId));
    if (enabled.length > 0) {
      const candidate = await createBackup({
        server_id: validServerId,
        trigger: "pre_restore",
        note: `Safety backup before restoring ${validBackupId}`,
      });
      if (candidate.destinations.some((d) => d.ok)) {
        safetyBackup = candidate;
      }
    }

    if (safetyBackup === undefined) {
      safetyBackup = await createLocalBackup({
        server_id: validServerId,
        trigger: "pre_restore",
        note: `Safety backup before restoring ${validBackupId}`,
      });
    }

    const extracted = restoreServerArchive({
      serversBaseDir,
      serverId: validServerId,
      archive,
      permissions: permissionContext,
    });

    return {
      server_id: validServerId,
      backup_id: validBackupId,
      destination: sourceDest.kind,
      safety_backup: safetyBackup,
      restored_files: extracted.files.length,
      restored_bytes: extracted.totalBytes,
    };
  }

  const scheduler = createBackupScheduler({
    configStore,
    runScheduledBackup: async (serverId, retentionCount) => {
      await createBackup({
        server_id: serverId,
        trigger: "scheduled",
        retention_count: retentionCount,
      });
    },
    ...(options.timers !== undefined ? { timers: options.timers } : {}),
    ...(options.logger !== undefined ? { logger: options.logger } : {}),
  });

  function setConfig(params: ServerBackupConfigSetBody): ServerBackupConfig {
    const updated = configStore.setServerConfig(params);
    scheduler.syncServer(updated.server_id, updated.schedule);
    return updated;
  }

  const manager: BackupManager = {
    configStore,
    scheduler,
    getConfig,
    setConfig,
    createBackup,
    createLocalBackup,
    listBackups,
    deleteBackup,
    restoreBackup,
    async waitForPendingUploads(): Promise<void> {
      while (activeBackgroundUploads.size > 0) {
        await Promise.all([...activeBackgroundUploads]);
      }
    },
    createBackupHook: () => createBackupHook(manager),
    start() {
      scheduler.start();
    },
    close() {
      scheduler.stop();
    },
  };

  return manager;
}

export function createBackupHook(manager: BackupManager): BackupHook {
  return {
    async beforeChange(serverId: string): Promise<void> {
      const validId = serverIdSchema.parse(serverId);
      const cfg = manager.getConfig(validId);
      if (!cfg.auto_before_change) {
        return;
      }
      await manager.createBackup({
        server_id: validId,
        trigger: "before_change",
      });
    },
  };
}

export function registerBackupHandlers(queue: CommandQueue, manager: BackupManager): void {
  queue.registerHandler("server.backup.config.set", (opened, ctx) => {
    const body = opened.body as ServerBackupConfigSetBody;
    const config = manager.setConfig(body);
    ctx.sendEvent("server.backup.config.updated", { config });
  });

  queue.registerHandler("server.backup.config.get", (opened, ctx) => {
    const body = opened.body as { readonly server_id: string };
    ctx.sendEvent("server.backup.config.result", { config: manager.getConfig(body.server_id) });
  });

  queue.registerHandler("server.backup.create", async (opened, ctx) => {
    const body = opened.body as ServerBackupCreateBody;
    const result = await manager.createBackup({
      server_id: body.server_id,
      trigger: "manual",
      ...(body.note !== undefined ? { note: body.note } : {}),
      ...(body.tegra_cloud_upload_url !== undefined
        ? { tegra_cloud_upload_url: body.tegra_cloud_upload_url }
        : {}),
    });
    ctx.sendEvent("server.backup.created", result);
  });

  queue.registerHandler("server.backup.list", async (opened, ctx) => {
    const body = opened.body as ServerBackupListBody;
    const result = await manager.listBackups(body);
    ctx.sendEvent("server.backup.list.result", result);
  });

  queue.registerHandler("server.backup.delete", async (opened, ctx) => {
    const body = opened.body as ServerBackupDeleteBody;
    const result = await manager.deleteBackup(body);
    ctx.sendEvent("server.backup.deleted", result);
  });

  queue.registerHandler("server.backup.restore", async (opened, ctx) => {
    const body = opened.body as ServerBackupRestoreBody;
    const result = await manager.restoreBackup(body);
    ctx.sendEvent("server.backup.restored", result);
  });
}
