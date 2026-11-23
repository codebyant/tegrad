// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { randomBytes } from "node:crypto";
import type { CommandQueue } from "../agent/jobs";
import type { Logger } from "../agent/logger";
import { DEFAULT_SERVERS_BASE_DIR } from "../files";
import {
  type BackupDestinationKind,
  backupIdSchema,
  ProtocolError,
  type ServerBackupConfigSetBody,
  type ServerBackupCreateBody,
  type ServerBackupDeleteBody,
  type ServerBackupListBody,
  type ServerBackupRestoreBody,
  serverIdSchema,
} from "../protocol";
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
  readonly s3MaxBytes?: number;
  readonly maxArchiveFiles?: number;
  readonly maxArchiveBytes?: number;
  readonly timers?: BackupTimerProvider;
  readonly now?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly logger?: Logger;
  readonly archiveImpl?: (options: ArchiveServerDirectoryOptions) => ServerArchiveResult;
}

export interface BackupManager {
  readonly configStore: BackupConfigStore;
  readonly scheduler: BackupScheduler;
  getConfig(serverId: string): ServerBackupConfig;
  setConfig(params: ServerBackupConfigSetBody): ServerBackupConfig;
  createBackup(params: CreateBackupOptions): Promise<BackupCreateResult>;
  listBackups(params: ServerBackupListBody): Promise<{
    readonly server_id: string;
    readonly backups: readonly BackupMetadata[];
    readonly errors: readonly BackupDestinationError[];
  }>;
  deleteBackup(params: ServerBackupDeleteBody): Promise<BackupDeleteResult>;
  restoreBackup(params: ServerBackupRestoreBody): Promise<BackupRestoreResult>;
  createBackupHook(): BackupHook;
  start(): void;
  close(): void;
}

export function createBackupManager(options: BackupManagerOptions): BackupManager {
  const serversBaseDir = options.serversBaseDir ?? DEFAULT_SERVERS_BASE_DIR;
  const allowInsecure = options.allowInsecure ?? false;
  const now = options.now ?? (() => Date.now());

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
    });

    const outcomes: BackupDestinationOutcome[] = [];
    for (const dest of enabledDestinations) {
      try {
        let cloudTarget: CloudUploadTarget | undefined;
        if (dest.kind === "tegra_cloud" && options.cloudUploadUrlProvider !== undefined) {
          cloudTarget = await options.cloudUploadUrlProvider({
            server_id: validServerId,
            size_bytes: archiveResult.buffer.byteLength,
          });
          if (archiveResult.buffer.byteLength > cloudTarget.max_bytes) {
            throw new ProtocolError(
              "backup_failed",
              `Backup archive size (${archiveResult.buffer.byteLength}) exceeds the allowed upload size (${cloudTarget.max_bytes})`,
            );
          }
        }
        const meta = await dest.upload(archiveResult.buffer, {
          serverId: validServerId,
          backupId,
          createdAt,
          sha256: archiveResult.sha256,
          trigger,
          ...(params.note !== undefined ? { note: params.note } : {}),
          ...(params.retention_count !== undefined
            ? { retentionCount: params.retention_count }
            : {}),
          ...(cloudTarget !== undefined
            ? {
                presignedUploadUrl: cloudTarget.put_url,
                presignedUploadHeaders: cloudTarget.headers,
              }
            : dest.kind === "tegra_cloud" && params.tegra_cloud_upload_url !== undefined
              ? { presignedUploadUrl: params.tegra_cloud_upload_url }
              : {}),
        });
        outcomes.push({
          destination: dest.kind,
          ok: true,
          backup: meta,
        });
      } catch (err) {
        const message = redactUrlQueryStrings(err instanceof Error ? err.message : String(err));
        options.logger?.error("Backup destination upload failed", {
          serverId: validServerId,
          backupId,
          destination: dest.kind,
          errName: err instanceof Error ? err.name : "Error",
        });
        outcomes.push({
          destination: dest.kind,
          ok: false,
          error: message,
        });
      }
    }

    return {
      backup_id: backupId,
      server_id: validServerId,
      created_at: createdAt,
      size_bytes: archiveResult.buffer.byteLength,
      sha256: archiveResult.sha256,
      trigger,
      destinations: outcomes,
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
    return {
      server_id: validServerId,
      backups: allBackups,
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
      return {
        server_id: validServerId,
        backup_id: validBackupId,
        results: [{ destination: dest.kind, ok: true }],
      };
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
      const createdAt = now();
      const safetyId = formatBackupId(createdAt);
      const localDest = destinationMap.get("local");
      if (localDest === undefined) {
        throw new ProtocolError(
          "backup_failed",
          "Failed to create pre-restore safety backup before restoring",
        );
      }
      const currentArchive = await createConsistentServerArchive({
        serversBaseDir,
        serverId: validServerId,
        ...(options.runtime !== undefined ? { runtime: options.runtime } : {}),
        ...(options.saveTimeoutMs !== undefined ? { saveTimeoutMs: options.saveTimeoutMs } : {}),
        ...(options.savePollIntervalMs !== undefined
          ? { savePollIntervalMs: options.savePollIntervalMs }
          : {}),
        ...(options.maxArchiveFiles !== undefined ? { maxFiles: options.maxArchiveFiles } : {}),
        ...(options.maxArchiveBytes !== undefined
          ? { maxTotalBytes: options.maxArchiveBytes }
          : {}),
        now,
        ...(options.sleep !== undefined ? { sleep: options.sleep } : {}),
        ...(options.logger !== undefined ? { logger: options.logger } : {}),
        ...(options.archiveImpl !== undefined ? { archiveImpl: options.archiveImpl } : {}),
      });
      const meta = await localDest.upload(currentArchive.buffer, {
        serverId: validServerId,
        backupId: safetyId,
        createdAt,
        sha256: currentArchive.sha256,
        trigger: "pre_restore",
        note: `Safety backup before restoring ${validBackupId}`,
      });
      safetyBackup = {
        backup_id: safetyId,
        server_id: validServerId,
        created_at: createdAt,
        size_bytes: currentArchive.buffer.byteLength,
        sha256: currentArchive.sha256,
        trigger: "pre_restore",
        destinations: [{ destination: "local", ok: true, backup: meta }],
      };
    }

    const extracted = restoreServerArchive({
      serversBaseDir,
      serverId: validServerId,
      archive,
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
    listBackups,
    deleteBackup,
    restoreBackup,
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
