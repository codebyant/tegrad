// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import { z } from "zod";
import { writeFileAtomic } from "../../agent/state";
import { backupIdSchema, ProtocolError, serverIdSchema } from "../../protocol";
import type { BackupConfigStore } from "../config";
import type { BackupDestination, BackupMetadata, BackupUploadContext } from "../types";

export const DEFAULT_LOCAL_BACKUPS_DIR = "/var/lib/tegrad-backups";

const BACKUP_DIR_MODE = 0o700;
const BACKUP_FILE_MODE = 0o600;

const localMetadataSchema = z
  .object({
    id: backupIdSchema,
    server_id: serverIdSchema,
    created_at: z.number().int().nonnegative(),
    size_bytes: z.number().int().nonnegative(),
    sha256: z.string().regex(/^[0-9a-f]{64}$/),
    trigger: z.enum(["manual", "scheduled", "before_change", "pre_restore"]),
    destination: z.literal("local"),
    note: z.string().max(256).optional(),
  })
  .strict();

function isPosix(platform: NodeJS.Platform = process.platform): boolean {
  return platform !== "win32";
}

function ensurePrivateDir(dirPath: string): void {
  mkdirSync(dirPath, { recursive: true, mode: BACKUP_DIR_MODE });
  if (isPosix()) {
    chmodSync(dirPath, BACKUP_DIR_MODE);
  }
}

function writeBinaryAtomic(filePath: string, data: Uint8Array): void {
  const dir = dirname(filePath);
  ensurePrivateDir(dir);

  const suffix = randomBytes(8).toString("hex");
  const tmpPath = join(dir, `.tmp-${basename(filePath)}-${process.pid}-${suffix}`);
  let fd: number | undefined;
  try {
    fd = openSync(tmpPath, "wx", BACKUP_FILE_MODE);
    writeFileSync(fd, data);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;

    if (isPosix()) {
      chmodSync(tmpPath, BACKUP_FILE_MODE);
    }
    renameSync(tmpPath, filePath);
  } catch (err) {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        // ignore close failure
      }
    }
    try {
      if (existsSync(tmpPath)) {
        unlinkSync(tmpPath);
      }
    } catch {
      // ignore cleanup failure
    }
    throw err;
  }
}

export interface LocalBackupDestinationOptions {
  readonly backupsDir?: string;
  readonly configStore: BackupConfigStore;
}

export class LocalBackupDestination implements BackupDestination {
  readonly kind = "local" as const;
  readonly backupsDir: string;
  private readonly configStore: BackupConfigStore;

  constructor(options: LocalBackupDestinationOptions) {
    this.backupsDir = options.backupsDir ?? DEFAULT_LOCAL_BACKUPS_DIR;
    this.configStore = options.configStore;
  }

  isEnabled(serverId: string): boolean {
    return this.configStore.getServerConfig(serverId).local.enabled;
  }

  private getServerBackupDir(serverId: string): string {
    const validId = serverIdSchema.parse(serverId);
    return join(this.backupsDir, validId);
  }

  private getBackupPaths(
    serverId: string,
    backupId: string,
  ): { readonly zipPath: string; readonly metaPath: string } {
    const validBackupId = backupIdSchema.parse(backupId);
    const serverDir = this.getServerBackupDir(serverId);
    return {
      zipPath: join(serverDir, `${validBackupId}.zip`),
      metaPath: join(serverDir, `${validBackupId}.json`),
    };
  }

  async upload(archive: Uint8Array, ctx: BackupUploadContext): Promise<BackupMetadata> {
    const validServerId = serverIdSchema.parse(ctx.serverId);
    const validBackupId = backupIdSchema.parse(ctx.backupId);
    ensurePrivateDir(this.backupsDir);
    ensurePrivateDir(this.getServerBackupDir(validServerId));

    const { zipPath, metaPath } = this.getBackupPaths(validServerId, validBackupId);
    writeBinaryAtomic(zipPath, archive);

    const metadata: BackupMetadata = {
      id: validBackupId,
      server_id: validServerId,
      created_at: ctx.createdAt,
      size_bytes: archive.byteLength,
      sha256: ctx.sha256,
      trigger: ctx.trigger,
      destination: "local",
      ...(ctx.note !== undefined ? { note: ctx.note } : {}),
    };

    writeFileAtomic(metaPath, `${JSON.stringify(metadata, null, 2)}\n`, {
      mode: BACKUP_FILE_MODE,
      dirMode: BACKUP_DIR_MODE,
    });

    const retention =
      ctx.retentionCount ?? this.configStore.getServerConfig(validServerId).local.retention_count;
    await this.rotate(validServerId, retention);

    return metadata;
  }

  private async rotate(serverId: string, retentionCount: number): Promise<void> {
    const backups = await this.list(serverId);
    if (backups.length <= retentionCount) {
      return;
    }
    const toRemove = backups.slice(retentionCount);
    for (const old of toRemove) {
      try {
        await this.delete(serverId, old.id);
      } catch {
        // Ignore individual rotation delete errors
      }
    }
  }

  async list(serverId: string): Promise<readonly BackupMetadata[]> {
    const serverDir = this.getServerBackupDir(serverId);
    if (!existsSync(serverDir)) {
      return [];
    }

    const entries = readdirSync(serverDir);
    const results: BackupMetadata[] = [];

    for (const name of entries) {
      if (!name.endsWith(".json") || name.startsWith(".tmp-")) {
        continue;
      }
      const fullPath = join(serverDir, name);
      const stat = lstatSync(fullPath, { throwIfNoEntry: false });
      if (stat === undefined || stat.isSymbolicLink() || !stat.isFile()) {
        continue;
      }
      try {
        const parsed = localMetadataSchema.safeParse(JSON.parse(readFileSync(fullPath, "utf8")));
        if (parsed.success && parsed.data.server_id === serverId) {
          results.push(parsed.data);
        }
      } catch {
        // Ignore corrupt metadata files during listing
      }
    }

    results.sort((a, b) => b.created_at - a.created_at || b.id.localeCompare(a.id));
    return results;
  }

  async download(serverId: string, backupId: string): Promise<Uint8Array> {
    const { zipPath } = this.getBackupPaths(serverId, backupId);
    const stat = lstatSync(zipPath, { throwIfNoEntry: false });
    if (stat === undefined) {
      throw new ProtocolError("backup_not_found", `Local backup not found: ${backupId}`);
    }
    if (stat.isSymbolicLink() || !stat.isFile()) {
      throw new ProtocolError("backup_failed", `Invalid local backup archive: ${backupId}`);
    }
    const buf = readFileSync(zipPath);
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  async delete(serverId: string, backupId: string): Promise<void> {
    const { zipPath, metaPath } = this.getBackupPaths(serverId, backupId);
    const zipExists = existsSync(zipPath);
    const metaExists = existsSync(metaPath);
    if (!zipExists && !metaExists) {
      throw new ProtocolError("backup_not_found", `Local backup not found: ${backupId}`);
    }
    if (zipExists) {
      unlinkSync(zipPath);
    }
    if (metaExists) {
      unlinkSync(metaPath);
    }
  }
}
