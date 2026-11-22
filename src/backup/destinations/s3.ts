// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
import { backupIdSchema, ProtocolError, serverIdSchema } from "../../protocol";
import { type BackupConfigStore, validateRemoteHttpsUrl } from "../config";
import type { BackupDestination, BackupMetadata, BackupUploadContext } from "../types";

const s3MetadataSchema = z
  .object({
    id: backupIdSchema,
    server_id: serverIdSchema,
    created_at: z.number().int().nonnegative(),
    size_bytes: z.number().int().nonnegative(),
    sha256: z.string().regex(/^[0-9a-f]{64}$/),
    trigger: z.enum(["manual", "scheduled", "before_change", "pre_restore"]),
    destination: z.literal("s3"),
    note: z.string().max(256).optional(),
  })
  .strict();

const s3IndexSchema = z
  .object({
    v: z.literal(1),
    backups: z.array(s3MetadataSchema),
  })
  .strict();

function normalizePrefix(prefix: string | undefined): string {
  if (!prefix) {
    return "";
  }
  const trimmed = prefix.replace(/^\/+/, "").replace(/\/+$/, "");
  return trimmed.length > 0 ? `${trimmed}/` : "";
}

export interface S3BackupDestinationOptions {
  readonly configStore: BackupConfigStore;
  readonly allowInsecure?: boolean;
}

export class S3BackupDestination implements BackupDestination {
  readonly kind = "s3" as const;
  private readonly configStore: BackupConfigStore;
  private readonly allowInsecure: boolean;

  constructor(options: S3BackupDestinationOptions) {
    this.configStore = options.configStore;
    this.allowInsecure = options.allowInsecure ?? false;
  }

  isEnabled(serverId: string): boolean {
    return this.configStore.getServerConfig(serverId).s3.enabled;
  }

  private createClient(serverId: string): {
    readonly client: Bun.S3Client;
    readonly prefix: string;
    readonly retentionCount: number;
  } {
    const validServerId = serverIdSchema.parse(serverId);
    const cfg = this.configStore.getServerConfig(validServerId).s3;
    if (!cfg.enabled) {
      throw new ProtocolError("backup_config_invalid", "S3 backup destination is not enabled");
    }
    if (!cfg.bucket || !cfg.endpoint) {
      throw new ProtocolError("backup_config_invalid", "S3 bucket and endpoint must be configured");
    }

    const endpoint = validateRemoteHttpsUrl(cfg.endpoint, "s3.endpoint", this.allowInsecure);
    const creds = this.configStore.getS3Credentials(validServerId);
    if (creds === null) {
      throw new ProtocolError("backup_config_invalid", "S3 credentials are not configured");
    }

    const client = new Bun.S3Client({
      accessKeyId: creds.access_key_id,
      secretAccessKey: creds.secret_access_key,
      ...(creds.session_token !== undefined ? { sessionToken: creds.session_token } : {}),
      bucket: cfg.bucket,
      endpoint,
      ...(cfg.region !== undefined ? { region: cfg.region } : {}),
    });

    return {
      client,
      prefix: normalizePrefix(cfg.prefix),
      retentionCount: cfg.retention_count,
    };
  }

  private archiveKey(prefix: string, serverId: string, backupId: string): string {
    return `${prefix}${serverId}/${backupId}.zip`;
  }

  private indexKey(prefix: string, serverId: string): string {
    return `${prefix}${serverId}/index.json`;
  }

  private async readIndex(
    client: Bun.S3Client,
    prefix: string,
    serverId: string,
  ): Promise<BackupMetadata[]> {
    const key = this.indexKey(prefix, serverId);
    try {
      const exists = await client.exists(key);
      if (!exists) {
        return [];
      }
      const text = await client.file(key).text();
      const parsed = s3IndexSchema.safeParse(JSON.parse(text));
      if (!parsed.success) {
        return [];
      }
      return [...parsed.data.backups];
    } catch {
      return [];
    }
  }

  private async writeIndex(
    client: Bun.S3Client,
    prefix: string,
    serverId: string,
    backups: readonly BackupMetadata[],
  ): Promise<void> {
    const key = this.indexKey(prefix, serverId);
    const payload = `${JSON.stringify({ v: 1, backups }, null, 2)}\n`;
    await client.write(key, payload, { type: "application/json" });
  }

  async upload(archive: Uint8Array, ctx: BackupUploadContext): Promise<BackupMetadata> {
    const validServerId = serverIdSchema.parse(ctx.serverId);
    const validBackupId = backupIdSchema.parse(ctx.backupId);
    const { client, prefix, retentionCount } = this.createClient(validServerId);

    const key = this.archiveKey(prefix, validServerId, validBackupId);
    await client.write(key, archive, { type: "application/zip" });

    const metadata: BackupMetadata = {
      id: validBackupId,
      server_id: validServerId,
      created_at: ctx.createdAt,
      size_bytes: archive.byteLength,
      sha256: ctx.sha256,
      trigger: ctx.trigger,
      destination: "s3",
      ...(ctx.note !== undefined ? { note: ctx.note } : {}),
    };

    const existing = await this.readIndex(client, prefix, validServerId);
    const combined = [metadata, ...existing.filter((b) => b.id !== validBackupId)].sort(
      (a, b) => b.created_at - a.created_at || b.id.localeCompare(a.id),
    );

    const limit = ctx.retentionCount ?? retentionCount;
    const kept = combined.slice(0, limit);
    const evicted = combined.slice(limit);

    for (const old of evicted) {
      try {
        await client.delete(this.archiveKey(prefix, validServerId, old.id));
      } catch {
        // Ignore individual eviction delete errors
      }
    }

    await this.writeIndex(client, prefix, validServerId, kept);
    return metadata;
  }

  async list(serverId: string): Promise<readonly BackupMetadata[]> {
    const validServerId = serverIdSchema.parse(serverId);
    const { client, prefix } = this.createClient(validServerId);
    const items = await this.readIndex(client, prefix, validServerId);
    items.sort((a, b) => b.created_at - a.created_at || b.id.localeCompare(a.id));
    return items;
  }

  async download(serverId: string, backupId: string): Promise<Uint8Array> {
    const validServerId = serverIdSchema.parse(serverId);
    const validBackupId = backupIdSchema.parse(backupId);
    const { client, prefix } = this.createClient(validServerId);
    const key = this.archiveKey(prefix, validServerId, validBackupId);

    const exists = await client.exists(key);
    if (!exists) {
      throw new ProtocolError("backup_not_found", `S3 backup not found: ${validBackupId}`);
    }

    return client.file(key).bytes();
  }

  async delete(serverId: string, backupId: string): Promise<void> {
    const validServerId = serverIdSchema.parse(serverId);
    const validBackupId = backupIdSchema.parse(backupId);
    const { client, prefix } = this.createClient(validServerId);
    const key = this.archiveKey(prefix, validServerId, validBackupId);

    await client.delete(key);
    const existing = await this.readIndex(client, prefix, validServerId);
    const next = existing.filter((b) => b.id !== validBackupId);
    await this.writeIndex(client, prefix, validServerId, next);
  }
}
