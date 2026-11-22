// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { writeFileAtomic } from "../../agent/state";
import { backupIdSchema, ProtocolError, serverIdSchema } from "../../protocol";
import { type BackupConfigStore, validateRemoteHttpsUrl } from "../config";
import type {
  BackupDestination,
  BackupDownloadOptions,
  BackupMetadata,
  BackupUploadContext,
} from "../types";

export const DEFAULT_TEGRA_CLOUD_TIMEOUT_MS = 120_000;
export const DEFAULT_TEGRA_CLOUD_MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2 GiB

const SECRET_FILE_MODE = 0o600;
const STATE_DIR_MODE = 0o700;

const cloudMetadataSchema = z
  .object({
    id: backupIdSchema,
    server_id: serverIdSchema,
    created_at: z.number().int().nonnegative(),
    size_bytes: z.number().int().nonnegative(),
    sha256: z.string().regex(/^[0-9a-f]{64}$/),
    trigger: z.enum(["manual", "scheduled", "before_change", "pre_restore"]),
    destination: z.literal("tegra_cloud"),
    note: z.string().max(256).optional(),
  })
  .strict();

const cloudIndexFileSchema = z
  .object({
    v: z.literal(1),
    servers: z.record(serverIdSchema, z.array(cloudMetadataSchema)),
  })
  .strict();

export type CloudFetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

/**
 * Tegra Cloud backup destination using short-lived presigned URLs provided by
 * the control plane per operation:
 *
 * - Upload contract:
 *   `PUT <presignedUploadUrl>` with `Content-Type: application/zip`,
 *   `Content-Length`, `X-Tegra-Backup-Id`, `X-Tegra-Server-Id`, and
 *   `X-Tegra-Backup-Sha256`. Redirects are rejected (`redirect: "error"`).
 *   Expects any 2xx response.
 *
 * - Download contract (for restore):
 *   `GET <presignedDownloadUrl>` with `redirect: "error"`. Expects 200 OK
 *   and streams up to `maxBytes`.
 *
 * Presigned URLs are never persisted on disk or logged.
 */
export interface TegraCloudBackupDestinationOptions {
  readonly stateDir: string;
  readonly configStore: BackupConfigStore;
  readonly allowInsecure?: boolean;
  readonly timeoutMs?: number;
  readonly maxBytes?: number;
  readonly fetchImpl?: CloudFetchLike;
}

async function readResponseBytesCapped(response: Response, maxBytes: number): Promise<Uint8Array> {
  const contentLengthHeader = response.headers.get("content-length");
  if (contentLengthHeader !== null) {
    const declared = Number(contentLengthHeader);
    if (Number.isFinite(declared) && declared > maxBytes) {
      throw new ProtocolError(
        "backup_failed",
        `Tegra Cloud download exceeds maximum allowed size (${maxBytes} bytes)`,
      );
    }
  }

  if (response.body === null) {
    return new Uint8Array(0);
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) {
        break;
      }
      if (value === undefined || value.byteLength === 0) {
        continue;
      }
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new ProtocolError(
          "backup_failed",
          `Tegra Cloud download exceeds maximum allowed size (${maxBytes} bytes)`,
        );
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

export class TegraCloudBackupDestination implements BackupDestination {
  readonly kind = "tegra_cloud" as const;
  readonly indexPath: string;
  private readonly configStore: BackupConfigStore;
  private readonly allowInsecure: boolean;
  private readonly timeoutMs: number;
  private readonly maxBytes: number;
  private readonly fetchImpl: CloudFetchLike;

  constructor(options: TegraCloudBackupDestinationOptions) {
    this.indexPath = join(options.stateDir, "backup-cloud-index.json");
    this.configStore = options.configStore;
    this.allowInsecure = options.allowInsecure ?? false;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TEGRA_CLOUD_TIMEOUT_MS;
    this.maxBytes = options.maxBytes ?? DEFAULT_TEGRA_CLOUD_MAX_BYTES;
    this.fetchImpl = options.fetchImpl ?? ((input, init) => fetch(input, init));
  }

  isEnabled(serverId: string): boolean {
    return this.configStore.getServerConfig(serverId).tegra_cloud.enabled;
  }

  private readIndex(): Record<string, BackupMetadata[]> {
    if (!existsSync(this.indexPath)) {
      return {};
    }
    try {
      const parsed = cloudIndexFileSchema.safeParse(
        JSON.parse(readFileSync(this.indexPath, "utf8")),
      );
      if (!parsed.success) {
        return {};
      }
      const copy: Record<string, BackupMetadata[]> = {};
      for (const [sid, list] of Object.entries(parsed.data.servers)) {
        copy[sid] = [...list];
      }
      return copy;
    } catch {
      return {};
    }
  }

  private writeIndex(servers: Record<string, BackupMetadata[]>): void {
    const payload = `${JSON.stringify({ v: 1, servers }, null, 2)}\n`;
    writeFileAtomic(this.indexPath, payload, {
      mode: SECRET_FILE_MODE,
      dirMode: STATE_DIR_MODE,
    });
  }

  async upload(archive: Uint8Array, ctx: BackupUploadContext): Promise<BackupMetadata> {
    const validServerId = serverIdSchema.parse(ctx.serverId);
    const validBackupId = backupIdSchema.parse(ctx.backupId);

    if (!ctx.presignedUploadUrl) {
      throw new ProtocolError(
        "backup_failed",
        "Tegra Cloud upload requires a presigned upload URL",
      );
    }

    if (archive.byteLength > this.maxBytes) {
      throw new ProtocolError(
        "backup_failed",
        `Backup archive size (${archive.byteLength}) exceeds Tegra Cloud limit (${this.maxBytes})`,
      );
    }

    const validatedUrl = validateRemoteHttpsUrl(
      ctx.presignedUploadUrl,
      "tegra_cloud_upload_url",
      this.allowInsecure,
    );

    const response = await this.fetchImpl(validatedUrl, {
      method: "PUT",
      headers: {
        "Content-Type": "application/zip",
        "Content-Length": String(archive.byteLength),
        "X-Tegra-Backup-Id": validBackupId,
        "X-Tegra-Server-Id": validServerId,
        "X-Tegra-Backup-Sha256": ctx.sha256,
      },
      body: archive,
      redirect: "error",
      signal: AbortSignal.timeout(this.timeoutMs),
    });

    if (!response.ok) {
      throw new ProtocolError(
        "backup_failed",
        `Tegra Cloud upload failed with HTTP ${response.status}`,
      );
    }

    const metadata: BackupMetadata = {
      id: validBackupId,
      server_id: validServerId,
      created_at: ctx.createdAt,
      size_bytes: archive.byteLength,
      sha256: ctx.sha256,
      trigger: ctx.trigger,
      destination: "tegra_cloud",
      ...(ctx.note !== undefined ? { note: ctx.note } : {}),
    };

    const index = this.readIndex();
    const existing = index[validServerId] ?? [];
    const retention =
      ctx.retentionCount ??
      this.configStore.getServerConfig(validServerId).tegra_cloud.retention_count;
    const next = [metadata, ...existing.filter((b) => b.id !== validBackupId)]
      .sort((a, b) => b.created_at - a.created_at || b.id.localeCompare(a.id))
      .slice(0, retention);
    index[validServerId] = next;
    this.writeIndex(index);

    return metadata;
  }

  async list(serverId: string): Promise<readonly BackupMetadata[]> {
    const validServerId = serverIdSchema.parse(serverId);
    const index = this.readIndex();
    const list = index[validServerId] ?? [];
    return [...list].sort((a, b) => b.created_at - a.created_at || b.id.localeCompare(a.id));
  }

  async download(
    serverId: string,
    backupId: string,
    options?: BackupDownloadOptions,
  ): Promise<Uint8Array> {
    serverIdSchema.parse(serverId);
    backupIdSchema.parse(backupId);

    const rawUrl = options?.presignedDownloadUrl;
    if (!rawUrl) {
      throw new ProtocolError(
        "backup_failed",
        "Tegra Cloud restore requires a presigned download URL",
      );
    }

    const validatedUrl = validateRemoteHttpsUrl(
      rawUrl,
      "tegra_cloud_download_url",
      this.allowInsecure,
    );

    const response = await this.fetchImpl(validatedUrl, {
      method: "GET",
      redirect: "error",
      signal: AbortSignal.timeout(this.timeoutMs),
    });

    if (response.status === 404) {
      throw new ProtocolError("backup_not_found", `Tegra Cloud backup not found: ${backupId}`);
    }
    if (!response.ok) {
      throw new ProtocolError(
        "backup_failed",
        `Tegra Cloud download failed with HTTP ${response.status}`,
      );
    }

    return readResponseBytesCapped(response, this.maxBytes);
  }

  async delete(serverId: string, backupId: string): Promise<void> {
    const validServerId = serverIdSchema.parse(serverId);
    const validBackupId = backupIdSchema.parse(backupId);
    const index = this.readIndex();
    const existing = index[validServerId] ?? [];
    const next = existing.filter((b) => b.id !== validBackupId);
    if (next.length === existing.length) {
      throw new ProtocolError("backup_not_found", `Tegra Cloud backup not found: ${validBackupId}`);
    }
    index[validServerId] = next;
    this.writeIndex(index);
  }
}
