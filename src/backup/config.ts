// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { assertStrictPermissions, writeFileAtomic } from "../agent/state";
import {
  backupScheduleConfigSchema,
  MAX_BACKUP_RETENTION_COUNT,
  MIN_BACKUP_RETENTION_COUNT,
  ProtocolError,
  type ServerBackupConfigSetBody,
  s3BucketSchema,
  s3PrefixSchema,
  s3RegionSchema,
  serverBackupConfigSetBodySchema,
  serverIdSchema,
} from "../protocol";
import type { S3Credentials, ServerBackupConfig } from "./types";

export const DEFAULT_LOCAL_RETENTION_COUNT = 10;
export const DEFAULT_S3_RETENTION_COUNT = 10;
export const DEFAULT_TEGRA_CLOUD_RETENTION_COUNT = 10;

const SECRET_FILE_MODE = 0o600;
const STATE_DIR_MODE = 0o700;

const storedS3ConfigSchema = z
  .object({
    enabled: z.boolean(),
    bucket: s3BucketSchema.optional(),
    region: s3RegionSchema.optional(),
    endpoint: z.string().min(1).max(512).optional(),
    prefix: s3PrefixSchema.optional(),
    retention_count: z
      .number()
      .int()
      .min(MIN_BACKUP_RETENTION_COUNT)
      .max(MAX_BACKUP_RETENTION_COUNT),
  })
  .strict();

const storedServerBackupConfigSchema = z
  .object({
    auto_before_change: z.boolean(),
    schedule: backupScheduleConfigSchema.optional(),
    local: z
      .object({
        enabled: z.boolean(),
        retention_count: z
          .number()
          .int()
          .min(MIN_BACKUP_RETENTION_COUNT)
          .max(MAX_BACKUP_RETENTION_COUNT),
      })
      .strict(),
    s3: storedS3ConfigSchema,
    tegra_cloud: z
      .object({
        enabled: z.boolean(),
        retention_count: z
          .number()
          .int()
          .min(MIN_BACKUP_RETENTION_COUNT)
          .max(MAX_BACKUP_RETENTION_COUNT),
      })
      .strict(),
  })
  .strict();

type StoredServerBackupConfig = z.infer<typeof storedServerBackupConfigSchema>;

const backupConfigFileSchema = z
  .object({
    v: z.literal(1),
    servers: z.record(serverIdSchema, storedServerBackupConfigSchema),
  })
  .strict();

const s3CredentialsEntrySchema = z
  .object({
    access_key_id: z.string().min(1).max(256),
    secret_access_key: z.string().min(1).max(256),
    session_token: z.string().min(1).max(2048).optional(),
  })
  .strict();

const s3CredentialsFileSchema = z
  .object({
    v: z.literal(1),
    servers: z.record(serverIdSchema, s3CredentialsEntrySchema),
  })
  .strict();

function isPrivateOrLoopbackIpv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) {
    return false;
  }
  const nums = parts.map((p) => Number(p));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return false;
  }
  const a = nums[0] ?? -1;
  const b = nums[1] ?? -1;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

function isBlockedPrivateOrLoopbackHost(rawHostname: string): boolean {
  const host = rawHostname.toLowerCase().replace(/^\[/, "").replace(/\]$/, "");
  if (host === "localhost" || host.endsWith(".localhost")) {
    return true;
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
    return isPrivateOrLoopbackIpv4(host);
  }
  if (host.includes(":")) {
    if (host === "::" || host === "::1" || /^0*(?::0*){6}:0*1$/.test(host)) {
      return true;
    }
    const mappedV4 = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(host);
    if (mappedV4?.[1] !== undefined) {
      return isPrivateOrLoopbackIpv4(mappedV4[1]);
    }
    const mappedHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
    if (mappedHex?.[1] !== undefined && mappedHex[2] !== undefined) {
      const hi = Number.parseInt(mappedHex[1], 16);
      const lo = Number.parseInt(mappedHex[2], 16);
      const ip = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
      return isPrivateOrLoopbackIpv4(ip);
    }
    const first = host.split(":")[0] ?? "";
    if (/^(?:fc|fd|fe[89ab])/.test(first)) {
      return true;
    }
  }
  return false;
}

export function redactUrlQueryStrings(message: string): string {
  return message.replace(/(https?:\/\/[^\s"'<>?]+)\?[^\s"'<>]+/gi, "$1?<redacted>");
}

export function validateRemoteHttpsUrl(
  rawUrl: string,
  label: string,
  allowInsecure: boolean,
  allowedHosts?: ReadonlySet<string>,
): string {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new ProtocolError("backup_config_invalid", `Invalid ${label}`);
  }

  if (parsed.username.length > 0 || parsed.password.length > 0) {
    throw new ProtocolError("backup_config_invalid", `${label} must not contain credentials`);
  }

  if (parsed.hash.length > 0) {
    throw new ProtocolError("backup_config_invalid", `${label} must not contain a URL fragment`);
  }

  const host = parsed.hostname.toLowerCase();
  const isLoopback =
    host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host === "::1";

  if (parsed.protocol === "https:") {
    if (!allowInsecure) {
      if (isBlockedPrivateOrLoopbackHost(host)) {
        throw new ProtocolError(
          "backup_config_invalid",
          `${label} must not target a private or loopback address`,
        );
      }
      if (allowedHosts !== undefined) {
        if (parsed.port !== "") {
          throw new ProtocolError(
            "backup_config_invalid",
            `${label} must not specify a non-standard port`,
          );
        }
        if (!allowedHosts.has(host)) {
          throw new ProtocolError("backup_config_invalid", `${label} host is not allowed`);
        }
      }
    }
    return parsed.toString();
  }

  if (allowInsecure && parsed.protocol === "http:" && isLoopback) {
    return parsed.toString();
  }

  throw new ProtocolError("backup_config_invalid", `${label} must use https://`);
}

function defaultStoredConfig(): StoredServerBackupConfig {
  return {
    auto_before_change: true,
    local: {
      enabled: true,
      retention_count: DEFAULT_LOCAL_RETENTION_COUNT,
    },
    s3: {
      enabled: false,
      retention_count: DEFAULT_S3_RETENTION_COUNT,
    },
    tegra_cloud: {
      enabled: false,
      retention_count: DEFAULT_TEGRA_CLOUD_RETENTION_COUNT,
    },
  };
}

function readJsonOrNull(filePath: string, strictPerms: boolean): unknown | null {
  if (!existsSync(filePath)) {
    return null;
  }
  if (strictPerms) {
    assertStrictPermissions(filePath);
  }
  let raw: string;
  try {
    raw = readFileSync(filePath, "utf8");
  } catch (err) {
    throw new ProtocolError(
      "backup_config_invalid",
      `Failed to read backup state file: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    throw new ProtocolError("backup_config_invalid", "Malformed JSON in backup state file");
  }
}

export interface BackupConfigStoreOptions {
  readonly stateDir: string;
  readonly allowInsecure?: boolean;
}

export class BackupConfigStore {
  readonly configPath: string;
  readonly s3CredentialsPath: string;
  private readonly allowInsecure: boolean;

  constructor(options: BackupConfigStoreOptions) {
    this.configPath = join(options.stateDir, "backup-config.json");
    this.s3CredentialsPath = join(options.stateDir, "backup-s3-credentials.json");
    this.allowInsecure = options.allowInsecure ?? false;
  }

  private readAllConfigs(): Record<string, StoredServerBackupConfig> {
    const raw = readJsonOrNull(this.configPath, false);
    if (raw === null) {
      return {};
    }
    const parsed = backupConfigFileSchema.safeParse(raw);
    if (!parsed.success) {
      throw new ProtocolError("backup_config_invalid", "Invalid backup-config.json");
    }
    return { ...parsed.data.servers };
  }

  private writeAllConfigs(servers: Record<string, StoredServerBackupConfig>): void {
    const payload = `${JSON.stringify({ v: 1, servers }, null, 2)}\n`;
    writeFileAtomic(this.configPath, payload, {
      mode: SECRET_FILE_MODE,
      dirMode: STATE_DIR_MODE,
    });
  }

  private readAllS3Credentials(): Record<string, S3Credentials> {
    const raw = readJsonOrNull(this.s3CredentialsPath, true);
    if (raw === null) {
      return {};
    }
    const parsed = s3CredentialsFileSchema.safeParse(raw);
    if (!parsed.success) {
      throw new ProtocolError("backup_config_invalid", "Invalid backup-s3-credentials.json");
    }
    return { ...parsed.data.servers };
  }

  private writeAllS3Credentials(servers: Record<string, S3Credentials>): void {
    const payload = `${JSON.stringify({ v: 1, servers }, null, 2)}\n`;
    writeFileAtomic(this.s3CredentialsPath, payload, {
      mode: SECRET_FILE_MODE,
      dirMode: STATE_DIR_MODE,
    });
  }

  getS3Credentials(serverId: string): S3Credentials | null {
    const validId = serverIdSchema.parse(serverId);
    const all = this.readAllS3Credentials();
    return all[validId] ?? null;
  }

  getServerConfig(serverId: string): ServerBackupConfig {
    const validId = serverIdSchema.parse(serverId);
    const all = this.readAllConfigs();
    const stored = all[validId] ?? defaultStoredConfig();
    const creds = this.getS3Credentials(validId);

    return {
      server_id: validId,
      auto_before_change: stored.auto_before_change,
      ...(stored.schedule !== undefined ? { schedule: stored.schedule } : {}),
      local: { ...stored.local },
      s3: {
        ...stored.s3,
        credentials_configured: creds !== null,
      },
      tegra_cloud: { ...stored.tegra_cloud },
    };
  }

  listConfiguredServerIds(): string[] {
    return Object.keys(this.readAllConfigs()).sort();
  }

  setServerConfig(input: ServerBackupConfigSetBody): ServerBackupConfig {
    const parsed = serverBackupConfigSetBodySchema.safeParse(input);
    if (!parsed.success) {
      throw new ProtocolError("invalid_body", "Invalid server.backup.config.set parameters");
    }

    const data = parsed.data;
    const validId = data.server_id;
    const allConfigs = this.readAllConfigs();
    const existing = allConfigs[validId] ?? defaultStoredConfig();

    const nextLocal =
      data.local !== undefined
        ? {
            enabled: data.local.enabled,
            retention_count: data.local.retention_count ?? existing.local.retention_count,
          }
        : existing.local;

    const nextTegraCloud =
      data.tegra_cloud !== undefined
        ? {
            enabled: data.tegra_cloud.enabled,
            retention_count:
              data.tegra_cloud.retention_count ?? existing.tegra_cloud.retention_count,
          }
        : existing.tegra_cloud;

    let nextS3 = existing.s3;
    let credsToSave: S3Credentials | undefined;

    if (data.s3 !== undefined) {
      const endpoint =
        data.s3.endpoint !== undefined
          ? validateRemoteHttpsUrl(data.s3.endpoint, "s3.endpoint", this.allowInsecure)
          : existing.s3.endpoint;
      const bucket = data.s3.bucket ?? existing.s3.bucket;
      const region = data.s3.region ?? existing.s3.region;
      const prefix = data.s3.prefix ?? existing.s3.prefix;
      const retentionCount = data.s3.retention_count ?? existing.s3.retention_count;

      if (data.s3.access_key_id !== undefined || data.s3.secret_access_key !== undefined) {
        if (data.s3.access_key_id === undefined || data.s3.secret_access_key === undefined) {
          throw new ProtocolError(
            "backup_config_invalid",
            "Both s3.access_key_id and s3.secret_access_key must be provided together",
          );
        }
        credsToSave = {
          access_key_id: data.s3.access_key_id,
          secret_access_key: data.s3.secret_access_key,
          ...(data.s3.session_token !== undefined ? { session_token: data.s3.session_token } : {}),
        };
      }

      if (data.s3.enabled) {
        if (bucket === undefined || bucket.length === 0) {
          throw new ProtocolError(
            "backup_config_invalid",
            "s3.bucket is required when S3 is enabled",
          );
        }
        if (endpoint === undefined || endpoint.length === 0) {
          throw new ProtocolError(
            "backup_config_invalid",
            "s3.endpoint is required when S3 is enabled",
          );
        }
        const existingCreds = credsToSave ?? this.getS3Credentials(validId);
        if (existingCreds === null) {
          throw new ProtocolError(
            "backup_config_invalid",
            "S3 credentials are required when S3 is enabled",
          );
        }
      }

      nextS3 = {
        enabled: data.s3.enabled,
        ...(bucket !== undefined ? { bucket } : {}),
        ...(region !== undefined ? { region } : {}),
        ...(endpoint !== undefined ? { endpoint } : {}),
        ...(prefix !== undefined ? { prefix } : {}),
        retention_count: retentionCount,
      };
    }

    const nextConfig: StoredServerBackupConfig = {
      auto_before_change: data.auto_before_change ?? existing.auto_before_change,
      ...(data.schedule !== undefined
        ? { schedule: data.schedule }
        : existing.schedule !== undefined
          ? { schedule: existing.schedule }
          : {}),
      local: nextLocal,
      s3: nextS3,
      tegra_cloud: nextTegraCloud,
    };

    if (credsToSave !== undefined) {
      const allCreds = this.readAllS3Credentials();
      allCreds[validId] = credsToSave;
      this.writeAllS3Credentials(allCreds);
    }

    allConfigs[validId] = nextConfig;
    this.writeAllConfigs(allConfigs);

    return this.getServerConfig(validId);
  }
}
