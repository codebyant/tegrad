// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, unlinkSync } from "node:fs";
import { basename, join } from "node:path";
import { z } from "zod";
import {
  AgentApiError,
  type ResolvedModpack,
  type ResolvedModpackFile,
  type ResolveModpackRequest,
} from "../agent/api-client";
import type { CommandQueue } from "../agent/jobs";
import type { Logger } from "../agent/logger";
import { writeFileAtomic } from "../agent/state";
import { redactUrlQueryStrings } from "../backup/config";
import {
  FileManagerError,
  findServerPackRoot,
  listZipEntryNames,
  readZipEntryFromBuffer,
  resolveConfinedPath,
  safeUnzipPrefixesFromBuffer,
  validateSingleFileName,
  writeConfinedFileAtomic,
} from "../files";
import {
  type ModpackInstallErrorCode,
  type ModpackInstallJobState,
  type ModpackInstallJobStatus,
  type ModpackInstallPhase,
  type ModpackInstallSkippedItem,
  type ModpackSource,
  modpackInstallErrorCodeSchema,
  modpackInstallJobStateSchema,
  modpackInstallPhaseSchema,
  modpackInstallSkippedItemSchema,
  modpackSourceSchema,
  ProtocolError,
  type ServerInstallModpackBody,
  type ServerInstallModpackCancelBody,
  type ServerInstallModpackProgressEvent,
  type ServerInstallModpackResultEvent,
  type ServerInstallModpackStatusResult,
  type ServerModEntry,
  type ServerOrigin,
  type ServerOriginSyncState,
  serverInstallModpackBodySchema,
  serverInstallModpackCancelBodySchema,
  serverModEntrySchema,
} from "../protocol";
import type { FetchLike } from "../server/download";
import { assertValidServerId, DEFAULT_SERVERS_DIR } from "../server/id";
import { createServerPermissionContext, type PermissionContext } from "../server/permissions";
import { readServerMetadata, type ServerMetadata, writeServerMetadata } from "../server/registry";
import {
  buildAllowedDownloadHosts,
  DEFAULT_MAX_MOD_BYTES,
  downloadVerifiedBuffer,
  downloadVerifiedToFile,
  isUrlHostAllowed,
} from "./download";
import { indexExtractedServerPackFiles, PROTECTED_SERVERPACK_PATHS } from "./manager";
import {
  isClientOnly,
  isServerContentPath,
  modIdentityKey,
  normalizeRelativePath,
} from "./sync-plan";

const MODS_DIR = "mods";
const JOBS_SUBDIR = "modpack-installs";
const DEFAULT_CONCURRENCY = 4;
/** Official server packs commonly reach 500-800 MB; the archive is streamed to disk. */
export const DEFAULT_MAX_MODPACK_SERVER_PACK_BYTES = 2 * 1024 * 1024 * 1024;
const SERVER_PACK_DOWNLOAD_TIMEOUT_MS = 30 * 60 * 1000;

export interface ModpackInstallerOptions {
  readonly stateDir: string;
  readonly serversDir?: string;
  readonly cdnHost?: string;
  readonly extraAllowedHosts?: readonly string[];
  readonly fetchImpl?: FetchLike;
  readonly maxModBytes?: number;
  readonly maxServerPackBytes?: number;
  readonly maxRedirects?: number;
  readonly downloadTimeoutMs?: number;
  readonly concurrency?: number;
  readonly now?: () => number;
  readonly logger?: Logger;
  readonly serverGroupId?: number | null;
  readonly isServerActive: (serverId: string) => Promise<boolean>;
  readonly resolveModpack: (
    request: ResolveModpackRequest,
    signal?: AbortSignal,
  ) => Promise<ResolvedModpack>;
  readonly onProgress?: (event: ServerInstallModpackProgressEvent) => void;
  readonly onResult?: (event: ServerInstallModpackResultEvent) => void;
}

export interface StartModpackInstallResult {
  readonly job_id: string;
  readonly server_id: string;
}

export interface CancelModpackInstallResult {
  readonly server_id: string;
  readonly job_id?: string | undefined;
  readonly cancelled: boolean;
}

export interface ModpackInstaller {
  startInstall(params: ServerInstallModpackBody): Promise<StartModpackInstallResult>;
  getStatus(serverId: string): ServerInstallModpackStatusResult;
  cancelInstall(params: ServerInstallModpackCancelBody): CancelModpackInstallResult;
  start(): void;
  waitForActiveJobs(): Promise<void>;
  close(): Promise<void>;
}

const persistedResolvedSchema = z.object({
  server_pack: z
    .object({
      url: z.string(),
      sha1: z.string().optional(),
      sha256: z.string().optional(),
      sha512: z.string().optional(),
      name: z.string(),
      size: z.number().int().nonnegative().optional(),
    })
    .optional(),
  files: z.array(
    z.object({
      name: z.string(),
      path: z.string().optional(),
      url: z.string().optional(),
      sha1: z.string().optional(),
      sha256: z.string().optional(),
      sha512: z.string().optional(),
      size: z.number().int().nonnegative().optional(),
      environment: z
        .object({
          client: z.enum(["required", "optional", "unsupported", "unknown"]).optional(),
          server: z.enum(["required", "optional", "unsupported", "unknown"]).optional(),
        })
        .optional(),
      project_id: z.string().optional(),
      version_id: z.string().optional(),
      blocked: z.boolean().optional(),
      blocked_reason: z.string().optional(),
    }),
  ),
  overrides: z
    .object({
      url: z.string(),
      sha1: z.string().optional(),
      sha256: z.string().optional(),
      sha512: z.string().optional(),
      size: z.number().int().nonnegative().optional(),
      prefix: z.string().optional(),
      format: z.enum(["mrpack", "zip"]).optional(),
    })
    .optional(),
  minecraft_version: z.string(),
  loader: z.string(),
  loader_version: z.string().optional(),
});

const persistedJobSchema = z.object({
  v: z.literal(1),
  job_id: z.string().min(1),
  server_id: z.string().min(1),
  source: modpackSourceSchema,
  modpack_id: z.string().min(1),
  version_id: z.string().min(1),
  modpack_name: z.string().optional(),
  version_label: z.string().optional(),
  status: modpackInstallJobStateSchema,
  phase: modpackInstallPhaseSchema,
  done: z.number().int().nonnegative(),
  total: z.number().int().nonnegative(),
  current: z.string().optional(),
  installed: z.number().int().nonnegative(),
  skipped: z.array(modpackInstallSkippedItemSchema),
  error_code: modpackInstallErrorCodeSchema.optional(),
  started_at: z.number().int().nonnegative(),
  updated_at: z.number().int().nonnegative(),
  finished_at: z.number().int().nonnegative().optional(),
  resolved: persistedResolvedSchema.optional(),
  server_pack_extracted: z.boolean().optional(),
  overrides_extracted: z.boolean().optional(),
  completed_files: z.array(z.string()).default([]),
  written_paths: z.array(z.string()).default([]),
  installed_mods: z.array(serverModEntrySchema).default([]),
  synced_files: z.array(z.string()).default([]),
});

interface PersistedJobRecord {
  readonly v: 1;
  readonly job_id: string;
  readonly server_id: string;
  readonly source: ModpackSource;
  readonly modpack_id: string;
  readonly version_id: string;
  readonly modpack_name?: string | undefined;
  readonly version_label?: string | undefined;
  status: ModpackInstallJobState;
  phase: ModpackInstallPhase;
  done: number;
  total: number;
  current?: string | undefined;
  installed: number;
  skipped: ModpackInstallSkippedItem[];
  error_code?: ModpackInstallErrorCode | undefined;
  readonly started_at: number;
  updated_at: number;
  finished_at?: number | undefined;
  resolved?: ResolvedModpack | undefined;
  server_pack_extracted?: boolean | undefined;
  overrides_extracted?: boolean | undefined;
  completed_files: string[];
  written_paths: string[];
  installed_mods: ServerModEntry[];
  synced_files: string[];
}

const mrpackIndexSchema = z.object({
  files: z.array(
    z.object({
      path: z.string().min(1),
      hashes: z
        .object({
          sha1: z.string().optional(),
          sha512: z.string().optional(),
        })
        .optional(),
      env: z
        .object({
          client: z.enum(["required", "optional", "unsupported", "unknown"]).optional(),
          server: z.enum(["required", "optional", "unsupported", "unknown"]).optional(),
        })
        .optional(),
      downloads: z.array(z.string()).default([]),
      fileSize: z.number().int().nonnegative().optional(),
    }),
  ),
});

function toJobStatusSnapshot(record: PersistedJobRecord): ModpackInstallJobStatus {
  return {
    job_id: record.job_id,
    server_id: record.server_id,
    source: record.source,
    modpack_id: record.modpack_id,
    version_id: record.version_id,
    ...(record.modpack_name !== undefined ? { modpack_name: record.modpack_name } : {}),
    ...(record.version_label !== undefined ? { version_label: record.version_label } : {}),
    status: record.status,
    phase: record.phase,
    done: record.done,
    total: record.total,
    ...(record.current !== undefined ? { current: record.current } : {}),
    installed: record.installed,
    skipped: [...record.skipped],
    ...(record.error_code !== undefined ? { error_code: record.error_code } : {}),
    started_at: record.started_at,
    updated_at: record.updated_at,
    ...(record.finished_at !== undefined ? { finished_at: record.finished_at } : {}),
  };
}

function classifyInstallError(err: unknown): ModpackInstallErrorCode {
  if (err instanceof AgentApiError) {
    if (err.code === "aborted") {
      return "cancelled";
    }
    if (err.code === "http_error" && err.status === 404) {
      return "pack_unavailable";
    }
    return "api_unavailable";
  }

  if (err instanceof FileManagerError) {
    switch (err.code) {
      case "zip_too_large":
      case "zip_entry_too_large":
      case "zip_compression_ratio_exceeded":
      case "file_too_large":
        return "too_large";
      case "zip_slip":
      case "path_traversal":
      case "zip_symlink_entry":
      case "zip_invalid":
      case "zip_crc_mismatch":
      case "zip_unsupported_method":
      case "zip_too_many_entries":
        return "pack_unavailable";
      default:
        return "io_error";
    }
  }

  if (err instanceof ProtocolError) {
    switch (err.code) {
      case "hash_mismatch":
        return "hash_mismatch";
      case "cancelled":
        return "cancelled";
      case "host_not_allowed":
        return "host_not_allowed";
      case "too_large":
        return "too_large";
      case "server_running":
        return "server_running";
      case "install_in_progress":
        return "install_in_progress";
      case "api_unavailable":
        return "api_unavailable";
      case "io_error":
        return "io_error";
      case "pack_unavailable":
        return "pack_unavailable";
      case "runtime_mismatch":
        return "runtime_mismatch";
      case "download_failed": {
        const msg = err.message.toLowerCase();
        if (msg.includes("not allowed")) {
          return "host_not_allowed";
        }
        if (msg.includes("maximum allowed size")) {
          return "too_large";
        }
        return "pack_unavailable";
      }
      default:
        return "pack_unavailable";
    }
  }

  if (typeof err === "object" && err !== null && "code" in err) {
    const code = (err as { readonly code?: unknown }).code;
    if (typeof code === "string" && /^[A-Z]/.test(code)) {
      return "io_error";
    }
  }
  return "pack_unavailable";
}

/**
 * Refuses a modpack built for another game version or loader than the server runs, so the
 * server never ends up with mods it cannot load. An empty version or a vanilla loader in the
 * resolved pack means the provider did not say, and is not treated as a mismatch.
 */
export function assertRuntimeMatches(
  meta: Pick<ServerMetadata, "minecraft_version" | "loader">,
  resolved: { readonly minecraft_version: string; readonly loader: string },
): void {
  const packVersion = resolved.minecraft_version.trim();
  const packLoader = resolved.loader.trim().toLowerCase();
  const versionDiffers = packVersion.length > 0 && packVersion !== meta.minecraft_version;
  const loaderDiffers =
    packLoader.length > 0 && packLoader !== "vanilla" && packLoader !== meta.loader;
  if (versionDiffers || loaderDiffers) {
    throw new ProtocolError(
      "runtime_mismatch",
      "Modpack targets a different Minecraft version or loader than the server",
    );
  }
}

/**
 * Maps the archive into memory (file-backed pages the kernel can drop under pressure) where the
 * platform supports it, and reads it normally otherwise (Windows development builds).
 */
function mapArchive(path: string): Uint8Array {
  if (process.platform !== "win32") {
    try {
      return Bun.mmap(path, { shared: false });
    } catch {
      // Fall back to a plain read below.
    }
  }
  return new Uint8Array(readFileSync(path));
}

function digestsEqual(actualHex: string, expectedHex: string): boolean {
  const a = Buffer.from(actualHex.toLowerCase(), "hex");
  const b = Buffer.from(expectedHex.toLowerCase(), "hex");
  if (a.byteLength === 0 || a.byteLength !== b.byteLength) {
    return false;
  }
  return timingSafeEqual(a, b);
}

function fileMatchesExpectedHashes(
  fullPath: string,
  file: Pick<ResolvedModpackFile, "sha1" | "sha256" | "sha512">,
): boolean {
  const buf = readFileSync(fullPath);
  if (file.sha1 !== undefined) {
    const actual = createHash("sha1").update(buf).digest("hex");
    if (!digestsEqual(actual, file.sha1)) return false;
  }
  if (file.sha256 !== undefined) {
    const actual = createHash("sha256").update(buf).digest("hex");
    if (!digestsEqual(actual, file.sha256)) return false;
  }
  if (file.sha512 !== undefined) {
    const actual = createHash("sha512").update(buf).digest("hex");
    if (!digestsEqual(actual, file.sha512)) return false;
  }
  return true;
}

function resolveModTargetRelPath(file: ResolvedModpackFile): string | null {
  if (file.path !== undefined && file.path.trim().length > 0) {
    const norm = normalizeRelativePath(file.path);
    if (PROTECTED_SERVERPACK_PATHS.has(norm.toLowerCase())) {
      return null;
    }
    if (norm.startsWith(`${MODS_DIR}/`) && !norm.slice(MODS_DIR.length + 1).includes("/")) {
      const safeName = validateSingleFileName(norm.slice(MODS_DIR.length + 1));
      return `${MODS_DIR}/${safeName}`;
    }
    if (isServerContentPath(norm)) {
      return norm;
    }
    return null;
  }

  const safeName = validateSingleFileName(file.name);
  return `${MODS_DIR}/${safeName}`;
}

export function createModpackInstaller(options: ModpackInstallerOptions): ModpackInstaller {
  const serversDir = options.serversDir ?? DEFAULT_SERVERS_DIR;
  const jobsDir = join(options.stateDir, JOBS_SUBDIR);
  const allowedHosts = buildAllowedDownloadHosts([
    options.cdnHost,
    ...(options.extraAllowedHosts ?? []),
  ]);
  const maxModBytes = options.maxModBytes ?? DEFAULT_MAX_MOD_BYTES;
  const maxServerPackBytes = options.maxServerPackBytes ?? DEFAULT_MAX_MODPACK_SERVER_PACK_BYTES;
  const concurrency = Math.max(1, options.concurrency ?? DEFAULT_CONCURRENCY);
  const now = options.now ?? (() => Date.now());
  const permissionContext: PermissionContext = createServerPermissionContext({
    serversRoot: serversDir,
    ...(options.serverGroupId !== undefined ? { serverGroupId: options.serverGroupId } : {}),
    ...(options.logger !== undefined ? { logger: options.logger } : {}),
  });

  const activeRuns = new Map<
    string,
    {
      readonly jobId: string;
      readonly controller: AbortController;
      readonly promise: Promise<void>;
    }
  >();
  const startupChecks = new Set<Promise<void>>();
  let closing = false;

  function jobFilePath(serverId: string): string {
    return join(jobsDir, `${serverId}.json`);
  }

  function persistJob(record: PersistedJobRecord): void {
    mkdirSync(jobsDir, { recursive: true, mode: 0o700 });
    record.updated_at = now();
    writeFileAtomic(jobFilePath(record.server_id), `${JSON.stringify(record, null, 2)}\n`, {
      mode: 0o600,
      dirMode: 0o700,
    });
  }

  function loadJob(serverId: string): PersistedJobRecord | null {
    const path = jobFilePath(serverId);
    if (!existsSync(path)) {
      return null;
    }
    try {
      const raw = JSON.parse(readFileSync(path, "utf8")) as unknown;
      const parsed = persistedJobSchema.safeParse(raw);
      return parsed.success ? parsed.data : null;
    } catch {
      return null;
    }
  }

  function emitProgress(record: PersistedJobRecord): void {
    if (options.onProgress === undefined) {
      return;
    }
    const event: ServerInstallModpackProgressEvent = {
      job_id: record.job_id,
      server_id: record.server_id,
      phase: record.phase,
      done: record.done,
      total: record.total,
      ...(record.current !== undefined ? { current: record.current } : {}),
    };
    try {
      options.onProgress(event);
    } catch {
      // Progress listener failures must never interrupt background installs.
    }
  }

  function emitResult(record: PersistedJobRecord): void {
    if (options.onResult === undefined) {
      return;
    }
    const event: ServerInstallModpackResultEvent = {
      job_id: record.job_id,
      server_id: record.server_id,
      ok: record.status === "completed",
      installed: record.installed,
      skipped: [...record.skipped],
      ...(record.error_code !== undefined ? { error_code: record.error_code } : {}),
    };
    try {
      options.onResult(event);
    } catch {
      // Result listener failures must never interrupt cleanup.
    }
  }

  function writeOriginMetadata(record: PersistedJobRecord): void {
    const meta = readServerMetadata(serversDir, record.server_id);
    const mergedMods = new Map<string, ServerModEntry>((meta.mods ?? []).map((m) => [m.file, m]));
    for (const modEntry of record.installed_mods) {
      mergedMods.set(modEntry.file, modEntry);
    }

    const nextOrigin: ServerOrigin = {
      kind: "modpack",
      source: record.source,
      modpack_id: record.modpack_id,
      version_id: record.version_id,
      ...(record.modpack_name !== undefined ? { modpack_name: record.modpack_name } : {}),
    };

    const syncedModKeys = [
      ...new Set(
        record.installed_mods.map((entry) =>
          modIdentityKey({
            filename: entry.file,
            modInfo: entry.project_id !== undefined ? { modId: entry.project_id } : null,
          }),
        ),
      ),
    ].sort();

    const nextSync: ServerOriginSyncState = {
      excluded_mod_keys: [],
      synced_mod_keys: syncedModKeys,
      removed_origin_files: [],
      synced_files: [...new Set(record.synced_files)].sort(),
      last_synced_at: new Date(now()).toISOString(),
      last_synced_version_id: record.version_id,
    };

    const nextMeta: ServerMetadata = {
      ...meta,
      origin: nextOrigin,
      mods: [...mergedMods.values()].sort((a, b) => a.file.localeCompare(b.file)),
      origin_sync: nextSync,
    };
    writeServerMetadata(serversDir, nextMeta, permissionContext);
  }

  function cleanupWrittenFiles(serverId: string, writtenPaths: readonly string[]): void {
    for (const relPath of writtenPaths) {
      if (PROTECTED_SERVERPACK_PATHS.has(relPath.toLowerCase())) {
        continue;
      }
      try {
        const resolved = resolveConfinedPath({
          serversBaseDir: serversDir,
          serverId,
          relPath,
          allowRoot: false,
        });
        if (!existsSync(resolved.fullPath)) {
          continue;
        }
        const st = lstatSync(resolved.fullPath);
        if (st.isFile() && !st.isSymbolicLink()) {
          unlinkSync(resolved.fullPath);
        }
      } catch {
        // Best-effort cleanup of partial artifacts.
      }
    }
  }

  function addSkippedUnique(record: PersistedJobRecord, name: string, reason: string): void {
    if (!record.skipped.some((item) => item.name === name && item.reason === reason)) {
      record.skipped.push({
        name: name.slice(0, 256),
        reason: reason.slice(0, 128),
      });
    }
  }

  function addWrittenPathUnique(record: PersistedJobRecord, relPath: string): void {
    if (!record.written_paths.includes(relPath)) {
      record.written_paths.push(relPath);
    }
  }

  async function downloadWithPolicy(
    url: string,
    expectedHashes: {
      readonly sha1?: string | undefined;
      readonly sha256?: string | undefined;
      readonly sha512?: string | undefined;
    },
    maxBytes: number,
    signal: AbortSignal,
  ) {
    const check = isUrlHostAllowed(url, allowedHosts);
    if (!check.ok) {
      throw new ProtocolError(
        check.reason === "host_not_allowed" ? "host_not_allowed" : "pack_unavailable",
        check.reason === "host_not_allowed"
          ? "Download host is not allowed"
          : "Invalid download URL",
      );
    }
    return await downloadVerifiedBuffer({
      url,
      allowedHosts,
      expectedHashes,
      maxBytes,
      signal,
      ...(options.maxRedirects !== undefined ? { maxRedirects: options.maxRedirects } : {}),
      ...(options.downloadTimeoutMs !== undefined ? { timeoutMs: options.downloadTimeoutMs } : {}),
      ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
    });
  }

  async function runJob(record: PersistedJobRecord, controller: AbortController): Promise<void> {
    const signal = controller.signal;

    const assertNotCancelled = (): void => {
      if (signal.aborted) {
        throw new ProtocolError("cancelled", "Modpack installation cancelled");
      }
    };

    try {
      // Yield a microtask so the caller finishes returning `accepted` before events start flowing.
      await Promise.resolve();
      assertNotCancelled();

      // 1. Resolve modpack manifest/server pack if not already persisted from a prior attempt.
      if (record.resolved === undefined) {
        record.phase = "resolving";
        record.done = 0;
        record.total = 1;
        delete record.current;
        persistJob(record);
        emitProgress(record);

        const resolved = await options.resolveModpack(
          {
            source: record.source,
            modpack_id: record.modpack_id,
            version_id: record.version_id,
          },
          signal,
        );
        assertNotCancelled();
        record.resolved = resolved;
        persistJob(record);
      }

      let resolved = record.resolved;
      assertRuntimeMatches(readServerMetadata(serversDir, record.server_id), resolved);
      let cachedMrpackBuffer: Uint8Array | null = null;

      if (resolved.server_pack !== undefined) {
        // 2a. Official server pack flow (reusing serverpack extraction and indexing).
        const pack = resolved.server_pack;
        const hostCheck = isUrlHostAllowed(pack.url, allowedHosts);
        if (!hostCheck.ok) {
          throw new ProtocolError(
            hostCheck.reason === "host_not_allowed" ? "host_not_allowed" : "pack_unavailable",
            "Server pack download host is not allowed",
          );
        }

        if (!record.server_pack_extracted) {
          record.phase = "downloading";
          record.done = 0;
          record.total = 1;
          record.current = pack.name.slice(0, 256);
          persistJob(record);
          emitProgress(record);

          // Server packs run to hundreds of megabytes: stream them to disk and read the
          // archive through a memory map instead of holding it in the process heap.
          const packPath = join(jobsDir, `${record.server_id}.serverpack.zip`);
          await downloadVerifiedToFile({
            url: pack.url,
            destPath: packPath,
            allowedHosts,
            expectedHashes: { sha1: pack.sha1, sha256: pack.sha256, sha512: pack.sha512 },
            maxBytes: maxServerPackBytes,
            signal,
            timeoutMs: options.downloadTimeoutMs ?? SERVER_PACK_DOWNLOAD_TIMEOUT_MS,
            ...(options.maxRedirects !== undefined ? { maxRedirects: options.maxRedirects } : {}),
            ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
          });
          assertNotCancelled();

          record.phase = "extracting";
          record.done = 0;
          record.total = 1;
          record.current = pack.name.slice(0, 256);
          persistJob(record);
          emitProgress(record);

          let unzipResult: ReturnType<typeof safeUnzipPrefixesFromBuffer>;
          try {
            const archive = mapArchive(packPath);
            // The pack's own start scripts and the agent's metadata are left as the agent
            // wrote them; everything else in the pack is installed.
            unzipResult = safeUnzipPrefixesFromBuffer({
              serversBaseDir: serversDir,
              serverId: record.server_id,
              buffer: archive,
              prefixes: [findServerPackRoot(listZipEntryNames(archive))],
              skipPaths: PROTECTED_SERVERPACK_PATHS,
              permissions: permissionContext,
            });
          } finally {
            try {
              unlinkSync(packPath);
            } catch {
              // Already removed.
            }
          }
          for (const rel of unzipResult.files) {
            addWrittenPathUnique(record, rel);
          }

          const indexed = indexExtractedServerPackFiles({
            serversDir,
            serverId: record.server_id,
            extractedFiles: unzipResult.files,
            existingMods: [],
            originSource: record.source,
            layer: "origin",
          });
          record.installed_mods = [...indexed.mods];
          record.synced_files = [...indexed.syncedFiles];
          record.server_pack_extracted = true;
          record.done = 1;
          record.total = 1;
          persistJob(record);
          emitProgress(record);
        }
      } else {
        // 2b. Mod list + optional .mrpack parsing + overrides flow.
        if (resolved.overrides?.format === "mrpack" && resolved.files.length === 0) {
          record.phase = "resolving";
          record.done = 0;
          record.total = 1;
          delete record.current;
          persistJob(record);
          emitProgress(record);

          const downloadedPack = await downloadWithPolicy(
            resolved.overrides.url,
            {
              sha1: resolved.overrides.sha1,
              sha256: resolved.overrides.sha256,
              sha512: resolved.overrides.sha512,
            },
            maxServerPackBytes,
            signal,
          );
          assertNotCancelled();
          cachedMrpackBuffer = downloadedPack.data;

          const indexBytes = readZipEntryFromBuffer({
            buffer: downloadedPack.data,
            entryName: "modrinth.index.json",
          });
          if (indexBytes === null) {
            throw new ProtocolError(
              "pack_unavailable",
              "Missing modrinth.index.json in modpack archive",
            );
          }

          let parsedIndex: z.infer<typeof mrpackIndexSchema>;
          try {
            const rawJson = JSON.parse(
              new TextDecoder("utf-8", { fatal: true }).decode(indexBytes),
            ) as unknown;
            parsedIndex = mrpackIndexSchema.parse(rawJson);
          } catch {
            throw new ProtocolError("pack_unavailable", "Malformed modrinth.index.json");
          }

          const mappedFiles: ResolvedModpackFile[] = parsedIndex.files.map((entry) => ({
            name: basename(normalizeRelativePath(entry.path)),
            path: normalizeRelativePath(entry.path),
            ...(entry.downloads[0] !== undefined ? { url: entry.downloads[0] } : {}),
            ...(entry.hashes?.sha1 !== undefined ? { sha1: entry.hashes.sha1 } : {}),
            ...(entry.hashes?.sha512 !== undefined ? { sha512: entry.hashes.sha512 } : {}),
            ...(entry.fileSize !== undefined ? { size: entry.fileSize } : {}),
            ...(entry.env !== undefined ? { environment: entry.env } : {}),
          }));
          resolved = { ...resolved, files: mappedFiles };
          record.resolved = resolved;
          persistJob(record);
        }

        // Exclude client-only mods (`environment.server === "unsupported"`). Unknown environment is included.
        const serverFiles = resolved.files.filter((file) => !isClientOnly(file.environment));
        const completedSet = new Set(record.completed_files);
        const modByFile = new Map(record.installed_mods.map((m) => [m.file, m]));
        const syncedFileSet = new Set(record.synced_files);

        record.phase = "downloading";
        record.total = serverFiles.length;
        record.done = 0;

        // Pre-count already completed files on resume so progress starts at the right offset.
        const pendingFiles: Array<{
          readonly file: ResolvedModpackFile;
          readonly relPath: string;
        }> = [];
        for (const file of serverFiles) {
          const relPath = resolveModTargetRelPath(file);
          if (relPath === null) {
            record.done++;
            continue;
          }
          if (completedSet.has(relPath)) {
            const resolvedDisk = resolveConfinedPath({
              serversBaseDir: serversDir,
              serverId: record.server_id,
              relPath,
              allowRoot: false,
            });
            if (
              existsSync(resolvedDisk.fullPath) &&
              fileMatchesExpectedHashes(resolvedDisk.fullPath, file)
            ) {
              record.done++;
              continue;
            }
            completedSet.delete(relPath);
          }
          pendingFiles.push({ file, relPath });
        }

        persistJob(record);
        emitProgress(record);

        let nextIndex = 0;
        let fatalError: unknown = null;

        const worker = async (): Promise<void> => {
          while (fatalError === null) {
            assertNotCancelled();
            const idx = nextIndex++;
            const item = pendingFiles[idx];
            if (item === undefined) {
              break;
            }

            const { file, relPath } = item;
            const hasUrl = file.url !== undefined && file.url.trim().length > 0;
            if (!hasUrl && file.blocked !== true && resolved.overrides !== undefined) {
              // Listed without a download link: the file ships inside the pack archive and is
              // written with the overrides, so there is nothing to fetch and nothing to report.
              completedSet.add(relPath);
              record.completed_files = [...completedSet];
              record.done++;
              persistJob(record);
              continue;
            }
            if (file.blocked === true || !hasUrl || file.url === undefined) {
              addSkippedUnique(record, file.name, file.blocked_reason ?? "distribution_disabled");
              completedSet.add(relPath);
              record.completed_files = [...completedSet];
              record.done++;
              record.current = file.name.slice(0, 256);
              persistJob(record);
              emitProgress(record);
              continue;
            }

            const hostCheck = isUrlHostAllowed(file.url, allowedHosts);
            if (!hostCheck.ok) {
              addSkippedUnique(
                record,
                file.name,
                hostCheck.reason === "host_not_allowed" ? "host_not_allowed" : "unavailable",
              );
              completedSet.add(relPath);
              record.completed_files = [...completedSet];
              record.done++;
              record.current = file.name.slice(0, 256);
              persistJob(record);
              emitProgress(record);
              continue;
            }

            let downloaded: Awaited<ReturnType<typeof downloadVerifiedBuffer>>;
            try {
              downloaded = await downloadVerifiedBuffer({
                url: file.url,
                allowedHosts,
                expectedHashes: {
                  sha1: file.sha1,
                  sha256: file.sha256,
                  sha512: file.sha512,
                },
                maxBytes: maxModBytes,
                signal,
                ...(options.maxRedirects !== undefined
                  ? { maxRedirects: options.maxRedirects }
                  : {}),
                ...(options.downloadTimeoutMs !== undefined
                  ? { timeoutMs: options.downloadTimeoutMs }
                  : {}),
                ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
              });
            } catch (err) {
              if (signal.aborted || (err instanceof ProtocolError && err.code === "cancelled")) {
                fatalError = err;
                controller.abort();
                break;
              }
              // One file that cannot be fetched never sinks the whole install: it is reported
              // as skipped with the reason and the rest of the pack keeps going.
              addSkippedUnique(record, file.name, classifyInstallError(err));
              completedSet.add(relPath);
              record.completed_files = [...completedSet];
              record.done++;
              record.current = file.name.slice(0, 256);
              persistJob(record);
              emitProgress(record);
              continue;
            }

            assertNotCancelled();
            const targetResolved = resolveConfinedPath({
              serversBaseDir: serversDir,
              serverId: record.server_id,
              relPath,
              allowRoot: false,
            });
            writeConfinedFileAtomic(targetResolved, downloaded.data, {
              createParents: true,
              permissions: permissionContext,
            });
            addWrittenPathUnique(record, targetResolved.relativePath);
            completedSet.add(targetResolved.relativePath);
            record.completed_files = [...completedSet];

            if (targetResolved.relativePath.startsWith(`${MODS_DIR}/`)) {
              const modFile = validateSingleFileName(
                targetResolved.relativePath.slice(MODS_DIR.length + 1),
              );
              const entry: ServerModEntry = {
                file: modFile,
                source: record.source,
                ...(file.project_id !== undefined ? { project_id: file.project_id } : {}),
                ...(file.version_id !== undefined ? { version_id: file.version_id } : {}),
                sha1: downloaded.sha1,
                sha256: downloaded.sha256,
                sha512: downloaded.sha512,
                layer: "origin",
              };
              modByFile.set(modFile, entry);
              record.installed_mods = [...modByFile.values()];
            } else {
              syncedFileSet.add(targetResolved.relativePath);
              record.synced_files = [...syncedFileSet];
            }

            record.done++;
            record.current = file.name.slice(0, 256);
            persistJob(record);
            emitProgress(record);
          }
        };

        await Promise.all(
          Array.from({ length: Math.min(concurrency, Math.max(1, pendingFiles.length)) }, () =>
            worker(),
          ),
        );

        if (fatalError !== null) {
          throw fatalError;
        }
        assertNotCancelled();

        // 3. Extract server-only overrides (`overrides/` and `server-overrides/`).
        if (resolved.overrides !== undefined && !record.overrides_extracted) {
          record.phase = "overrides";
          record.done = 0;
          record.total = 1;
          delete record.current;
          persistJob(record);
          emitProgress(record);

          try {
            let archiveBuffer = cachedMrpackBuffer;
            if (archiveBuffer === null) {
              const downloadedOverrides = await downloadWithPolicy(
                resolved.overrides.url,
                {
                  sha1: resolved.overrides.sha1,
                  sha256: resolved.overrides.sha256,
                  sha512: resolved.overrides.sha512,
                },
                maxServerPackBytes,
                signal,
              );
              assertNotCancelled();
              archiveBuffer = downloadedOverrides.data;
            }

            // "." means the pack keeps its server files at the archive root (Tegra packs);
            // otherwise the named folder, defaulting to `overrides/`, plus `server-overrides/`.
            const rawPrefix = resolved.overrides.prefix?.trim();
            const atRoot = rawPrefix === "." || rawPrefix === "./";
            const customPrefix = atRoot ? "" : rawPrefix?.replace(/^\/+|\/+$/g, "");
            const prefixes: string[] = atRoot
              ? [""]
              : [
                  customPrefix !== undefined && customPrefix.length > 0
                    ? customPrefix
                    : "overrides",
                ];
            if (!atRoot && !prefixes.includes("server-overrides")) {
              prefixes.push("server-overrides");
            }

            const unzipOverrides = safeUnzipPrefixesFromBuffer({
              serversBaseDir: serversDir,
              serverId: record.server_id,
              buffer: archiveBuffer,
              prefixes,
              excludePrefixes: atRoot
                ? ["client-overrides", "shaderpacks", "mods"]
                : ["client-overrides"],
              skipPaths: PROTECTED_SERVERPACK_PATHS,
              permissions: permissionContext,
            });

            for (const rel of unzipOverrides.files) {
              addWrittenPathUnique(record, rel);
              if (isServerContentPath(rel)) {
                syncedFileSet.add(rel);
              }
            }
            record.synced_files = [...syncedFileSet];
          } catch (err) {
            const code = classifyInstallError(err);
            if (code === "cancelled") throw err;
            // Configs and scripts that could not be applied are reported; the mods already
            // installed stay on the server.
            addSkippedUnique(record, "overrides", code);
            options.logger?.warn("Modpack overrides were not applied", {
              serverId: record.server_id,
              jobId: record.job_id,
              errorCode: code,
              reason: redactUrlQueryStrings(err instanceof Error ? err.message : String(err)),
            });
          }
          record.overrides_extracted = true;
          record.done = 1;
          record.total = 1;
          persistJob(record);
          emitProgress(record);
        }
      }

      assertNotCancelled();

      // 4. Finalizing: update tegrad-server.json origin, mods, and origin_sync.
      record.phase = "finalizing";
      record.done = 0;
      record.total = 1;
      delete record.current;
      persistJob(record);
      emitProgress(record);

      writeOriginMetadata(record);

      record.status = "completed";
      record.done = 1;
      record.total = 1;
      record.installed = record.installed_mods.length;
      record.finished_at = now();
      persistJob(record);
      emitProgress(record);
      emitResult(record);

      options.logger?.info("Installed modpack on server", {
        serverId: record.server_id,
        jobId: record.job_id,
        source: record.source,
        installed: record.installed,
        skippedCount: record.skipped.length,
      });
    } catch (err) {
      const errorCode = classifyInstallError(err);
      // Graceful shutdown aborts active I/O without failing or cleaning up the job so it resumes on restart.
      if (closing && errorCode === "cancelled") {
        options.logger?.info("Paused modpack install for agent shutdown", {
          serverId: record.server_id,
          jobId: record.job_id,
          phase: record.phase,
        });
        return;
      }

      if (errorCode === "cancelled") {
        cleanupWrittenFiles(record.server_id, record.written_paths);
        record.installed = 0;
      } else {
        // Keep every file that already landed and record it, so the server is never left
        // with fewer mods than the install managed to put on it.
        try {
          if (record.installed_mods.length > 0 || record.synced_files.length > 0) {
            writeOriginMetadata(record);
          }
        } catch (metaErr) {
          options.logger?.warn("Could not record the partial modpack install", {
            serverId: record.server_id,
            jobId: record.job_id,
            reason: metaErr instanceof Error ? metaErr.message : String(metaErr),
          });
        }
        record.installed = record.installed_mods.length;
      }
      record.status = errorCode === "cancelled" ? "cancelled" : "failed";
      record.error_code = errorCode;
      record.finished_at = now();
      persistJob(record);
      emitResult(record);

      options.logger?.warn("Modpack install did not complete", {
        serverId: record.server_id,
        jobId: record.job_id,
        phase: record.phase,
        errorCode,
        reason: redactUrlQueryStrings(err instanceof Error ? err.message : String(err)),
      });
    } finally {
      const active = activeRuns.get(record.server_id);
      if (active !== undefined && active.jobId === record.job_id) {
        activeRuns.delete(record.server_id);
      }
    }
  }

  function launchJob(record: PersistedJobRecord): void {
    const controller = new AbortController();
    const promise = runJob(record, controller);
    activeRuns.set(record.server_id, {
      jobId: record.job_id,
      controller,
      promise,
    });
  }

  return {
    async startInstall(params: ServerInstallModpackBody): Promise<StartModpackInstallResult> {
      const parsed = serverInstallModpackBodySchema.safeParse(params);
      if (!parsed.success) {
        throw new ProtocolError("invalid_body", "Invalid server.install_modpack parameters");
      }
      const input = parsed.data;
      readServerMetadata(serversDir, input.server_id);

      if (await options.isServerActive(input.server_id)) {
        throw new ProtocolError(
          "server_running",
          "The server must be stopped before installing a modpack",
        );
      }

      if (activeRuns.has(input.server_id)) {
        throw new ProtocolError(
          "install_in_progress",
          "A modpack installation is already running for this server",
        );
      }
      const existing = loadJob(input.server_id);
      if (existing !== null && existing.status === "running") {
        throw new ProtocolError(
          "install_in_progress",
          "A modpack installation is already running for this server",
        );
      }

      const timestamp = now();
      const jobId = `mpi-${randomBytes(8).toString("hex")}`;
      const record: PersistedJobRecord = {
        v: 1,
        job_id: jobId,
        server_id: input.server_id,
        source: input.source,
        modpack_id: input.modpack_id,
        version_id: input.version_id,
        ...(input.modpack_name !== undefined ? { modpack_name: input.modpack_name } : {}),
        ...(input.version_label !== undefined ? { version_label: input.version_label } : {}),
        status: "running",
        phase: "resolving",
        done: 0,
        total: 1,
        installed: 0,
        skipped: [],
        started_at: timestamp,
        updated_at: timestamp,
        completed_files: [],
        written_paths: [],
        installed_mods: [],
        synced_files: [],
      };
      persistJob(record);
      launchJob(record);

      return { job_id: jobId, server_id: input.server_id };
    },

    getStatus(serverId: string): ServerInstallModpackStatusResult {
      const validId = assertValidServerId(serverId);
      readServerMetadata(serversDir, validId);
      const record = loadJob(validId);
      return {
        server_id: validId,
        job: record !== null ? toJobStatusSnapshot(record) : null,
      };
    },

    cancelInstall(params: ServerInstallModpackCancelBody): CancelModpackInstallResult {
      const parsed = serverInstallModpackCancelBodySchema.safeParse(params);
      if (!parsed.success) {
        throw new ProtocolError("invalid_body", "Invalid server.install_modpack.cancel parameters");
      }
      const { server_id: serverId, job_id: jobId } = parsed.data;
      readServerMetadata(serversDir, serverId);

      const active = activeRuns.get(serverId);
      if (active !== undefined) {
        if (jobId !== undefined && active.jobId !== jobId) {
          return { server_id: serverId, cancelled: false };
        }
        active.controller.abort();
        return { server_id: serverId, job_id: active.jobId, cancelled: true };
      }

      const persisted = loadJob(serverId);
      if (
        persisted !== null &&
        persisted.status === "running" &&
        (jobId === undefined || persisted.job_id === jobId)
      ) {
        cleanupWrittenFiles(serverId, persisted.written_paths);
        persisted.status = "cancelled";
        persisted.error_code = "cancelled";
        persisted.installed = 0;
        persisted.finished_at = now();
        persistJob(persisted);
        emitResult(persisted);
        return { server_id: serverId, job_id: persisted.job_id, cancelled: true };
      }

      return { server_id: serverId, cancelled: false };
    },

    start(): void {
      if (!existsSync(jobsDir)) {
        return;
      }
      let entries: string[];
      try {
        entries = readdirSync(jobsDir).filter((name) => name.endsWith(".json"));
      } catch {
        return;
      }

      for (const file of entries) {
        const serverId = file.slice(0, -".json".length);
        let record: PersistedJobRecord | null;
        try {
          assertValidServerId(serverId);
          record = loadJob(serverId);
        } catch {
          continue;
        }
        if (record === null || record.status !== "running" || activeRuns.has(serverId)) {
          continue;
        }
        try {
          readServerMetadata(serversDir, serverId);
        } catch {
          continue;
        }
        const checkPromise = (async () => {
          const active = await options.isServerActive(serverId).catch(() => true);
          if (closing) {
            return;
          }
          if (active) {
            record.status = "failed";
            record.error_code = "server_running";
            record.finished_at = now();
            persistJob(record);
            emitResult(record);
            return;
          }
          launchJob(record);
        })();
        startupChecks.add(checkPromise);
        void checkPromise.finally(() => {
          startupChecks.delete(checkPromise);
        });
      }
    },

    async waitForActiveJobs(): Promise<void> {
      while (startupChecks.size > 0 || activeRuns.size > 0) {
        if (startupChecks.size > 0) {
          await Promise.allSettled([...startupChecks]);
        }
        if (activeRuns.size > 0) {
          const promises = [...activeRuns.values()].map((entry) => entry.promise);
          await Promise.allSettled(promises);
        }
      }
    },

    async close(): Promise<void> {
      closing = true;
      for (const entry of activeRuns.values()) {
        entry.controller.abort();
      }
      await Promise.allSettled([...activeRuns.values()].map((entry) => entry.promise));
    },
  };
}

export function registerModpackHandlers(queue: CommandQueue, installer: ModpackInstaller): void {
  queue.registerHandler("server.install_modpack", async (opened, ctx) => {
    const body = opened.body as ServerInstallModpackBody;
    const accepted = await installer.startInstall(body);
    ctx.sendEvent("server.install_modpack.accepted", accepted);
  });

  queue.registerHandler("server.install_modpack.status", (opened, ctx) => {
    const body = opened.body as { readonly server_id: string };
    const status = installer.getStatus(body.server_id);
    ctx.sendEvent("server.install_modpack.status.result", status);
  });

  queue.registerHandler("server.install_modpack.cancel", (opened, ctx) => {
    const body = opened.body as ServerInstallModpackCancelBody;
    const result = installer.cancelInstall(body);
    ctx.sendEvent("server.install_modpack.cancelled", result);
  });
}
