// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import {
  existsSync,
  lstatSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  unlinkSync,
} from "node:fs";
import { join } from "node:path";
import type { CommandQueue } from "../agent/jobs";
import type { Logger } from "../agent/logger";
import { collectChunks, decryptBlobChunks, fromBase64Url } from "../crypto";
import {
  decodeStrictBase64,
  FileManagerError,
  resolveConfinedPath,
  safeUnzipBuffer,
  validateSingleFileName,
  writeConfinedFileAtomic,
} from "../files";
import {
  ProtocolError,
  type ServerDeployServerpackBody,
  type ServerLoader,
  type ServerModEntry,
  type ServerModsInstallBody,
  type ServerModsRemoveBody,
  type ServerOrigin,
  type ServerOriginApplyBody,
  type ServerOriginPlanBody,
  type ServerOriginSyncState,
  type ServerWorldImportBody,
  serverDeployServerpackBodySchema,
  serverModsInstallBodySchema,
  serverModsRemoveBodySchema,
  serverOriginApplyBodySchema,
  serverOriginPlanBodySchema,
  serverWorldImportBodySchema,
} from "../protocol";
import type { FetchLike } from "../server/download";
import { assertValidServerId, DEFAULT_SERVERS_DIR } from "../server/id";
import {
  type PermissionContext,
  resolveGroupId,
  SERVER_TREE_PLAN,
  secureTree,
} from "../server/permissions";
import { readServerMetadata, type ServerMetadata, writeServerMetadata } from "../server/registry";
import { type BackupHook, noopBackupHook } from "./backup-hook";
import {
  buildAllowedDownloadHosts,
  DEFAULT_MAX_MOD_BYTES,
  DEFAULT_MAX_SERVERPACK_BYTES,
  downloadVerifiedBuffer,
} from "./download";
import { assertVersionLoaderUnlocked, isVersionLoaderLocked } from "./lock";
import {
  buildOriginSyncChanges,
  emptyOriginSyncState,
  isServerContentPath,
  modIdentityKey,
  nextOriginSyncState,
  normalizeRelativePath,
  type OriginSyncChanges,
  type PlanFile,
  type PlanMod,
} from "./sync-plan";

export const DEFAULT_PLAN_TTL_MS = 15 * 60 * 1000; // 15 minutes
export const DEFAULT_MAX_STORED_PLANS = 64;
const MODS_DIR = "mods";

export interface StateManagerOptions {
  readonly serversDir?: string;
  readonly cdnHost?: string;
  readonly extraAllowedHosts?: readonly string[];
  readonly backupHook?: BackupHook;
  readonly backupBeforeChange?: boolean;
  readonly fetchImpl?: FetchLike;
  readonly maxModBytes?: number;
  readonly maxServerPackBytes?: number;
  readonly maxRedirects?: number;
  readonly downloadTimeoutMs?: number;
  readonly planTtlMs?: number;
  readonly maxStoredPlans?: number;
  readonly now?: () => number;
  readonly logger?: Logger;
  /** True when the server's unit is not stopped. Required to allow world imports. */
  readonly isServerActive?: (serverId: string) => Promise<boolean>;
  /** Group id of the server user's group; resolved from /etc/group when omitted, null to skip. */
  readonly serverGroupId?: number | null;
  readonly maxWorldBytes?: number;
}

export interface WorldImportResult {
  readonly server_id: string;
  readonly world_name: string;
}

export interface ModsListResult {
  readonly server_id: string;
  readonly origin: ServerOrigin;
  readonly version_loader_locked: boolean;
  readonly mods: readonly ServerModEntry[];
}

export interface ModInstallResult {
  readonly server_id: string;
  readonly mod: ServerModEntry;
  readonly bytes: number;
}

export interface ModRemoveResult {
  readonly server_id: string;
  readonly file: string;
  readonly removed: boolean;
  readonly tracked_origin_removal: boolean;
}

export interface OriginPlanResult {
  readonly plan_id: string;
  readonly server_id: string;
  readonly from_version_id: string | null;
  readonly to_version_id: string;
  readonly expires_at: number;
  readonly state_fingerprint: string;
  readonly changes: OriginSyncChanges;
}

export interface OriginApplyResult {
  readonly server_id: string;
  readonly plan_id: string;
  readonly origin: ServerOrigin;
  readonly mods_added: number;
  readonly mods_updated: number;
  readonly mods_removed: number;
  readonly files_written: number;
  readonly files_removed: number;
}

export interface OriginUnlinkResult {
  readonly server_id: string;
  readonly origin: null;
  readonly version_loader_locked: false;
}

export interface ServerPackDeployResult {
  readonly server_id: string;
  readonly bytes: number;
  readonly sha256: string;
  readonly entry_count: number;
  readonly extracted_files: readonly string[];
  readonly origin: ServerOrigin;
}

export interface UpdateVersionLoaderParams {
  readonly server_id: string;
  readonly minecraft_version?: string;
  readonly loader?: ServerLoader;
  readonly loader_version?: string | null;
}

interface StoredOriginPlan {
  readonly planId: string;
  readonly serverId: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly stateFingerprint: string;
  readonly input: ServerOriginPlanBody;
  readonly sourceMods: readonly PlanMod[];
  readonly sourceFiles: readonly PlanFile[];
  readonly changes: OriginSyncChanges;
}

export interface StateManager {
  listMods(serverId: string): ModsListResult;
  installMod(params: ServerModsInstallBody): Promise<ModInstallResult>;
  removeMod(params: ServerModsRemoveBody): ModRemoveResult;
  unlinkOrigin(serverId: string): OriginUnlinkResult;
  updateVersionLoader(params: UpdateVersionLoaderParams): ServerMetadata;
  planOriginSync(params: ServerOriginPlanBody): OriginPlanResult;
  applyOriginSync(params: ServerOriginApplyBody): Promise<OriginApplyResult>;
  deployServerPack(params: ServerDeployServerpackBody): Promise<ServerPackDeployResult>;
  importWorld(params: ServerWorldImportBody): Promise<WorldImportResult>;
}

export const DEFAULT_MAX_WORLD_BYTES = 2 * 1024 * 1024 * 1024; // 2 GiB of ciphertext

/** Decrypts a downloaded TGB1 blob chunk by chunk and returns the plaintext. */
async function decryptDownloadedBlob(
  data: Uint8Array,
  keyB64: string,
  maxPlaintextBytes: number,
): Promise<Uint8Array> {
  try {
    return await collectChunks(
      decryptBlobChunks(data, fromBase64Url(keyB64), { maxPlaintextBytes }),
    );
  } catch {
    throw new ProtocolError("decrypt_failed", "Failed to decrypt the downloaded blob");
  }
}

const PROTECTED_SERVERPACK_PATHS: ReadonlySet<string> = new Set(["start.sh", "tegrad-server.json"]);

function hexDigestsEqual(actualHex: string, expectedHex: string): boolean {
  const a = Buffer.from(actualHex.toLowerCase(), "hex");
  const b = Buffer.from(expectedHex.toLowerCase(), "hex");
  if (a.byteLength === 0 || a.byteLength !== b.byteLength) {
    return false;
  }
  return timingSafeEqual(a, b);
}

function modKeyFromMetadataEntry(entry: ServerModEntry): string {
  return modIdentityKey({
    filename: entry.file,
    modInfo: entry.project_id !== undefined ? { modId: entry.project_id } : null,
  });
}

function hashFileSha1(fullPath: string): string {
  const content = readFileSync(fullPath);
  return createHash("sha1").update(content).digest("hex");
}

function hashFileSha256(fullPath: string): string {
  const content = readFileSync(fullPath);
  return createHash("sha256").update(content).digest("hex");
}

function scanExistingServerFiles(
  serversDir: string,
  serverId: string,
  candidatePaths: ReadonlySet<string>,
): PlanFile[] {
  const result: PlanFile[] = [];
  for (const rel of candidatePaths) {
    const norm = normalizeRelativePath(rel);
    if (!isServerContentPath(norm)) {
      continue;
    }
    let resolved: ReturnType<typeof resolveConfinedPath>;
    try {
      resolved = resolveConfinedPath({
        serversBaseDir: serversDir,
        serverId,
        relPath: norm,
        allowRoot: false,
      });
    } catch {
      continue;
    }
    if (!existsSync(resolved.fullPath)) {
      continue;
    }
    const stats = lstatSync(resolved.fullPath);
    if (stats.isSymbolicLink() || !stats.isFile()) {
      continue;
    }
    result.push({
      path: norm,
      sha1: hashFileSha1(resolved.fullPath),
      size_bytes: stats.size,
    });
  }
  return result;
}

function computeServerStateFingerprint(
  serversDir: string,
  serverId: string,
  meta: ServerMetadata,
  trackedFilePaths: ReadonlySet<string>,
): string {
  const hasher = createHash("sha256");
  hasher.update(JSON.stringify(meta));
  hasher.update("\0");

  // Include actual mods/ directory files and hashes.
  const modsResolved = resolveConfinedPath({
    serversBaseDir: serversDir,
    serverId,
    relPath: MODS_DIR,
    allowRoot: false,
  });
  if (existsSync(modsResolved.fullPath)) {
    const stats = lstatSync(modsResolved.fullPath);
    if (stats.isDirectory() && !stats.isSymbolicLink()) {
      const names = readdirSync(modsResolved.fullPath).sort();
      for (const name of names) {
        if (name.startsWith(".tmp-")) {
          continue;
        }
        const full = join(modsResolved.fullPath, name);
        const st = lstatSync(full);
        if (st.isFile() && !st.isSymbolicLink()) {
          hasher.update(`mod:${name}:${st.size}:${hashFileSha256(full)}\n`);
        }
      }
    }
  }

  hasher.update("\0");
  const sortedPaths = [...trackedFilePaths].sort();
  for (const rel of sortedPaths) {
    const norm = normalizeRelativePath(rel);
    let resolved: ReturnType<typeof resolveConfinedPath>;
    try {
      resolved = resolveConfinedPath({
        serversBaseDir: serversDir,
        serverId,
        relPath: norm,
        allowRoot: false,
      });
    } catch {
      continue;
    }
    if (!existsSync(resolved.fullPath)) {
      hasher.update(`file:${norm}:missing\n`);
      continue;
    }
    const st = lstatSync(resolved.fullPath);
    if (st.isFile() && !st.isSymbolicLink()) {
      hasher.update(`file:${norm}:${st.size}:${hashFileSha256(resolved.fullPath)}\n`);
    }
  }

  return hasher.digest("hex");
}

function removeConfinedFileIfExists(
  serversDir: string,
  serverId: string,
  relPath: string,
): boolean {
  const resolved = resolveConfinedPath({
    serversBaseDir: serversDir,
    serverId,
    relPath,
    allowRoot: false,
  });
  if (!existsSync(resolved.fullPath)) {
    return false;
  }
  const stats = lstatSync(resolved.fullPath);
  if (stats.isSymbolicLink()) {
    throw new FileManagerError("symlink_forbidden", `Refusing to delete symlink "${relPath}"`);
  }
  if (!stats.isFile()) {
    throw new FileManagerError("is_a_directory", `Refusing to delete non-file "${relPath}"`);
  }
  unlinkSync(resolved.fullPath);
  return true;
}

export function createStateManager(options: StateManagerOptions = {}): StateManager {
  const serversDir = options.serversDir ?? DEFAULT_SERVERS_DIR;
  const allowedHosts = buildAllowedDownloadHosts([
    options.cdnHost,
    ...(options.extraAllowedHosts ?? []),
  ]);
  const backupHook = options.backupHook ?? noopBackupHook;
  const backupBeforeChange = options.backupBeforeChange ?? true;
  const maxModBytes = options.maxModBytes ?? DEFAULT_MAX_MOD_BYTES;
  const maxServerPackBytes = options.maxServerPackBytes ?? DEFAULT_MAX_SERVERPACK_BYTES;
  const maxWorldBytes = options.maxWorldBytes ?? DEFAULT_MAX_WORLD_BYTES;
  const permissionContext: PermissionContext = {
    gid: options.serverGroupId !== undefined ? options.serverGroupId : resolveGroupId(),
    onChownError: (path, err) => {
      options.logger?.warn("Could not set the server group on a path", {
        path,
        errName: err instanceof Error ? err.name : "Error",
      });
    },
  };
  const planTtlMs = options.planTtlMs ?? DEFAULT_PLAN_TTL_MS;
  const maxStoredPlans = options.maxStoredPlans ?? DEFAULT_MAX_STORED_PLANS;
  const now = options.now ?? (() => Date.now());

  const plans = new Map<string, StoredOriginPlan>();

  function pruneExpiredPlans(): void {
    const current = now();
    for (const [id, plan] of plans) {
      if (current > plan.expiresAt) {
        plans.delete(id);
      }
    }
  }

  function invalidatePlansForServer(serverId: string): void {
    for (const [id, plan] of plans) {
      if (plan.serverId === serverId) {
        plans.delete(id);
      }
    }
  }

  function listMods(serverId: string): ModsListResult {
    const validId = assertValidServerId(serverId);
    const meta = readServerMetadata(serversDir, validId);
    return {
      server_id: validId,
      origin: meta.origin ?? null,
      version_loader_locked: isVersionLoaderLocked(meta),
      mods: meta.mods ?? [],
    };
  }

  async function installMod(params: ServerModsInstallBody): Promise<ModInstallResult> {
    const parsed = serverModsInstallBodySchema.safeParse(params);
    if (!parsed.success) {
      throw new ProtocolError("invalid_body", "Invalid server.mods.install parameters");
    }
    const {
      server_id: serverId,
      url,
      source,
      project_id,
      version_id,
      sha1,
      sha256,
      sha512,
    } = parsed.data;
    const safeFile = validateSingleFileName(parsed.data.file);
    const meta = readServerMetadata(serversDir, serverId);

    const downloaded = await downloadVerifiedBuffer({
      url,
      allowedHosts,
      expectedHashes: { sha1, sha256, sha512 },
      maxBytes: maxModBytes,
      ...(options.maxRedirects !== undefined ? { maxRedirects: options.maxRedirects } : {}),
      ...(options.downloadTimeoutMs !== undefined ? { timeoutMs: options.downloadTimeoutMs } : {}),
      ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
    });

    const targetResolved = resolveConfinedPath({
      serversBaseDir: serversDir,
      serverId,
      relPath: `${MODS_DIR}/${safeFile}`,
      allowRoot: false,
    });
    writeConfinedFileAtomic(targetResolved, downloaded.data, { createParents: true });

    const newEntry: ServerModEntry = {
      file: safeFile,
      source,
      ...(project_id !== undefined ? { project_id } : {}),
      ...(version_id !== undefined ? { version_id } : {}),
      sha1: downloaded.sha1,
      sha256: downloaded.sha256,
      sha512: downloaded.sha512,
      layer: "user",
    };

    const existingMods = (meta.mods ?? []).filter((m) => m.file !== safeFile);
    const nextMeta: ServerMetadata = {
      ...meta,
      mods: [...existingMods, newEntry].sort((a, b) => a.file.localeCompare(b.file)),
    };
    writeServerMetadata(serversDir, nextMeta);

    options.logger?.info("Installed server mod", { serverId, file: safeFile, source });

    return {
      server_id: serverId,
      mod: newEntry,
      bytes: downloaded.bytes,
    };
  }

  function removeMod(params: ServerModsRemoveBody): ModRemoveResult {
    const parsed = serverModsRemoveBodySchema.safeParse(params);
    if (!parsed.success) {
      throw new ProtocolError("invalid_body", "Invalid server.mods.remove parameters");
    }
    const serverId = parsed.data.server_id;
    const safeFile = validateSingleFileName(parsed.data.file);
    const meta = readServerMetadata(serversDir, serverId);

    const existingMods = meta.mods ?? [];
    const targetEntry = existingMods.find((m) => m.file === safeFile);
    const removedFromDisk = removeConfinedFileIfExists(
      serversDir,
      serverId,
      `${MODS_DIR}/${safeFile}`,
    );

    if (!removedFromDisk && targetEntry === undefined) {
      throw new ProtocolError("mod_not_found", `Mod "${safeFile}" not found on server ${serverId}`);
    }

    const nextMods = existingMods.filter((m) => m.file !== safeFile);
    let nextOriginSync = meta.origin_sync;
    let trackedOriginRemoval = false;

    if (targetEntry?.layer === "origin") {
      trackedOriginRemoval = true;
      const baseSync = meta.origin_sync ?? emptyOriginSyncState();
      const modKey = modKeyFromMetadataEntry(targetEntry);
      const excludedSet = new Set(baseSync.excluded_mod_keys);
      excludedSet.add(modKey);
      const removedFilesSet = new Set(baseSync.removed_origin_files ?? []);
      removedFilesSet.add(`${MODS_DIR}/${safeFile}`);
      nextOriginSync = {
        ...baseSync,
        excluded_mod_keys: [...excludedSet].sort(),
        removed_origin_files: [...removedFilesSet].sort(),
      };
    }

    const nextMeta: ServerMetadata = {
      ...meta,
      mods: nextMods,
      ...(nextOriginSync !== undefined ? { origin_sync: nextOriginSync } : {}),
    };
    writeServerMetadata(serversDir, nextMeta);

    options.logger?.info("Removed server mod", { serverId, file: safeFile, trackedOriginRemoval });

    return {
      server_id: serverId,
      file: safeFile,
      removed: true,
      tracked_origin_removal: trackedOriginRemoval,
    };
  }

  function unlinkOrigin(serverId: string): OriginUnlinkResult {
    const validId = assertValidServerId(serverId);
    const meta = readServerMetadata(serversDir, validId);

    const promotedMods: ServerModEntry[] = (meta.mods ?? []).map((mod) =>
      mod.layer === "origin" ? { ...mod, layer: "user" } : mod,
    );

    const { origin_sync: _droppedSync, ...rest } = meta;
    const nextMeta: ServerMetadata = {
      ...rest,
      origin: null,
      mods: promotedMods,
    };
    writeServerMetadata(serversDir, nextMeta);
    invalidatePlansForServer(validId);

    options.logger?.info("Unlinked server modpack origin", { serverId: validId });

    return {
      server_id: validId,
      origin: null,
      version_loader_locked: false,
    };
  }

  function updateVersionLoader(params: UpdateVersionLoaderParams): ServerMetadata {
    const validId = assertValidServerId(params.server_id);
    const meta = readServerMetadata(serversDir, validId);
    assertVersionLoaderUnlocked(meta);

    const nextMeta: ServerMetadata = {
      ...meta,
      ...(params.minecraft_version !== undefined
        ? { minecraft_version: params.minecraft_version }
        : {}),
      ...(params.loader !== undefined ? { loader: params.loader } : {}),
      ...(params.loader_version !== undefined ? { loader_version: params.loader_version } : {}),
    };
    writeServerMetadata(serversDir, nextMeta);
    return nextMeta;
  }

  function planOriginSync(params: ServerOriginPlanBody): OriginPlanResult {
    const parsed = serverOriginPlanBodySchema.safeParse(params);
    if (!parsed.success) {
      throw new ProtocolError("invalid_body", "Invalid server.origin.plan parameters");
    }
    const input = parsed.data;
    const serverId = input.server_id;
    const meta = readServerMetadata(serversDir, serverId);
    const syncState = meta.origin_sync ?? emptyOriginSyncState();

    // Validate all mod filenames and file paths up front.
    const sourceMods: PlanMod[] = input.mods.map((m) => {
      const safeFile = validateSingleFileName(m.file);
      return {
        key: m.key,
        filename: safeFile,
        enabled: m.enabled ?? true,
        name: m.name ?? safeFile,
        version: m.version_id,
        sha1: m.sha1,
        sha512: m.sha512,
        environment: m.environment,
      };
    });

    const sourceFiles: PlanFile[] = [];
    const candidateFilePaths = new Set<string>(syncState.synced_files ?? []);
    for (const f of input.files ?? []) {
      const norm = normalizeRelativePath(f.path);
      // Enforce confinement on every planned file path.
      try {
        resolveConfinedPath({
          serversBaseDir: serversDir,
          serverId,
          relPath: norm,
          allowRoot: false,
        });
      } catch (err) {
        if (err instanceof FileManagerError) {
          throw new ProtocolError("invalid_body", `Invalid planned file path: ${err.message}`);
        }
        throw err;
      }
      if (!isServerContentPath(norm)) {
        continue;
      }
      candidateFilePaths.add(norm);
      sourceFiles.push({
        path: norm,
        sha1: f.sha1,
        size_bytes: f.size_bytes,
      });
    }

    const targetMods: PlanMod[] = (meta.mods ?? []).map((m) => ({
      key: modKeyFromMetadataEntry(m),
      filename: m.file,
      enabled: true,
      name: m.file,
      version: m.version_id,
      sha1: m.sha1,
      sha512: m.sha512,
    }));

    const targetFiles = scanExistingServerFiles(serversDir, serverId, candidateFilePaths);

    const changes = buildOriginSyncChanges({
      sourceMods,
      targetMods,
      sourceFiles,
      targetFiles,
      state: syncState,
    });

    const stateFingerprint = computeServerStateFingerprint(
      serversDir,
      serverId,
      meta,
      candidateFilePaths,
    );

    pruneExpiredPlans();
    while (plans.size >= maxStoredPlans) {
      const oldestKey = plans.keys().next().value;
      if (oldestKey === undefined) {
        break;
      }
      plans.delete(oldestKey);
    }

    const createdAt = now();
    const expiresAt = createdAt + planTtlMs;
    const planId = randomBytes(16).toString("base64url");

    plans.set(planId, {
      planId,
      serverId,
      createdAt,
      expiresAt,
      stateFingerprint,
      input,
      sourceMods,
      sourceFiles,
      changes,
    });

    const fromVersionId = meta.origin?.kind === "modpack" ? meta.origin.version_id : null;

    return {
      plan_id: planId,
      server_id: serverId,
      from_version_id: fromVersionId,
      to_version_id: input.to_version_id,
      expires_at: expiresAt,
      state_fingerprint: stateFingerprint,
      changes,
    };
  }

  async function applyOriginSync(params: ServerOriginApplyBody): Promise<OriginApplyResult> {
    const parsed = serverOriginApplyBodySchema.safeParse(params);
    if (!parsed.success) {
      throw new ProtocolError("invalid_body", "Invalid server.origin.apply parameters");
    }
    const { server_id: serverId, plan_id: planId } = parsed.data;
    const plan = plans.get(planId);
    if (plan === undefined || plan.serverId !== serverId) {
      throw new ProtocolError("plan_not_found", `Unknown origin sync plan: ${planId}`);
    }

    const currentTime = now();
    if (currentTime > plan.expiresAt) {
      plans.delete(planId);
      throw new ProtocolError("plan_expired", `Origin sync plan has expired: ${planId}`);
    }

    const meta = readServerMetadata(serversDir, serverId);
    const syncState = meta.origin_sync ?? emptyOriginSyncState();
    const candidateFilePaths = new Set<string>(syncState.synced_files ?? []);
    for (const f of plan.sourceFiles) {
      candidateFilePaths.add(f.path);
    }

    const currentFingerprint = computeServerStateFingerprint(
      serversDir,
      serverId,
      meta,
      candidateFilePaths,
    );
    if (currentFingerprint !== plan.stateFingerprint) {
      plans.delete(planId);
      throw new ProtocolError(
        "plan_stale",
        "Server state changed after plan was generated; generate a new plan before applying",
      );
    }

    // Consume plan so it cannot be applied twice.
    plans.delete(planId);

    const selectedModKeys = new Set<string>(
      parsed.data.selected_mod_keys ??
        plan.changes.mods.filter((c) => c.selected_by_default).map((c) => c.key),
    );
    const selectedFilePaths = new Set<string>(
      (
        parsed.data.selected_file_paths ??
        plan.changes.files.filter((c) => c.selected_by_default).map((c) => c.path)
      ).map(normalizeRelativePath),
    );

    const inputModByKey = new Map(plan.input.mods.map((m) => [m.key, m]));
    const inputFileByPath = new Map(
      (plan.input.files ?? []).map((f) => [normalizeRelativePath(f.path), f]),
    );

    // Phase 1: Download & verify all required artifacts BEFORE mutating server state or invoking backup hook.
    const downloadedMods = new Map<
      string,
      {
        readonly file: string;
        readonly data: Uint8Array;
        readonly sha1: string;
        readonly sha256: string;
        readonly sha512: string;
      }
    >();
    for (const change of plan.changes.mods) {
      if (!selectedModKeys.has(change.key)) {
        continue;
      }
      if (change.kind === "added" || change.kind === "updated") {
        const spec = inputModByKey.get(change.key);
        if (!spec?.url) {
          throw new ProtocolError(
            "download_failed",
            `Missing download URL for planned mod "${change.key}"`,
          );
        }
        const safeFile = validateSingleFileName(spec.file);
        const dl = await downloadVerifiedBuffer({
          url: spec.url,
          allowedHosts,
          expectedHashes: { sha1: spec.sha1, sha256: spec.sha256, sha512: spec.sha512 },
          maxBytes: maxModBytes,
          ...(options.maxRedirects !== undefined ? { maxRedirects: options.maxRedirects } : {}),
          ...(options.downloadTimeoutMs !== undefined
            ? { timeoutMs: options.downloadTimeoutMs }
            : {}),
          ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
        });
        downloadedMods.set(change.key, {
          file: safeFile,
          data: dl.data,
          sha1: dl.sha1,
          sha256: dl.sha256,
          sha512: dl.sha512,
        });
      }
    }

    const downloadedFiles = new Map<string, Uint8Array>();
    for (const change of plan.changes.files) {
      if (!selectedFilePaths.has(change.path)) {
        continue;
      }
      if (change.kind === "added" || change.kind === "changed") {
        const spec = inputFileByPath.get(change.path);
        if (!spec) {
          continue;
        }
        if (spec.url !== undefined) {
          const dl = await downloadVerifiedBuffer({
            url: spec.url,
            allowedHosts,
            expectedHashes: { sha1: spec.sha1, sha256: spec.sha256 },
            maxBytes: maxModBytes,
            ...(options.maxRedirects !== undefined ? { maxRedirects: options.maxRedirects } : {}),
            ...(options.downloadTimeoutMs !== undefined
              ? { timeoutMs: options.downloadTimeoutMs }
              : {}),
            ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
          });
          downloadedFiles.set(change.path, dl.data);
        } else if (spec.content_base64 !== undefined) {
          const decoded = decodeStrictBase64(spec.content_base64, maxModBytes);
          const actualSha1 = createHash("sha1").update(decoded).digest("hex");
          if (!hexDigestsEqual(actualSha1, spec.sha1)) {
            throw new ProtocolError(
              "hash_mismatch",
              `Checksum mismatch for planned file "${change.path}"`,
            );
          }
          if (spec.sha256 !== undefined) {
            const actualSha256 = createHash("sha256").update(decoded).digest("hex");
            if (!hexDigestsEqual(actualSha256, spec.sha256)) {
              throw new ProtocolError(
                "hash_mismatch",
                `SHA-256 checksum mismatch for planned file "${change.path}"`,
              );
            }
          }
          downloadedFiles.set(change.path, decoded);
        } else {
          throw new ProtocolError(
            "download_failed",
            `Missing content or download URL for planned file "${change.path}"`,
          );
        }
      }
    }

    // Phase 2: Invoke backup hook before mutating the server.
    if (backupBeforeChange) {
      await backupHook.beforeChange(serverId);
    }

    // Phase 3: Apply filesystem changes via confined writes/deletions.
    let modsAdded = 0;
    let modsUpdated = 0;
    let modsRemoved = 0;
    let filesWritten = 0;
    let filesRemoved = 0;

    const currentModsByFile = new Map<string, ServerModEntry>(
      (meta.mods ?? []).map((m) => [m.file, m]),
    );

    const originSource =
      plan.input.source ?? (meta.origin?.kind === "modpack" ? meta.origin.source : "tegra");

    for (const change of plan.changes.mods) {
      if (!selectedModKeys.has(change.key)) {
        continue;
      }
      if (change.kind === "removed") {
        if (change.target_filename !== undefined) {
          const safeTarget = validateSingleFileName(change.target_filename);
          removeConfinedFileIfExists(serversDir, serverId, `${MODS_DIR}/${safeTarget}`);
          currentModsByFile.delete(safeTarget);
          modsRemoved++;
        }
        continue;
      }

      const downloaded = downloadedMods.get(change.key);
      const spec = inputModByKey.get(change.key);
      if (!downloaded || !spec) {
        continue;
      }

      if (
        change.kind === "updated" &&
        change.target_filename !== undefined &&
        change.target_filename !== downloaded.file
      ) {
        const oldSafe = validateSingleFileName(change.target_filename);
        removeConfinedFileIfExists(serversDir, serverId, `${MODS_DIR}/${oldSafe}`);
        currentModsByFile.delete(oldSafe);
      }

      const resolved = resolveConfinedPath({
        serversBaseDir: serversDir,
        serverId,
        relPath: `${MODS_DIR}/${downloaded.file}`,
        allowRoot: false,
      });
      writeConfinedFileAtomic(resolved, downloaded.data, { createParents: true });

      const entry: ServerModEntry = {
        file: downloaded.file,
        source: spec.source ?? originSource,
        ...(spec.project_id !== undefined ? { project_id: spec.project_id } : {}),
        ...(spec.version_id !== undefined ? { version_id: spec.version_id } : {}),
        sha1: downloaded.sha1,
        sha256: downloaded.sha256,
        sha512: downloaded.sha512,
        layer: "origin",
      };
      currentModsByFile.set(downloaded.file, entry);

      if (change.kind === "added") {
        modsAdded++;
      } else {
        modsUpdated++;
      }
    }

    for (const change of plan.changes.files) {
      if (!selectedFilePaths.has(change.path)) {
        continue;
      }
      if (change.kind === "removed") {
        if (removeConfinedFileIfExists(serversDir, serverId, change.path)) {
          filesRemoved++;
        }
        continue;
      }
      const fileData = downloadedFiles.get(change.path);
      if (fileData !== undefined) {
        const resolved = resolveConfinedPath({
          serversBaseDir: serversDir,
          serverId,
          relPath: change.path,
          allowRoot: false,
        });
        writeConfinedFileAtomic(resolved, fileData, { createParents: true });
        filesWritten++;
      }
    }

    const nextSync = nextOriginSyncState({
      state: syncState,
      modChanges: plan.changes.mods,
      fileChanges: plan.changes.files,
      selectedModKeys,
      selectedFilePaths,
      sourceMods: plan.sourceMods,
      sourceFiles: plan.sourceFiles,
      versionId: plan.input.to_version_id,
      nowIso: new Date(currentTime).toISOString(),
    });

    const nextOrigin: ServerOrigin =
      plan.input.modpack_id !== undefined
        ? {
            kind: "modpack",
            source: originSource,
            modpack_id: plan.input.modpack_id,
            version_id: plan.input.to_version_id,
          }
        : meta.origin?.kind === "modpack"
          ? {
              ...meta.origin,
              version_id: plan.input.to_version_id,
            }
          : (meta.origin ?? null);

    const nextMeta: ServerMetadata = {
      ...meta,
      ...(plan.input.minecraft_version !== undefined
        ? { minecraft_version: plan.input.minecraft_version }
        : {}),
      ...(plan.input.loader !== undefined ? { loader: plan.input.loader } : {}),
      ...(plan.input.loader_version !== undefined
        ? { loader_version: plan.input.loader_version }
        : {}),
      origin: nextOrigin,
      mods: [...currentModsByFile.values()].sort((a, b) => a.file.localeCompare(b.file)),
      origin_sync: nextSync,
    };
    writeServerMetadata(serversDir, nextMeta);

    options.logger?.info("Applied origin sync plan", {
      serverId,
      planId,
      modsAdded,
      modsUpdated,
      modsRemoved,
      filesWritten,
      filesRemoved,
    });

    return {
      server_id: serverId,
      plan_id: planId,
      origin: nextOrigin,
      mods_added: modsAdded,
      mods_updated: modsUpdated,
      mods_removed: modsRemoved,
      files_written: filesWritten,
      files_removed: filesRemoved,
    };
  }

  async function deployServerPack(
    params: ServerDeployServerpackBody,
  ): Promise<ServerPackDeployResult> {
    const parsed = serverDeployServerpackBodySchema.safeParse(params);
    if (!parsed.success) {
      throw new ProtocolError("invalid_body", "Invalid server.deploy.serverpack parameters");
    }
    const { server_id: serverId, url, sha1, sha256, sha512, origin, key } = parsed.data;
    const meta = readServerMetadata(serversDir, serverId);

    // Download & verify hash BEFORE backup hook or extraction.
    const downloaded = await downloadVerifiedBuffer({
      url,
      allowedHosts,
      expectedHashes: { sha1, sha256, sha512 },
      maxBytes: maxServerPackBytes,
      ...(options.maxRedirects !== undefined ? { maxRedirects: options.maxRedirects } : {}),
      ...(options.downloadTimeoutMs !== undefined ? { timeoutMs: options.downloadTimeoutMs } : {}),
      ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
    });

    // With a key the blob is TGB1-encrypted: decrypt (and authenticate) before touching the server.
    const packBytes =
      key !== undefined
        ? await decryptDownloadedBlob(downloaded.data, key, maxServerPackBytes * 4)
        : downloaded.data;

    if (backupBeforeChange) {
      await backupHook.beforeChange(serverId);
    }

    const unzipResult = safeUnzipBuffer({
      serversBaseDir: serversDir,
      serverId,
      buffer: packBytes,
      forbiddenPaths: PROTECTED_SERVERPACK_PATHS,
    });

    const nextOrigin: ServerOrigin = origin !== undefined ? origin : (meta.origin ?? null);
    const modEntriesByFile = new Map<string, ServerModEntry>(
      (meta.mods ?? []).map((m) => [m.file, m]),
    );
    const originSource = nextOrigin?.kind === "modpack" ? nextOrigin.source : "local";

    const extractedSyncedFiles: string[] = [];
    const extractedModKeys: string[] = [];

    for (const relPath of unzipResult.files) {
      if (relPath.startsWith(`${MODS_DIR}/`) && !relPath.slice(MODS_DIR.length + 1).includes("/")) {
        const fileName = validateSingleFileName(relPath.slice(MODS_DIR.length + 1));
        const resolved = resolveConfinedPath({
          serversBaseDir: serversDir,
          serverId,
          relPath,
          allowRoot: false,
        });
        const fileSha1 = hashFileSha1(resolved.fullPath);
        const fileSha256 = hashFileSha256(resolved.fullPath);
        const entry: ServerModEntry = {
          file: fileName,
          source: originSource,
          sha1: fileSha1,
          sha256: fileSha256,
          layer: nextOrigin?.kind === "modpack" ? "origin" : "user",
        };
        modEntriesByFile.set(fileName, entry);
        extractedModKeys.push(modKeyFromMetadataEntry(entry));
      } else if (isServerContentPath(relPath)) {
        extractedSyncedFiles.push(relPath);
      }
    }

    const nextSync: ServerOriginSyncState | undefined =
      nextOrigin?.kind === "modpack"
        ? {
            excluded_mod_keys: [],
            synced_mod_keys: [...new Set(extractedModKeys)].sort(),
            removed_origin_files: [],
            synced_files: [...new Set(extractedSyncedFiles)].sort(),
            last_synced_at: new Date(now()).toISOString(),
            last_synced_version_id: nextOrigin.version_id,
          }
        : meta.origin_sync;

    const nextMeta: ServerMetadata = {
      ...meta,
      origin: nextOrigin,
      mods: [...modEntriesByFile.values()].sort((a, b) => a.file.localeCompare(b.file)),
      ...(nextSync !== undefined ? { origin_sync: nextSync } : {}),
    };
    writeServerMetadata(serversDir, nextMeta);
    invalidatePlansForServer(serverId);

    options.logger?.info("Deployed server pack", {
      serverId,
      bytes: downloaded.bytes,
      entryCount: unzipResult.entryCount,
    });

    return {
      server_id: serverId,
      bytes: downloaded.bytes,
      sha256: downloaded.sha256,
      entry_count: unzipResult.entryCount,
      extracted_files: unzipResult.files,
      origin: nextOrigin,
    };
  }

  async function importWorld(params: ServerWorldImportBody): Promise<WorldImportResult> {
    const parsed = serverWorldImportBodySchema.safeParse(params);
    if (!parsed.success) {
      throw new ProtocolError("invalid_body", "Invalid server.world.import parameters");
    }
    const { server_id: serverId, world_name: worldName, url, sha256, key } = parsed.data;
    readServerMetadata(serversDir, serverId);

    if (options.isServerActive === undefined || (await options.isServerActive(serverId))) {
      throw new ProtocolError("server_running", "The server must be stopped to import a world");
    }

    // Download and authenticate everything before anything on disk changes.
    const downloaded = await downloadVerifiedBuffer({
      url,
      allowedHosts,
      expectedHashes: { sha256 },
      maxBytes: maxWorldBytes,
      ...(options.maxRedirects !== undefined ? { maxRedirects: options.maxRedirects } : {}),
      ...(options.downloadTimeoutMs !== undefined ? { timeoutMs: options.downloadTimeoutMs } : {}),
      ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
    });
    const archive = await decryptDownloadedBlob(downloaded.data, key, maxWorldBytes * 2);

    const serverDir = join(serversDir, serverId);
    const suffix = randomBytes(6).toString("hex");
    const stagingName = `.tegrad-import-${suffix}`;
    const previousName = `.tegrad-previous-${suffix}`;
    const stagingPath = join(serverDir, stagingName);
    const previousPath = join(serverDir, previousName);
    const worldPath = join(serverDir, worldName);

    // The safety backup runs before the staging folder exists so it is not archived with it.
    if (backupBeforeChange) {
      await backupHook.beforeChange(serverId);
    }

    try {
      let unzip: ReturnType<typeof safeUnzipBuffer>;
      try {
        unzip = safeUnzipBuffer({
          serversBaseDir: serversDir,
          serverId,
          buffer: archive,
          destPath: stagingName,
        });
      } catch (err) {
        if (err instanceof FileManagerError) {
          throw new ProtocolError("invalid_body", `World archive rejected: ${err.code}`);
        }
        throw err;
      }
      if (unzip.files.length === 0) {
        throw new ProtocolError("invalid_body", "World archive has no files");
      }

      // A single top-level folder inside the archive is the world itself.
      let source = stagingPath;
      const top = readdirSync(stagingPath, { withFileTypes: true });
      const only = top[0];
      if (top.length === 1 && only !== undefined && only.isDirectory()) {
        source = join(stagingPath, only.name);
      }

      secureTree(source, SERVER_TREE_PLAN, permissionContext);

      const hadWorld = existsSync(worldPath);
      if (hadWorld) {
        renameSync(worldPath, previousPath);
      }
      try {
        renameSync(source, worldPath);
      } catch (err) {
        if (hadWorld) {
          renameSync(previousPath, worldPath);
        }
        throw err;
      }
      if (hadWorld) {
        rmSync(previousPath, { recursive: true, force: true });
      }
      options.logger?.info("Imported world", { serverId, worldName, entryCount: unzip.entryCount });
      return { server_id: serverId, world_name: worldName };
    } finally {
      rmSync(stagingPath, { recursive: true, force: true });
    }
  }

  return {
    importWorld,
    listMods,
    installMod,
    removeMod,
    unlinkOrigin,
    updateVersionLoader,
    planOriginSync,
    applyOriginSync,
    deployServerPack,
  };
}

export function registerStateHandlers(queue: CommandQueue, manager: StateManager): void {
  queue.registerHandler("server.mods.list", (opened, ctx) => {
    const body = opened.body as { readonly server_id: string };
    const result = manager.listMods(body.server_id);
    ctx.sendEvent("server.mods.list.result", result);
  });

  queue.registerHandler("server.mods.install", async (opened, ctx) => {
    const body = opened.body as ServerModsInstallBody;
    const result = await manager.installMod(body);
    ctx.sendEvent("server.mods.installed", result);
  });

  queue.registerHandler("server.mods.remove", (opened, ctx) => {
    const body = opened.body as ServerModsRemoveBody;
    const result = manager.removeMod(body);
    ctx.sendEvent("server.mods.removed", result);
  });

  queue.registerHandler("server.origin.plan", (opened, ctx) => {
    const body = opened.body as ServerOriginPlanBody;
    const result = manager.planOriginSync(body);
    ctx.sendEvent("server.origin.planned", result);
  });

  queue.registerHandler("server.origin.apply", async (opened, ctx) => {
    const body = opened.body as ServerOriginApplyBody;
    const result = await manager.applyOriginSync(body);
    ctx.sendEvent("server.origin.applied", result);
  });

  queue.registerHandler("server.origin.unlink", (opened, ctx) => {
    const body = opened.body as { readonly server_id: string };
    const result = manager.unlinkOrigin(body.server_id);
    ctx.sendEvent("server.origin.unlinked", result);
  });

  queue.registerHandler("server.world.import", async (opened, ctx) => {
    const body = opened.body as ServerWorldImportBody;
    const result = await manager.importWorld(body);
    ctx.sendEvent("server.world.imported", result);
  });

  queue.registerHandler("server.deploy.serverpack", async (opened, ctx) => {
    const body = opened.body as ServerDeployServerpackBody;
    const result = await manager.deployServerPack(body);
    ctx.sendEvent("server.deploy.serverpack.result", result);
  });
}
