// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import type { ModEnvironmentInfo, ServerOriginSyncState } from "../protocol";

export const SERVER_PACK_MANIFEST_FILE = "tegra.manifest.json";
export const SERVER_PACK_WORLD_DIR = "world";

const CLIENT_ONLY_ROOT_DIRS = new Set([
  "mods",
  "saves",
  "resourcepacks",
  "shaderpacks",
  "screenshots",
  "logs",
  "crash-reports",
  "backups",
  "downloads",
  "debug",
  "journeymap",
  "xaero",
  "xaeroworldmap",
  "xaerowaypoints",
  ".tegra",
  ".fabric",
  ".mixin.out",
  ".cache",
  ".runtime",
  ".tegrad-uploads",
]);

const CLIENT_ONLY_ROOT_FILES = new Set([
  "options.txt",
  "optionsof.txt",
  "optionsshaders.txt",
  "servers.dat",
  "servers.dat_old",
  "usercache.json",
  "usernamecache.json",
  "realms_persistence.json",
  "command_history.txt",
  "mods-manifest.json",
  "modpack.json",
  "tegrad-server.json",
  "start.sh",
]);

const CREATE_COPY_EXCLUDED_DIRS = new Set([
  "resourcepacks",
  "shaderpacks",
  "screenshots",
  "logs",
  "crash-reports",
  "backups",
  "debug",
  ".tegra",
  ".fabric",
  ".mixin.out",
  ".cache",
  ".runtime",
  ".tegrad-uploads",
]);

export function normalizeRelativePath(filePath: string): string {
  return filePath.replace(/\\/g, "/").replace(/^\/+/, "");
}

function rootSegment(relativePath: string): string {
  return (normalizeRelativePath(relativePath).split("/")[0] ?? "").toLowerCase();
}

export function isServerContentPath(relativePath: string): boolean {
  const normalized = normalizeRelativePath(relativePath);
  if (!normalized) {
    return false;
  }
  const segments = normalized.split("/");
  const root = (segments[0] ?? "").toLowerCase();
  if (segments.length === 1) {
    if (CLIENT_ONLY_ROOT_FILES.has(root)) {
      return false;
    }
    if (root.endsWith(".log") || root.startsWith("hs_err")) {
      return false;
    }
    return true;
  }
  return !CLIENT_ONLY_ROOT_DIRS.has(root);
}

export function shouldCopyOnCreate(relativePath: string, includeSaves: boolean): boolean {
  const root = rootSegment(relativePath);
  if (!root) {
    return true;
  }
  if (root === "saves") {
    return includeSaves;
  }
  return !CREATE_COPY_EXCLUDED_DIRS.has(root);
}

export function worldArchivePath(worldName: string, relativePath: string): string | null {
  const normalized = normalizeRelativePath(relativePath);
  const prefix = `saves/${worldName}/`;
  if (!normalized.startsWith(prefix)) {
    return null;
  }
  const rest = normalized.slice(prefix.length);
  return rest ? `${SERVER_PACK_WORLD_DIR}/${rest}` : null;
}

export function stripDisabledSuffix(filename: string): string {
  return filename.replace(/\.disabled$/i, "");
}

export interface ModIdentitySource {
  readonly filename: string;
  readonly modInfo?: { readonly modId?: string; readonly name?: string } | null;
}

export function modIdentityKey(entry: ModIdentitySource): string {
  const modId =
    typeof entry.modInfo?.modId === "string" ? entry.modInfo.modId.trim().toLowerCase() : "";
  if (modId) {
    return `id:${modId}`;
  }
  const name =
    typeof entry.modInfo?.name === "string" ? entry.modInfo.name.trim().toLowerCase() : "";
  if (name) {
    return `name:${name}`;
  }
  return `file:${stripDisabledSuffix(entry.filename).toLowerCase()}`;
}

export interface ModRedistributionInfo {
  readonly allowed: boolean | null;
  readonly license?: string;
}

export function isClientOnly(environment?: ModEnvironmentInfo | null): boolean {
  return environment?.server === "unsupported";
}

export function isRedistributionRestricted(redistribution?: ModRedistributionInfo | null): boolean {
  return redistribution?.allowed === false;
}

export function redistributionFromModrinthLicense(licenseId: unknown): ModRedistributionInfo {
  const id = typeof licenseId === "string" ? licenseId.trim() : "";
  if (!id) {
    return { allowed: null };
  }
  if (id === "LicenseRef-All-Rights-Reserved") {
    return { allowed: false, license: id };
  }
  if (id.startsWith("LicenseRef-")) {
    return { allowed: null, license: id };
  }
  return { allowed: true, license: id };
}

export interface PlanMod {
  readonly key: string;
  readonly filename: string;
  readonly enabled: boolean;
  readonly name: string;
  readonly version?: string | undefined;
  readonly sha1?: string | undefined;
  readonly sha512?: string | undefined;
  readonly environment?: ModEnvironmentInfo | undefined;
}

export interface PlanFile {
  readonly path: string;
  readonly sha1: string;
  readonly size_bytes: number;
}

export type ModExcludedReason = "excluded" | "removed_locally";

export interface OriginModChange {
  readonly key: string;
  readonly name: string;
  readonly kind: "added" | "updated" | "removed";
  readonly source_filename?: string;
  readonly target_filename?: string;
  readonly source_version?: string;
  readonly target_version?: string;
  readonly client_only: boolean;
  readonly excluded_reason?: ModExcludedReason;
  readonly selected_by_default: boolean;
}

export interface OriginFileChange {
  readonly path: string;
  readonly kind: "added" | "changed" | "removed";
  readonly size_bytes: number;
  readonly excluded_reason?: "removed_locally";
  readonly selected_by_default: boolean;
}

export interface OriginSyncChanges {
  readonly mods: readonly OriginModChange[];
  readonly files: readonly OriginFileChange[];
}

export function emptyOriginSyncState(): ServerOriginSyncState {
  return {
    excluded_mod_keys: [],
    synced_mod_keys: [],
    removed_origin_files: [],
    synced_files: [],
    last_synced_at: null,
    last_synced_version_id: null,
  };
}

function hasModContentChanged(source: PlanMod, target: PlanMod): boolean {
  if (source.sha512 && target.sha512) {
    return source.sha512.toLowerCase() !== target.sha512.toLowerCase();
  }
  if (source.sha1 && target.sha1) {
    return source.sha1.toLowerCase() !== target.sha1.toLowerCase();
  }
  if (source.version && target.version) {
    return source.version !== target.version;
  }
  return false;
}

export function buildOriginSyncChanges(input: {
  readonly sourceMods: readonly PlanMod[];
  readonly targetMods: readonly PlanMod[];
  readonly sourceFiles: readonly PlanFile[];
  readonly targetFiles: readonly PlanFile[];
  readonly state: ServerOriginSyncState;
}): OriginSyncChanges {
  const sourceMods = input.sourceMods.filter((mod) => mod.enabled);
  const sourceByKey = new Map(sourceMods.map((mod) => [mod.key, mod]));
  const targetByKey = new Map(input.targetMods.map((mod) => [mod.key, mod]));
  const explicitExcluded = new Set(input.state.excluded_mod_keys);
  const synced = new Set(input.state.synced_mod_keys);
  const removedOriginFiles = new Set(
    (input.state.removed_origin_files ?? []).map(normalizeRelativePath),
  );
  const syncedFiles = new Set((input.state.synced_files ?? []).map(normalizeRelativePath));

  const mods: OriginModChange[] = [];
  for (const source of sourceMods) {
    const target = targetByKey.get(source.key);
    const clientOnly = isClientOnly(source.environment);
    if (!target) {
      const excludedReason: ModExcludedReason | undefined = explicitExcluded.has(source.key)
        ? "excluded"
        : synced.has(source.key)
          ? "removed_locally"
          : undefined;
      mods.push({
        key: source.key,
        name: source.name,
        kind: "added",
        source_filename: source.filename,
        ...(source.version !== undefined ? { source_version: source.version } : {}),
        client_only: clientOnly,
        ...(excludedReason !== undefined ? { excluded_reason: excludedReason } : {}),
        selected_by_default: excludedReason === undefined,
      });
      continue;
    }

    if (hasModContentChanged(source, target)) {
      mods.push({
        key: source.key,
        name: source.name,
        kind: "updated",
        source_filename: source.filename,
        target_filename: target.filename,
        ...(source.version !== undefined ? { source_version: source.version } : {}),
        ...(target.version !== undefined ? { target_version: target.version } : {}),
        client_only: clientOnly,
        selected_by_default: true,
      });
    }
  }

  for (const target of input.targetMods) {
    if (sourceByKey.has(target.key) || !synced.has(target.key)) {
      continue;
    }
    mods.push({
      key: target.key,
      name: target.name,
      kind: "removed",
      target_filename: target.filename,
      ...(target.version !== undefined ? { target_version: target.version } : {}),
      client_only: isClientOnly(target.environment),
      selected_by_default: true,
    });
  }

  const sourceFilesByPath = new Map(
    input.sourceFiles.map((file) => [normalizeRelativePath(file.path), file]),
  );
  const targetFilesByPath = new Map(
    input.targetFiles.map((file) => [normalizeRelativePath(file.path), file]),
  );

  const files: OriginFileChange[] = [];
  for (const [normPath, source] of sourceFilesByPath) {
    const target = targetFilesByPath.get(normPath);
    if (!target) {
      const wasRemovedLocally = removedOriginFiles.has(normPath) || syncedFiles.has(normPath);
      files.push({
        path: normPath,
        kind: "added",
        size_bytes: source.size_bytes,
        ...(wasRemovedLocally ? { excluded_reason: "removed_locally" as const } : {}),
        selected_by_default: !wasRemovedLocally,
      });
    } else if (target.sha1.toLowerCase() !== source.sha1.toLowerCase()) {
      files.push({
        path: normPath,
        kind: "changed",
        size_bytes: source.size_bytes,
        selected_by_default: true,
      });
    }
  }

  for (const [normPath, target] of targetFilesByPath) {
    if (sourceFilesByPath.has(normPath) || !syncedFiles.has(normPath)) {
      continue;
    }
    files.push({
      path: normPath,
      kind: "removed",
      size_bytes: target.size_bytes,
      selected_by_default: true,
    });
  }

  const byLabel = (a: { name?: string; path?: string }, b: { name?: string; path?: string }) =>
    String(a.name ?? a.path).localeCompare(String(b.name ?? b.path), undefined, {
      sensitivity: "base",
    });

  return {
    mods: mods.sort(byLabel),
    files: files.sort(byLabel),
  };
}

export function nextOriginSyncState(input: {
  readonly state: ServerOriginSyncState;
  readonly modChanges: readonly OriginModChange[];
  readonly fileChanges?: readonly OriginFileChange[];
  readonly selectedModKeys: ReadonlySet<string>;
  readonly selectedFilePaths?: ReadonlySet<string>;
  readonly sourceMods: readonly PlanMod[];
  readonly sourceFiles?: readonly PlanFile[];
  readonly versionId: string;
  readonly nowIso: string;
}): ServerOriginSyncState {
  const excluded = new Set(input.state.excluded_mod_keys);
  for (const change of input.modChanges) {
    if (change.kind !== "added") {
      continue;
    }
    if (input.selectedModKeys.has(change.key)) {
      excluded.delete(change.key);
    } else if (change.excluded_reason === undefined) {
      excluded.add(change.key);
    }
  }

  const removedFiles = new Set((input.state.removed_origin_files ?? []).map(normalizeRelativePath));
  const selectedFiles = input.selectedFilePaths ?? new Set<string>();
  for (const change of input.fileChanges ?? []) {
    if (change.kind !== "added") {
      continue;
    }
    if (selectedFiles.has(change.path)) {
      removedFiles.delete(change.path);
    } else {
      removedFiles.add(change.path);
    }
  }

  const syncedModKeys = [
    ...new Set(input.sourceMods.filter((mod) => mod.enabled).map((mod) => mod.key)),
  ].sort();

  const syncedFiles = [
    ...new Set((input.sourceFiles ?? []).map((f) => normalizeRelativePath(f.path))),
  ].sort();

  return {
    excluded_mod_keys: [...excluded].sort(),
    synced_mod_keys: syncedModKeys,
    removed_origin_files: [...removedFiles].sort(),
    synced_files: syncedFiles,
    last_synced_at: input.nowIso,
    last_synced_version_id: input.versionId,
  };
}
