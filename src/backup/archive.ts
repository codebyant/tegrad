// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readdirSync,
  readSync,
  type Stats,
} from "node:fs";
import { join } from "node:path";
import type { Logger } from "../agent/logger";
import {
  createZipBuffer,
  DEFAULT_SERVERS_BASE_DIR,
  MAX_ZIP_CREATE_BYTES,
  MAX_ZIP_CREATE_FILES,
  openConfinedFileForRead,
  RUNTIME_DIR_NAME,
  resolveConfinedPath,
  resolveServerRoot,
  type SafeUnzipResult,
  safeUnzipBuffer,
  sha256Hex,
  UPLOAD_STAGING_DIR_NAME,
  UPLOAD_STAGING_FILE_PREFIX,
  validateServerId,
  type ZipEntryInput,
} from "../files";
import { ProtocolError } from "../protocol";
import type { PermissionContext } from "../server/permissions";
import type { ServerRuntimeProvider } from "./types";

export const DEFAULT_SAVE_TIMEOUT_MS = 30_000;
export const DEFAULT_SAVE_POLL_INTERVAL_MS = 100;

const SAVE_CONFIRMATION_PATTERN = /Saved the (?:game|world)/i;
const PROTECTED_RESTORE_PATHS: ReadonlySet<string> = new Set(["start.sh"]);

function readAllFromFd(fd: number, maxBytes: number): Uint8Array {
  const chunks: Uint8Array[] = [];
  let total = 0;
  const scratch = Buffer.allocUnsafe(64 * 1024);

  while (true) {
    const toRead = Math.min(scratch.byteLength, maxBytes - total + 1);
    const bytesRead = readSync(fd, scratch, 0, toRead, null);
    if (bytesRead === 0) {
      break;
    }
    total += bytesRead;
    if (total > maxBytes) {
      throw new ProtocolError("backup_failed", "Server archive exceeds maximum allowed size");
    }
    const copy = new Uint8Array(bytesRead);
    copy.set(scratch.subarray(0, bytesRead));
    chunks.push(copy);
  }

  const out = new Uint8Array(total);
  let pos = 0;
  for (const chunk of chunks) {
    out.set(chunk, pos);
    pos += chunk.byteLength;
  }
  return out;
}

function getConsoleLogSize(logPath: string): number {
  const lstat = lstatSync(logPath, { throwIfNoEntry: false });
  if (lstat === undefined || lstat.isSymbolicLink() || !lstat.isFile()) {
    return 0;
  }
  return lstat.size;
}

function readLogTailText(
  logPath: string,
  fromOffset: number,
): {
  readonly text: string;
  readonly nextOffset: number;
} {
  const lstat = lstatSync(logPath, { throwIfNoEntry: false });
  if (lstat === undefined || lstat.isSymbolicLink() || !lstat.isFile()) {
    return { text: "", nextOffset: fromOffset };
  }

  const size = lstat.size;
  const effectiveOffset = size < fromOffset ? 0 : fromOffset;
  const available = size - effectiveOffset;
  if (available <= 0) {
    return { text: "", nextOffset: effectiveOffset };
  }

  const toRead = Math.min(available, 256 * 1024);
  const buf = Buffer.allocUnsafe(toRead);
  const openFlags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
  let fd: number | undefined;
  try {
    fd = openSync(logPath, openFlags);
    const fdStat = fstatSync(fd);
    if (!fdStat.isFile()) {
      return { text: "", nextOffset: effectiveOffset };
    }
    const bytesRead = readSync(fd, buf, 0, toRead, effectiveOffset);
    if (bytesRead <= 0) {
      return { text: "", nextOffset: effectiveOffset };
    }
    return {
      text: buf.subarray(0, bytesRead).toString("utf8"),
      nextOffset: effectiveOffset + bytesRead,
    };
  } catch {
    return { text: "", nextOffset: effectiveOffset };
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        // ignore close failure
      }
    }
  }
}

export interface WaitForSaveOptions {
  readonly logPath: string;
  readonly startOffset: number;
  readonly timeoutMs: number;
  readonly pollIntervalMs: number;
  readonly now: () => number;
  readonly sleep: (ms: number) => Promise<void>;
}

export async function waitForSaveConfirmation(options: WaitForSaveOptions): Promise<void> {
  const deadline = options.now() + options.timeoutMs;
  let offset = options.startOffset;
  let buffer = "";

  while (true) {
    const chunk = readLogTailText(options.logPath, offset);
    offset = chunk.nextOffset;
    if (chunk.text.length > 0) {
      buffer += chunk.text;
      if (SAVE_CONFIRMATION_PATTERN.test(buffer)) {
        return;
      }
      // Keep only the last 4 KiB to avoid unbounded memory growth on noisy logs.
      if (buffer.length > 4096) {
        buffer = buffer.slice(buffer.length - 4096);
      }
    }

    if (options.now() >= deadline) {
      throw new ProtocolError(
        "backup_failed",
        `Timed out waiting for Minecraft server save confirmation after ${options.timeoutMs}ms`,
      );
    }

    const remaining = Math.max(1, Math.min(options.pollIntervalMs, deadline - options.now()));
    await options.sleep(remaining);
  }
}

export interface ArchiveServerDirectoryOptions {
  readonly serversBaseDir?: string;
  readonly serverId: string;
  readonly maxFiles?: number;
  readonly maxTotalBytes?: number;
  readonly logger?: Logger;
}

export interface ServerArchiveResult {
  readonly buffer: Uint8Array;
  readonly sha256: string;
  readonly entryCount: number;
  readonly uncompressedBytes: number;
}

export function archiveServerDirectory(
  options: ArchiveServerDirectoryOptions,
): ServerArchiveResult {
  const serversBaseDir = options.serversBaseDir ?? DEFAULT_SERVERS_BASE_DIR;
  const validId = validateServerId(options.serverId);
  const maxFiles = options.maxFiles ?? MAX_ZIP_CREATE_FILES;
  const maxTotalBytes = options.maxTotalBytes ?? MAX_ZIP_CREATE_BYTES;

  const { realServerRoot } = resolveServerRoot(validId, serversBaseDir);
  if (!existsSync(realServerRoot)) {
    throw new ProtocolError("server_not_found", `Server directory not found: ${validId}`);
  }

  const entries: ZipEntryInput[] = [];
  let totalUncompressed = 0;

  function walkDir(relDir: string): void {
    const resolvedDir = resolveConfinedPath({
      serversBaseDir,
      serverId: validId,
      relPath: relDir,
      allowRoot: true,
    });

    const children = readdirSync(resolvedDir.fullPath).sort();
    for (const child of children) {
      if (
        child === RUNTIME_DIR_NAME ||
        child === UPLOAD_STAGING_DIR_NAME ||
        child.startsWith(UPLOAD_STAGING_FILE_PREFIX) ||
        child.startsWith(".tmp-") ||
        (relDir.length === 0 && child === "start.sh")
      ) {
        continue;
      }

      const childRel = relDir.length > 0 ? `${relDir}/${child}` : child;
      const childFull = join(resolvedDir.fullPath, child);
      const stats: Stats = lstatSync(childFull);

      if (stats.isSymbolicLink()) {
        options.logger?.warn("Skipping symbolic link while archiving server backup", {
          serverId: validId,
          path: childRel,
        });
        continue;
      }

      if (stats.isDirectory()) {
        if (entries.length >= maxFiles) {
          throw new ProtocolError("backup_failed", "Backup archive entry count limit exceeded");
        }
        entries.push({
          name: `${childRel}/`,
          data: new Uint8Array(0),
          isDirectory: true,
          mtime: stats.mtime,
        });
        walkDir(childRel);
        continue;
      }

      if (!stats.isFile()) {
        continue;
      }

      if (entries.length >= maxFiles) {
        throw new ProtocolError("backup_failed", "Backup archive entry count limit exceeded");
      }

      const confinedFile = resolveConfinedPath({
        serversBaseDir,
        serverId: validId,
        relPath: childRel,
        allowRoot: false,
      });
      const { fd, stats: fdStats } = openConfinedFileForRead(confinedFile);
      let data: Uint8Array;
      try {
        if (totalUncompressed + fdStats.size > maxTotalBytes) {
          throw new ProtocolError("backup_failed", "Backup archive total size limit exceeded");
        }
        data = readAllFromFd(fd, maxTotalBytes - totalUncompressed);
      } finally {
        closeSync(fd);
      }

      totalUncompressed += data.byteLength;
      entries.push({
        name: childRel,
        data,
        isDirectory: false,
        mtime: fdStats.mtime,
      });
    }
  }

  walkDir("");

  const buffer = createZipBuffer(entries);
  const sha256 = sha256Hex(buffer);

  return {
    buffer,
    sha256,
    entryCount: entries.length,
    uncompressedBytes: totalUncompressed,
  };
}

export interface CreateConsistentArchiveOptions {
  readonly serversBaseDir?: string;
  readonly serverId: string;
  readonly runtime?: ServerRuntimeProvider;
  readonly saveTimeoutMs?: number;
  readonly savePollIntervalMs?: number;
  readonly maxFiles?: number;
  readonly maxTotalBytes?: number;
  readonly now?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly logger?: Logger;
  readonly archiveImpl?: (options: ArchiveServerDirectoryOptions) => ServerArchiveResult;
}

export async function createConsistentServerArchive(
  options: CreateConsistentArchiveOptions,
): Promise<ServerArchiveResult> {
  const serversBaseDir = options.serversBaseDir ?? DEFAULT_SERVERS_BASE_DIR;
  const validId = validateServerId(options.serverId);
  const saveTimeoutMs = options.saveTimeoutMs ?? DEFAULT_SAVE_TIMEOUT_MS;
  const savePollIntervalMs = options.savePollIntervalMs ?? DEFAULT_SAVE_POLL_INTERVAL_MS;
  const now = options.now ?? (() => Date.now());
  const sleep = options.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
  const archiveFn = options.archiveImpl ?? archiveServerDirectory;

  const isRunning =
    options.runtime !== undefined ? await options.runtime.isRunning(validId) : false;

  if (!isRunning || options.runtime === undefined) {
    return archiveFn({
      serversBaseDir,
      serverId: validId,
      ...(options.maxFiles !== undefined ? { maxFiles: options.maxFiles } : {}),
      ...(options.maxTotalBytes !== undefined ? { maxTotalBytes: options.maxTotalBytes } : {}),
      ...(options.logger !== undefined ? { logger: options.logger } : {}),
    });
  }

  const logResolved = resolveConfinedPath({
    serversBaseDir,
    serverId: validId,
    relPath: "logs/console.log",
    allowRoot: false,
  });
  const logPath = logResolved.fullPath;
  const startOffset = getConsoleLogSize(logPath);

  await options.runtime.sendConsole(validId, "save-off");
  try {
    await options.runtime.sendConsole(validId, "save-all flush");
    await waitForSaveConfirmation({
      logPath,
      startOffset,
      timeoutMs: saveTimeoutMs,
      pollIntervalMs: savePollIntervalMs,
      now,
      sleep,
    });
    return archiveFn({
      serversBaseDir,
      serverId: validId,
      ...(options.maxFiles !== undefined ? { maxFiles: options.maxFiles } : {}),
      ...(options.maxTotalBytes !== undefined ? { maxTotalBytes: options.maxTotalBytes } : {}),
      ...(options.logger !== undefined ? { logger: options.logger } : {}),
    });
  } finally {
    try {
      await options.runtime.sendConsole(validId, "save-on");
    } catch (err) {
      options.logger?.error("Failed to re-enable saving (save-on) after backup", {
        serverId: validId,
        errName: err instanceof Error ? err.name : "Error",
      });
    }
  }
}

export interface RestoreServerArchiveOptions {
  readonly serversBaseDir?: string;
  readonly serverId: string;
  readonly archive: Uint8Array;
  readonly maxEntries?: number;
  readonly maxUncompressedBytes?: number;
  readonly maxEntryBytes?: number;
  readonly permissions?: PermissionContext;
}

export function restoreServerArchive(options: RestoreServerArchiveOptions): SafeUnzipResult {
  const serversBaseDir = options.serversBaseDir ?? DEFAULT_SERVERS_BASE_DIR;
  const validId = validateServerId(options.serverId);

  return safeUnzipBuffer({
    serversBaseDir,
    serverId: validId,
    buffer: options.archive,
    destPath: "",
    forbiddenPaths: PROTECTED_RESTORE_PATHS,
    ...(options.permissions !== undefined ? { permissions: options.permissions } : {}),
    ...(options.maxEntries !== undefined ? { maxEntries: options.maxEntries } : {}),
    ...(options.maxUncompressedBytes !== undefined
      ? { maxUncompressedBytes: options.maxUncompressedBytes }
      : {}),
    ...(options.maxEntryBytes !== undefined ? { maxEntryBytes: options.maxEntryBytes } : {}),
  });
}
