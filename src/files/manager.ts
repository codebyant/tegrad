// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import {
  closeSync,
  readSync,
  renameSync,
  rmdirSync,
  type Stats,
  unlinkSync,
  writeSync,
} from "node:fs";
import type { CommandQueue } from "../agent/jobs";
import type { Logger } from "../agent/logger";
import type { DirHandle } from "../server/open-beneath";
import { createServerPermissionContext, type PermissionContext } from "../server/permissions";
import { type MakeServerReadableLike, makeServerReadable } from "../server/readable";
import {
  DEFAULT_SERVERS_BASE_DIR,
  isEaccesError,
  isErrnoCode,
  isSameOrSubpath,
  mkdirConfined,
  type openConfinedFileForRead,
  openConfinedFileForReadWithRetry,
  RUNTIME_DIR_NAME,
  resolveConfinedPath,
  UPLOAD_STAGING_DIR_NAME,
  UPLOAD_STAGING_FILE_PREFIX,
  validateSingleFileName,
  withConfinedDir,
  withConfinedParent,
  wrapIoError,
  writeConfinedFileAtomic,
} from "./confinement";
import { FileManagerError } from "./errors";
import {
  type DownloadBeginParams,
  type DownloadBeginResult,
  type DownloadCloseParams,
  type DownloadPartParams,
  type DownloadPartResult,
  type DownloadRangeParams,
  type DownloadRangeResult,
  decodeStrictBase64,
  TransferManager,
  type UploadAbortParams,
  type UploadBeginParams,
  type UploadBeginResult,
  type UploadCommitParams,
  type UploadCommitResult,
  type UploadPartParams,
  type UploadPartResult,
} from "./transfers";
import { type SafeUnzipResult, type SafeZipResult, safeUnzipFile, safeZipFiles } from "./zip";

export const MAX_READ_WRITE_BYTES = 2 * 1024 * 1024; // 2 MiB
export const DEFAULT_MAX_COPY_FILES = 10_000;
export const DEFAULT_MAX_COPY_BYTES = 2 * 1024 * 1024 * 1024; // 2 GiB

export type FileEncoding = "utf8" | "base64";

export interface FileListEntry {
  readonly name: string;
  readonly type: "file" | "directory";
  readonly size: number;
  readonly mtime_ms: number;
}

export interface FileListResult {
  readonly path: string;
  readonly entries: readonly FileListEntry[];
}

export interface FileStatResult {
  readonly path: string;
  readonly exists: boolean;
  readonly type?: "file" | "directory";
  readonly size?: number;
  readonly mtime_ms?: number;
}

export interface FileReadResult {
  readonly path: string;
  readonly encoding: FileEncoding;
  readonly content: string;
  readonly size: number;
}

export interface FileWriteResult {
  readonly path: string;
  readonly size: number;
}

export interface FileCopyResult {
  readonly from_path: string;
  readonly to_path: string;
  readonly files_copied: number;
  readonly bytes_copied: number;
}

export interface FileManagerOptions {
  readonly serversBaseDir?: string;
  readonly maxReadWriteBytes?: number;
  readonly maxCopyFiles?: number;
  readonly maxCopyBytes?: number;
  readonly maxUploadBytes?: number;
  readonly maxPartBytes?: number;
  readonly maxConcurrentUploads?: number;
  readonly maxConcurrentDownloads?: number;
  readonly maxZipEntries?: number;
  readonly maxZipUncompressedBytes?: number;
  readonly maxZipEntryBytes?: number;
  readonly maxZipCompressionRatio?: number;
  readonly zipRatioMinBytes?: number;
  readonly serverGroupId?: number | null;
  readonly logger?: Logger;
  readonly permissions?: PermissionContext;
  readonly makeServerReadableImpl?: MakeServerReadableLike;
  readonly openForReadImpl?: typeof openConfinedFileForRead;
}

function validateFileEncoding(encoding: unknown): FileEncoding {
  if (encoding === undefined) {
    return "utf8";
  }
  if (encoding !== "utf8" && encoding !== "base64") {
    throw new FileManagerError("invalid_encoding", "Encoding must be 'utf8' or 'base64'");
  }
  return encoding;
}

function isInternalEntryName(name: string): boolean {
  return (
    name === RUNTIME_DIR_NAME ||
    name === UPLOAD_STAGING_DIR_NAME ||
    name.startsWith(UPLOAD_STAGING_FILE_PREFIX) ||
    name.startsWith(".tmp-")
  );
}

function readExactUpToLimit(fd: number, maxBytes: number): Uint8Array {
  const chunks: Uint8Array[] = [];
  let total = 0;
  const scratch = Buffer.allocUnsafe(64 * 1024);

  while (true) {
    const toRead = Math.min(scratch.byteLength, maxBytes - total + 1);
    let bytesRead: number;
    try {
      bytesRead = readSync(fd, scratch, 0, toRead, null);
    } catch (err) {
      throw wrapIoError(err, "Failed to read file");
    }
    if (bytesRead === 0) {
      break;
    }
    total += bytesRead;
    if (total > maxBytes) {
      throw new FileManagerError(
        "file_too_large",
        `File exceeds maximum allowed size of ${maxBytes} bytes`,
      );
    }
    const copy = new Uint8Array(bytesRead);
    copy.set(scratch.subarray(0, bytesRead));
    chunks.push(copy);
  }

  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

function streamCopyWithLimit(srcFd: number, dstFd: number, maxRemainingBytes: number): number {
  const scratch = Buffer.allocUnsafe(64 * 1024);
  let copied = 0;

  while (true) {
    const toRead = Math.min(scratch.byteLength, maxRemainingBytes - copied + 1);
    let bytesRead: number;
    try {
      bytesRead = readSync(srcFd, scratch, 0, toRead, null);
    } catch (err) {
      throw wrapIoError(err, "Failed to read source file during copy");
    }
    if (bytesRead === 0) {
      break;
    }
    copied += bytesRead;
    if (copied > maxRemainingBytes) {
      throw new FileManagerError("copy_limit_exceeded", "Copy exceeds maximum total byte limit");
    }
    let writeOffset = 0;
    while (writeOffset < bytesRead) {
      let written: number;
      try {
        written = writeSync(dstFd, scratch, writeOffset, bytesRead - writeOffset);
      } catch (err) {
        throw wrapIoError(err, "Failed to write copied file");
      }
      if (written <= 0) {
        throw new FileManagerError("io_error", "Short write while copying file");
      }
      writeOffset += written;
    }
  }

  return copied;
}

function isNotFoundError(err: unknown): boolean {
  return err instanceof FileManagerError && err.code === "not_found";
}

function lstatChildOrThrow(dir: DirHandle, name: string, context: string): Stats {
  let stats: Stats | undefined;
  try {
    stats = dir.lstatChild(name);
  } catch (err) {
    throw wrapIoError(err, context);
  }
  if (stats === undefined) {
    throw new FileManagerError("not_found", `${context}: path does not exist`);
  }
  return stats;
}

function openChildDir(dir: DirHandle, name: string, context: string): DirHandle {
  try {
    return dir.openDir(name);
  } catch (err) {
    throw wrapIoError(err, context);
  }
}

function listDir(dir: DirHandle, context: string): string[] {
  try {
    return dir.list();
  } catch (err) {
    throw wrapIoError(err, context);
  }
}

// Recursive walks hold each folder open and reach children through it, so mod code
// swapping a folder for a symbolic link mid-walk cannot redirect the agent elsewhere.
function ensureSubtreeHasNoSymlinks(parent: DirHandle, dirName: string): void {
  const dir = openChildDir(parent, dirName, "Failed to read directory");
  try {
    for (const name of listDir(dir, "Failed to read directory")) {
      const stats = lstatChildOrThrow(dir, name, `Failed to inspect "${name}"`);
      if (stats.isSymbolicLink()) {
        throw new FileManagerError(
          "symlink_forbidden",
          `Refusing recursive operation containing symbolic link "${name}"`,
        );
      }
      if (stats.isDirectory()) {
        ensureSubtreeHasNoSymlinks(dir, name);
      }
    }
  } finally {
    dir.close();
  }
}

function deleteSubtreeSafely(parent: DirHandle, dirName: string): void {
  const dir = openChildDir(parent, dirName, "Failed to read directory during delete");
  try {
    for (const name of listDir(dir, "Failed to read directory during delete")) {
      const stats = lstatChildOrThrow(dir, name, `Failed to inspect "${name}" during delete`);
      if (stats.isSymbolicLink()) {
        throw new FileManagerError(
          "symlink_forbidden",
          `Symbolic link encountered during delete at "${name}"`,
        );
      }
      if (stats.isDirectory()) {
        deleteSubtreeSafely(dir, name);
      } else {
        try {
          unlinkSync(dir.child(name));
        } catch (err) {
          throw wrapIoError(err, `Failed to unlink "${name}"`);
        }
      }
    }
  } finally {
    dir.close();
  }
  try {
    rmdirSync(parent.child(dirName));
  } catch (err) {
    throw wrapIoError(err, "Failed to remove directory");
  }
}

export class FileManager {
  readonly #serversBaseDir: string;
  readonly #maxReadWriteBytes: number;
  readonly #maxCopyFiles: number;
  readonly #maxCopyBytes: number;
  readonly #permissions: PermissionContext;
  readonly #logger: Logger | undefined;
  readonly #makeServerReadable: MakeServerReadableLike;
  readonly #openForReadImpl: typeof openConfinedFileForRead | undefined;
  readonly #transfers: TransferManager;
  readonly #zipOptions: {
    readonly maxEntries?: number;
    readonly maxUncompressedBytes?: number;
    readonly maxEntryBytes?: number;
    readonly maxCompressionRatio?: number;
    readonly ratioMinBytes?: number;
  };

  constructor(options: FileManagerOptions = {}) {
    this.#serversBaseDir = options.serversBaseDir ?? DEFAULT_SERVERS_BASE_DIR;
    this.#maxReadWriteBytes = options.maxReadWriteBytes ?? MAX_READ_WRITE_BYTES;
    this.#maxCopyFiles = options.maxCopyFiles ?? DEFAULT_MAX_COPY_FILES;
    this.#maxCopyBytes = options.maxCopyBytes ?? DEFAULT_MAX_COPY_BYTES;
    this.#logger = options.logger;
    this.#makeServerReadable = options.makeServerReadableImpl ?? makeServerReadable;
    this.#openForReadImpl = options.openForReadImpl;
    this.#permissions =
      options.permissions ??
      createServerPermissionContext({
        serversRoot: this.#serversBaseDir,
        ...(options.serverGroupId !== undefined ? { serverGroupId: options.serverGroupId } : {}),
        ...(options.logger !== undefined ? { logger: options.logger } : {}),
      });
    this.#transfers = new TransferManager({
      serversBaseDir: this.#serversBaseDir,
      permissions: this.#permissions,
      makeServerReadableImpl: this.#makeServerReadable,
      ...(this.#logger !== undefined ? { logger: this.#logger } : {}),
      ...(this.#openForReadImpl !== undefined ? { openForReadImpl: this.#openForReadImpl } : {}),
      ...(options.maxUploadBytes !== undefined ? { maxUploadBytes: options.maxUploadBytes } : {}),
      ...(options.maxPartBytes !== undefined ? { maxPartBytes: options.maxPartBytes } : {}),
      ...(options.maxConcurrentUploads !== undefined
        ? { maxConcurrentUploads: options.maxConcurrentUploads }
        : {}),
      ...(options.maxConcurrentDownloads !== undefined
        ? { maxConcurrentDownloads: options.maxConcurrentDownloads }
        : {}),
    });
    this.#zipOptions = {
      ...(options.maxZipEntries !== undefined ? { maxEntries: options.maxZipEntries } : {}),
      ...(options.maxZipUncompressedBytes !== undefined
        ? { maxUncompressedBytes: options.maxZipUncompressedBytes }
        : {}),
      ...(options.maxZipEntryBytes !== undefined
        ? { maxEntryBytes: options.maxZipEntryBytes }
        : {}),
      ...(options.maxZipCompressionRatio !== undefined
        ? { maxCompressionRatio: options.maxZipCompressionRatio }
        : {}),
      ...(options.zipRatioMinBytes !== undefined
        ? { ratioMinBytes: options.zipRatioMinBytes }
        : {}),
    };
  }

  list(params: { readonly server_id: string; readonly path?: string | undefined }): FileListResult {
    const resolved = resolveConfinedPath({
      serversBaseDir: this.#serversBaseDir,
      serverId: params.server_id,
      relPath: params.path ?? "",
      allowRoot: true,
    });

    const entries: FileListEntry[] = withConfinedDir(resolved, (dir) => {
      const rawNames = listDir(dir, "Failed to list directory").sort();
      const out: FileListEntry[] = [];
      for (const name of rawNames) {
        if (isInternalEntryName(name)) {
          continue;
        }
        let entryStats: Stats | undefined;
        try {
          entryStats = dir.lstatChild(name);
        } catch {
          continue;
        }
        if (entryStats === undefined || entryStats.isSymbolicLink()) {
          // Ignore symlinks without following them.
          continue;
        }
        if (entryStats.isDirectory()) {
          out.push({
            name,
            type: "directory",
            size: 0,
            mtime_ms: Math.floor(entryStats.mtimeMs),
          });
        } else if (entryStats.isFile()) {
          out.push({
            name,
            type: "file",
            size: entryStats.size,
            mtime_ms: Math.floor(entryStats.mtimeMs),
          });
        }
      }
      return out;
    });

    return {
      path: resolved.relativePath,
      entries,
    };
  }

  stat(params: { readonly server_id: string; readonly path: string }): FileStatResult {
    const resolved = resolveConfinedPath({
      serversBaseDir: this.#serversBaseDir,
      serverId: params.server_id,
      relPath: params.path,
      allowRoot: true,
    });

    let stats: Stats | undefined;
    try {
      stats =
        resolved.segments.length === 0
          ? withConfinedDir(resolved, (dir) => dir.stat())
          : withConfinedParent(resolved, (dir, name) => dir.lstatChild(name));
    } catch (err) {
      if (isErrnoCode(err, "ENOENT") || isNotFoundError(err)) {
        return { path: resolved.relativePath, exists: false };
      }
      throw wrapIoError(err, "Failed to stat path");
    }
    if (stats === undefined) {
      return { path: resolved.relativePath, exists: false };
    }

    if (stats.isSymbolicLink()) {
      throw new FileManagerError("symlink_forbidden", "Target path is a symbolic link");
    }
    if (stats.isDirectory()) {
      return {
        path: resolved.relativePath,
        exists: true,
        type: "directory",
        size: 0,
        mtime_ms: Math.floor(stats.mtimeMs),
      };
    }
    if (stats.isFile()) {
      return {
        path: resolved.relativePath,
        exists: true,
        type: "file",
        size: stats.size,
        mtime_ms: Math.floor(stats.mtimeMs),
      };
    }

    throw new FileManagerError("not_a_file", "Unsupported filesystem entry type");
  }

  async #ensureReadable(serverId: string): Promise<void> {
    await this.#makeServerReadable(serverId, {
      ...(this.#logger !== undefined ? { logger: this.#logger } : {}),
    });
  }

  async read(params: {
    readonly server_id: string;
    readonly path: string;
    readonly encoding?: FileEncoding | undefined;
  }): Promise<FileReadResult> {
    const encoding = validateFileEncoding(params.encoding);
    const resolved = resolveConfinedPath({
      serversBaseDir: this.#serversBaseDir,
      serverId: params.server_id,
      relPath: params.path,
      allowRoot: false,
    });

    const { fd, stats } = await openConfinedFileForReadWithRetry(resolved, {
      onEacces: () => this.#ensureReadable(resolved.serverId),
      ...(this.#openForReadImpl !== undefined ? { openImpl: this.#openForReadImpl } : {}),
    });
    let data: Uint8Array;
    try {
      if (stats.size > this.#maxReadWriteBytes) {
        throw new FileManagerError(
          "file_too_large",
          `File size ${stats.size} exceeds maximum direct read limit of ${this.#maxReadWriteBytes} bytes`,
        );
      }
      data = readExactUpToLimit(fd, this.#maxReadWriteBytes);
    } finally {
      closeSync(fd);
    }

    const content =
      encoding === "base64"
        ? Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString("base64")
        : new TextDecoder("utf-8").decode(data);

    return {
      path: resolved.relativePath,
      encoding,
      content,
      size: data.byteLength,
    };
  }

  write(params: {
    readonly server_id: string;
    readonly path: string;
    readonly content: string;
    readonly encoding?: FileEncoding | undefined;
  }): FileWriteResult {
    const encoding = validateFileEncoding(params.encoding);
    let data: Uint8Array;
    if (encoding === "base64") {
      data = decodeStrictBase64(params.content, this.#maxReadWriteBytes);
    } else {
      const byteLen = Buffer.byteLength(params.content, "utf8");
      if (byteLen > this.#maxReadWriteBytes) {
        throw new FileManagerError(
          "file_too_large",
          `Content size ${byteLen} exceeds maximum direct write limit of ${this.#maxReadWriteBytes} bytes`,
        );
      }
      data = new TextEncoder().encode(params.content);
    }

    if (data.byteLength > this.#maxReadWriteBytes) {
      throw new FileManagerError(
        "file_too_large",
        `Content size ${data.byteLength} exceeds maximum direct write limit of ${this.#maxReadWriteBytes} bytes`,
      );
    }

    const resolved = resolveConfinedPath({
      serversBaseDir: this.#serversBaseDir,
      serverId: params.server_id,
      relPath: params.path,
      allowRoot: false,
    });

    writeConfinedFileAtomic(resolved, data, { permissions: this.#permissions });
    return {
      path: resolved.relativePath,
      size: data.byteLength,
    };
  }

  mkdir(params: { readonly server_id: string; readonly path: string }): { readonly path: string } {
    const resolved = mkdirConfined({
      serversBaseDir: this.#serversBaseDir,
      serverId: params.server_id,
      relPath: params.path,
      permissions: this.#permissions,
    });
    return { path: resolved.relativePath };
  }

  rename(params: {
    readonly server_id: string;
    readonly path: string;
    readonly new_name: string;
  }): { readonly from_path: string; readonly to_path: string } {
    const sourceResolved = resolveConfinedPath({
      serversBaseDir: this.#serversBaseDir,
      serverId: params.server_id,
      relPath: params.path,
      allowRoot: false,
    });
    const newName = validateSingleFileName(params.new_name);
    const parentSegments = sourceResolved.segments.slice(0, -1);
    const destRelPath = [...parentSegments, newName].join("/");

    return this.move({
      server_id: params.server_id,
      from_path: sourceResolved.relativePath,
      to_path: destRelPath,
    });
  }

  move(params: {
    readonly server_id: string;
    readonly from_path: string;
    readonly to_path: string;
  }): { readonly from_path: string; readonly to_path: string } {
    const fromResolved = resolveConfinedPath({
      serversBaseDir: this.#serversBaseDir,
      serverId: params.server_id,
      relPath: params.from_path,
      allowRoot: false,
    });
    const toResolved = resolveConfinedPath({
      serversBaseDir: this.#serversBaseDir,
      serverId: params.server_id,
      relPath: params.to_path,
      allowRoot: false,
    });

    if (isSameOrSubpath(fromResolved.relativePath, toResolved.relativePath)) {
      throw new FileManagerError(
        "invalid_path",
        "Cannot move a path onto itself or inside its own subtree",
      );
    }

    withConfinedParent(fromResolved, (fromDir, fromName) => {
      withConfinedParent(toResolved, (toDir, toName) => {
        const fromStats = lstatChildOrThrow(fromDir, fromName, "Source path does not exist");
        if (fromStats.isSymbolicLink()) {
          throw new FileManagerError("symlink_forbidden", "Cannot move a symbolic link");
        }

        let toStats: Stats | undefined;
        try {
          toStats = toDir.lstatChild(toName);
        } catch (err) {
          throw wrapIoError(err, "Failed to inspect destination path");
        }
        if (toStats !== undefined) {
          if (toStats.isSymbolicLink()) {
            throw new FileManagerError("symlink_forbidden", "Destination is a symbolic link");
          }
          throw new FileManagerError("already_exists", "Destination path already exists");
        }

        try {
          renameSync(fromDir.child(fromName), toDir.child(toName));
        } catch (err) {
          throw wrapIoError(err, "Failed to move path");
        }
      });
    });

    return {
      from_path: fromResolved.relativePath,
      to_path: toResolved.relativePath,
    };
  }

  async copy(params: {
    readonly server_id: string;
    readonly from_path: string;
    readonly to_path: string;
  }): Promise<FileCopyResult> {
    const fromResolved = resolveConfinedPath({
      serversBaseDir: this.#serversBaseDir,
      serverId: params.server_id,
      relPath: params.from_path,
      allowRoot: false,
    });
    const toResolved = resolveConfinedPath({
      serversBaseDir: this.#serversBaseDir,
      serverId: params.server_id,
      relPath: params.to_path,
      allowRoot: false,
    });

    if (isSameOrSubpath(fromResolved.relativePath, toResolved.relativePath)) {
      throw new FileManagerError(
        "invalid_path",
        "Cannot copy a path onto itself or inside its own subtree",
      );
    }

    const fromStats = withConfinedParent(fromResolved, (dir, name) =>
      lstatChildOrThrow(dir, name, "Source path does not exist"),
    );
    if (fromStats.isSymbolicLink()) {
      throw new FileManagerError("symlink_forbidden", "Cannot copy a symbolic link");
    }

    let toStats: Stats | undefined;
    try {
      toStats = withConfinedParent(toResolved, (dir, name) => dir.lstatChild(name));
    } catch (err) {
      if (!isNotFoundError(err)) {
        throw wrapIoError(err, "Failed to inspect destination path");
      }
    }
    if (toStats !== undefined) {
      if (toStats.isSymbolicLink()) {
        throw new FileManagerError("symlink_forbidden", "Destination is a symbolic link");
      }
      throw new FileManagerError("already_exists", "Destination path already exists");
    }

    // Pre-scan subtree for symlinks, unsupported types, and count/byte ceilings
    // before creating destination directories or files.
    let scannedFiles = 0;
    let scannedBytes = 0;
    const preScan = (dir: DirHandle, name: string, stats: Stats, label: string): void => {
      if (stats.isSymbolicLink()) {
        throw new FileManagerError("symlink_forbidden", `Cannot copy symbolic link "${label}"`);
      }
      if (stats.isDirectory()) {
        const sub = openChildDir(dir, name, `Failed to read directory "${label}"`);
        try {
          const children = listDir(sub, `Failed to read directory "${label}"`).sort();
          for (const child of children) {
            const childStats = lstatChildOrThrow(
              sub,
              child,
              `Failed to inspect "${label}/${child}"`,
            );
            if (childStats.isSymbolicLink()) {
              throw new FileManagerError(
                "symlink_forbidden",
                `Cannot copy symbolic link "${label}/${child}"`,
              );
            }
            if (isInternalEntryName(child)) {
              continue;
            }
            preScan(sub, child, childStats, `${label}/${child}`);
          }
        } finally {
          sub.close();
        }
        return;
      }
      if (!stats.isFile()) {
        throw new FileManagerError("not_a_file", `Cannot copy non-regular file "${label}"`);
      }
      scannedFiles += 1;
      if (scannedFiles > this.#maxCopyFiles) {
        throw new FileManagerError(
          "copy_limit_exceeded",
          `Copy exceeds maximum file count of ${this.#maxCopyFiles}`,
        );
      }
      scannedBytes += stats.size;
      if (scannedBytes > this.#maxCopyBytes) {
        throw new FileManagerError(
          "copy_limit_exceeded",
          `Copy exceeds maximum total byte limit of ${this.#maxCopyBytes}`,
        );
      }
    };

    withConfinedParent(fromResolved, (dir, name) =>
      preScan(dir, name, fromStats, fromResolved.relativePath),
    );

    let filesCopied = 0;
    let bytesCopied = 0;
    let retriedReadable = false;

    const copyRecursive = async (srcRel: string, dstRel: string): Promise<void> => {
      const srcConfined = resolveConfinedPath({
        serversBaseDir: this.#serversBaseDir,
        serverId: params.server_id,
        relPath: srcRel,
        allowRoot: false,
      });
      const dstConfined = resolveConfinedPath({
        serversBaseDir: this.#serversBaseDir,
        serverId: params.server_id,
        relPath: dstRel,
        allowRoot: false,
      });

      const stats = withConfinedParent(srcConfined, (dir, name) =>
        lstatChildOrThrow(dir, name, `Failed to inspect "${srcRel}"`),
      );
      if (stats.isSymbolicLink()) {
        throw new FileManagerError("symlink_forbidden", `Cannot copy symbolic link "${srcRel}"`);
      }

      if (stats.isDirectory()) {
        mkdirConfined({
          serversBaseDir: this.#serversBaseDir,
          serverId: params.server_id,
          relPath: dstConfined.relativePath,
          permissions: this.#permissions,
        });
        const children = withConfinedDir(srcConfined, (dir) => {
          const names = listDir(dir, `Failed to read directory "${srcRel}"`).sort();
          for (const child of names) {
            const childStats = lstatChildOrThrow(
              dir,
              child,
              `Failed to inspect "${srcRel}/${child}"`,
            );
            if (childStats.isSymbolicLink()) {
              throw new FileManagerError(
                "symlink_forbidden",
                `Cannot copy symbolic link "${srcRel}/${child}"`,
              );
            }
          }
          return names;
        });
        for (const child of children) {
          if (isInternalEntryName(child)) {
            continue;
          }
          await copyRecursive(
            `${srcConfined.relativePath}/${child}`,
            `${dstConfined.relativePath}/${child}`,
          );
        }
        return;
      }

      if (!stats.isFile()) {
        throw new FileManagerError("not_a_file", `Cannot copy non-regular file "${srcRel}"`);
      }

      if (filesCopied + 1 > this.#maxCopyFiles) {
        throw new FileManagerError(
          "copy_limit_exceeded",
          `Copy exceeds maximum file count of ${this.#maxCopyFiles}`,
        );
      }

      const { fd, stats: fdStats } = await openConfinedFileForReadWithRetry(srcConfined, {
        ...(!retriedReadable
          ? {
              onEacces: async () => {
                retriedReadable = true;
                await this.#ensureReadable(srcConfined.serverId);
              },
            }
          : {}),
        ...(this.#openForReadImpl !== undefined ? { openImpl: this.#openForReadImpl } : {}),
      });
      let fileBytes = 0;
      try {
        if (bytesCopied + fdStats.size > this.#maxCopyBytes) {
          throw new FileManagerError(
            "copy_limit_exceeded",
            `Copy exceeds maximum total byte limit of ${this.#maxCopyBytes}`,
          );
        }
        const remainingLimit = this.#maxCopyBytes - bytesCopied;
        writeConfinedFileAtomic(dstConfined, new Uint8Array(0), {
          permissions: this.#permissions,
          writeHook(dstFd) {
            fileBytes = streamCopyWithLimit(fd, dstFd, remainingLimit);
          },
        });
      } finally {
        closeSync(fd);
      }

      filesCopied += 1;
      bytesCopied += fileBytes;
    };

    await copyRecursive(fromResolved.relativePath, toResolved.relativePath);
    return {
      from_path: fromResolved.relativePath,
      to_path: toResolved.relativePath,
      files_copied: filesCopied,
      bytes_copied: bytesCopied,
    };
  }

  delete(params: {
    readonly server_id: string;
    readonly path: string;
    readonly recursive?: boolean | undefined;
  }): { readonly path: string; readonly deleted: boolean } {
    const resolved = resolveConfinedPath({
      serversBaseDir: this.#serversBaseDir,
      serverId: params.server_id,
      relPath: params.path,
      allowRoot: false,
    });

    return withConfinedParent(resolved, (dir, name) => {
      const stats = lstatChildOrThrow(dir, name, "Target path does not exist");

      if (stats.isSymbolicLink()) {
        throw new FileManagerError("symlink_forbidden", "Refusing to operate on a symbolic link");
      }

      if (stats.isDirectory()) {
        const recursive = params.recursive ?? false;
        if (!recursive) {
          try {
            rmdirSync(dir.child(name));
          } catch (err) {
            if (isErrnoCode(err, "ENOTEMPTY") || isErrnoCode(err, "EEXIST")) {
              throw new FileManagerError(
                "is_a_directory",
                "Directory is not empty; pass recursive: true to delete",
              );
            }
            throw wrapIoError(err, "Failed to remove directory");
          }
          return { path: resolved.relativePath, deleted: true };
        }
        ensureSubtreeHasNoSymlinks(dir, name);
        deleteSubtreeSafely(dir, name);
        return { path: resolved.relativePath, deleted: true };
      }

      try {
        unlinkSync(dir.child(name));
      } catch (err) {
        throw wrapIoError(err, "Failed to delete file");
      }
      return { path: resolved.relativePath, deleted: true };
    });
  }

  uploadBegin(params: UploadBeginParams): UploadBeginResult {
    return this.#transfers.beginUpload(params);
  }

  uploadPart(params: UploadPartParams): UploadPartResult {
    return this.#transfers.appendUploadPart(params);
  }

  uploadCommit(params: UploadCommitParams): UploadCommitResult {
    return this.#transfers.commitUpload(params);
  }

  uploadAbort(params: UploadAbortParams): {
    readonly upload_id: string;
    readonly aborted: boolean;
  } {
    return this.#transfers.abortUpload(params);
  }

  async downloadBegin(params: DownloadBeginParams): Promise<DownloadBeginResult> {
    return await this.#transfers.beginDownload(params);
  }

  downloadPart(params: DownloadPartParams): DownloadPartResult {
    return this.#transfers.readDownloadPart(params);
  }

  downloadClose(params: DownloadCloseParams): {
    readonly download_id: string;
    readonly closed: boolean;
  } {
    return this.#transfers.closeDownload(params);
  }

  async download(params: DownloadRangeParams): Promise<DownloadRangeResult> {
    return await this.#transfers.downloadRange(params);
  }

  async zip(params: {
    readonly server_id: string;
    readonly paths: readonly string[];
    readonly dest_path: string;
  }): Promise<SafeZipResult> {
    const runZip = () =>
      safeZipFiles({
        serversBaseDir: this.#serversBaseDir,
        serverId: params.server_id,
        paths: params.paths,
        destPath: params.dest_path,
        permissions: this.#permissions,
        ...(this.#openForReadImpl !== undefined ? { openForReadImpl: this.#openForReadImpl } : {}),
      });
    try {
      return runZip();
    } catch (err) {
      if (!isEaccesError(err)) {
        throw err;
      }
      await this.#ensureReadable(params.server_id);
      return runZip();
    }
  }

  async unzip(params: {
    readonly server_id: string;
    readonly zip_path: string;
    readonly dest_path?: string | undefined;
  }): Promise<SafeUnzipResult> {
    const runUnzip = () =>
      safeUnzipFile({
        serversBaseDir: this.#serversBaseDir,
        serverId: params.server_id,
        zipPath: params.zip_path,
        ...(params.dest_path !== undefined ? { destPath: params.dest_path } : {}),
        permissions: this.#permissions,
        ...(this.#openForReadImpl !== undefined ? { openForReadImpl: this.#openForReadImpl } : {}),
        ...this.#zipOptions,
      });
    try {
      return runUnzip();
    } catch (err) {
      if (!isEaccesError(err)) {
        throw err;
      }
      await this.#ensureReadable(params.server_id);
      return runUnzip();
    }
  }

  dispose(): void {
    this.#transfers.closeAll();
  }
}

export function registerFileCommandHandlers(queue: CommandQueue, manager: FileManager): void {
  function wrap<TBody>(
    eventType: string,
    fn: (body: TBody) => unknown,
  ): Parameters<CommandQueue["registerHandler"]>[1] {
    return async (opened, ctx) => {
      try {
        const result = await fn(opened.body as TBody);
        ctx.sendEvent(eventType, result);
      } catch (err) {
        if (err instanceof FileManagerError) {
          ctx.sendEvent("files.error", {
            command_id: opened.header.id,
            command_type: opened.header.type,
            code: err.code,
            message: err.message,
          });
        }
        throw err;
      }
    };
  }

  queue.registerHandler(
    "files.list",
    wrap<{ readonly server_id: string; readonly path?: string }>("files.list.result", (body) =>
      manager.list(body),
    ),
  );
  queue.registerHandler(
    "files.stat",
    wrap<{ readonly server_id: string; readonly path: string }>("files.stat.result", (body) =>
      manager.stat(body),
    ),
  );
  queue.registerHandler(
    "files.read",
    wrap<{
      readonly server_id: string;
      readonly path: string;
      readonly encoding?: FileEncoding;
    }>("files.read.result", (body) => manager.read(body)),
  );
  queue.registerHandler(
    "files.write",
    wrap<{
      readonly server_id: string;
      readonly path: string;
      readonly content: string;
      readonly encoding?: FileEncoding;
    }>("files.write.result", (body) => manager.write(body)),
  );
  queue.registerHandler(
    "files.mkdir",
    wrap<{ readonly server_id: string; readonly path: string }>("files.mkdir.result", (body) =>
      manager.mkdir(body),
    ),
  );
  queue.registerHandler(
    "files.rename",
    wrap<{ readonly server_id: string; readonly path: string; readonly new_name: string }>(
      "files.rename.result",
      (body) => manager.rename(body),
    ),
  );
  queue.registerHandler(
    "files.move",
    wrap<{ readonly server_id: string; readonly from_path: string; readonly to_path: string }>(
      "files.move.result",
      (body) => manager.move(body),
    ),
  );
  queue.registerHandler(
    "files.copy",
    wrap<{ readonly server_id: string; readonly from_path: string; readonly to_path: string }>(
      "files.copy.result",
      (body) => manager.copy(body),
    ),
  );
  queue.registerHandler(
    "files.delete",
    wrap<{ readonly server_id: string; readonly path: string; readonly recursive?: boolean }>(
      "files.delete.result",
      (body) => manager.delete(body),
    ),
  );
  queue.registerHandler(
    "files.upload.begin",
    wrap<UploadBeginParams>("files.upload.began", (body) => manager.uploadBegin(body)),
  );
  queue.registerHandler(
    "files.upload.part",
    wrap<UploadPartParams>("files.upload.part.result", (body) => manager.uploadPart(body)),
  );
  queue.registerHandler(
    "files.upload.commit",
    wrap<UploadCommitParams>("files.upload.committed", (body) => manager.uploadCommit(body)),
  );
  queue.registerHandler(
    "files.upload.abort",
    wrap<UploadAbortParams>("files.upload.aborted", (body) => manager.uploadAbort(body)),
  );
  queue.registerHandler(
    "files.download.begin",
    wrap<DownloadBeginParams>("files.download.began", (body) => manager.downloadBegin(body)),
  );
  queue.registerHandler(
    "files.download.part",
    wrap<DownloadPartParams>("files.download.part.result", (body) => manager.downloadPart(body)),
  );
  queue.registerHandler(
    "files.download.close",
    wrap<DownloadCloseParams>("files.download.closed", (body) => manager.downloadClose(body)),
  );
  queue.registerHandler(
    "files.download",
    wrap<DownloadRangeParams>("files.download.result", (body) => manager.download(body)),
  );
  queue.registerHandler(
    "files.zip",
    wrap<{
      readonly server_id: string;
      readonly paths: readonly string[];
      readonly dest_path: string;
    }>("files.zip.result", (body) => manager.zip(body)),
  );
  queue.registerHandler(
    "files.unzip",
    wrap<{
      readonly server_id: string;
      readonly zip_path: string;
      readonly dest_path?: string;
    }>("files.unzip.result", (body) => manager.unzip(body)),
  );
}
