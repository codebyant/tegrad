// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import {
  closeSync,
  lstatSync,
  readdirSync,
  readSync,
  renameSync,
  rmdirSync,
  type Stats,
  unlinkSync,
} from "node:fs";
import { dirname, join } from "node:path";
import type { CommandQueue } from "../agent/jobs";
import {
  assertNoSymlinkPath,
  DEFAULT_SERVERS_BASE_DIR,
  isErrnoCode,
  mkdirConfined,
  openConfinedFileForRead,
  resolveConfinedPath,
  validateSingleFileName,
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
}

function readExactUpToLimit(fd: number, maxBytes: number): Uint8Array {
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

function ensureSubtreeHasNoSymlinks(dirFullPath: string): void {
  const names = readdirSync(dirFullPath);
  for (const name of names) {
    const childPath = join(dirFullPath, name);
    const stats = lstatSync(childPath);
    if (stats.isSymbolicLink()) {
      throw new FileManagerError(
        "symlink_forbidden",
        `Refusing recursive delete containing symbolic link "${name}"`,
      );
    }
    if (stats.isDirectory()) {
      ensureSubtreeHasNoSymlinks(childPath);
    }
  }
}

function deleteSubtreeSafely(dirFullPath: string): void {
  const names = readdirSync(dirFullPath);
  for (const name of names) {
    const childPath = join(dirFullPath, name);
    const stats = lstatSync(childPath);
    if (stats.isSymbolicLink()) {
      throw new FileManagerError(
        "symlink_forbidden",
        `Symbolic link encountered during delete at "${name}"`,
      );
    }
    if (stats.isDirectory()) {
      deleteSubtreeSafely(childPath);
    } else {
      unlinkSync(childPath);
    }
  }
  rmdirSync(dirFullPath);
}

export class FileManager {
  readonly #serversBaseDir: string;
  readonly #maxReadWriteBytes: number;
  readonly #maxCopyFiles: number;
  readonly #maxCopyBytes: number;
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
    this.#transfers = new TransferManager({
      serversBaseDir: this.#serversBaseDir,
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

    let dirStats: Stats;
    try {
      dirStats = lstatSync(resolved.fullPath);
    } catch (err) {
      throw wrapIoError(err, "Failed to stat directory");
    }

    if (dirStats.isSymbolicLink()) {
      throw new FileManagerError("symlink_forbidden", "Target directory is a symbolic link");
    }
    if (!dirStats.isDirectory()) {
      throw new FileManagerError("not_a_directory", "Target path is not a directory");
    }

    const rawNames = readdirSync(resolved.fullPath).sort();
    const entries: FileListEntry[] = [];

    for (const name of rawNames) {
      if (name === ".runtime" || name.startsWith(".tmp-upload-")) {
        continue;
      }
      const entryPath = join(resolved.fullPath, name);
      let entryStats: Stats;
      try {
        entryStats = lstatSync(entryPath);
      } catch {
        continue;
      }

      if (entryStats.isSymbolicLink()) {
        // Ignore symlinks without following them.
        continue;
      }
      if (entryStats.isDirectory()) {
        entries.push({
          name,
          type: "directory",
          size: 0,
          mtime_ms: Math.floor(entryStats.mtimeMs),
        });
      } else if (entryStats.isFile()) {
        entries.push({
          name,
          type: "file",
          size: entryStats.size,
          mtime_ms: Math.floor(entryStats.mtimeMs),
        });
      }
    }

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

    let stats: Stats;
    try {
      stats = lstatSync(resolved.fullPath);
    } catch (err) {
      if (isErrnoCode(err, "ENOENT")) {
        return { path: resolved.relativePath, exists: false };
      }
      throw wrapIoError(err, "Failed to stat path");
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

  read(params: {
    readonly server_id: string;
    readonly path: string;
    readonly encoding?: FileEncoding | undefined;
  }): FileReadResult {
    const encoding = params.encoding ?? "utf8";
    const resolved = resolveConfinedPath({
      serversBaseDir: this.#serversBaseDir,
      serverId: params.server_id,
      relPath: params.path,
      allowRoot: false,
    });

    const { fd, stats } = openConfinedFileForRead(resolved);
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
    const encoding = params.encoding ?? "utf8";
    const data =
      encoding === "base64"
        ? decodeStrictBase64(params.content)
        : new TextEncoder().encode(params.content);

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

    writeConfinedFileAtomic(resolved, data);
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

    if (
      toResolved.relativePath === fromResolved.relativePath ||
      toResolved.relativePath.startsWith(`${fromResolved.relativePath}/`)
    ) {
      throw new FileManagerError(
        "invalid_path",
        "Cannot move a path onto itself or inside its own subtree",
      );
    }

    let fromStats: Stats;
    try {
      fromStats = lstatSync(fromResolved.fullPath);
    } catch (err) {
      throw wrapIoError(err, "Source path does not exist");
    }
    if (fromStats.isSymbolicLink()) {
      throw new FileManagerError("symlink_forbidden", "Cannot move a symbolic link");
    }

    let toStats: Stats | undefined;
    try {
      toStats = lstatSync(toResolved.fullPath);
    } catch (err) {
      if (!isErrnoCode(err, "ENOENT")) {
        throw wrapIoError(err, "Failed to inspect destination path");
      }
    }
    if (toStats !== undefined) {
      if (toStats.isSymbolicLink()) {
        throw new FileManagerError("symlink_forbidden", "Destination is a symbolic link");
      }
      throw new FileManagerError("already_exists", "Destination path already exists");
    }

    const destParent = dirname(toResolved.fullPath);
    let destParentStats: Stats;
    try {
      destParentStats = lstatSync(destParent);
    } catch (err) {
      throw wrapIoError(err, "Destination parent directory does not exist");
    }
    if (destParentStats.isSymbolicLink()) {
      throw new FileManagerError("symlink_forbidden", "Destination parent is a symbolic link");
    }
    if (!destParentStats.isDirectory()) {
      throw new FileManagerError("not_a_directory", "Destination parent is not a directory");
    }

    assertNoSymlinkPath(fromResolved);
    assertNoSymlinkPath(toResolved);

    try {
      renameSync(fromResolved.fullPath, toResolved.fullPath);
    } catch (err) {
      throw wrapIoError(err, "Failed to move path");
    }

    return {
      from_path: fromResolved.relativePath,
      to_path: toResolved.relativePath,
    };
  }

  copy(params: {
    readonly server_id: string;
    readonly from_path: string;
    readonly to_path: string;
  }): FileCopyResult {
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

    if (
      toResolved.relativePath === fromResolved.relativePath ||
      toResolved.relativePath.startsWith(`${fromResolved.relativePath}/`)
    ) {
      throw new FileManagerError(
        "invalid_path",
        "Cannot copy a path onto itself or inside its own subtree",
      );
    }

    let fromStats: Stats;
    try {
      fromStats = lstatSync(fromResolved.fullPath);
    } catch (err) {
      throw wrapIoError(err, "Source path does not exist");
    }
    if (fromStats.isSymbolicLink()) {
      throw new FileManagerError("symlink_forbidden", "Cannot copy a symbolic link");
    }

    let toStats: Stats | undefined;
    try {
      toStats = lstatSync(toResolved.fullPath);
    } catch (err) {
      if (!isErrnoCode(err, "ENOENT")) {
        throw wrapIoError(err, "Failed to inspect destination path");
      }
    }
    if (toStats !== undefined) {
      if (toStats.isSymbolicLink()) {
        throw new FileManagerError("symlink_forbidden", "Destination is a symbolic link");
      }
      throw new FileManagerError("already_exists", "Destination path already exists");
    }

    let filesCopied = 0;
    let bytesCopied = 0;

    const copyRecursive = (srcRel: string, dstRel: string): void => {
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

      const stats = lstatSync(srcConfined.fullPath);
      if (stats.isSymbolicLink()) {
        throw new FileManagerError("symlink_forbidden", `Cannot copy symbolic link "${srcRel}"`);
      }

      if (stats.isDirectory()) {
        mkdirConfined({
          serversBaseDir: this.#serversBaseDir,
          serverId: params.server_id,
          relPath: dstConfined.relativePath,
        });
        const children = readdirSync(srcConfined.fullPath).sort();
        for (const child of children) {
          const childFull = join(srcConfined.fullPath, child);
          const childStats = lstatSync(childFull);
          if (childStats.isSymbolicLink()) {
            throw new FileManagerError(
              "symlink_forbidden",
              `Cannot copy symbolic link "${srcRel}/${child}"`,
            );
          }
          copyRecursive(
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

      const { fd, stats: fdStats } = openConfinedFileForRead(srcConfined);
      let data: Uint8Array;
      try {
        if (bytesCopied + fdStats.size > this.#maxCopyBytes) {
          throw new FileManagerError(
            "copy_limit_exceeded",
            `Copy exceeds maximum total byte limit of ${this.#maxCopyBytes}`,
          );
        }
        try {
          data = readExactUpToLimit(fd, this.#maxCopyBytes - bytesCopied);
        } catch (err) {
          if (err instanceof FileManagerError && err.code === "file_too_large") {
            throw new FileManagerError(
              "copy_limit_exceeded",
              `Copy exceeds maximum total byte limit of ${this.#maxCopyBytes}`,
            );
          }
          throw err;
        }
      } finally {
        closeSync(fd);
      }

      writeConfinedFileAtomic(dstConfined, data);
      filesCopied += 1;
      bytesCopied += data.byteLength;
    };

    // Pre-scan directory source for symlinks before writing anything.
    if (fromStats.isDirectory()) {
      ensureSubtreeHasNoSymlinks(fromResolved.fullPath);
    }

    copyRecursive(fromResolved.relativePath, toResolved.relativePath);
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

    let stats: Stats;
    try {
      stats = lstatSync(resolved.fullPath);
    } catch (err) {
      throw wrapIoError(err, "Target path does not exist");
    }

    if (stats.isSymbolicLink()) {
      throw new FileManagerError("symlink_forbidden", "Refusing to operate on a symbolic link");
    }

    if (stats.isDirectory()) {
      const recursive = params.recursive ?? false;
      const children = readdirSync(resolved.fullPath);
      if (children.length > 0 && !recursive) {
        throw new FileManagerError(
          "is_a_directory",
          "Directory is not empty; pass recursive: true to delete",
        );
      }
      if (recursive) {
        ensureSubtreeHasNoSymlinks(resolved.fullPath);
        deleteSubtreeSafely(resolved.fullPath);
      } else {
        rmdirSync(resolved.fullPath);
      }
      return { path: resolved.relativePath, deleted: true };
    }

    try {
      unlinkSync(resolved.fullPath);
    } catch (err) {
      throw wrapIoError(err, "Failed to delete file");
    }
    return { path: resolved.relativePath, deleted: true };
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

  downloadBegin(params: DownloadBeginParams): DownloadBeginResult {
    return this.#transfers.beginDownload(params);
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

  download(params: DownloadRangeParams): DownloadRangeResult {
    return this.#transfers.downloadRange(params);
  }

  zip(params: {
    readonly server_id: string;
    readonly paths: readonly string[];
    readonly dest_path: string;
  }): SafeZipResult {
    return safeZipFiles({
      serversBaseDir: this.#serversBaseDir,
      serverId: params.server_id,
      paths: params.paths,
      destPath: params.dest_path,
    });
  }

  unzip(params: {
    readonly server_id: string;
    readonly zip_path: string;
    readonly dest_path?: string | undefined;
  }): SafeUnzipResult {
    return safeUnzipFile({
      serversBaseDir: this.#serversBaseDir,
      serverId: params.server_id,
      zipPath: params.zip_path,
      ...(params.dest_path !== undefined ? { destPath: params.dest_path } : {}),
      ...this.#zipOptions,
    });
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
    return (opened, ctx) => {
      try {
        const result = fn(opened.body as TBody);
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
