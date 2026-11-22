// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { createHash, type Hash, randomBytes } from "node:crypto";
import {
  closeSync,
  fchmodSync,
  constants as fsConstants,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readSync,
  renameSync,
  rmdirSync,
  type Stats,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { SHA256_HEX_PATTERN } from "../protocol";
import {
  assertConfinedInternalDir,
  assertNoSymlinkPath,
  DEFAULT_SERVERS_BASE_DIR,
  ensureConfinedInternalDir,
  isErrnoCode,
  isPosix,
  mkdirConfined,
  openConfinedFileForRead,
  resolveConfinedPath,
  UPLOAD_STAGING_DIR_NAME,
  wrapIoError,
} from "./confinement";
import { FileManagerError } from "./errors";

export const DEFAULT_MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024; // 2 GiB
export const DEFAULT_MAX_PART_BYTES = 8 * 1024 * 1024; // 8 MiB
export const DEFAULT_PART_BYTES = 1 * 1024 * 1024; // 1 MiB
export const DEFAULT_MAX_CONCURRENT_UPLOADS = 16;
export const DEFAULT_MAX_CONCURRENT_DOWNLOADS = 16;

const STRICT_BASE64_REGEX = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function decodeStrictBase64(input: string, maxDecodedBytes?: number): Uint8Array {
  if (input.length === 0) {
    return new Uint8Array(0);
  }
  if (maxDecodedBytes !== undefined) {
    const maxEncodedLen = Math.ceil(maxDecodedBytes / 3) * 4;
    if (input.length > maxEncodedLen) {
      throw new FileManagerError(
        "file_too_large",
        `Encoded payload exceeds maximum allowed ${maxDecodedBytes} bytes`,
      );
    }
  }
  if (input.length % 4 !== 0 || !STRICT_BASE64_REGEX.test(input)) {
    throw new FileManagerError("invalid_encoding", "Invalid base64 payload");
  }
  if (maxDecodedBytes !== undefined) {
    const padding = input.endsWith("==") ? 2 : input.endsWith("=") ? 1 : 0;
    const decodedSize = (input.length / 4) * 3 - padding;
    if (decodedSize > maxDecodedBytes) {
      throw new FileManagerError(
        "file_too_large",
        `Decoded payload size ${decodedSize} exceeds maximum ${maxDecodedBytes}`,
      );
    }
  }
  const buf = Buffer.from(input, "base64");
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

export function sha256Hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

interface UploadSession {
  readonly uploadId: string;
  readonly serverId: string;
  readonly targetRelPath: string;
  readonly stagingDir: string;
  readonly stagingPath: string;
  readonly stagingDev: number;
  readonly stagingIno: number;
  readonly totalSize: number;
  readonly expectedSha256: string;
  readonly partSize: number;
  readonly hash: Hash;
  fd: number | undefined;
  nextPartIndex: number;
  receivedBytes: number;
}

interface DownloadSession {
  readonly downloadId: string;
  readonly serverId: string;
  readonly relPath: string;
  readonly totalSize: number;
  readonly partSize: number;
  readonly totalParts: number;
  fd: number | undefined;
}

export interface TransferManagerOptions {
  readonly serversBaseDir?: string;
  readonly maxUploadBytes?: number;
  readonly maxPartBytes?: number;
  readonly maxConcurrentUploads?: number;
  readonly maxConcurrentDownloads?: number;
}

export interface UploadBeginParams {
  readonly server_id: string;
  readonly path: string;
  readonly total_size: number;
  readonly sha256: string;
  readonly part_size?: number | undefined;
}

export interface UploadBeginResult {
  readonly upload_id: string;
  readonly path: string;
  readonly total_size: number;
  readonly part_size: number;
}

export interface UploadPartParams {
  readonly server_id: string;
  readonly upload_id: string;
  readonly part_index: number;
  readonly data_base64: string;
}

export interface UploadPartResult {
  readonly upload_id: string;
  readonly part_index: number;
  readonly received_bytes: number;
}

export interface UploadCommitParams {
  readonly server_id: string;
  readonly upload_id: string;
}

export interface UploadCommitResult {
  readonly upload_id: string;
  readonly path: string;
  readonly size: number;
  readonly sha256: string;
}

export interface UploadAbortParams {
  readonly server_id: string;
  readonly upload_id: string;
}

export interface DownloadBeginParams {
  readonly server_id: string;
  readonly path: string;
  readonly part_size?: number | undefined;
}

export interface DownloadBeginResult {
  readonly download_id: string;
  readonly path: string;
  readonly total_size: number;
  readonly part_size: number;
  readonly total_parts: number;
}

export interface DownloadPartParams {
  readonly server_id: string;
  readonly download_id: string;
  readonly part_index: number;
}

export interface DownloadPartResult {
  readonly download_id: string;
  readonly part_index: number;
  readonly offset: number;
  readonly size: number;
  readonly total_size: number;
  readonly eof: boolean;
  readonly sha256: string;
  readonly data_base64: string;
}

export interface DownloadCloseParams {
  readonly server_id: string;
  readonly download_id: string;
}

export interface DownloadRangeParams {
  readonly server_id: string;
  readonly path: string;
  readonly offset: number;
  readonly length: number;
}

export interface DownloadRangeResult {
  readonly path: string;
  readonly offset: number;
  readonly size: number;
  readonly total_size: number;
  readonly eof: boolean;
  readonly sha256: string;
  readonly data_base64: string;
}

function writeAllAt(fd: number, data: Uint8Array, position: number): void {
  let offset = 0;
  while (offset < data.byteLength) {
    const written = writeSync(fd, data, offset, data.byteLength - offset, position + offset);
    if (written <= 0) {
      throw new FileManagerError("io_error", "Short write on staging file");
    }
    offset += written;
  }
}

export class TransferManager {
  readonly #serversBaseDir: string;
  readonly #maxUploadBytes: number;
  readonly #maxPartBytes: number;
  readonly #maxConcurrentUploads: number;
  readonly #maxConcurrentDownloads: number;
  readonly #uploads = new Map<string, UploadSession>();
  readonly #downloads = new Map<string, DownloadSession>();

  constructor(options: TransferManagerOptions = {}) {
    this.#serversBaseDir = options.serversBaseDir ?? DEFAULT_SERVERS_BASE_DIR;
    this.#maxUploadBytes = options.maxUploadBytes ?? DEFAULT_MAX_UPLOAD_BYTES;
    this.#maxPartBytes = options.maxPartBytes ?? DEFAULT_MAX_PART_BYTES;
    this.#maxConcurrentUploads = options.maxConcurrentUploads ?? DEFAULT_MAX_CONCURRENT_UPLOADS;
    this.#maxConcurrentDownloads =
      options.maxConcurrentDownloads ?? DEFAULT_MAX_CONCURRENT_DOWNLOADS;
  }

  #cleanupUpload(session: UploadSession, unlinkStaging: boolean): void {
    if (session.fd !== undefined) {
      try {
        closeSync(session.fd);
      } catch {
        // ignore close failure on cleanup
      }
      session.fd = undefined;
    }
    if (unlinkStaging) {
      try {
        unlinkSync(session.stagingPath);
      } catch {
        // ignore unlink failure on cleanup
      }
    }
    try {
      rmdirSync(session.stagingDir);
    } catch {
      // ignore if another upload still uses stagingDir or it does not exist
    }
  }

  #cleanupDownload(session: DownloadSession): void {
    if (session.fd !== undefined) {
      try {
        closeSync(session.fd);
      } catch {
        // ignore close failure on cleanup
      }
      session.fd = undefined;
    }
  }

  beginUpload(params: UploadBeginParams): UploadBeginResult {
    if (!Number.isSafeInteger(params.total_size) || params.total_size < 0) {
      throw new FileManagerError("size_mismatch", "total_size must be a non-negative integer");
    }
    if (params.total_size > this.#maxUploadBytes) {
      throw new FileManagerError(
        "file_too_large",
        `Upload size ${params.total_size} exceeds maximum ${this.#maxUploadBytes}`,
      );
    }
    if (!SHA256_HEX_PATTERN.test(params.sha256)) {
      throw new FileManagerError("hash_mismatch", "Invalid sha256 digest format");
    }

    const requestedPartSize = params.part_size ?? Math.min(DEFAULT_PART_BYTES, this.#maxPartBytes);
    if (!Number.isSafeInteger(requestedPartSize) || requestedPartSize <= 0) {
      throw new FileManagerError("part_too_large", "part_size must be a positive integer");
    }
    if (requestedPartSize > this.#maxPartBytes) {
      throw new FileManagerError(
        "part_too_large",
        `part_size ${requestedPartSize} exceeds maximum ${this.#maxPartBytes}`,
      );
    }

    if (this.#uploads.size >= this.#maxConcurrentUploads) {
      throw new FileManagerError(
        "upload_limit_exceeded",
        "Maximum concurrent upload sessions reached",
      );
    }

    const resolved = resolveConfinedPath({
      serversBaseDir: this.#serversBaseDir,
      serverId: params.server_id,
      relPath: params.path,
      allowRoot: false,
    });

    let existingTarget: Stats | undefined;
    try {
      existingTarget = lstatSync(resolved.fullPath);
    } catch (err) {
      if (!isErrnoCode(err, "ENOENT")) {
        throw wrapIoError(err, "Failed to inspect upload target");
      }
    }
    if (existingTarget !== undefined) {
      if (existingTarget.isSymbolicLink()) {
        throw new FileManagerError("symlink_forbidden", "Upload target is a symbolic link");
      }
      if (existingTarget.isDirectory()) {
        throw new FileManagerError("is_a_directory", "Upload target is a directory");
      }
      if (!existingTarget.isFile()) {
        throw new FileManagerError("not_a_file", "Upload target is not a regular file");
      }
    }

    const stagingDir = ensureConfinedInternalDir(
      resolved.serverRoot,
      resolved.realServerRoot,
      UPLOAD_STAGING_DIR_NAME,
      0o700,
    );
    const uploadId = randomBytes(16).toString("hex");
    const stagingPath = join(stagingDir, uploadId);
    const noFollow = fsConstants.O_NOFOLLOW ?? 0;
    const flags = fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_RDWR | noFollow;

    let fd: number;
    try {
      fd = openSync(stagingPath, flags, 0o600);
    } catch (err) {
      try {
        rmdirSync(stagingDir);
      } catch {
        // ignore cleanup failure
      }
      throw wrapIoError(err, "Failed to create upload staging file");
    }

    let stagingStats: Stats;
    try {
      stagingStats = fstatSync(fd);
      if (!stagingStats.isFile()) {
        throw new FileManagerError("not_a_file", "Upload staging file is not a regular file");
      }
    } catch (err) {
      try {
        closeSync(fd);
      } catch {
        // ignore cleanup close error
      }
      try {
        unlinkSync(stagingPath);
      } catch {
        // ignore cleanup unlink error
      }
      try {
        rmdirSync(stagingDir);
      } catch {
        // ignore cleanup rmdir error
      }
      throw wrapIoError(err, "Failed to inspect upload staging file");
    }

    const session: UploadSession = {
      uploadId,
      serverId: resolved.serverId,
      targetRelPath: resolved.relativePath,
      stagingDir,
      stagingPath,
      stagingDev: stagingStats.dev,
      stagingIno: stagingStats.ino,
      totalSize: params.total_size,
      expectedSha256: params.sha256,
      partSize: requestedPartSize,
      hash: createHash("sha256"),
      fd,
      nextPartIndex: 0,
      receivedBytes: 0,
    };

    this.#uploads.set(uploadId, session);
    return {
      upload_id: uploadId,
      path: resolved.relativePath,
      total_size: params.total_size,
      part_size: requestedPartSize,
    };
  }

  appendUploadPart(params: UploadPartParams): UploadPartResult {
    const session = this.#uploads.get(params.upload_id);
    if (
      session === undefined ||
      session.serverId !== params.server_id ||
      session.fd === undefined
    ) {
      throw new FileManagerError("upload_not_found", "Upload session not found");
    }

    if (!Number.isSafeInteger(params.part_index) || params.part_index !== session.nextPartIndex) {
      throw new FileManagerError(
        "part_out_of_order",
        `Expected part_index ${session.nextPartIndex}, received ${params.part_index}`,
      );
    }

    const maxAllowedPartBytes = Math.min(session.partSize, this.#maxPartBytes);
    let chunk: Uint8Array;
    try {
      chunk = decodeStrictBase64(params.data_base64, maxAllowedPartBytes);
    } catch (err) {
      if (err instanceof FileManagerError && err.code === "file_too_large") {
        throw new FileManagerError(
          "part_too_large",
          `Part size exceeds maximum ${session.partSize}`,
        );
      }
      throw err;
    }

    if (chunk.byteLength > maxAllowedPartBytes) {
      throw new FileManagerError(
        "part_too_large",
        `Part size ${chunk.byteLength} exceeds maximum ${session.partSize}`,
      );
    }

    if (session.receivedBytes + chunk.byteLength > session.totalSize) {
      throw new FileManagerError(
        "size_mismatch",
        `Upload part exceeds declared total_size ${session.totalSize}`,
      );
    }

    try {
      if (chunk.byteLength > 0) {
        writeAllAt(session.fd, chunk, session.receivedBytes);
        session.hash.update(chunk);
      }
    } catch (err) {
      throw wrapIoError(err, "Failed to write upload part");
    }

    session.receivedBytes += chunk.byteLength;
    session.nextPartIndex += 1;

    return {
      upload_id: session.uploadId,
      part_index: params.part_index,
      received_bytes: session.receivedBytes,
    };
  }

  commitUpload(params: UploadCommitParams): UploadCommitResult {
    const session = this.#uploads.get(params.upload_id);
    if (
      session === undefined ||
      session.serverId !== params.server_id ||
      session.fd === undefined
    ) {
      throw new FileManagerError("upload_not_found", "Upload session not found");
    }

    this.#uploads.delete(session.uploadId);
    let renamed = false;

    try {
      if (session.receivedBytes !== session.totalSize) {
        throw new FileManagerError(
          "size_mismatch",
          `Received ${session.receivedBytes} bytes, expected ${session.totalSize}`,
        );
      }

      const actualSha256 = session.hash.digest("hex");
      if (actualSha256 !== session.expectedSha256) {
        throw new FileManagerError(
          "hash_mismatch",
          "Uploaded content SHA-256 does not match declared digest",
        );
      }

      const resolved = resolveConfinedPath({
        serversBaseDir: this.#serversBaseDir,
        serverId: session.serverId,
        relPath: session.targetRelPath,
        allowRoot: false,
      });

      assertConfinedInternalDir(resolved.serverRoot, resolved.realServerRoot, session.stagingDir);

      const fdStat = fstatSync(session.fd);
      if (
        !fdStat.isFile() ||
        fdStat.dev !== session.stagingDev ||
        fdStat.ino !== session.stagingIno
      ) {
        throw new FileManagerError("toctou_detected", "Upload staging file descriptor changed");
      }
      if (fdStat.size !== session.totalSize) {
        throw new FileManagerError(
          "size_mismatch",
          `Staging file size ${fdStat.size} does not match declared ${session.totalSize}`,
        );
      }

      const stagingPathStat = lstatSync(session.stagingPath);
      if (stagingPathStat.isSymbolicLink()) {
        throw new FileManagerError("symlink_forbidden", "Upload staging path became a symlink");
      }
      if (
        !stagingPathStat.isFile() ||
        stagingPathStat.dev !== session.stagingDev ||
        stagingPathStat.ino !== session.stagingIno
      ) {
        throw new FileManagerError(
          "toctou_detected",
          "Upload staging path was replaced before commit",
        );
      }

      fsyncSync(session.fd);
      if (isPosix()) {
        fchmodSync(session.fd, 0o640);
      }
      closeSync(session.fd);
      session.fd = undefined;

      const parentSegments = resolved.segments.slice(0, -1);
      if (parentSegments.length > 0) {
        mkdirConfined({
          serversBaseDir: this.#serversBaseDir,
          serverId: session.serverId,
          relPath: parentSegments.join("/"),
        });
      }

      assertNoSymlinkPath(resolved);

      const parentDir = dirname(resolved.fullPath);
      const parentStats = lstatSync(parentDir);
      if (parentStats.isSymbolicLink()) {
        throw new FileManagerError("symlink_forbidden", "Invalid upload destination parent");
      }
      if (!parentStats.isDirectory()) {
        throw new FileManagerError(
          "not_a_directory",
          "Upload destination parent is not a directory",
        );
      }

      let destStats: Stats | undefined;
      try {
        destStats = lstatSync(resolved.fullPath);
      } catch (err) {
        if (!isErrnoCode(err, "ENOENT")) {
          throw wrapIoError(err, "Failed to inspect upload destination");
        }
      }
      if (destStats !== undefined) {
        if (destStats.isSymbolicLink()) {
          throw new FileManagerError("symlink_forbidden", "Upload destination is a symbolic link");
        }
        if (destStats.isDirectory()) {
          throw new FileManagerError("is_a_directory", "Upload destination is a directory");
        }
        if (!destStats.isFile()) {
          throw new FileManagerError("not_a_file", "Upload destination is not a regular file");
        }
      }

      const preRenameStagingStat = lstatSync(session.stagingPath);
      if (
        preRenameStagingStat.isSymbolicLink() ||
        !preRenameStagingStat.isFile() ||
        preRenameStagingStat.dev !== session.stagingDev ||
        preRenameStagingStat.ino !== session.stagingIno
      ) {
        throw new FileManagerError(
          "toctou_detected",
          "Upload staging path changed before atomic rename",
        );
      }

      renameSync(session.stagingPath, resolved.fullPath);
      renamed = true;

      return {
        upload_id: session.uploadId,
        path: resolved.relativePath,
        size: session.receivedBytes,
        sha256: actualSha256,
      };
    } catch (err) {
      throw wrapIoError(err, "Failed to commit upload");
    } finally {
      this.#cleanupUpload(session, !renamed);
    }
  }

  abortUpload(params: UploadAbortParams): {
    readonly upload_id: string;
    readonly aborted: boolean;
  } {
    const session = this.#uploads.get(params.upload_id);
    if (session === undefined || session.serverId !== params.server_id) {
      throw new FileManagerError("upload_not_found", "Upload session not found");
    }
    this.#uploads.delete(session.uploadId);
    this.#cleanupUpload(session, true);
    return { upload_id: session.uploadId, aborted: true };
  }

  beginDownload(params: DownloadBeginParams): DownloadBeginResult {
    const requestedPartSize = params.part_size ?? Math.min(DEFAULT_PART_BYTES, this.#maxPartBytes);
    if (!Number.isSafeInteger(requestedPartSize) || requestedPartSize <= 0) {
      throw new FileManagerError("part_too_large", "part_size must be a positive integer");
    }
    if (requestedPartSize > this.#maxPartBytes) {
      throw new FileManagerError(
        "part_too_large",
        `part_size ${requestedPartSize} exceeds maximum ${this.#maxPartBytes}`,
      );
    }
    if (this.#downloads.size >= this.#maxConcurrentDownloads) {
      throw new FileManagerError(
        "download_limit_exceeded",
        "Maximum concurrent download sessions reached",
      );
    }

    const resolved = resolveConfinedPath({
      serversBaseDir: this.#serversBaseDir,
      serverId: params.server_id,
      relPath: params.path,
      allowRoot: false,
    });

    const { fd, stats } = openConfinedFileForRead(resolved);
    const downloadId = randomBytes(16).toString("hex");
    const totalParts = stats.size === 0 ? 1 : Math.ceil(stats.size / requestedPartSize);

    const session: DownloadSession = {
      downloadId,
      serverId: resolved.serverId,
      relPath: resolved.relativePath,
      totalSize: stats.size,
      partSize: requestedPartSize,
      totalParts,
      fd,
    };

    this.#downloads.set(downloadId, session);
    return {
      download_id: downloadId,
      path: resolved.relativePath,
      total_size: stats.size,
      part_size: requestedPartSize,
      total_parts: totalParts,
    };
  }

  readDownloadPart(params: DownloadPartParams): DownloadPartResult {
    const session = this.#downloads.get(params.download_id);
    if (
      session === undefined ||
      session.serverId !== params.server_id ||
      session.fd === undefined
    ) {
      throw new FileManagerError("download_not_found", "Download session not found");
    }
    if (
      !Number.isSafeInteger(params.part_index) ||
      params.part_index < 0 ||
      params.part_index >= session.totalParts
    ) {
      throw new FileManagerError(
        "part_out_of_order",
        `part_index ${params.part_index} is out of range`,
      );
    }

    const offset = params.part_index * session.partSize;
    const remaining = Math.max(0, session.totalSize - offset);
    const toRead = Math.min(session.partSize, remaining);
    const buf = Buffer.allocUnsafe(toRead);
    let bytesRead: number;
    try {
      bytesRead = toRead > 0 ? readSync(session.fd, buf, 0, toRead, offset) : 0;
    } catch (err) {
      throw wrapIoError(err, "Failed to read download part");
    }
    const slice = buf.subarray(0, bytesRead);
    const view = new Uint8Array(slice.buffer, slice.byteOffset, slice.byteLength);

    return {
      download_id: session.downloadId,
      part_index: params.part_index,
      offset,
      size: bytesRead,
      total_size: session.totalSize,
      eof: offset + bytesRead >= session.totalSize,
      sha256: sha256Hex(view),
      data_base64: slice.toString("base64"),
    };
  }

  closeDownload(params: DownloadCloseParams): {
    readonly download_id: string;
    readonly closed: boolean;
  } {
    const session = this.#downloads.get(params.download_id);
    if (session === undefined || session.serverId !== params.server_id) {
      throw new FileManagerError("download_not_found", "Download session not found");
    }
    this.#downloads.delete(session.downloadId);
    this.#cleanupDownload(session);
    return { download_id: session.downloadId, closed: true };
  }

  downloadRange(params: DownloadRangeParams): DownloadRangeResult {
    if (!Number.isSafeInteger(params.offset) || params.offset < 0) {
      throw new FileManagerError("invalid_path", "offset must be a non-negative integer");
    }
    if (!Number.isSafeInteger(params.length) || params.length <= 0) {
      throw new FileManagerError("part_too_large", "length must be a positive integer");
    }
    if (params.length > this.#maxPartBytes) {
      throw new FileManagerError(
        "part_too_large",
        `Requested length ${params.length} exceeds maximum ${this.#maxPartBytes}`,
      );
    }

    const resolved = resolveConfinedPath({
      serversBaseDir: this.#serversBaseDir,
      serverId: params.server_id,
      relPath: params.path,
      allowRoot: false,
    });

    const { fd, stats } = openConfinedFileForRead(resolved);
    try {
      const remaining = Math.max(0, stats.size - params.offset);
      const toRead = Math.min(params.length, remaining);
      const buf = Buffer.allocUnsafe(toRead);
      let bytesRead: number;
      try {
        bytesRead = toRead > 0 ? readSync(fd, buf, 0, toRead, params.offset) : 0;
      } catch (err) {
        throw wrapIoError(err, "Failed to read download range");
      }
      const slice = buf.subarray(0, bytesRead);
      const view = new Uint8Array(slice.buffer, slice.byteOffset, slice.byteLength);

      return {
        path: resolved.relativePath,
        offset: params.offset,
        size: bytesRead,
        total_size: stats.size,
        eof: params.offset + bytesRead >= stats.size,
        sha256: sha256Hex(view),
        data_base64: slice.toString("base64"),
      };
    } finally {
      closeSync(fd);
    }
  }

  closeAll(): void {
    for (const session of this.#uploads.values()) {
      this.#cleanupUpload(session, true);
    }
    this.#uploads.clear();

    for (const session of this.#downloads.values()) {
      this.#cleanupDownload(session);
    }
    this.#downloads.clear();
  }
}
