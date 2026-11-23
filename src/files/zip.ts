// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { closeSync, lstatSync, readdirSync, readSync, type Stats } from "node:fs";
import { join } from "node:path";
import { deflateRawSync, inflateRawSync } from "node:zlib";
import type { PermissionContext } from "../server/permissions";
import {
  DEFAULT_SERVERS_BASE_DIR,
  isErrnoCode,
  isSameOrSubpath,
  mkdirConfined,
  openConfinedFileForRead,
  RUNTIME_DIR_NAME,
  resolveConfinedPath,
  UPLOAD_STAGING_DIR_NAME,
  UPLOAD_STAGING_FILE_PREFIX,
  wrapIoError,
  writeConfinedFileAtomic,
} from "./confinement";
import { FileManagerError } from "./errors";

export const MAX_ZIP_ENTRIES = 10_000;
export const MAX_ZIP_UNCOMPRESSED_BYTES = 10 * 1024 * 1024 * 1024; // 10 GiB
export const MAX_ZIP_ENTRY_BYTES = 512 * 1024 * 1024; // 512 MiB
export const MAX_ZIP_COMPRESSION_RATIO = 100;
export const DEFAULT_ZIP_RATIO_MIN_BYTES = 64 * 1024; // 64 KiB
export const DEFAULT_MAX_ZIP_FILE_BYTES = 512 * 1024 * 1024; // 512 MiB
export const MAX_ZIP_CREATE_FILES = 10_000;
export const MAX_ZIP_CREATE_BYTES = 2 * 1024 * 1024 * 1024; // 2 GiB

const SIG_LOCAL_FILE_HEADER = 0x04034b50;
const SIG_CENTRAL_DIR_HEADER = 0x02014b50;
const SIG_EOCD = 0x06054b50;

const METHOD_STORE = 0;
const METHOD_DEFLATE = 8;

const FLAG_ENCRYPTED = 0x0001;
const FLAG_DATA_DESCRIPTOR = 0x0008;
const FLAG_STRONG_ENCRYPTED = 0x0040;
const FLAG_UTF8 = 0x0800;

const MAX_ZLIB_OUTPUT_BYTES = 4294967296;

const UNIX_MODE_MASK = 0o170000;
const UNIX_MODE_SYMLINK = 0o120000;
const UNIX_MODE_DIRECTORY = 0o040000;
const UNIX_MODE_REGULAR = 0o100000;

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

export function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.byteLength; i++) {
    const b = data[i];
    if (b === undefined) {
      continue;
    }
    const entry = CRC32_TABLE[(crc ^ b) & 0xff];
    if (entry !== undefined) {
      crc = entry ^ (crc >>> 8);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function toDosTimeDate(date: Date): { readonly dosTime: number; readonly dosDate: number } {
  const year = Math.max(1980, Math.min(2107, date.getUTCFullYear()));
  const month = date.getUTCMonth() + 1;
  const day = date.getUTCDate();
  const hours = date.getUTCHours();
  const minutes = date.getUTCMinutes();
  const seconds = Math.floor(date.getUTCSeconds() / 2);

  const dosTime = (hours << 11) | (minutes << 5) | seconds;
  const dosDate = ((year - 1980) << 9) | (month << 5) | day;
  return { dosTime, dosDate };
}

export interface ZipEntryInput {
  readonly name: string;
  readonly data: Uint8Array;
  readonly isDirectory?: boolean;
  readonly mtime?: Date;
  readonly unixMode?: number;
  readonly store?: boolean;
}

export function createZipBuffer(entries: readonly ZipEntryInput[]): Uint8Array {
  if (entries.length > 0xffff) {
    throw new FileManagerError("zip_too_many_entries", "ZIP entry count exceeds 65535 limit");
  }

  const encoder = new TextEncoder();
  const localParts: Uint8Array[] = [];
  const centralParts: Uint8Array[] = [];
  let offset = 0;

  for (const entry of entries) {
    const isDir = entry.isDirectory ?? entry.name.endsWith("/");
    const entryName = isDir && !entry.name.endsWith("/") ? `${entry.name}/` : entry.name;
    const nameBytes = encoder.encode(entryName);
    const plain = isDir ? new Uint8Array(0) : entry.data;
    const checksum = crc32(plain);

    let method = METHOD_STORE;
    let payload: Uint8Array = plain;
    if (!isDir && !entry.store && plain.byteLength > 0) {
      const deflated = deflateRawSync(plain);
      const deflatedView = new Uint8Array(
        deflated.buffer,
        deflated.byteOffset,
        deflated.byteLength,
      );
      if (deflatedView.byteLength < plain.byteLength) {
        method = METHOD_DEFLATE;
        payload = deflatedView;
      }
    }

    const { dosTime, dosDate } = toDosTimeDate(entry.mtime ?? new Date(0));
    const unixMode =
      entry.unixMode ?? (isDir ? UNIX_MODE_DIRECTORY | 0o755 : UNIX_MODE_REGULAR | 0o644);
    const externalAttr = ((unixMode & 0xffff) << 16) >>> 0;

    // Local file header (30 bytes + name)
    const lfh = new Uint8Array(30 + nameBytes.byteLength);
    const lfhView = new DataView(lfh.buffer);
    lfhView.setUint32(0, SIG_LOCAL_FILE_HEADER, true);
    lfhView.setUint16(4, 20, true); // version needed
    lfhView.setUint16(6, FLAG_UTF8, true);
    lfhView.setUint16(8, method, true);
    lfhView.setUint16(10, dosTime, true);
    lfhView.setUint16(12, dosDate, true);
    lfhView.setUint32(14, checksum, true);
    lfhView.setUint32(18, payload.byteLength, true);
    lfhView.setUint32(22, plain.byteLength, true);
    lfhView.setUint16(26, nameBytes.byteLength, true);
    lfhView.setUint16(28, 0, true); // extra length
    lfh.set(nameBytes, 30);

    // Central directory header (46 bytes + name)
    const cdh = new Uint8Array(46 + nameBytes.byteLength);
    const cdhView = new DataView(cdh.buffer);
    cdhView.setUint32(0, SIG_CENTRAL_DIR_HEADER, true);
    cdhView.setUint16(4, 0x0314, true); // version made by: Unix (3), spec 2.0 (20)
    cdhView.setUint16(6, 20, true); // version needed
    cdhView.setUint16(8, FLAG_UTF8, true);
    cdhView.setUint16(10, method, true);
    cdhView.setUint16(12, dosTime, true);
    cdhView.setUint16(14, dosDate, true);
    cdhView.setUint32(16, checksum, true);
    cdhView.setUint32(20, payload.byteLength, true);
    cdhView.setUint32(24, plain.byteLength, true);
    cdhView.setUint16(28, nameBytes.byteLength, true);
    cdhView.setUint16(30, 0, true); // extra length
    cdhView.setUint16(32, 0, true); // comment length
    cdhView.setUint16(34, 0, true); // disk number start
    cdhView.setUint16(36, 0, true); // internal attrs
    cdhView.setUint32(38, externalAttr, true);
    cdhView.setUint32(42, offset, true); // relative offset of local header
    cdh.set(nameBytes, 46);

    localParts.push(lfh, payload);
    centralParts.push(cdh);
    offset += lfh.byteLength + payload.byteLength;
  }

  const cdOffset = offset;
  let cdSize = 0;
  for (const part of centralParts) {
    cdSize += part.byteLength;
  }

  const totalLength = cdOffset + cdSize + 22;
  if (cdOffset > 0xffffffff || cdSize > 0xffffffff || totalLength > 0xffffffff) {
    throw new FileManagerError("zip_too_large", "ZIP archive exceeds 4 GiB ZIP32 limit");
  }

  const eocd = new Uint8Array(22);
  const eocdView = new DataView(eocd.buffer);
  eocdView.setUint32(0, SIG_EOCD, true);
  eocdView.setUint16(4, 0, true); // disk number
  eocdView.setUint16(6, 0, true); // cd start disk
  eocdView.setUint16(8, entries.length, true);
  eocdView.setUint16(10, entries.length, true);
  eocdView.setUint32(12, cdSize, true);
  eocdView.setUint32(16, cdOffset, true);
  eocdView.setUint16(20, 0, true); // comment length
  const output = new Uint8Array(totalLength);
  let cursor = 0;
  for (const part of localParts) {
    output.set(part, cursor);
    cursor += part.byteLength;
  }
  for (const part of centralParts) {
    output.set(part, cursor);
    cursor += part.byteLength;
  }
  output.set(eocd, cursor);
  return output;
}

interface ParsedCentralEntry {
  readonly rawName: string;
  readonly targetRelPath: string;
  readonly isDirectory: boolean;
  readonly flags: number;
  readonly method: number;
  readonly crc32: number;
  readonly compressedSize: number;
  readonly uncompressedSize: number;
  readonly localHeaderOffset: number;
  readonly dataStart: number;
  readonly dataEnd: number;
}

function findEocdOffset(view: DataView, byteLength: number): number {
  if (byteLength < 22) {
    throw new FileManagerError("zip_invalid", "Archive is smaller than minimum ZIP size");
  }
  const minOffset = Math.max(0, byteLength - 22 - 0xffff);
  for (let pos = byteLength - 22; pos >= minOffset; pos--) {
    if (view.getUint32(pos, true) === SIG_EOCD) {
      const commentLength = view.getUint16(pos + 20, true);
      if (pos + 22 + commentLength === byteLength) {
        return pos;
      }
    }
  }
  throw new FileManagerError("zip_invalid", "End of Central Directory record not found");
}

function isBufferTooLargeError(err: unknown): boolean {
  if (typeof err !== "object" || err === null) {
    return false;
  }
  const code = "code" in err ? (err as { readonly code?: unknown }).code : undefined;
  if (code === "ERR_BUFFER_TOO_LARGE") {
    return true;
  }
  const message = err instanceof Error ? err.message : "";
  return /Cannot create a Buffer larger|maxOutputLength|too large/i.test(message);
}

function readAllFromFd(fd: number, maxBytes: number): Uint8Array {
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
      throw new FileManagerError("file_too_large", `File exceeds maximum allowed size`);
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

export interface SafeUnzipOptions {
  readonly serversBaseDir?: string;
  readonly serverId: string;
  readonly destPath?: string;
  readonly maxEntries?: number;
  readonly maxUncompressedBytes?: number;
  readonly maxEntryBytes?: number;
  readonly maxCompressionRatio?: number;
  readonly ratioMinBytes?: number;
  readonly forbiddenPaths?: ReadonlySet<string>;
  readonly permissions?: PermissionContext;
}

export interface SafeUnzipBufferOptions extends SafeUnzipOptions {
  readonly buffer: Uint8Array;
}

export interface SafeUnzipFileOptions extends SafeUnzipOptions {
  readonly zipPath: string;
  readonly maxZipFileBytes?: number;
}

export interface SafeUnzipResult {
  readonly destPath: string;
  readonly entryCount: number;
  readonly totalBytes: number;
  readonly files: readonly string[];
}

function validateZipEntryName(
  rawName: string,
  destRelPath: string,
  serversBaseDir: string,
  serverId: string,
  isDirectoryFlag: boolean,
): { readonly targetRelPath: string; readonly isDirectory: boolean } {
  if (rawName.length === 0) {
    throw new FileManagerError("zip_invalid", "ZIP entry has empty filename");
  }
  if (rawName.includes("\0")) {
    throw new FileManagerError("zip_slip", "ZIP entry contains NUL byte");
  }
  if (rawName.includes("\\")) {
    throw new FileManagerError("zip_slip", "ZIP entry contains backslash");
  }
  if (rawName.startsWith("/") || /^[A-Za-z]:/.test(rawName)) {
    throw new FileManagerError("zip_slip", "ZIP entry uses absolute path");
  }

  const hasTrailingSlash = rawName.endsWith("/");
  const isDirectory = isDirectoryFlag || hasTrailingSlash;
  const trimmed = hasTrailingSlash ? rawName.slice(0, -1) : rawName;

  if (trimmed.length === 0 || trimmed.endsWith("/")) {
    throw new FileManagerError("zip_slip", `Invalid ZIP entry path "${rawName}"`);
  }

  const combined = destRelPath.length > 0 ? `${destRelPath}/${trimmed}` : trimmed;

  try {
    const resolved = resolveConfinedPath({
      serversBaseDir,
      serverId,
      relPath: combined,
      allowRoot: false,
    });
    return { targetRelPath: resolved.relativePath, isDirectory };
  } catch (err) {
    if (err instanceof FileManagerError) {
      if (err.code === "path_traversal" || err.code === "invalid_path") {
        throw new FileManagerError("zip_slip", `Unsafe ZIP entry "${rawName}": ${err.message}`);
      }
      throw err;
    }
    throw wrapIoError(err, `Failed to validate ZIP entry "${rawName}"`);
  }
}

export function safeUnzipBuffer(options: SafeUnzipBufferOptions): SafeUnzipResult {
  const serversBaseDir = options.serversBaseDir ?? DEFAULT_SERVERS_BASE_DIR;
  const maxEntries = options.maxEntries ?? MAX_ZIP_ENTRIES;
  const maxUncompressedBytes = options.maxUncompressedBytes ?? MAX_ZIP_UNCOMPRESSED_BYTES;
  const maxEntryBytes = options.maxEntryBytes ?? MAX_ZIP_ENTRY_BYTES;
  const maxCompressionRatio = options.maxCompressionRatio ?? MAX_ZIP_COMPRESSION_RATIO;
  const ratioMinBytes = options.ratioMinBytes ?? DEFAULT_ZIP_RATIO_MIN_BYTES;
  const forbiddenPathsLower =
    options.forbiddenPaths !== undefined
      ? new Set([...options.forbiddenPaths].map((p) => p.replace(/^\/+/, "").toLowerCase()))
      : undefined;

  const destResolved = resolveConfinedPath({
    serversBaseDir,
    serverId: options.serverId,
    relPath: options.destPath ?? "",
    allowRoot: true,
  });

  const buf = options.buffer;
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const decoder = new TextDecoder("utf-8", { fatal: true });

  const eocdOffset = findEocdOffset(view, buf.byteLength);
  const diskNumber = view.getUint16(eocdOffset + 4, true);
  const cdStartDisk = view.getUint16(eocdOffset + 6, true);
  const entriesOnDisk = view.getUint16(eocdOffset + 8, true);
  const totalEntries = view.getUint16(eocdOffset + 10, true);
  const cdSize = view.getUint32(eocdOffset + 12, true);
  const cdOffset = view.getUint32(eocdOffset + 16, true);

  if (diskNumber !== 0 || cdStartDisk !== 0 || entriesOnDisk !== totalEntries) {
    throw new FileManagerError("zip_invalid", "Multi-disk ZIP archives are not supported");
  }
  if (totalEntries === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    throw new FileManagerError("zip_invalid", "ZIP64 archives are not supported");
  }
  if (totalEntries > maxEntries) {
    throw new FileManagerError(
      "zip_too_many_entries",
      `ZIP entry count ${totalEntries} exceeds limit ${maxEntries}`,
    );
  }
  if (cdOffset + cdSize > eocdOffset) {
    throw new FileManagerError("zip_invalid", "Central Directory exceeds archive bounds");
  }

  // Phase 1: Validate every Central Directory entry, Local File Header, and byte range
  // BEFORE creating any directories or files on disk.
  const entries: ParsedCentralEntry[] = [];
  const lowerFiles = new Map<string, string>();
  const lowerDirs = new Map<string, string>();
  const explicitDirs = new Set<string>();
  let declaredTotalUncompressed = 0;
  let pos = cdOffset;
  const cdEnd = cdOffset + cdSize;

  for (let i = 0; i < totalEntries; i++) {
    if (pos + 46 > cdEnd) {
      throw new FileManagerError("zip_invalid", "Truncated Central Directory header");
    }
    if (view.getUint32(pos, true) !== SIG_CENTRAL_DIR_HEADER) {
      throw new FileManagerError("zip_invalid", "Invalid Central Directory header signature");
    }

    const flags = view.getUint16(pos + 8, true);
    const method = view.getUint16(pos + 10, true);
    const entryCrc = view.getUint32(pos + 16, true);
    const compressedSize = view.getUint32(pos + 20, true);
    const uncompressedSize = view.getUint32(pos + 24, true);
    const nameLen = view.getUint16(pos + 28, true);
    const extraLen = view.getUint16(pos + 30, true);
    const commentLen = view.getUint16(pos + 32, true);
    const externalAttr = view.getUint32(pos + 38, true);
    const localHeaderOffset = view.getUint32(pos + 42, true);

    const nextPos = pos + 46 + nameLen + extraLen + commentLen;
    if (nextPos > cdEnd) {
      throw new FileManagerError("zip_invalid", "Central Directory entry extends past CD end");
    }

    if ((flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTED)) !== 0) {
      throw new FileManagerError("zip_unsupported_method", "Encrypted ZIP entries are forbidden");
    }
    if (method !== METHOD_STORE && method !== METHOD_DEFLATE) {
      throw new FileManagerError(
        "zip_unsupported_method",
        `Unsupported ZIP compression method: ${method}`,
      );
    }

    const unixType = (externalAttr >>> 16) & UNIX_MODE_MASK;
    if (unixType === UNIX_MODE_SYMLINK) {
      throw new FileManagerError(
        "zip_symlink_entry",
        "Symbolic link entries inside ZIP archives are forbidden",
      );
    }
    if (unixType !== 0 && unixType !== UNIX_MODE_REGULAR && unixType !== UNIX_MODE_DIRECTORY) {
      throw new FileManagerError(
        "zip_invalid",
        "Special UNIX device/FIFO/socket entries are forbidden",
      );
    }

    let rawName: string;
    try {
      rawName = decoder.decode(buf.subarray(pos + 46, pos + 46 + nameLen));
    } catch {
      throw new FileManagerError("zip_invalid", "ZIP entry name is not valid UTF-8");
    }

    const validated = validateZipEntryName(
      rawName,
      destResolved.relativePath,
      serversBaseDir,
      options.serverId,
      unixType === UNIX_MODE_DIRECTORY,
    );

    const lowerRelPath = validated.targetRelPath.toLowerCase();
    if (forbiddenPathsLower?.has(lowerRelPath)) {
      throw new FileManagerError("zip_slip", `Refusing to extract protected path "${rawName}"`);
    }
    if (validated.isDirectory) {
      if (compressedSize !== 0 || uncompressedSize !== 0) {
        throw new FileManagerError("zip_invalid", "Directory entry must have zero size");
      }
      if (lowerFiles.has(lowerRelPath)) {
        throw new FileManagerError("zip_invalid", "Conflicting file and directory path in archive");
      }
      const existingDir = lowerDirs.get(lowerRelPath);
      if (existingDir !== undefined && existingDir !== validated.targetRelPath) {
        throw new FileManagerError(
          "zip_invalid",
          "Case-colliding directory paths in archive are forbidden",
        );
      }
      if (explicitDirs.has(lowerRelPath)) {
        throw new FileManagerError("zip_invalid", "Duplicate directory entry in archive");
      }
      lowerDirs.set(lowerRelPath, validated.targetRelPath);
      explicitDirs.add(lowerRelPath);
    } else {
      if (lowerFiles.has(lowerRelPath) || lowerDirs.has(lowerRelPath)) {
        throw new FileManagerError(
          "zip_invalid",
          "Duplicate or case-colliding entry path in archive",
        );
      }
      lowerFiles.set(lowerRelPath, validated.targetRelPath);

      const parts = validated.targetRelPath.split("/");
      for (let p = 1; p < parts.length; p++) {
        const ancestor = parts.slice(0, p).join("/");
        const lowerAncestor = ancestor.toLowerCase();
        if (lowerFiles.has(lowerAncestor)) {
          throw new FileManagerError(
            "zip_invalid",
            "Conflicting file and directory ancestor in archive",
          );
        }
        const existingAncestorDir = lowerDirs.get(lowerAncestor);
        if (existingAncestorDir !== undefined && existingAncestorDir !== ancestor) {
          throw new FileManagerError(
            "zip_invalid",
            "Case-colliding ancestor directory paths in archive are forbidden",
          );
        }
        lowerDirs.set(lowerAncestor, ancestor);
      }

      if (uncompressedSize > maxEntryBytes) {
        throw new FileManagerError(
          "zip_entry_too_large",
          `ZIP entry "${rawName}" declared size ${uncompressedSize} exceeds limit ${maxEntryBytes}`,
        );
      }

      declaredTotalUncompressed += uncompressedSize;
      if (declaredTotalUncompressed > maxUncompressedBytes) {
        throw new FileManagerError(
          "zip_too_large",
          `ZIP total declared size exceeds limit ${maxUncompressedBytes}`,
        );
      }

      if (method === METHOD_DEFLATE) {
        if (compressedSize === 0) {
          throw new FileManagerError(
            "zip_invalid",
            `Deflated ZIP entry "${rawName}" has zero compressed size`,
          );
        }
        const ratioLimit = Math.max(
          ratioMinBytes,
          Math.max(1, compressedSize) * maxCompressionRatio,
        );
        if (uncompressedSize > ratioLimit) {
          throw new FileManagerError(
            "zip_compression_ratio_exceeded",
            `ZIP entry "${rawName}" exceeds maximum compression ratio`,
          );
        }
      } else if (compressedSize !== uncompressedSize) {
        throw new FileManagerError(
          "zip_invalid",
          `Stored ZIP entry "${rawName}" has mismatched compressed/uncompressed sizes`,
        );
      }
    }

    if (localHeaderOffset + 30 > cdOffset) {
      throw new FileManagerError("zip_invalid", "Local File Header offset out of bounds");
    }
    if (view.getUint32(localHeaderOffset, true) !== SIG_LOCAL_FILE_HEADER) {
      throw new FileManagerError("zip_invalid", "Invalid Local File Header signature");
    }

    const lfhFlags = view.getUint16(localHeaderOffset + 6, true);
    const lfhMethod = view.getUint16(localHeaderOffset + 8, true);
    const lfhCrc = view.getUint32(localHeaderOffset + 14, true);
    const lfhCompressedSize = view.getUint32(localHeaderOffset + 18, true);
    const lfhUncompressedSize = view.getUint32(localHeaderOffset + 22, true);
    const lfhNameLen = view.getUint16(localHeaderOffset + 26, true);
    const lfhExtraLen = view.getUint16(localHeaderOffset + 28, true);

    if ((lfhFlags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTED)) !== 0) {
      throw new FileManagerError("zip_unsupported_method", "Encrypted ZIP entries are forbidden");
    }
    if (lfhMethod !== method) {
      throw new FileManagerError("zip_invalid", "Local and Central header compression mismatch");
    }

    const dataStart = localHeaderOffset + 30 + lfhNameLen + lfhExtraLen;
    const dataEnd = dataStart + compressedSize;
    if (dataEnd > cdOffset) {
      throw new FileManagerError("zip_invalid", "Local File Header data exceeds archive bounds");
    }

    let lfhName: string;
    try {
      lfhName = decoder.decode(
        buf.subarray(localHeaderOffset + 30, localHeaderOffset + 30 + lfhNameLen),
      );
    } catch {
      throw new FileManagerError("zip_invalid", "Local header filename is not valid UTF-8");
    }
    if (lfhName !== rawName) {
      throw new FileManagerError("zip_invalid", "Local and Central header filename mismatch");
    }

    const hasDataDescriptor = (lfhFlags & FLAG_DATA_DESCRIPTOR) !== 0;
    if (
      !hasDataDescriptor &&
      (lfhCrc !== entryCrc ||
        lfhCompressedSize !== compressedSize ||
        lfhUncompressedSize !== uncompressedSize)
    ) {
      throw new FileManagerError("zip_invalid", "Local and Central header metadata mismatch");
    }

    entries.push({
      rawName,
      targetRelPath: validated.targetRelPath,
      isDirectory: validated.isDirectory,
      flags,
      method,
      crc32: entryCrc,
      compressedSize,
      uncompressedSize,
      localHeaderOffset,
      dataStart,
      dataEnd,
    });

    pos = nextPos;
  }

  if (pos !== cdEnd) {
    throw new FileManagerError("zip_invalid", "Central Directory size does not match entries");
  }

  // Verify no two entries overlap in their [localHeaderOffset, dataEnd) byte ranges.
  const sortedRanges = [...entries].sort((a, b) => a.localHeaderOffset - b.localHeaderOffset);
  for (let i = 1; i < sortedRanges.length; i++) {
    const prev = sortedRanges[i - 1];
    const curr = sortedRanges[i];
    if (prev !== undefined && curr !== undefined && prev.dataEnd > curr.localHeaderOffset) {
      throw new FileManagerError("zip_invalid", "Overlapping ZIP entry offsets are forbidden");
    }
  }

  // Phase 2: Extract entries safely with strict runtime decompression budgets.
  if (destResolved.relativePath.length > 0) {
    mkdirConfined({
      serversBaseDir,
      serverId: options.serverId,
      relPath: destResolved.relativePath,
      ...(options.permissions !== undefined ? { permissions: options.permissions } : {}),
    });
  }

  let actualTotalBytes = 0;
  const extractedFiles: string[] = [];

  for (const entry of entries) {
    if (entry.isDirectory) {
      mkdirConfined({
        serversBaseDir,
        serverId: options.serverId,
        relPath: entry.targetRelPath,
        ...(options.permissions !== undefined ? { permissions: options.permissions } : {}),
      });
      continue;
    }

    const remainingTotalBudget = maxUncompressedBytes - actualTotalBytes;
    if (remainingTotalBudget < 0) {
      throw new FileManagerError("zip_too_large", "ZIP total uncompressed byte limit exceeded");
    }

    const compressedData = buf.subarray(entry.dataStart, entry.dataEnd);
    let plain: Uint8Array;

    if (entry.method === METHOD_STORE) {
      if (compressedData.byteLength > remainingTotalBudget) {
        throw new FileManagerError("zip_too_large", "ZIP total uncompressed byte limit exceeded");
      }
      if (compressedData.byteLength > maxEntryBytes) {
        throw new FileManagerError("zip_entry_too_large", "ZIP entry exceeds maximum byte limit");
      }
      plain = compressedData;
    } else {
      const ratioBudget = Math.max(
        ratioMinBytes,
        Math.max(1, entry.compressedSize) * maxCompressionRatio,
      );
      const maxOutputLength = Math.min(remainingTotalBudget, maxEntryBytes, ratioBudget);
      const boundedMaxOutput = Math.min(MAX_ZLIB_OUTPUT_BYTES, Math.max(1, maxOutputLength));

      try {
        const inflated = inflateRawSync(compressedData, { maxOutputLength: boundedMaxOutput });
        plain = new Uint8Array(inflated.buffer, inflated.byteOffset, inflated.byteLength);
      } catch (err) {
        if (isBufferTooLargeError(err)) {
          if (remainingTotalBudget <= maxEntryBytes && remainingTotalBudget <= ratioBudget) {
            throw new FileManagerError(
              "zip_too_large",
              "Decompressed archive exceeded total uncompressed size budget",
            );
          }
          if (maxEntryBytes <= ratioBudget) {
            throw new FileManagerError(
              "zip_entry_too_large",
              "Decompressed entry exceeded maximum entry size",
            );
          }
          throw new FileManagerError(
            "zip_compression_ratio_exceeded",
            "Decompressed entry exceeded maximum compression ratio",
          );
        }
        throw new FileManagerError(
          "zip_invalid",
          `Failed to decompress ZIP entry "${entry.rawName}"`,
        );
      }

      if (plain.byteLength > remainingTotalBudget) {
        throw new FileManagerError("zip_too_large", "ZIP total uncompressed byte limit exceeded");
      }
    }

    if (plain.byteLength !== entry.uncompressedSize) {
      throw new FileManagerError(
        "zip_invalid",
        `Actual uncompressed size (${plain.byteLength}) does not match header (${entry.uncompressedSize})`,
      );
    }

    if (crc32(plain) !== entry.crc32) {
      throw new FileManagerError(
        "zip_crc_mismatch",
        `CRC-32 mismatch for ZIP entry "${entry.rawName}"`,
      );
    }

    actualTotalBytes += plain.byteLength;
    if (actualTotalBytes > maxUncompressedBytes) {
      throw new FileManagerError("zip_too_large", "ZIP total uncompressed byte limit exceeded");
    }

    const targetResolved = resolveConfinedPath({
      serversBaseDir,
      serverId: options.serverId,
      relPath: entry.targetRelPath,
      allowRoot: false,
    });
    writeConfinedFileAtomic(targetResolved, plain, {
      createParents: true,
      ...(options.permissions !== undefined ? { permissions: options.permissions } : {}),
    });
    extractedFiles.push(targetResolved.relativePath);
  }

  return {
    destPath: destResolved.relativePath,
    entryCount: entries.length,
    totalBytes: actualTotalBytes,
    files: extractedFiles,
  };
}

export function safeUnzipFile(options: SafeUnzipFileOptions): SafeUnzipResult {
  const serversBaseDir = options.serversBaseDir ?? DEFAULT_SERVERS_BASE_DIR;
  const maxZipFileBytes = options.maxZipFileBytes ?? DEFAULT_MAX_ZIP_FILE_BYTES;
  const zipResolved = resolveConfinedPath({
    serversBaseDir,
    serverId: options.serverId,
    relPath: options.zipPath,
    allowRoot: false,
  });

  const { fd, stats } = openConfinedFileForRead(zipResolved);
  let buffer: Uint8Array;
  try {
    if (stats.size > maxZipFileBytes) {
      throw new FileManagerError("file_too_large", "ZIP file exceeds maximum readable size");
    }
    buffer = readAllFromFd(fd, maxZipFileBytes);
  } finally {
    closeSync(fd);
  }

  return safeUnzipBuffer({
    serversBaseDir,
    serverId: options.serverId,
    buffer,
    ...(options.destPath !== undefined ? { destPath: options.destPath } : {}),
    ...(options.maxEntries !== undefined ? { maxEntries: options.maxEntries } : {}),
    ...(options.maxUncompressedBytes !== undefined
      ? { maxUncompressedBytes: options.maxUncompressedBytes }
      : {}),
    ...(options.maxEntryBytes !== undefined ? { maxEntryBytes: options.maxEntryBytes } : {}),
    ...(options.maxCompressionRatio !== undefined
      ? { maxCompressionRatio: options.maxCompressionRatio }
      : {}),
    ...(options.ratioMinBytes !== undefined ? { ratioMinBytes: options.ratioMinBytes } : {}),
    ...(options.forbiddenPaths !== undefined ? { forbiddenPaths: options.forbiddenPaths } : {}),
    ...(options.permissions !== undefined ? { permissions: options.permissions } : {}),
  });
}

export interface SafeZipFilesOptions {
  readonly serversBaseDir?: string;
  readonly serverId: string;
  readonly paths: readonly string[];
  readonly destPath: string;
  readonly maxFiles?: number;
  readonly maxTotalBytes?: number;
  readonly permissions?: PermissionContext;
}

export interface SafeZipResult {
  readonly destPath: string;
  readonly entryCount: number;
  readonly uncompressedBytes: number;
  readonly compressedBytes: number;
}

export function safeZipFiles(options: SafeZipFilesOptions): SafeZipResult {
  if (options.paths.length === 0) {
    throw new FileManagerError("invalid_path", "At least one source path is required");
  }

  const serversBaseDir = options.serversBaseDir ?? DEFAULT_SERVERS_BASE_DIR;
  const maxFiles = options.maxFiles ?? MAX_ZIP_CREATE_FILES;
  const maxTotalBytes = options.maxTotalBytes ?? MAX_ZIP_CREATE_BYTES;

  const destResolved = resolveConfinedPath({
    serversBaseDir,
    serverId: options.serverId,
    relPath: options.destPath,
    allowRoot: false,
  });

  let destStats: Stats | undefined;
  try {
    destStats = lstatSync(destResolved.fullPath);
  } catch (err) {
    if (!isErrnoCode(err, "ENOENT")) {
      throw wrapIoError(err, "Failed to inspect ZIP destination");
    }
  }
  if (destStats !== undefined) {
    if (destStats.isSymbolicLink()) {
      throw new FileManagerError("symlink_forbidden", "ZIP destination is a symbolic link");
    }
    if (destStats.isDirectory()) {
      throw new FileManagerError("is_a_directory", "ZIP destination is a directory");
    }
    if (!destStats.isFile()) {
      throw new FileManagerError("not_a_file", "ZIP destination is not a regular file");
    }
  }

  const entries: ZipEntryInput[] = [];
  const seenNames = new Set<string>();
  let totalUncompressed = 0;

  function collectEntry(relPath: string): void {
    const resolved = resolveConfinedPath({
      serversBaseDir,
      serverId: options.serverId,
      relPath,
      allowRoot: false,
    });

    let stats: Stats;
    try {
      stats = lstatSync(resolved.fullPath);
    } catch (err) {
      throw wrapIoError(err, `Failed to stat "${relPath}"`);
    }

    if (stats.isSymbolicLink()) {
      throw new FileManagerError("symlink_forbidden", `Cannot archive symbolic link "${relPath}"`);
    }

    if (stats.isDirectory()) {
      if (isSameOrSubpath(resolved.relativePath, destResolved.relativePath)) {
        throw new FileManagerError(
          "invalid_path",
          "Destination ZIP path cannot be inside a source directory",
        );
      }

      const dirEntryName = `${resolved.relativePath}/`;
      if (!seenNames.has(dirEntryName)) {
        if (entries.length >= maxFiles) {
          throw new FileManagerError("zip_too_many_entries", "Archive file count limit exceeded");
        }
        seenNames.add(dirEntryName);
        entries.push({
          name: dirEntryName,
          data: new Uint8Array(0),
          isDirectory: true,
          mtime: stats.mtime,
        });
      }

      let children: string[];
      try {
        children = readdirSync(resolved.fullPath).sort();
      } catch (err) {
        throw wrapIoError(err, `Failed to read directory "${relPath}"`);
      }
      for (const child of children) {
        const childFull = join(resolved.fullPath, child);
        let childStats: Stats;
        try {
          childStats = lstatSync(childFull);
        } catch (err) {
          throw wrapIoError(err, `Failed to inspect "${resolved.relativePath}/${child}"`);
        }
        if (childStats.isSymbolicLink()) {
          throw new FileManagerError(
            "symlink_forbidden",
            `Cannot archive symbolic link "${resolved.relativePath}/${child}"`,
          );
        }
        if (
          child === RUNTIME_DIR_NAME ||
          child === UPLOAD_STAGING_DIR_NAME ||
          child.startsWith(UPLOAD_STAGING_FILE_PREFIX) ||
          child.startsWith(".tmp-")
        ) {
          continue;
        }
        collectEntry(`${resolved.relativePath}/${child}`);
      }
      return;
    }

    if (!stats.isFile()) {
      throw new FileManagerError("not_a_file", `Cannot archive non-regular file "${relPath}"`);
    }

    if (seenNames.has(resolved.relativePath)) {
      return;
    }
    if (entries.length >= maxFiles) {
      throw new FileManagerError("zip_too_many_entries", "Archive file count limit exceeded");
    }

    const { fd, stats: fdStats } = openConfinedFileForRead(resolved);
    let data: Uint8Array;
    try {
      if (totalUncompressed + fdStats.size > maxTotalBytes) {
        throw new FileManagerError("zip_too_large", "Archive total size limit exceeded");
      }
      data = readAllFromFd(fd, maxTotalBytes - totalUncompressed);
    } finally {
      closeSync(fd);
    }

    totalUncompressed += data.byteLength;
    seenNames.add(resolved.relativePath);
    entries.push({
      name: resolved.relativePath,
      data,
      isDirectory: false,
      mtime: fdStats.mtime,
    });
  }

  for (const sourcePath of options.paths) {
    collectEntry(sourcePath);
  }

  const archive = createZipBuffer(entries);
  writeConfinedFileAtomic(destResolved, archive, {
    ...(options.permissions !== undefined ? { permissions: options.permissions } : {}),
  });

  return {
    destPath: destResolved.relativePath,
    entryCount: entries.length,
    uncompressedBytes: totalUncompressed,
    compressedBytes: archive.byteLength,
  };
}
