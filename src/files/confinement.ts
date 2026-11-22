// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { randomBytes } from "node:crypto";
import {
  closeSync,
  fchmodSync,
  constants as fsConstants,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  realpathSync,
  renameSync,
  type Stats,
  unlinkSync,
  writeSync,
} from "node:fs";
import { basename, dirname, join, resolve, sep } from "node:path";
import { SERVER_ID_PATTERN } from "../protocol";
import { FileManagerError } from "./errors";

export const DEFAULT_SERVERS_BASE_DIR = "/var/lib/tegrad-servers";
export const MAX_PATH_BYTES = 1024;
export const MAX_COMPONENT_BYTES = 255;
export const RUNTIME_DIR_NAME = ".runtime";
export const UPLOAD_STAGING_DIR_NAME = ".tegrad-uploads";
export const UPLOAD_STAGING_FILE_PREFIX = ".tmp-upload-";

const FORBIDDEN_COMPONENT_NAMES = new Set([RUNTIME_DIR_NAME, UPLOAD_STAGING_DIR_NAME]);
const RESERVED_WINDOWS_NAME_REGEX =
  /^(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³]|CONIN\$|CONOUT\$|CLOCK\$)\s*(?:\.|$)/i;
const WINDOWS_DRIVE_PREFIX_REGEX = /^[A-Za-z]:/;
const ENCODED_TRAVERSAL_REGEX = /%(?:2f|5c|00)/i;
// Blocks ASCII/C1 control characters (Cc), invisible format/bidi characters (Cf),
// line/paragraph separators (U+2028/U+2029), and known invisible filler code points.
const UNSAFE_UNICODE_CHAR_REGEX = /(?:\p{Cc}|\p{Cf}|\u034F|\u180E|\u2028|\u2029|\u3164|\uFFA0)/u;
const DEFAULT_FILE_MODE = 0o640;
const DEFAULT_DIR_MODE = 0o750;

export interface ConfinedPath {
  readonly serverId: string;
  readonly serverRoot: string;
  readonly realServerRoot: string;
  readonly relativePath: string;
  readonly segments: readonly string[];
  readonly fullPath: string;
}

export interface ResolveConfinedPathOptions {
  readonly serversBaseDir?: string;
  readonly serverId: string;
  readonly relPath: string;
  readonly allowRoot?: boolean;
}

export interface AtomicWriteOptions {
  readonly mode?: number;
  readonly createParents?: boolean;
  readonly writeHook?: (fd: number, data: Uint8Array) => void;
}

export function isPosix(platform: NodeJS.Platform = process.platform): boolean {
  return platform !== "win32";
}

export function isErrnoCode(err: unknown, code: string): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "code" in err &&
    (err as { readonly code?: unknown }).code === code
  );
}

export function wrapIoError(err: unknown, context: string): FileManagerError {
  if (err instanceof FileManagerError) {
    return err;
  }
  if (isErrnoCode(err, "ENOENT")) {
    return new FileManagerError("not_found", `${context}: path does not exist`);
  }
  if (isErrnoCode(err, "ELOOP")) {
    return new FileManagerError("symlink_forbidden", `${context}: symbolic link is not allowed`);
  }
  if (isErrnoCode(err, "EEXIST")) {
    return new FileManagerError("already_exists", `${context}: target already exists`);
  }
  if (isErrnoCode(err, "ENOTDIR")) {
    return new FileManagerError("not_a_directory", `${context}: path component is not a directory`);
  }
  if (isErrnoCode(err, "EISDIR")) {
    return new FileManagerError("is_a_directory", `${context}: path is a directory`);
  }
  const message = err instanceof Error ? err.message : String(err);
  return new FileManagerError("io_error", `${context}: ${message}`);
}

function hasUnsafeChars(value: string): boolean {
  return UNSAFE_UNICODE_CHAR_REGEX.test(value);
}

function assertNormalizedAndSafeChars(value: string, label: string): void {
  if (hasUnsafeChars(value)) {
    throw new FileManagerError(
      "invalid_path",
      `${label} contains control, NUL, or invisible format characters`,
    );
  }
  const normalized = value.normalize("NFC");
  if (normalized !== value || hasUnsafeChars(normalized)) {
    throw new FileManagerError("invalid_path", `${label} must be NFC-normalized Unicode`);
  }
  if (value.includes("\\")) {
    throw new FileManagerError("path_traversal", `${label} must not contain backslashes`);
  }
}

export function isSameOrSubpath(parentRel: string, candidateRel: string): boolean {
  const caseInsensitive = process.platform === "win32" || process.platform === "darwin";
  const parent = caseInsensitive ? parentRel.toLowerCase() : parentRel;
  const candidate = caseInsensitive ? candidateRel.toLowerCase() : candidateRel;
  return candidate === parent || candidate.startsWith(`${parent}/`);
}

export function validateServerId(serverId: string): string {
  if (
    typeof serverId !== "string" ||
    !SERVER_ID_PATTERN.test(serverId) ||
    FORBIDDEN_COMPONENT_NAMES.has(serverId.toLowerCase())
  ) {
    throw new FileManagerError("invalid_server_id", "Invalid server_id");
  }
  return serverId;
}

function validateSegment(segment: string): void {
  if (segment.length === 0) {
    throw new FileManagerError("invalid_path", "Path must not contain empty segments");
  }
  if (segment === "." || segment === "..") {
    throw new FileManagerError("path_traversal", `Forbidden path segment "${segment}"`);
  }
  const lower = segment.toLowerCase();
  if (FORBIDDEN_COMPONENT_NAMES.has(lower) || lower.startsWith(UPLOAD_STAGING_FILE_PREFIX)) {
    throw new FileManagerError("path_traversal", `Access to "${segment}" is forbidden`);
  }
  if (WINDOWS_DRIVE_PREFIX_REGEX.test(segment)) {
    throw new FileManagerError("path_traversal", "Drive-prefixed path segments are forbidden");
  }
  if (segment.includes(":")) {
    throw new FileManagerError("invalid_path", "Path component must not contain ':'");
  }
  if (ENCODED_TRAVERSAL_REGEX.test(segment)) {
    throw new FileManagerError("path_traversal", "Encoded path separator or NUL is forbidden");
  }
  if (Buffer.byteLength(segment, "utf8") > MAX_COMPONENT_BYTES) {
    throw new FileManagerError(
      "invalid_path",
      `Path component exceeds ${MAX_COMPONENT_BYTES} bytes`,
    );
  }
  if (segment.endsWith(".") || segment.endsWith(" ")) {
    throw new FileManagerError("invalid_path", "Path component must not end with dot or space");
  }
  if (RESERVED_WINDOWS_NAME_REGEX.test(segment)) {
    throw new FileManagerError("invalid_path", `Reserved device name "${segment}" is forbidden`);
  }
}

export function validateSingleFileName(name: string): string {
  if (typeof name !== "string" || name.length === 0) {
    throw new FileManagerError("invalid_path", "File name must not be empty");
  }
  assertNormalizedAndSafeChars(name, "File name");
  if (name.includes("/") || WINDOWS_DRIVE_PREFIX_REGEX.test(name)) {
    throw new FileManagerError("path_traversal", "File name must be a single path component");
  }
  validateSegment(name);
  return name;
}

export function parseAndValidateRelativePath(
  relPath: string,
  allowRoot: boolean,
): readonly string[] {
  if (typeof relPath !== "string") {
    throw new FileManagerError("invalid_path", "Path must be a string");
  }
  assertNormalizedAndSafeChars(relPath, "Path");

  if (Buffer.byteLength(relPath, "utf8") > MAX_PATH_BYTES) {
    throw new FileManagerError("invalid_path", `Path exceeds maximum length of ${MAX_PATH_BYTES}`);
  }

  if (relPath === "" || relPath === ".") {
    if (!allowRoot) {
      throw new FileManagerError(
        "root_operation_forbidden",
        "Operation is not permitted on the server root",
      );
    }
    return [];
  }

  if (relPath.startsWith("/") || WINDOWS_DRIVE_PREFIX_REGEX.test(relPath)) {
    throw new FileManagerError("path_traversal", "Absolute paths are forbidden");
  }

  const segments = relPath.split("/");
  for (const segment of segments) {
    validateSegment(segment);
  }
  return segments;
}

function normalizeForPrefixComparison(p: string): string {
  return process.platform === "win32" ? p.toLowerCase() : p;
}

function isStrictlyInsideOrEqual(root: string, candidate: string, allowEqual: boolean): boolean {
  const normRoot = normalizeForPrefixComparison(root);
  const normCandidate = normalizeForPrefixComparison(candidate);
  if (allowEqual && normCandidate === normRoot) {
    return true;
  }
  const prefix = normRoot.endsWith(sep) ? normRoot : `${normRoot}${sep}`;
  return normCandidate.startsWith(prefix);
}

export function resolveServerRoot(
  serverId: string,
  serversBaseDir: string = DEFAULT_SERVERS_BASE_DIR,
): { readonly serverRoot: string; readonly realServerRoot: string } {
  validateServerId(serverId);
  const baseDir = resolve(serversBaseDir);
  const serverRoot = resolve(baseDir, serverId);

  if (!isStrictlyInsideOrEqual(baseDir, serverRoot, false)) {
    throw new FileManagerError("invalid_server_id", "Server root escaped base directory");
  }

  let rootStats: Stats;
  try {
    rootStats = lstatSync(serverRoot);
  } catch (err) {
    if (isErrnoCode(err, "ENOENT")) {
      throw new FileManagerError("server_not_found", `Server directory does not exist`);
    }
    throw wrapIoError(err, "Failed to inspect server root");
  }

  if (rootStats.isSymbolicLink()) {
    throw new FileManagerError("symlink_forbidden", "Server root must not be a symbolic link");
  }
  if (!rootStats.isDirectory()) {
    throw new FileManagerError("server_not_found", "Server root is not a directory");
  }

  let realServerRoot: string;
  try {
    realServerRoot = realpathSync(serverRoot);
  } catch (err) {
    throw wrapIoError(err, "Failed to resolve server root");
  }

  return { serverRoot, realServerRoot };
}

export function assertNoSymlinkSegments(
  serverRoot: string,
  realServerRoot: string,
  segments: readonly string[],
): void {
  let rootStats: Stats;
  try {
    rootStats = lstatSync(serverRoot);
  } catch (err) {
    if (isErrnoCode(err, "ENOENT")) {
      throw new FileManagerError("server_not_found", "Server directory does not exist");
    }
    throw wrapIoError(err, "Failed to inspect server root");
  }
  if (rootStats.isSymbolicLink()) {
    throw new FileManagerError("symlink_forbidden", "Server root must not be a symbolic link");
  }
  if (!rootStats.isDirectory()) {
    throw new FileManagerError("server_not_found", "Server root is not a directory");
  }

  let current = serverRoot;
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    if (seg === undefined) {
      continue;
    }
    current = join(current, seg);
    let stats: Stats;
    try {
      stats = lstatSync(current);
    } catch (err) {
      if (isErrnoCode(err, "ENOENT")) {
        break;
      }
      throw wrapIoError(err, "Failed to inspect path component");
    }

    if (stats.isSymbolicLink()) {
      throw new FileManagerError(
        "symlink_forbidden",
        `Symbolic link encountered at segment "${seg}"`,
      );
    }

    let realCurrent: string;
    try {
      realCurrent = realpathSync(current);
    } catch (err) {
      throw wrapIoError(err, "Failed to resolve real path");
    }

    if (!isStrictlyInsideOrEqual(realServerRoot, realCurrent, false)) {
      throw new FileManagerError("path_traversal", "Real path escaped server root");
    }

    if (i < segments.length - 1 && !stats.isDirectory()) {
      throw new FileManagerError(
        "not_a_directory",
        `Intermediate path component "${seg}" is not a directory`,
      );
    }
  }
}

export function resolveConfinedPath(options: ResolveConfinedPathOptions): ConfinedPath {
  const allowRoot = options.allowRoot ?? false;
  const serverId = validateServerId(options.serverId);
  const segments = parseAndValidateRelativePath(options.relPath, allowRoot);
  const { serverRoot, realServerRoot } = resolveServerRoot(
    serverId,
    options.serversBaseDir ?? DEFAULT_SERVERS_BASE_DIR,
  );

  assertNoSymlinkSegments(serverRoot, realServerRoot, segments);

  const fullPath = resolve(serverRoot, ...segments);
  if (!isStrictlyInsideOrEqual(serverRoot, fullPath, allowRoot)) {
    throw new FileManagerError("path_traversal", "Resolved path escaped server root");
  }

  return {
    serverId,
    serverRoot,
    realServerRoot,
    relativePath: segments.join("/"),
    segments,
    fullPath,
  };
}

export function assertNoSymlinkPath(resolved: ConfinedPath): void {
  assertNoSymlinkSegments(resolved.serverRoot, resolved.realServerRoot, resolved.segments);
}

export function ensureConfinedInternalDir(
  serverRoot: string,
  realServerRoot: string,
  dirName: string,
  mode: number = 0o700,
): string {
  const dirPath = join(serverRoot, dirName);
  let stats: Stats | undefined;
  try {
    stats = lstatSync(dirPath);
  } catch (err) {
    if (!isErrnoCode(err, "ENOENT")) {
      throw wrapIoError(err, "Failed to inspect internal directory");
    }
  }

  if (stats === undefined) {
    try {
      mkdirSync(dirPath, { mode });
    } catch (err) {
      if (!isErrnoCode(err, "EEXIST")) {
        throw wrapIoError(err, "Failed to create internal directory");
      }
    }
    try {
      stats = lstatSync(dirPath);
    } catch (err) {
      throw wrapIoError(err, "Failed to verify internal directory");
    }
  }

  if (stats.isSymbolicLink()) {
    throw new FileManagerError("symlink_forbidden", `Internal directory "${dirName}" is a symlink`);
  }
  if (!stats.isDirectory()) {
    throw new FileManagerError("not_a_directory", `Internal path "${dirName}" is not a directory`);
  }

  let realDir: string;
  try {
    realDir = realpathSync(dirPath);
  } catch (err) {
    throw wrapIoError(err, "Failed to resolve internal directory");
  }
  if (!isStrictlyInsideOrEqual(realServerRoot, realDir, false)) {
    throw new FileManagerError("path_traversal", "Internal directory escaped server root");
  }

  return dirPath;
}

export function assertConfinedInternalDir(
  serverRoot: string,
  realServerRoot: string,
  dirPath: string,
): void {
  let rootStats: Stats;
  try {
    rootStats = lstatSync(serverRoot);
  } catch (err) {
    throw wrapIoError(err, "Failed to inspect server root");
  }
  if (rootStats.isSymbolicLink()) {
    throw new FileManagerError("symlink_forbidden", "Server root must not be a symbolic link");
  }
  if (!rootStats.isDirectory()) {
    throw new FileManagerError("server_not_found", "Server root is not a directory");
  }

  let stats: Stats;
  try {
    stats = lstatSync(dirPath);
  } catch (err) {
    throw wrapIoError(err, "Failed to inspect internal directory");
  }
  if (stats.isSymbolicLink()) {
    throw new FileManagerError("symlink_forbidden", "Internal directory is a symbolic link");
  }
  if (!stats.isDirectory()) {
    throw new FileManagerError("not_a_directory", "Internal directory is not a directory");
  }

  let realDir: string;
  try {
    realDir = realpathSync(dirPath);
  } catch (err) {
    throw wrapIoError(err, "Failed to resolve internal directory");
  }
  if (!isStrictlyInsideOrEqual(realServerRoot, realDir, false)) {
    throw new FileManagerError("path_traversal", "Internal directory escaped server root");
  }
}

export function openConfinedFileForRead(resolved: ConfinedPath): {
  readonly fd: number;
  readonly stats: Stats;
} {
  if (resolved.segments.length === 0) {
    throw new FileManagerError("root_operation_forbidden", "Cannot open server root as a file");
  }
  assertNoSymlinkPath(resolved);

  let preStat: Stats;
  try {
    preStat = lstatSync(resolved.fullPath);
  } catch (err) {
    throw wrapIoError(err, "Failed to stat target file");
  }

  if (preStat.isSymbolicLink()) {
    throw new FileManagerError("symlink_forbidden", "Target file is a symbolic link");
  }
  if (preStat.isDirectory()) {
    throw new FileManagerError("is_a_directory", "Target path is a directory");
  }
  if (!preStat.isFile()) {
    throw new FileManagerError("not_a_file", "Target path is not a regular file");
  }

  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  const nonBlock = isPosix() ? (fsConstants.O_NONBLOCK ?? 0) : 0;
  let fd: number;
  try {
    fd = openSync(resolved.fullPath, fsConstants.O_RDONLY | noFollow | nonBlock);
  } catch (err) {
    throw wrapIoError(err, "Failed to open target file");
  }

  try {
    const fdStat = fstatSync(fd);
    if (!fdStat.isFile()) {
      throw new FileManagerError("not_a_file", "Opened descriptor is not a regular file");
    }
    if (preStat.dev !== fdStat.dev || preStat.ino !== fdStat.ino) {
      throw new FileManagerError("toctou_detected", "File identity changed between lstat and open");
    }
    return { fd, stats: fdStat };
  } catch (err) {
    try {
      closeSync(fd);
    } catch {
      // ignore close error on failure path
    }
    throw wrapIoError(err, "Failed to validate opened file");
  }
}

export function mkdirConfined(options: {
  readonly serversBaseDir?: string;
  readonly serverId: string;
  readonly relPath: string;
  readonly mode?: number;
}): ConfinedPath {
  const mode = options.mode ?? DEFAULT_DIR_MODE;
  const resolved = resolveConfinedPath({
    ...(options.serversBaseDir !== undefined ? { serversBaseDir: options.serversBaseDir } : {}),
    serverId: options.serverId,
    relPath: options.relPath,
    allowRoot: false,
  });

  let current = resolved.serverRoot;
  for (const seg of resolved.segments) {
    current = join(current, seg);
    let stats: Stats | undefined;
    try {
      stats = lstatSync(current);
    } catch (err) {
      if (!isErrnoCode(err, "ENOENT")) {
        throw wrapIoError(err, "Failed to inspect directory component");
      }
    }

    if (stats === undefined) {
      try {
        mkdirSync(current, { mode });
      } catch (err) {
        if (!isErrnoCode(err, "EEXIST")) {
          throw wrapIoError(err, "Failed to create directory");
        }
      }
      try {
        stats = lstatSync(current);
      } catch (err) {
        throw wrapIoError(err, "Failed to verify created directory");
      }
    }

    if (stats.isSymbolicLink()) {
      throw new FileManagerError(
        "symlink_forbidden",
        `Symbolic link encountered at segment "${seg}"`,
      );
    }
    if (!stats.isDirectory()) {
      throw new FileManagerError("not_a_directory", `Path component "${seg}" is not a directory`);
    }

    let realCurrent: string;
    try {
      realCurrent = realpathSync(current);
    } catch (err) {
      throw wrapIoError(err, "Failed to resolve directory path");
    }
    if (!isStrictlyInsideOrEqual(resolved.realServerRoot, realCurrent, false)) {
      throw new FileManagerError("path_traversal", "Directory escaped server root");
    }
  }

  return resolved;
}

function writeAllBytes(fd: number, data: Uint8Array): void {
  let offset = 0;
  while (offset < data.byteLength) {
    const written = writeSync(fd, data, offset, data.byteLength - offset);
    if (written <= 0) {
      throw new FileManagerError("io_error", "Short write while persisting file");
    }
    offset += written;
  }
}

export function writeConfinedFileAtomic(
  resolved: ConfinedPath,
  data: Uint8Array,
  options: AtomicWriteOptions = {},
): void {
  if (resolved.segments.length === 0) {
    throw new FileManagerError("root_operation_forbidden", "Cannot write directly to server root");
  }

  const mode = options.mode ?? DEFAULT_FILE_MODE;
  const parentSegments = resolved.segments.slice(0, -1);

  if (options.createParents && parentSegments.length > 0) {
    mkdirConfined({
      serversBaseDir: dirname(resolved.serverRoot),
      serverId: resolved.serverId,
      relPath: parentSegments.join("/"),
    });
  }

  assertNoSymlinkPath(resolved);

  const parentDir = dirname(resolved.fullPath);
  let parentStats: Stats;
  try {
    parentStats = lstatSync(parentDir);
  } catch (err) {
    throw wrapIoError(err, "Parent directory does not exist");
  }
  if (parentStats.isSymbolicLink()) {
    throw new FileManagerError("symlink_forbidden", "Parent directory must not be a symbolic link");
  }
  if (!parentStats.isDirectory()) {
    throw new FileManagerError("not_a_directory", "Parent path is not a directory");
  }

  let existingTarget: Stats | undefined;
  try {
    existingTarget = lstatSync(resolved.fullPath);
  } catch (err) {
    if (!isErrnoCode(err, "ENOENT")) {
      throw wrapIoError(err, "Failed to inspect target path");
    }
  }
  if (existingTarget !== undefined) {
    if (existingTarget.isSymbolicLink()) {
      throw new FileManagerError("symlink_forbidden", "Refusing to overwrite symbolic link");
    }
    if (existingTarget.isDirectory()) {
      throw new FileManagerError("is_a_directory", "Refusing to overwrite directory with file");
    }
    if (!existingTarget.isFile()) {
      throw new FileManagerError("not_a_file", "Refusing to overwrite non-regular file");
    }
  }

  const suffix = randomBytes(8).toString("hex");
  const tmpPath = join(parentDir, `.tmp-${basename(resolved.fullPath)}-${process.pid}-${suffix}`);
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  const flags = fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | noFollow;

  let fd: number | undefined;
  let renamed = false;

  try {
    fd = openSync(tmpPath, flags, mode);
    if (options.writeHook !== undefined) {
      options.writeHook(fd, data);
    } else {
      writeAllBytes(fd, data);
    }
    fsyncSync(fd);
    if (isPosix()) {
      fchmodSync(fd, mode);
    }
    closeSync(fd);
    fd = undefined;

    // Re-validate full path right before atomic rename to mitigate TOCTOU.
    assertNoSymlinkPath(resolved);
    let preRenameTarget: Stats | undefined;
    try {
      preRenameTarget = lstatSync(resolved.fullPath);
    } catch (err) {
      if (!isErrnoCode(err, "ENOENT")) {
        throw wrapIoError(err, "Failed to re-validate target before rename");
      }
    }
    if (preRenameTarget !== undefined) {
      if (preRenameTarget.isSymbolicLink()) {
        throw new FileManagerError("symlink_forbidden", "Target became a symbolic link");
      }
      if (preRenameTarget.isDirectory()) {
        throw new FileManagerError("is_a_directory", "Target became a directory");
      }
      if (!preRenameTarget.isFile()) {
        throw new FileManagerError("not_a_file", "Target became a non-regular file");
      }
    }

    renameSync(tmpPath, resolved.fullPath);
    renamed = true;
  } catch (err) {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        // ignore cleanup close error
      }
    }
    if (!renamed) {
      try {
        unlinkSync(tmpPath);
      } catch {
        // ignore cleanup unlink error
      }
    }
    throw wrapIoError(err, "Failed to write file atomically");
  }
}
