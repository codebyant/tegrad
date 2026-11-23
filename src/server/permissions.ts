// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { chmodSync, chownSync, existsSync, lstatSync, readdirSync, readFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { sanitizeErrorMessage } from "../agent/jobs";
import type { Logger } from "../agent/logger";

/** Group that the Minecraft server processes run as. The agent is a member, not the owner. */
export const SERVER_GROUP_NAME = "tegrad-srv";
export const DEFAULT_GROUP_FILE = "/etc/group";

/**
 * Server data: the server user reads and writes it.
 * Never include setgid/setuid bits here: tegrad.service runs with RestrictSUIDSGID=yes,
 * which makes chmod with 0o2000/0o4000 fail with EPERM.
 */
export const SERVER_DIR_MODE = 0o770;
export const SERVER_FILE_MODE = 0o660;
export const SERVER_EXEC_MODE = 0o770;
/** Shared runtimes (Java): the server user may read and execute, never write. */
export const SHARED_DIR_MODE = 0o750;
export const SHARED_FILE_MODE = 0o640;
export const SHARED_EXEC_MODE = 0o750;

export interface TreePermissionPlan {
  readonly dirMode: number;
  readonly fileMode: number;
  readonly execMode: number;
}

export const SERVER_TREE_PLAN: TreePermissionPlan = {
  dirMode: SERVER_DIR_MODE,
  fileMode: SERVER_FILE_MODE,
  execMode: SERVER_EXEC_MODE,
};

export const SHARED_TREE_PLAN: TreePermissionPlan = {
  dirMode: SHARED_DIR_MODE,
  fileMode: SHARED_FILE_MODE,
  execMode: SHARED_EXEC_MODE,
};

export interface PermissionStatLike {
  readonly mode: number;
  readonly uid: number;
  readonly gid: number;
  isSymbolicLink(): boolean;
  isDirectory(): boolean;
  isFile(): boolean;
}

export interface PermissionDirentLike {
  readonly name: string;
  isSymbolicLink(): boolean;
  isDirectory(): boolean;
  isFile(): boolean;
}

export interface PermissionFsOps {
  readonly lstatSync: (path: string) => PermissionStatLike;
  readonly chownSync: (path: string, uid: number, gid: number) => void;
  readonly chmodSync: (path: string, mode: number) => void;
  readonly readdirSync: (path: string) => readonly PermissionDirentLike[];
  readonly existsSync: (path: string) => boolean;
}

const DEFAULT_FS_OPS: PermissionFsOps = {
  lstatSync: (p) => lstatSync(p),
  chownSync: (p, uid, gid) => chownSync(p, uid, gid),
  chmodSync: (p, mode) => chmodSync(p, mode),
  readdirSync: (p) => readdirSync(p, { withFileTypes: true }),
  existsSync: (p) => existsSync(p),
};

function resolveFsOps(overrides?: Partial<PermissionFsOps>): PermissionFsOps {
  if (overrides === undefined) {
    return DEFAULT_FS_OPS;
  }
  return {
    lstatSync: overrides.lstatSync ?? DEFAULT_FS_OPS.lstatSync,
    chownSync: overrides.chownSync ?? DEFAULT_FS_OPS.chownSync,
    chmodSync: overrides.chmodSync ?? DEFAULT_FS_OPS.chmodSync,
    readdirSync: overrides.readdirSync ?? DEFAULT_FS_OPS.readdirSync,
    existsSync: overrides.existsSync ?? DEFAULT_FS_OPS.existsSync,
  };
}

function isPosix(platform: NodeJS.Platform = process.platform): boolean {
  return platform !== "win32";
}

function extractErrorCode(err: unknown): string {
  if (typeof err === "object" && err !== null && "code" in err) {
    const code = (err as { readonly code?: unknown }).code;
    if (typeof code === "string" && code.length > 0) {
      return code;
    }
  }
  if (err instanceof Error && err.name.length > 0) {
    return err.name;
  }
  return "UNKNOWN";
}

function extractErrno(err: unknown): number | undefined {
  if (typeof err === "object" && err !== null && "errno" in err) {
    const errno = (err as { readonly errno?: unknown }).errno;
    if (typeof errno === "number" && Number.isInteger(errno)) {
      return errno;
    }
  }
  return undefined;
}

function buildFailure(path: string, op: PermissionFailure["op"], err: unknown): PermissionFailure {
  const errno = extractErrno(err);
  return {
    path,
    op,
    code: extractErrorCode(err),
    ...(errno !== undefined ? { errno } : {}),
    message: sanitizeErrorMessage(err),
  };
}

/** Looks a group up in /etc/group. Returns null when the file or the group is missing. */
export function resolveGroupId(
  name: string = SERVER_GROUP_NAME,
  groupFile: string = DEFAULT_GROUP_FILE,
): number | null {
  let content: string;
  try {
    content = readFileSync(groupFile, "utf8");
  } catch {
    return null;
  }
  for (const line of content.split("\n")) {
    const parts = line.split(":");
    if (parts[0] === name && parts[2] !== undefined) {
      const gid = Number(parts[2]);
      return Number.isInteger(gid) && gid >= 0 ? gid : null;
    }
  }
  return null;
}

export interface PermissionFailure {
  readonly path: string;
  readonly op: "lstat" | "chown" | "chmod" | "readdir";
  readonly code: string;
  readonly errno?: number;
  readonly message: string;
}

export interface PermissionContext {
  /** Group to hand files to, or null to leave the group alone (development machines). */
  readonly gid: number | null;
  readonly platform?: NodeJS.Platform;
  /** Absolute path to the servers root (/var/lib/tegrad-servers). Never chmod/chown this directory. */
  readonly serversRoot?: string;
  /** Optional FS overrides for unit testing. */
  readonly fs?: Partial<PermissionFsOps>;
  /** Called when a permission operation fails on a path. */
  readonly onError?: (failure: PermissionFailure) => void;
  /** Legacy callback invoked when chown fails. */
  readonly onChownError?: (path: string, err: unknown) => void;
}

export interface CreateServerPermissionContextOptions {
  readonly serversRoot?: string;
  readonly serverGroupId?: number | null;
  readonly platform?: NodeJS.Platform;
  readonly logger?: Logger;
  readonly fs?: Partial<PermissionFsOps>;
}

/** Builds a standard PermissionContext that logs warnings with path and error code only. */
export function createServerPermissionContext(
  options: CreateServerPermissionContextOptions = {},
): PermissionContext {
  const gid = options.serverGroupId !== undefined ? options.serverGroupId : resolveGroupId();
  return {
    gid,
    ...(options.platform !== undefined ? { platform: options.platform } : {}),
    ...(options.serversRoot !== undefined ? { serversRoot: options.serversRoot } : {}),
    ...(options.fs !== undefined ? { fs: options.fs } : {}),
    onError: (failure) => {
      options.logger?.warn("Could not adjust server path permissions", {
        path: failure.path,
        op: failure.op,
        code: failure.code,
        ...(failure.errno !== undefined ? { errno: failure.errno } : {}),
        message: failure.message,
      });
    },
  };
}

function reportFailure(ctx: PermissionContext, failure: PermissionFailure, err: unknown): void {
  ctx.onError?.(failure);
  if (failure.op === "chown") {
    ctx.onChownError?.(failure.path, err);
  }
}

function isServersRoot(targetPath: string, ctx: PermissionContext): boolean {
  if (ctx.serversRoot === undefined) {
    return false;
  }
  return resolve(targetPath) === resolve(ctx.serversRoot);
}

/**
 * Single helper to finalize a path created or written by the agent:
 * - Never touches the servers root directory itself (owned by the installer).
 * - Never follows or modifies symbolic links.
 * - Explicitly sets the server group via chown(stat.uid, gid) when the group differs
 *   (passing the real uid avoids EINVAL on Bun 1.3.12 where uid -1 is rejected).
 * - Strips any SUID/SGID/sticky bits and only calls chmod when the lower 9 bits
 *   actually differ, avoiding EPERM under RestrictSUIDSGID=yes and preserving any
 *   inherited setgid bit when the mode already matches.
 * - Never throws on chown/chmod/lstat errors; returns collected failures instead.
 */
export function finalizeServerPath(
  targetPath: string,
  mode: number,
  ctx: PermissionContext,
): PermissionFailure[] {
  if (!isPosix(ctx.platform)) {
    return [];
  }
  if (isServersRoot(targetPath, ctx)) {
    return [];
  }

  const fsOps = resolveFsOps(ctx.fs);
  const desiredMode = mode & 0o777;
  const failures: PermissionFailure[] = [];

  let stat: PermissionStatLike;
  try {
    stat = fsOps.lstatSync(targetPath);
  } catch (err) {
    const failure = buildFailure(targetPath, "lstat", err);
    reportFailure(ctx, failure, err);
    return [failure];
  }

  if (stat.isSymbolicLink()) {
    return [];
  }

  if (ctx.gid !== null && stat.gid !== ctx.gid) {
    try {
      fsOps.chownSync(targetPath, stat.uid, ctx.gid);
    } catch (err) {
      const failure = buildFailure(targetPath, "chown", err);
      failures.push(failure);
      reportFailure(ctx, failure, err);
    }
  }

  if ((stat.mode & 0o777) !== desiredMode) {
    try {
      fsOps.chmodSync(targetPath, desiredMode);
    } catch (err) {
      const failure = buildFailure(targetPath, "chmod", err);
      failures.push(failure);
      reportFailure(ctx, failure, err);
    }
  }

  return failures;
}

/** Finalizes group and mode of one directory via finalizeServerPath. */
export function secureDirectory(
  dirPath: string,
  mode: number,
  ctx: PermissionContext,
): PermissionFailure[] {
  return finalizeServerPath(dirPath, mode, ctx);
}

/**
 * Walks a tree and applies the plan via finalizeServerPath: group, directory mode
 * (without setgid) and file mode. A file that is already executable by its owner
 * stays executable by the group (start.sh, the Java launcher). Symbolic links are
 * never followed or changed. A failure on one path never aborts the rest of the walk.
 */
export function secureTree(
  root: string,
  plan: TreePermissionPlan,
  ctx: PermissionContext,
): PermissionFailure[] {
  if (!isPosix(ctx.platform)) {
    return [];
  }

  const fsOps = resolveFsOps(ctx.fs);
  const failures: PermissionFailure[] = [];

  function walk(dir: string): void {
    failures.push(...finalizeServerPath(dir, plan.dirMode, ctx));

    let entries: readonly PermissionDirentLike[];
    try {
      entries = fsOps.readdirSync(dir);
    } catch (err) {
      const failure = buildFailure(dir, "readdir", err);
      failures.push(failure);
      reportFailure(ctx, failure, err);
      return;
    }

    for (const entry of entries) {
      if (entry.isSymbolicLink()) {
        continue;
      }
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        let stat: PermissionStatLike;
        try {
          stat = fsOps.lstatSync(fullPath);
        } catch (err) {
          const failure = buildFailure(fullPath, "lstat", err);
          failures.push(failure);
          reportFailure(ctx, failure, err);
          continue;
        }
        const executable = (stat.mode & 0o100) !== 0;
        failures.push(
          ...finalizeServerPath(fullPath, executable ? plan.execMode : plan.fileMode, ctx),
        );
      }
    }
  }

  walk(root);
  return failures;
}

export interface EssentialPathCheck {
  readonly path: string;
  readonly executable?: boolean;
}

/**
 * Verifies that essential server paths (such as start.sh, server.jar, java) belong to
 * the expected server group and have the required group access bits. Throws a clear
 * error if any essential path cannot be used by the server user.
 */
export function assertServerPathsUsable(
  checks: readonly EssentialPathCheck[],
  ctx: PermissionContext,
): void {
  if (!isPosix(ctx.platform) || ctx.gid === null) {
    return;
  }

  const fsOps = resolveFsOps(ctx.fs);
  const issues: string[] = [];

  for (const check of checks) {
    let stat: PermissionStatLike;
    try {
      stat = fsOps.lstatSync(check.path);
    } catch (err) {
      issues.push(`${check.path} (unreadable: ${extractErrorCode(err)})`);
      continue;
    }
    if (stat.gid !== ctx.gid) {
      issues.push(
        `${check.path} (group is ${stat.gid}, expected '${SERVER_GROUP_NAME}' gid ${ctx.gid})`,
      );
      continue;
    }
    const mode = stat.mode & 0o777;
    const needed = check.executable ? 0o050 : 0o040;
    if ((mode & needed) !== needed) {
      issues.push(
        `${check.path} (mode ${mode.toString(8).padStart(3, "0")} lacks required group ${check.executable ? "read+exec" : "read"} permission)`,
      );
    }
  }

  if (issues.length > 0) {
    throw new Error(
      `Server files are not accessible to group '${SERVER_GROUP_NAME}': ${issues.join("; ")}`,
    );
  }
}

export interface PermissionProblem {
  readonly path: string;
  readonly problem: string;
}

/**
 * Read-only check of the servers root directory (/var/lib/tegrad-servers) for `tegrad doctor`.
 * The root directory is owned by the installer and must carry the setgid bit so new
 * subdirectories inherit the server group.
 */
export function inspectServersRoot(
  serversDir: string,
  gid: number | null,
  fsOverrides?: Partial<PermissionFsOps>,
): PermissionProblem[] {
  const fsOps = resolveFsOps(fsOverrides);
  const problems: PermissionProblem[] = [];
  if (!fsOps.existsSync(serversDir)) {
    return problems;
  }

  const stat = fsOps.lstatSync(serversDir);
  const mode = stat.mode & 0o7777;

  if (gid !== null && stat.gid !== gid) {
    problems.push({ path: serversDir, problem: `group is ${stat.gid}, expected ${gid}` });
    return problems;
  }
  if ((mode & 0o2000) === 0) {
    problems.push({ path: serversDir, problem: "missing the setgid bit" });
  }
  if ((mode & 0o070) !== 0o070) {
    problems.push({
      path: serversDir,
      problem: `group lacks rwx access (mode ${mode.toString(8)})`,
    });
  }
  if ((mode & 0o007) !== 0) {
    problems.push({ path: serversDir, problem: "readable or writable by others" });
  }
  return problems;
}

/**
 * Read-only check of a tree against the plan, for `tegrad doctor`.
 * Does NOT require setgid on server subdirectories (only the root carries setgid).
 * Checks: expected group, required group access bits from the plan (including group
 * execute for start.sh, java, and owner-executable files), and no access for others.
 */
export function inspectTree(
  root: string,
  plan: TreePermissionPlan,
  gid: number | null,
  limit = 20,
  fsOverrides?: Partial<PermissionFsOps>,
): PermissionProblem[] {
  const fsOps = resolveFsOps(fsOverrides);
  const problems: PermissionProblem[] = [];
  if (!fsOps.existsSync(root)) {
    return problems;
  }

  const requiredDirGroupBits = plan.dirMode & 0o070;
  const requiredFileGroupBits = plan.fileMode & 0o070;
  const requiredExecGroupBits = plan.execMode & 0o070;

  function visit(path: string, isDir: boolean): void {
    if (problems.length >= limit) {
      return;
    }
    const stat = fsOps.lstatSync(path);
    const mode = stat.mode & 0o7777;
    if (gid !== null && stat.gid !== gid) {
      problems.push({ path, problem: `group is ${stat.gid}, expected ${gid}` });
      return;
    }
    if (isDir) {
      if ((mode & requiredDirGroupBits) !== requiredDirGroupBits) {
        problems.push({
          path,
          problem: `group access missing (mode ${mode.toString(8)})`,
        });
      }
    } else {
      const name = basename(path);
      const needsExec = (mode & 0o100) !== 0 || name === "start.sh" || name === "java";
      const needed = needsExec ? requiredExecGroupBits : requiredFileGroupBits;
      if ((mode & needed) !== needed) {
        problems.push({
          path,
          problem: needsExec
            ? `group execute/read access missing (mode ${mode.toString(8)})`
            : `group access missing (mode ${mode.toString(8)})`,
        });
      }
    }
    if ((mode & 0o007) !== 0) {
      problems.push({ path, problem: "readable or writable by others" });
    }
  }

  function walk(dir: string): void {
    visit(dir, true);
    for (const entry of fsOps.readdirSync(dir)) {
      if (problems.length >= limit) {
        return;
      }
      if (entry.isSymbolicLink()) {
        continue;
      }
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile()) {
        visit(full, false);
      }
    }
  }

  walk(root);
  return problems;
}
