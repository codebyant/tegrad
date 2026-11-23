// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { chmodSync, chownSync, existsSync, lstatSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

/** Group that the Minecraft server processes run as. The agent is a member, not the owner. */
export const SERVER_GROUP_NAME = "tegrad-srv";
export const DEFAULT_GROUP_FILE = "/etc/group";

/** Server data: the server user reads and writes it, and new files inherit the group (setgid). */
export const SERVER_DIR_MODE = 0o2770;
export const SERVER_FILE_MODE = 0o660;
export const SERVER_EXEC_MODE = 0o770;
/** Shared runtimes (Java): the server user may read and execute, never write. */
export const SHARED_DIR_MODE = 0o2750;
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

function isPosix(platform: NodeJS.Platform = process.platform): boolean {
  return platform !== "win32";
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

export interface PermissionContext {
  /** Group to hand files to, or null to leave the group alone (development machines). */
  readonly gid: number | null;
  readonly platform?: NodeJS.Platform;
  /** Called when the group cannot be changed (e.g. the agent is not a member). */
  readonly onChownError?: (path: string, err: unknown) => void;
}

function setGroup(path: string, ctx: PermissionContext): void {
  if (ctx.gid === null) {
    return;
  }
  try {
    chownSync(path, -1, ctx.gid);
  } catch (err) {
    ctx.onChownError?.(path, err);
  }
}

/** Sets group and mode of one directory; the explicit chmod keeps the setgid bit. */
export function secureDirectory(dirPath: string, mode: number, ctx: PermissionContext): void {
  if (!isPosix(ctx.platform)) {
    return;
  }
  setGroup(dirPath, ctx);
  chmodSync(dirPath, mode);
}

/**
 * Walks a tree and applies the plan: group, directory mode (with setgid) and file
 * mode. A file that is already executable by its owner stays executable by the
 * group (start.sh, the Java launcher). Symbolic links are never followed or changed.
 */
export function secureTree(root: string, plan: TreePermissionPlan, ctx: PermissionContext): void {
  if (!isPosix(ctx.platform)) {
    return;
  }
  secureDirectory(root, plan.dirMode, ctx);
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const fullPath = join(root, entry.name);
    if (entry.isSymbolicLink()) {
      continue;
    }
    if (entry.isDirectory()) {
      secureTree(fullPath, plan, ctx);
    } else if (entry.isFile()) {
      setGroup(fullPath, ctx);
      const executable = (lstatSync(fullPath).mode & 0o100) !== 0;
      chmodSync(fullPath, executable ? plan.execMode : plan.fileMode);
    }
  }
}

export interface PermissionProblem {
  readonly path: string;
  readonly problem: string;
}

/**
 * Read-only check of a tree against the plan, for `tegrad doctor`. Reports what is
 * not owned by the expected group or whose mode is looser or tighter than needed.
 */
export function inspectTree(
  root: string,
  _plan: TreePermissionPlan,
  gid: number | null,
  limit = 20,
): PermissionProblem[] {
  const problems: PermissionProblem[] = [];
  if (!existsSync(root)) {
    return problems;
  }

  function visit(path: string, isDir: boolean): void {
    if (problems.length >= limit) {
      return;
    }
    const stat = lstatSync(path);
    const mode = stat.mode & 0o7777;
    if (gid !== null && stat.gid !== gid) {
      problems.push({ path, problem: `group is ${stat.gid}, expected ${gid}` });
      return;
    }
    if (isDir) {
      if ((mode & 0o2000) === 0) {
        problems.push({ path, problem: "missing the setgid bit" });
      }
      if ((mode & 0o050) !== 0o050) {
        problems.push({ path, problem: `group cannot enter it (mode ${mode.toString(8)})` });
      }
    } else {
      const needed = (mode & 0o100) !== 0 ? 0o050 : 0o040;
      if ((mode & needed) !== needed) {
        problems.push({ path, problem: `group access missing (mode ${mode.toString(8)})` });
      }
    }
    if ((mode & 0o007) !== 0) {
      problems.push({ path, problem: "readable or writable by others" });
    }
  }

  function walk(dir: string): void {
    visit(dir, true);
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (problems.length >= limit) {
        return;
      }
      const full = join(dir, entry.name);
      if (entry.isSymbolicLink()) {
        continue;
      }
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
