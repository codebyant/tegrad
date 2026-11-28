// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { closeSync, lstatSync, openSync, renameSync, rmSync } from "node:fs";
import { join } from "node:path";
import { finalizeServerPath, type PermissionContext } from "./permissions";

export const CONSOLE_LOG_MODE = 0o660;

export interface EnsureConsoleLogOptions {
  /** Effective uid of the agent. Defaults to `process.getuid()` (absent on Windows). */
  readonly uid?: number | undefined;
  readonly now?: () => number;
}

/**
 * The unit writes the server console to `logs/console.log` with `StandardOutput=append:`.
 * systemd opens that file as root before dropping privileges, so when it does not exist yet
 * it is created `root:root` and the agent can no longer read it (backups and the live
 * console both read it). Creating the file up front, as the agent and with the server
 * group, keeps it readable: systemd then only appends to the existing file.
 */
export function ensureConsoleLog(
  serverDir: string,
  permissions: PermissionContext,
  options: EnsureConsoleLogOptions = {},
): void {
  const logPath = join(serverDir, "logs", "console.log");
  const uid = "uid" in options ? options.uid : currentUid();
  const now = options.now ?? Date.now;

  let stat: ReturnType<typeof lstatSync> | null;
  try {
    stat = lstatSync(logPath);
  } catch {
    stat = null;
  }

  if (stat !== null && !stat.isFile()) {
    // A link or anything else planted in the log folder is never followed.
    rmSync(logPath, { force: true, recursive: false });
    stat = null;
  }

  if (stat !== null && uid !== undefined && stat.uid !== uid) {
    // Left over from a start that created it as root: keep it aside and replace it.
    renameSync(logPath, join(serverDir, "logs", `console.${now()}.log`));
    stat = null;
  }

  if (stat === null) {
    const fd = openSync(logPath, "a", CONSOLE_LOG_MODE);
    closeSync(fd);
  }

  finalizeServerPath(logPath, CONSOLE_LOG_MODE, permissions);
}

function currentUid(): number | undefined {
  return typeof process.getuid === "function" ? process.getuid() : undefined;
}
