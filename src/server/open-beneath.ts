// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { closeSync, constants as fsConstants, openSync } from "node:fs";
import { isAbsolute, relative, sep } from "node:path";

const O_NOFOLLOW = fsConstants.O_NOFOLLOW ?? 0;
const O_DIRECTORY = fsConstants.O_DIRECTORY ?? 0;
const DIR_FLAGS = fsConstants.O_RDONLY | O_DIRECTORY | O_NOFOLLOW;

/**
 * Server folders are writable by the Minecraft process, which runs untrusted mod code
 * and can swap any file or folder for a symbolic link at any moment. A plain
 * `lstat` then `open(path)` leaves a window where an intermediate folder becomes a
 * link to the agent's own state, so every path is resolved one component at a time
 * from directory descriptors instead.
 */
export function procFdPathSupported(platform: NodeJS.Platform = process.platform): boolean {
  return platform === "linux";
}

/** Path that the kernel resolves through an open descriptor, never through the folder names. */
export function fdPath(fd: number, name?: string): string {
  return name === undefined ? `/proc/self/fd/${fd}` : `/proc/self/fd/${fd}/${name}`;
}

/**
 * Opens `target`, which must live under `root`, without following a symbolic link at
 * any component below `root`. On Linux each folder is opened through the descriptor of
 * its parent (`/proc/self/fd/N/name`, the same guarantee as `openat2` with
 * `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`). Elsewhere, or when `target` is not under
 * `root`, only the last component is protected (`O_NOFOLLOW`).
 *
 * Throws the raw errno error (`ELOOP` or `ENOTDIR` when a link was met).
 */
export function openBeneath(root: string | undefined, target: string, flags: number): number {
  const rel = root === undefined ? undefined : relative(root, target);
  const beneath =
    rel !== undefined &&
    rel !== "" &&
    !rel.startsWith(`..${sep}`) &&
    rel !== ".." &&
    !isAbsolute(rel);
  if (!beneath || root === undefined || rel === undefined || !procFdPathSupported()) {
    return openSync(target, flags | O_NOFOLLOW);
  }

  const segments = rel.split(sep).filter((segment) => segment.length > 0);
  let dirFd = openSync(root, fsConstants.O_RDONLY | O_DIRECTORY);
  try {
    for (let i = 0; i < segments.length - 1; i++) {
      const next = openSync(fdPath(dirFd, segments[i]), DIR_FLAGS);
      closeSync(dirFd);
      dirFd = next;
    }
    const last = segments[segments.length - 1] ?? "";
    return openSync(fdPath(dirFd, last), flags | O_NOFOLLOW);
  } finally {
    closeSync(dirFd);
  }
}

/** True when an open failed because a symbolic link was in the way. */
export function isLinkRefusal(err: unknown): boolean {
  if (typeof err !== "object" || err === null || !("code" in err)) return false;
  const code = (err as { readonly code?: unknown }).code;
  return code === "ELOOP" || code === "ENOTDIR" || code === "EMLINK";
}
