// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readdirSync,
  type Stats,
} from "node:fs";
import { isAbsolute, join, relative, sep } from "node:path";

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

/**
 * An open folder that every child operation goes through. On Linux the folder is held
 * by a descriptor and children are reached as `/proc/self/fd/N/name`, so swapping the
 * folder (or any folder above it) for a symbolic link after it was opened has no
 * effect. Elsewhere it falls back to plain paths, which is enough for development.
 *
 * `child(name)` is safe to hand to calls that never follow the last component
 * (`lstat`, `unlink`, `rmdir`, `mkdir`, `rename`, and `open` with `O_NOFOLLOW`). Never
 * hand it to `readdir` or other calls that follow it: open the child with
 * `openDir` instead.
 */
export interface DirHandle {
  /** Display path for logs and errors; never used to reach the folder on Linux. */
  readonly path: string;
  child(name: string): string;
  list(): string[];
  lstatChild(name: string): Stats | undefined;
  /** Opens a child folder, refusing a symbolic link (`ELOOP`/`ENOTDIR`). */
  openDir(name: string): DirHandle;
  /** Opens a child file; `O_NOFOLLOW` is always added. */
  openFile(name: string, flags: number, mode?: number): number;
  stat(): Stats;
  close(): void;
}

class FdDirHandle implements DirHandle {
  readonly path: string;
  readonly #fd: number;
  #closed = false;

  constructor(path: string, fd: number) {
    this.path = path;
    this.#fd = fd;
  }

  child(name: string): string {
    return fdPath(this.#fd, name);
  }

  list(): string[] {
    return readdirSync(fdPath(this.#fd));
  }

  lstatChild(name: string): Stats | undefined {
    return lstatSync(fdPath(this.#fd, name), { throwIfNoEntry: false });
  }

  openDir(name: string): DirHandle {
    return new FdDirHandle(join(this.path, name), openSync(fdPath(this.#fd, name), DIR_FLAGS));
  }

  openFile(name: string, flags: number, mode?: number): number {
    return openSync(fdPath(this.#fd, name), flags | O_NOFOLLOW, mode);
  }

  stat(): Stats {
    return fstatSync(this.#fd);
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    closeSync(this.#fd);
  }
}

class PathDirHandle implements DirHandle {
  readonly path: string;

  constructor(path: string) {
    this.path = path;
  }

  child(name: string): string {
    return join(this.path, name);
  }

  list(): string[] {
    return readdirSync(this.path);
  }

  lstatChild(name: string): Stats | undefined {
    return lstatSync(join(this.path, name), { throwIfNoEntry: false });
  }

  openDir(name: string): DirHandle {
    return openPathDir(join(this.path, name));
  }

  openFile(name: string, flags: number, mode?: number): number {
    return openSync(join(this.path, name), flags | O_NOFOLLOW, mode);
  }

  stat(): Stats {
    return lstatSync(this.path);
  }

  close(): void {}
}

function openPathDir(path: string): DirHandle {
  const st = lstatSync(path);
  if (st.isSymbolicLink()) {
    throw Object.assign(new Error(`ELOOP: symbolic link, open '${path}'`), { code: "ELOOP" });
  }
  if (!st.isDirectory()) {
    throw Object.assign(new Error(`ENOTDIR: not a directory, open '${path}'`), {
      code: "ENOTDIR",
    });
  }
  return new PathDirHandle(path);
}

/** Opens the folder `target` under `root` with no symbolic link followed below `root`. */
export function openDirBeneath(root: string, target: string): DirHandle {
  if (!procFdPathSupported()) {
    return openPathDir(target);
  }
  return new FdDirHandle(target, openBeneath(root, target, DIR_FLAGS));
}

export function withDirBeneath<T>(root: string, target: string, fn: (dir: DirHandle) => T): T {
  const dir = openDirBeneath(root, target);
  try {
    return fn(dir);
  } finally {
    dir.close();
  }
}
