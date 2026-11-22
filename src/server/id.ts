// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { existsSync, lstatSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { ProtocolError, SERVER_ID_REGEX, serverIdSchema } from "../protocol";

export { SERVER_ID_REGEX, serverIdSchema };

export const DEFAULT_SERVERS_DIR = "/var/lib/tegrad-servers";
export const DEFAULT_RUN_DIR = "/run/tegrad-server";

export function assertValidServerId(id: string): string {
  const parsed = serverIdSchema.safeParse(id);
  if (!parsed.success) {
    throw new ProtocolError(
      "invalid_body",
      "Invalid server_id: must match ^[a-z0-9][a-z0-9-]{0,62}$",
    );
  }
  return parsed.data;
}

function findDeepestExistingAncestor(targetPath: string, stopAtRoot: string): string | null {
  let current = targetPath;
  while (true) {
    if (existsSync(current)) {
      return current;
    }
    if (current === stopAtRoot) {
      return null;
    }
    const parent = dirname(current);
    if (parent === current) {
      return null;
    }
    current = parent;
  }
}

function assertStrictlyInside(rootDir: string, candidatePath: string, label: string): void {
  const resolvedRoot = resolve(rootDir);
  const resolvedCandidate = resolve(candidatePath);
  const rel = relative(resolvedRoot, resolvedCandidate);

  if (rel.length === 0 || rel === "." || rel.startsWith("..") || isAbsolute(rel)) {
    throw new ProtocolError("invalid_body", `${label} escapes allowed directory`);
  }

  const candidateLstat = lstatSync(resolvedCandidate, { throwIfNoEntry: false });
  if (candidateLstat?.isSymbolicLink() && !existsSync(resolvedCandidate)) {
    throw new ProtocolError("invalid_body", `${label} dangling symlink is not allowed`);
  }

  if (existsSync(resolvedRoot)) {
    const realRoot = realpathSync(resolvedRoot);
    if (existsSync(resolvedCandidate)) {
      const realCandidate = realpathSync(resolvedCandidate);
      const realRel = relative(realRoot, realCandidate);
      if (
        realRel.length === 0 ||
        realRel === "." ||
        realRel.startsWith("..") ||
        isAbsolute(realRel)
      ) {
        throw new ProtocolError("invalid_body", `${label} symlink escapes allowed directory`);
      }
    } else {
      const ancestor = findDeepestExistingAncestor(resolvedCandidate, resolvedRoot);
      if (ancestor !== null && ancestor !== resolvedRoot) {
        const realAncestor = realpathSync(ancestor);
        const ancestorRel = relative(realRoot, realAncestor);
        if (
          ancestorRel.length === 0 ||
          ancestorRel === "." ||
          ancestorRel.startsWith("..") ||
          isAbsolute(ancestorRel)
        ) {
          throw new ProtocolError("invalid_body", `${label} symlink escapes allowed directory`);
        }
      }
    }
  }
}

export function resolveServerDir(serversDir: string, id: string): string {
  const validId = assertValidServerId(id);
  const root = resolve(serversDir);
  const target = resolve(root, validId);
  assertStrictlyInside(root, target, "Server directory");
  return target;
}

export function resolveServerSubpath(serverDir: string, relativePath: string): string {
  if (relativePath.length === 0 || relativePath.includes("\0")) {
    throw new ProtocolError("invalid_body", "Invalid server subpath");
  }
  if (isAbsolute(relativePath)) {
    throw new ProtocolError("invalid_body", "Server subpath must be relative");
  }
  const root = resolve(serverDir);
  const target = resolve(root, relativePath);
  assertStrictlyInside(root, target, "Server subpath");
  return target;
}

export function resolveFifoPath(runDir: string, id: string): string {
  const validId = assertValidServerId(id);
  const root = resolve(runDir);
  const target = resolve(root, `${validId}.stdin`);
  assertStrictlyInside(root, target, "Console FIFO path");
  return target;
}

export function formatServiceUnit(id: string): string {
  const validId = assertValidServerId(id);
  return `tegrad-server@${validId}.service`;
}

export function formatSocketUnit(id: string): string {
  const validId = assertValidServerId(id);
  return `tegrad-server@${validId}.socket`;
}
