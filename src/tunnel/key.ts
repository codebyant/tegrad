// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { existsSync, lstatSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { assertStrictPermissions, writeFileAtomic } from "../agent/state";
import { ProtocolError, playitSecretKeySchema } from "../protocol";

export const PLAYIT_KEY_FILENAME = "playit.key";

const SECRET_FILE_MODE = 0o600;
const STATE_DIR_MODE = 0o700;

export function getPlayitKeyPath(stateDir: string): string {
  return join(stateDir, PLAYIT_KEY_FILENAME);
}

/**
 * Validates and atomically stores the playit secret key at `<stateDir>/playit.key`
 * with strict 0600 permissions. The key is never logged.
 */
export function savePlayitSecretKey(stateDir: string, secretKey: string): string {
  const parsed = playitSecretKeySchema.safeParse(secretKey);
  if (!parsed.success) {
    throw new ProtocolError("invalid_body", "Invalid playit secret key format");
  }

  const keyPath = getPlayitKeyPath(stateDir);
  writeFileAtomic(keyPath, `${parsed.data}\n`, {
    mode: SECRET_FILE_MODE,
    dirMode: STATE_DIR_MODE,
  });
  return keyPath;
}

/**
 * Verifies `<stateDir>/playit.key` exists, is not a symlink, enforces 0600
 * permissions on POSIX, and contains a syntactically valid secret key.
 * Does not return the key contents.
 */
export function assertPlayitSecretKey(stateDir: string): string {
  const keyPath = getPlayitKeyPath(stateDir);
  if (!existsSync(keyPath)) {
    throw new ProtocolError("tunnel_not_configured", "Playit secret key is not configured");
  }

  const stat = lstatSync(keyPath);
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new ProtocolError("tunnel_failed", "Playit secret key path must be a regular file");
  }

  assertStrictPermissions(keyPath);

  let raw: string;
  try {
    raw = readFileSync(keyPath, "utf8");
  } catch (err) {
    throw new ProtocolError(
      "tunnel_failed",
      `Failed to read playit secret key: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  const parsed = playitSecretKeySchema.safeParse(raw);
  if (!parsed.success) {
    throw new ProtocolError("tunnel_failed", "Stored playit secret key is invalid");
  }

  return keyPath;
}

export function hasPlayitSecretKey(stateDir: string): boolean {
  try {
    assertPlayitSecretKey(stateDir);
    return true;
  } catch {
    return false;
  }
}
