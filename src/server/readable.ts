// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { existsSync } from "node:fs";
import { runFixed } from "../agent/exec";
import type { Logger } from "../agent/logger";
import { ProtocolError } from "../protocol";
import { assertValidServerId, formatPermsUnit } from "./id";
import type { RunFixedLike } from "./java";

export const DEFAULT_PERMS_TIMEOUT_MS = 120_000;

export const DEFAULT_PERMS_UNIT_PATHS: readonly string[] = [
  "/etc/systemd/system/tegrad-perms@.service",
  "/lib/systemd/system/tegrad-perms@.service",
  "/usr/lib/systemd/system/tegrad-perms@.service",
];

export interface MakeServerReadableOptions {
  readonly runFixedImpl?: RunFixedLike;
  readonly logger?: Logger;
  readonly timeoutMs?: number;
  readonly platform?: NodeJS.Platform;
  readonly unitExists?: () => boolean;
}

export type MakeServerReadableLike = (
  serverId: string,
  options?: MakeServerReadableOptions,
) => Promise<boolean>;

const inFlightByServer = new Map<string, Promise<void>>();

function defaultPermsUnitExists(): boolean {
  return DEFAULT_PERMS_UNIT_PATHS.some((unitPath) => existsSync(unitPath));
}

function isUnitNotFoundFailure(code: number, stderr: string): boolean {
  if (code === 5) {
    return true;
  }
  const lower = stderr.toLowerCase();
  return (
    /unit\s+\S+\s+not found/.test(lower) ||
    lower.includes("could not be found") ||
    lower.includes("not-found") ||
    lower.includes("system has not been booted with systemd")
  );
}

function isEnoentError(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "code" in err &&
    (err as { readonly code?: unknown }).code === "ENOENT"
  );
}

async function runMakeServerReadableOnce(
  validId: string,
  options: MakeServerReadableOptions,
): Promise<boolean> {
  const permsUnit = formatPermsUnit(validId);

  if (options.runFixedImpl === undefined) {
    const platform = options.platform ?? process.platform;
    if (platform !== "linux") {
      options.logger?.warn("Skipping tegrad-perms unit on non-Linux host", {
        serverId: validId,
        unit: permsUnit,
        platform,
      });
      return false;
    }

    const checkUnitExists = options.unitExists ?? defaultPermsUnitExists;
    if (!checkUnitExists()) {
      options.logger?.warn(
        "tegrad-perms@.service unit is not installed; skipping permission sync",
        {
          serverId: validId,
          unit: permsUnit,
        },
      );
      return false;
    }
  }

  const runCmd: RunFixedLike = options.runFixedImpl ?? runFixed;
  const timeoutMs = options.timeoutMs ?? DEFAULT_PERMS_TIMEOUT_MS;

  let result: Awaited<ReturnType<RunFixedLike>>;
  try {
    result = await runCmd("systemctl", ["start", "--wait", permsUnit], { timeoutMs });
  } catch (err) {
    if (isEnoentError(err)) {
      options.logger?.warn("systemctl is unavailable; skipping permission sync", {
        serverId: validId,
        unit: permsUnit,
      });
      return false;
    }
    throw new ProtocolError(
      "perms_unavailable",
      `Failed to invoke ${permsUnit}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  if (result.timedOut) {
    throw new ProtocolError("perms_unavailable", `Timed out waiting for ${permsUnit}`);
  }

  if (result.code === 0) {
    return true;
  }

  if (isUnitNotFoundFailure(result.code, result.stderr)) {
    options.logger?.warn("tegrad-perms unit is not available; continuing without permission sync", {
      serverId: validId,
      unit: permsUnit,
      code: result.code,
    });
    return false;
  }

  const detail = result.stderr.trim();
  throw new ProtocolError(
    "perms_unavailable",
    detail.length > 0
      ? `Failed to run ${permsUnit} (exit ${result.code}): ${detail}`
      : `Failed to run ${permsUnit} (exit ${result.code})`,
  );
}

/**
 * Triggers the unprivileged `tegrad-perms@<id>.service` oneshot unit (running as
 * `tegrad-srv`) so files created with explicit mode 0600 by the JVM become
 * group-readable and group-writable by the `tegrad` agent.
 *
 * Calls for the same server are serialized; calls for different servers may run
 * concurrently. Returns `true` when the unit ran successfully and `false` when
 * degraded because the unit or systemd is unavailable (e.g. in development).
 */
export async function makeServerReadable(
  serverId: string,
  options: MakeServerReadableOptions = {},
): Promise<boolean> {
  const validId = assertValidServerId(serverId);
  const prev = inFlightByServer.get(validId) ?? Promise.resolve();

  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const nextTail = prev.then(() => gate);
  inFlightByServer.set(validId, nextTail);

  await prev;
  try {
    return await runMakeServerReadableOnce(validId, options);
  } finally {
    release();
    if (inFlightByServer.get(validId) === nextTail) {
      inFlightByServer.delete(validId);
    }
  }
}
