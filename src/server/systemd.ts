// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { runFixed } from "../agent/exec";
import type { Logger } from "../agent/logger";
import { ProtocolError } from "../protocol";
import { type FifoWriter, sendConsoleLine } from "./console";
import { assertValidServerId, DEFAULT_RUN_DIR, formatServiceUnit, formatSocketUnit } from "./id";
import type { RunFixedLike } from "./java";

export const DEFAULT_STOP_POLL_INTERVAL_MS = 500;
export const DEFAULT_STOP_TIMEOUT_MS = 60_000;
export const MEMORY_MAX_MULTIPLIER = 1.25;

export interface SystemdUnitStatus {
  readonly activeState: string;
  readonly subState: string;
  readonly mainPid: number;
  readonly memoryCurrentBytes: number | null;
}

export function computeMemoryMaxMb(memoryMb: number): number {
  return Math.ceil(memoryMb * MEMORY_MAX_MULTIPLIER);
}

export function parseSystemdShowOutput(stdout: string): SystemdUnitStatus {
  let activeState = "unknown";
  let subState = "unknown";
  let mainPid = 0;
  let memoryCurrentBytes: number | null = null;

  for (const rawLine of stdout.split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (trimmed.length === 0) {
      continue;
    }
    const eqIndex = trimmed.indexOf("=");
    if (eqIndex === -1) {
      continue;
    }
    const key = trimmed.slice(0, eqIndex);
    const value = trimmed.slice(eqIndex + 1);

    if (key === "ActiveState") {
      activeState = value;
    } else if (key === "SubState") {
      subState = value;
    } else if (key === "MainPID") {
      const parsed = Number(value);
      mainPid = Number.isInteger(parsed) && parsed >= 0 ? parsed : 0;
    } else if (key === "MemoryCurrent") {
      if (value === "[not set]" || value === "infinity" || value === "18446744073709551615") {
        memoryCurrentBytes = null;
      } else {
        const parsed = Number(value);
        memoryCurrentBytes = Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
      }
    }
  }

  return {
    activeState,
    subState,
    mainPid,
    memoryCurrentBytes,
  };
}

export function isUnitActive(status: Pick<SystemdUnitStatus, "activeState">): boolean {
  return (
    status.activeState === "active" ||
    status.activeState === "activating" ||
    status.activeState === "reloading"
  );
}

export function isUnitStopped(status: SystemdUnitStatus): boolean {
  return status.activeState === "inactive" || status.activeState === "failed";
}

export async function getUnitStatus(
  serverId: string,
  runFixedImpl: RunFixedLike = runFixed,
): Promise<SystemdUnitStatus> {
  const validId = assertValidServerId(serverId);
  const serviceUnit = formatServiceUnit(validId);
  const result = await runFixedImpl("systemctl", [
    "show",
    "-p",
    "ActiveState,SubState,MainPID,MemoryCurrent",
    serviceUnit,
  ]);
  if (result.timedOut || result.code !== 0) {
    throw new ProtocolError(
      "systemd_error",
      `Failed to query systemd status for ${serviceUnit} (exit ${result.code})`,
    );
  }
  return parseSystemdShowOutput(result.stdout);
}

export interface StartServerUnitOptions {
  readonly runFixedImpl?: RunFixedLike;
  readonly logger?: Logger;
}

export async function startServerUnit(
  serverId: string,
  memoryMb: number,
  options: StartServerUnitOptions = {},
): Promise<void> {
  const validId = assertValidServerId(serverId);
  const serviceUnit = formatServiceUnit(validId);
  const runCmd: RunFixedLike = options.runFixedImpl ?? runFixed;

  const startResult = await runCmd("systemctl", ["start", serviceUnit]);
  if (startResult.timedOut || startResult.code !== 0) {
    throw new ProtocolError(
      "systemd_error",
      `Failed to start ${serviceUnit} (exit ${startResult.code})`,
    );
  }

  const maxMb = computeMemoryMaxMb(memoryMb);
  const propResult = await runCmd("systemctl", [
    "set-property",
    "--runtime",
    serviceUnit,
    `MemoryMax=${maxMb}M`,
  ]);

  if (propResult.timedOut || propResult.code !== 0) {
    const stderrLower = propResult.stderr.toLowerCase();
    const isPolkitDenied =
      stderrLower.includes("access denied") ||
      stderrLower.includes("interactive authentication required") ||
      stderrLower.includes("polkit");
    if (isPolkitDenied) {
      options.logger?.warn("systemctl set-property MemoryMax was denied by polkit", {
        serverId: validId,
        memoryMaxMb: maxMb,
      });
      return;
    }
    throw new ProtocolError(
      "systemd_error",
      `Failed to apply MemoryMax=${maxMb}M on ${serviceUnit} (exit ${propResult.code})`,
    );
  }
}

export interface StopServerUnitOptions {
  readonly runDir?: string;
  readonly runFixedImpl?: RunFixedLike;
  readonly writeFifoImpl?: FifoWriter;
  readonly pollIntervalMs?: number;
  readonly stopTimeoutMs?: number;
  readonly now?: () => number;
  readonly sleepImpl?: (ms: number) => Promise<void>;
}

async function defaultSleep(ms: number): Promise<void> {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });
}

export async function stopServerUnit(
  serverId: string,
  options: StopServerUnitOptions = {},
): Promise<SystemdUnitStatus> {
  const validId = assertValidServerId(serverId);
  const runDir = options.runDir ?? DEFAULT_RUN_DIR;
  const runCmd: RunFixedLike = options.runFixedImpl ?? runFixed;
  const pollIntervalMs = options.pollIntervalMs ?? DEFAULT_STOP_POLL_INTERVAL_MS;
  const stopTimeoutMs = options.stopTimeoutMs ?? DEFAULT_STOP_TIMEOUT_MS;
  const now = options.now ?? (() => Date.now());
  const sleep = options.sleepImpl ?? defaultSleep;

  const serviceUnit = formatServiceUnit(validId);
  const socketUnit = formatSocketUnit(validId);

  try {
    sendConsoleLine({
      runDir,
      serverId: validId,
      line: "stop",
      ...(options.writeFifoImpl !== undefined ? { writeFifoImpl: options.writeFifoImpl } : {}),
    });
  } catch (err) {
    // If FIFO has no reader or does not exist, proceed to status check and systemctl stop.
    if (!(err instanceof ProtocolError && err.code === "server_stopped")) {
      throw err;
    }
  }

  const deadline = now() + stopTimeoutMs;
  let lastStatus = await getUnitStatus(validId, runCmd);

  while (!isUnitStopped(lastStatus) && now() < deadline) {
    await sleep(pollIntervalMs);
    lastStatus = await getUnitStatus(validId, runCmd);
  }

  if (!isUnitStopped(lastStatus)) {
    const stopService = await runCmd("systemctl", ["stop", serviceUnit]);
    if (stopService.timedOut || stopService.code !== 0) {
      throw new ProtocolError(
        "systemd_error",
        `Failed to stop ${serviceUnit} (exit ${stopService.code})`,
      );
    }
    lastStatus = await getUnitStatus(validId, runCmd);
  }

  const stopSocket = await runCmd("systemctl", ["stop", socketUnit]);
  if (stopSocket.timedOut || stopSocket.code !== 0) {
    throw new ProtocolError(
      "systemd_error",
      `Failed to stop ${socketUnit} (exit ${stopSocket.code})`,
    );
  }

  return lastStatus;
}
