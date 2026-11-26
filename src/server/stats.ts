// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { availableParallelism } from "node:os";
import { runFixed } from "../agent/exec";
import { ProtocolError, type ServerStatsResult } from "../protocol";
import { assertValidServerId, DEFAULT_SERVERS_DIR, formatServiceUnit } from "./id";
import type { RunFixedLike } from "./java";
import { readServerMetadata, type ServerMetadata } from "./registry";
import { isUnitActive } from "./systemd";

const UINT64_MAX = 18_446_744_073_709_551_615n;
const BYTES_PER_MIB = 1024 * 1024;
const NS_PER_MS = 1_000_000;

export interface SystemdUnitStats {
  readonly activeState: string;
  readonly memoryCurrentBytes: number | null;
  readonly cpuUsageNs: bigint | null;
  readonly activeEnterTimestampMs: number | null;
}

function parseUint64Property(value: string): bigint | null {
  const trimmed = value.trim();
  if (
    trimmed.length === 0 ||
    trimmed === "[not set]" ||
    trimmed === "infinity" ||
    !/^\d+$/.test(trimmed)
  ) {
    return null;
  }
  const parsed = BigInt(trimmed);
  return parsed < UINT64_MAX ? parsed : null;
}

function parseMemoryBytesProperty(value: string): number | null {
  const parsed = parseUint64Property(value);
  if (parsed === null) {
    return null;
  }
  const asNumber = Number(parsed);
  return Number.isSafeInteger(asNumber) && asNumber >= 0 ? asNumber : null;
}

export function parseActiveEnterTimestampMs(value: string): number | null {
  const trimmed = value.trim();
  if (
    trimmed.length === 0 ||
    trimmed === "n/a" ||
    trimmed === "[not set]" ||
    trimmed === "0" ||
    trimmed === "@0"
  ) {
    return null;
  }
  if (trimmed.startsWith("@")) {
    const rawSec = trimmed.slice(1);
    if (!/^\d+(?:\.\d+)?$/.test(rawSec)) {
      return null;
    }
    const sec = Number(rawSec);
    if (!Number.isFinite(sec) || sec <= 0) {
      return null;
    }
    return Math.floor(sec * 1000);
  }
  const parsed = Date.parse(trimmed);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

export function parseSystemdStatsOutput(stdout: string): SystemdUnitStats {
  let activeState = "unknown";
  let memoryCurrentBytes: number | null = null;
  let cpuUsageNs: bigint | null = null;
  let activeEnterTimestampMs: number | null = null;

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
    } else if (key === "MemoryCurrent") {
      memoryCurrentBytes = parseMemoryBytesProperty(value);
    } else if (key === "CPUUsageNSec") {
      cpuUsageNs = parseUint64Property(value);
    } else if (key === "ActiveEnterTimestamp") {
      activeEnterTimestampMs = parseActiveEnterTimestampMs(value);
    }
  }

  return {
    activeState,
    memoryCurrentBytes,
    cpuUsageNs,
    activeEnterTimestampMs,
  };
}

/**
 * Queries systemd unit accounting properties over D-Bus (`systemctl show`).
 * The agent service runs with `ProtectControlGroups=yes`, empty `CapabilityBoundingSet=`,
 * and `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, so D-Bus via `AF_UNIX` works
 * without widening the sandbox and avoids cgroup v1/v2 or slice path differences.
 */
export async function getUnitStats(
  serverId: string,
  runFixedImpl: RunFixedLike = runFixed,
): Promise<SystemdUnitStats> {
  const validId = assertValidServerId(serverId);
  const serviceUnit = formatServiceUnit(validId);
  const result = await runFixedImpl("systemctl", [
    "show",
    "--timestamp=unix",
    "-p",
    "ActiveState,MemoryCurrent,CPUUsageNSec,ActiveEnterTimestamp",
    serviceUnit,
  ]);
  if (result.timedOut || result.code !== 0) {
    throw new ProtocolError(
      "systemd_error",
      `Failed to query systemd stats for ${serviceUnit} (exit ${result.code})`,
    );
  }
  return parseSystemdStatsOutput(result.stdout);
}

export interface ServerStatsCollectorOptions {
  readonly serversDir?: string;
  readonly readServerMetadataImpl?: (serverId: string) => ServerMetadata;
  readonly getUnitStatsImpl?: (serverId: string) => Promise<SystemdUnitStats>;
  readonly runFixedImpl?: RunFixedLike;
  readonly availableParallelismImpl?: () => number;
  readonly now?: () => number;
}

export interface ServerStatsCollector {
  readStats(serverId: string): Promise<ServerStatsResult>;
  forget(serverId: string): void;
}

interface CpuSample {
  readonly cpuUsageNs: bigint;
  readonly sampledAtMs: number;
  readonly activeEnterTimestampMs: number | null;
}

export function createServerStatsCollector(
  options: ServerStatsCollectorOptions = {},
): ServerStatsCollector {
  const serversDir = options.serversDir ?? DEFAULT_SERVERS_DIR;
  const readMeta =
    options.readServerMetadataImpl ?? ((id: string) => readServerMetadata(serversDir, id));
  const queryUnit =
    options.getUnitStatsImpl ?? ((id: string) => getUnitStats(id, options.runFixedImpl));
  const getCpuCount = options.availableParallelismImpl ?? availableParallelism;
  const now = options.now ?? (() => Date.now());

  const lastCpuSamples = new Map<string, CpuSample>();

  function computeCpuPercent(
    serverId: string,
    cpuUsageNs: bigint | null,
    activeEnterTimestampMs: number | null,
    sampledAtMs: number,
  ): number {
    if (cpuUsageNs === null) {
      lastCpuSamples.delete(serverId);
      return 0;
    }

    const previous = lastCpuSamples.get(serverId);
    lastCpuSamples.set(serverId, {
      cpuUsageNs,
      sampledAtMs,
      activeEnterTimestampMs,
    });

    if (previous === undefined) {
      return 0;
    }
    if (
      previous.activeEnterTimestampMs !== null &&
      activeEnterTimestampMs !== null &&
      previous.activeEnterTimestampMs !== activeEnterTimestampMs
    ) {
      return 0;
    }

    const deltaMs = sampledAtMs - previous.sampledAtMs;
    const deltaNs = cpuUsageNs - previous.cpuUsageNs;
    if (deltaMs <= 0 || deltaNs < 0n) {
      return 0;
    }

    const rawPercent = (Number(deltaNs) / (deltaMs * NS_PER_MS)) * 100;
    if (!Number.isFinite(rawPercent) || rawPercent < 0) {
      return 0;
    }
    return Math.round(rawPercent * 10) / 10;
  }

  return {
    async readStats(serverId: string): Promise<ServerStatsResult> {
      const validId = assertValidServerId(serverId);
      const meta = readMeta(validId);
      const unit = await queryUnit(validId);
      const sampledAtMs = now();
      const cpuCount = Math.max(1, Math.trunc(getCpuCount()));
      const running = isUnitActive(unit);

      if (!running) {
        lastCpuSamples.delete(validId);
        return {
          server_id: validId,
          running: false,
          memory_used_mb: 0,
          memory_limit_mb: meta.memory_mb,
          cpu_percent: 0,
          cpu_count: cpuCount,
          uptime_seconds: 0,
        };
      }

      const memoryUsedMb =
        unit.memoryCurrentBytes !== null ? Math.round(unit.memoryCurrentBytes / BYTES_PER_MIB) : 0;
      const uptimeSeconds =
        unit.activeEnterTimestampMs !== null && sampledAtMs >= unit.activeEnterTimestampMs
          ? Math.floor((sampledAtMs - unit.activeEnterTimestampMs) / 1000)
          : 0;
      const cpuPercent = computeCpuPercent(
        validId,
        unit.cpuUsageNs,
        unit.activeEnterTimestampMs,
        sampledAtMs,
      );

      return {
        server_id: validId,
        running: true,
        memory_used_mb: memoryUsedMb,
        memory_limit_mb: meta.memory_mb,
        cpu_percent: cpuPercent,
        cpu_count: cpuCount,
        uptime_seconds: uptimeSeconds,
      };
    },

    forget(serverId: string): void {
      lastCpuSamples.delete(serverId);
    },
  };
}
