// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { readFileSync } from "node:fs";
import { ProtocolError } from "../protocol";

export const DEFAULT_MEMINFO_PATH = "/proc/meminfo";
export const RESERVED_SYSTEM_MEMORY_MB = 1024;

export interface Meminfo {
  readonly memTotalMb: number;
  readonly memAvailableMb: number;
}

export function parseMeminfo(content: string): Meminfo {
  let memTotalKb: number | null = null;
  let memAvailableKb: number | null = null;

  for (const rawLine of content.split(/\r?\n/)) {
    const match = /^(MemTotal|MemAvailable):\s+(\d+)\s+kB$/i.exec(rawLine.trim());
    if (!match) {
      continue;
    }
    const key = match[1]?.toLowerCase();
    const kb = Number(match[2]);
    if (!Number.isSafeInteger(kb) || kb < 0) {
      continue;
    }
    if (key === "memtotal") {
      memTotalKb = kb;
    } else if (key === "memavailable") {
      memAvailableKb = kb;
    }
  }

  if (memTotalKb === null || memAvailableKb === null) {
    throw new ProtocolError(
      "insufficient_memory",
      "Unable to determine MemTotal and MemAvailable from /proc/meminfo",
    );
  }

  return {
    memTotalMb: Math.floor(memTotalKb / 1024),
    memAvailableMb: Math.floor(memAvailableKb / 1024),
  };
}

export function readMeminfo(meminfoPath: string = DEFAULT_MEMINFO_PATH): Meminfo {
  let raw: string;
  try {
    raw = readFileSync(meminfoPath, "utf8");
  } catch {
    throw new ProtocolError("insufficient_memory", "Failed to read host memory information");
  }
  return parseMeminfo(raw);
}

export interface MemoryCheckParams {
  readonly requestedMemoryMb: number;
  readonly runningServersMemoryMb: number;
  readonly meminfo: Meminfo;
  readonly reservedSystemMb?: number;
}

export function checkMemoryForServer(params: MemoryCheckParams): void {
  const reservedSystemMb = params.reservedSystemMb ?? RESERVED_SYSTEM_MEMORY_MB;
  const maxAllocatableMb = params.meminfo.memTotalMb - reservedSystemMb;
  const totalAllocatedMb = params.runningServersMemoryMb + params.requestedMemoryMb;

  if (totalAllocatedMb > maxAllocatableMb) {
    throw new ProtocolError(
      "insufficient_memory",
      `Requested ${params.requestedMemoryMb} MB plus running ${params.runningServersMemoryMb} MB exceeds host budget (${maxAllocatableMb} MB)`,
    );
  }

  if (params.requestedMemoryMb > params.meminfo.memAvailableMb) {
    throw new ProtocolError(
      "insufficient_memory",
      `Requested ${params.requestedMemoryMb} MB exceeds available host memory (${params.meminfo.memAvailableMb} MB)`,
    );
  }
}
