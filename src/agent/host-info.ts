// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { availableParallelism, networkInterfaces } from "node:os";
import type { HostInfoResult } from "../protocol";
import {
  DEFAULT_MEMINFO_PATH,
  type Meminfo,
  RESERVED_SYSTEM_MEMORY_MB,
  readMeminfo,
} from "../server/memory";

export interface ReadHostInfoOptions {
  readonly meminfoPath?: string;
  readonly readMeminfoImpl?: () => Meminfo;
  readonly availableParallelismImpl?: () => number;
  readonly reservedMemoryMb?: number;
  readonly networkInterfacesImpl?: () => ReturnType<typeof networkInterfaces>;
}

const MAX_ADDRESSES = 16;

/** Non-internal IPv4 addresses, without link-local (169.254.x.x) ones. */
export function readHostAddresses(
  interfaces: ReturnType<typeof networkInterfaces> = networkInterfaces(),
): string[] {
  const found: string[] = [];
  for (const entries of Object.values(interfaces)) {
    for (const entry of entries ?? []) {
      if (entry.family !== "IPv4" || entry.internal) continue;
      if (entry.address.startsWith("169.254.")) continue;
      if (!found.includes(entry.address)) found.push(entry.address);
    }
  }
  return found.slice(0, MAX_ADDRESSES);
}

export function readHostInfo(options: ReadHostInfoOptions = {}): HostInfoResult {
  const meminfo = options.readMeminfoImpl
    ? options.readMeminfoImpl()
    : readMeminfo(options.meminfoPath ?? DEFAULT_MEMINFO_PATH);
  const cpuCount = options.availableParallelismImpl
    ? options.availableParallelismImpl()
    : availableParallelism();
  const reservedMemoryMb = options.reservedMemoryMb ?? RESERVED_SYSTEM_MEMORY_MB;

  return {
    memory_total_mb: meminfo.memTotalMb,
    memory_available_mb: meminfo.memAvailableMb,
    cpu_count: cpuCount,
    reserved_memory_mb: reservedMemoryMb,
    addresses: readHostAddresses(options.networkInterfacesImpl?.()),
  };
}
