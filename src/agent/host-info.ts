// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { readFileSync } from "node:fs";
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
  readonly fibTriePath?: string;
}

const MAX_ADDRESSES = 16;
const DEFAULT_FIB_TRIE_PATH = "/proc/net/fib_trie";

function isUsableIpv4(address: string): boolean {
  return !address.startsWith("127.") && !address.startsWith("169.254.") && address !== "0.0.0.0";
}

/**
 * Local IPv4 addresses from the kernel routing trie. The service sandbox only
 * allows AF_INET, AF_INET6 and AF_UNIX sockets, which blocks the netlink call
 * behind `os.networkInterfaces()`, so this plain file read is the fallback.
 */
export function readAddressesFromFibTrie(path: string = DEFAULT_FIB_TRIE_PATH): string[] {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return [];
  }
  const found: string[] = [];
  let lastAddress: string | null = null;
  for (const line of text.split("\n")) {
    const addressMatch = line.match(/\|--\s+(\d{1,3}(?:\.\d{1,3}){3})\s*$/);
    if (addressMatch) {
      lastAddress = addressMatch[1] ?? null;
      continue;
    }
    if (lastAddress && /\/32 host LOCAL/.test(line)) {
      if (isUsableIpv4(lastAddress) && !found.includes(lastAddress)) found.push(lastAddress);
      lastAddress = null;
    }
  }
  return found.slice(0, MAX_ADDRESSES);
}

/** Non-internal IPv4 addresses, without link-local (169.254.x.x) ones. */
export function readHostAddresses(
  source: () => ReturnType<typeof networkInterfaces> = networkInterfaces,
): string[] {
  let all: ReturnType<typeof networkInterfaces>;
  try {
    all = source();
  } catch {
    // The service sandbox blocks the netlink call and getifaddrs throws.
    return [];
  }
  const found: string[] = [];
  for (const entries of Object.values(all)) {
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
  let addresses = readHostAddresses(options.networkInterfacesImpl);
  if (addresses.length === 0) addresses = readAddressesFromFibTrie(options.fibTriePath);

  return {
    memory_total_mb: meminfo.memTotalMb,
    memory_available_mb: meminfo.memAvailableMb,
    cpu_count: cpuCount,
    reserved_memory_mb: reservedMemoryMb,
    addresses,
  };
}
