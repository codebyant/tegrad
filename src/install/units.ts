// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";

export const NETWORK_DENY_RANGES: readonly string[] = [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "169.254.0.0/16",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "fc00::/7",
  "fe80::/10",
  "::1/128",
];

export interface ParsedIpAddress {
  readonly version: 4 | 6;
  readonly address: string;
}

export interface ParsedCidr {
  readonly version: 4 | 6;
  readonly address: string;
  readonly prefix: number;
  readonly cidr: string;
}

export interface RenderNetworkDropInOptions {
  readonly resolvers?: readonly string[];
  readonly allowLan?: readonly string[];
}

const renderOptionsSchema = z.object({
  resolvers: z.array(z.string()).optional(),
  allowLan: z.array(z.string()).optional(),
});

function isUintNoLeadingZero(value: string): boolean {
  if (value.length === 0) return false;
  if (value === "0") return true;
  if (value.startsWith("0")) return false;
  return /^[0-9]+$/.test(value);
}

function parseIpv4Octets(raw: string): readonly [number, number, number, number] | null {
  if (raw.length === 0 || !/^[0-9.]+$/.test(raw)) {
    return null;
  }
  const parts = raw.split(".");
  if (parts.length !== 4) {
    return null;
  }
  const octets: number[] = [];
  for (const part of parts) {
    if (!isUintNoLeadingZero(part)) {
      return null;
    }
    const num = Number(part);
    if (!Number.isInteger(num) || num < 0 || num > 255) {
      return null;
    }
    octets.push(num);
  }
  const [a, b, c, d] = octets;
  if (a === undefined || b === undefined || c === undefined || d === undefined) {
    return null;
  }
  return [a, b, c, d];
}

function expandIpv6Groups(raw: string): readonly string[] | null {
  if (raw.length === 0 || !/^[0-9a-fA-F:]+$/.test(raw) || !raw.includes(":")) {
    return null;
  }
  if (raw.includes(":::")) {
    return null;
  }
  if (
    (raw.startsWith(":") && !raw.startsWith("::")) ||
    (raw.endsWith(":") && !raw.endsWith("::"))
  ) {
    return null;
  }

  const dcIndex = raw.indexOf("::");
  let leftGroups: string[];
  let rightGroups: string[];
  let hasCompression = false;

  if (dcIndex !== -1) {
    if (raw.indexOf("::", dcIndex + 2) !== -1) {
      return null;
    }
    hasCompression = true;
    const leftPart = raw.slice(0, dcIndex);
    const rightPart = raw.slice(dcIndex + 2);
    leftGroups = leftPart.length > 0 ? leftPart.split(":") : [];
    rightGroups = rightPart.length > 0 ? rightPart.split(":") : [];
  } else {
    leftGroups = raw.split(":");
    rightGroups = [];
  }

  const validateGroup = (group: string): string | null => {
    if (group.length === 0 || group.length > 4 || !/^[0-9a-fA-F]+$/.test(group)) {
      return null;
    }
    return group.toLowerCase().padStart(4, "0");
  };

  const expandedLeft: string[] = [];
  for (const g of leftGroups) {
    const norm = validateGroup(g);
    if (norm === null) return null;
    expandedLeft.push(norm);
  }

  const expandedRight: string[] = [];
  for (const g of rightGroups) {
    const norm = validateGroup(g);
    if (norm === null) return null;
    expandedRight.push(norm);
  }

  const totalExplicit = expandedLeft.length + expandedRight.length;
  if (hasCompression) {
    if (totalExplicit >= 8) {
      return null;
    }
    const missing = 8 - totalExplicit;
    return [...expandedLeft, ...Array<string>(missing).fill("0000"), ...expandedRight];
  }

  if (totalExplicit !== 8) {
    return null;
  }
  return expandedLeft;
}

export function parseIpAddress(raw: string): ParsedIpAddress | null {
  if (parseIpv4Octets(raw) !== null) {
    return { version: 4, address: raw };
  }
  if (expandIpv6Groups(raw) !== null) {
    return { version: 6, address: raw };
  }
  return null;
}

export function parseCidr(raw: string): ParsedCidr | null {
  const slashIndex = raw.indexOf("/");
  if (slashIndex === -1 || raw.indexOf("/", slashIndex + 1) !== -1) {
    return null;
  }
  const addrPart = raw.slice(0, slashIndex);
  const prefixPart = raw.slice(slashIndex + 1);
  if (!isUintNoLeadingZero(prefixPart)) {
    return null;
  }
  const prefix = Number(prefixPart);
  const parsedIp = parseIpAddress(addrPart);
  if (parsedIp === null) {
    return null;
  }
  const maxPrefix = parsedIp.version === 4 ? 32 : 128;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) {
    return null;
  }
  return {
    version: parsedIp.version,
    address: parsedIp.address,
    prefix,
    cidr: `${parsedIp.address}/${prefix}`,
  };
}

export function isPrivateOrLoopbackIp(raw: string): boolean {
  const v4 = parseIpv4Octets(raw);
  if (v4 !== null) {
    const [a, b] = v4;
    // 10.0.0.0/8
    if (a === 10) return true;
    // 127.0.0.0/8
    if (a === 127) return true;
    // 169.254.0.0/16
    if (a === 169 && b === 254) return true;
    // 172.16.0.0/12
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16
    if (a === 192 && b === 168) return true;
    // 100.64.0.0/10
    if (a === 100 && b >= 64 && b <= 127) return true;
    return false;
  }

  const v6 = expandIpv6Groups(raw);
  if (v6 !== null) {
    // ::1/128
    if (v6.join(":") === "0000:0000:0000:0000:0000:0000:0000:0001") {
      return true;
    }
    const first = v6[0];
    if (first === undefined) return false;
    // fc00::/7 (fc00..fdff)
    if (first.startsWith("fc") || first.startsWith("fd")) {
      return true;
    }
    // fe80::/10 (fe80..febf)
    if (
      first.startsWith("fe8") ||
      first.startsWith("fe9") ||
      first.startsWith("fea") ||
      first.startsWith("feb")
    ) {
      return true;
    }
    return false;
  }

  return false;
}

export function parseResolvConf(content: string): string[] {
  const resolvers: string[] = [];
  for (const rawLine of content.split(/\r?\n/)) {
    const noHash = rawLine.split("#")[0] ?? "";
    const noSemi = noHash.split(";")[0] ?? "";
    const trimmed = noSemi.replace(/\t/g, " ").trim();
    if (!trimmed.startsWith("nameserver ")) {
      continue;
    }
    const rest = trimmed.slice("nameserver ".length).trim();
    const token = rest.split(" ")[0] ?? "";
    if (parseIpAddress(token) !== null) {
      resolvers.push(token);
    }
  }
  return resolvers;
}

export function renderNetworkDropIn(options: RenderNetworkDropInOptions = {}): string {
  const parsed = renderOptionsSchema.parse(options);
  const resolvers = parsed.resolvers ?? [];
  const allowLan = parsed.allowLan ?? [];

  const allowed: string[] = [];
  const seen = new Set<string>();

  for (const resolver of resolvers) {
    if (parseIpAddress(resolver) === null) {
      throw new Error(`Invalid resolver IP address: "${resolver}"`);
    }
    if (isPrivateOrLoopbackIp(resolver) && !seen.has(resolver)) {
      seen.add(resolver);
      allowed.push(resolver);
    }
  }

  for (const cidr of allowLan) {
    if (parseCidr(cidr) === null) {
      throw new Error(`Invalid allowLan CIDR: "${cidr}"`);
    }
    if (!seen.has(cidr)) {
      seen.add(cidr);
      allowed.push(cidr);
    }
  }

  const lines = [
    "# SPDX-License-Identifier: AGPL-3.0-only",
    "# Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>",
    "# Generated by tegrad installer. Re-run installer to refresh DNS resolvers.",
    "",
    "[Service]",
    `IPAddressDeny=${NETWORK_DENY_RANGES.join(" ")}`,
  ];

  if (allowed.length > 0) {
    lines.push(`IPAddressAllow=${allowed.join(" ")}`);
  }

  return `${lines.join("\n")}\n`;
}
