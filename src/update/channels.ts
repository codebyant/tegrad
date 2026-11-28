// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
import { UpdateError } from "./errors";

export const RELEASE_CHANNELS = ["stable", "beta", "nightly"] as const;
export type ReleaseChannel = (typeof RELEASE_CHANNELS)[number];

export const releaseChannelSchema = z.enum(RELEASE_CHANNELS);

const STABLE_RE = /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const BETA_RE = /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)-beta\.(0|[1-9]\d*)$/;
const NIGHTLY_RE = /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)-nightly\.(\d{12})$/;

export interface ParsedVersion {
  readonly raw: string;
  readonly tag: string;
  readonly major: number;
  readonly minor: number;
  readonly patch: number;
  readonly channel: ReleaseChannel;
  readonly prereleaseNumber: number | null;
  readonly nightlyTimestamp: string | null;
}

const CHANNEL_PRECEDENCE: Readonly<Record<ReleaseChannel, number>> = {
  beta: 0,
  nightly: 1,
  stable: 2,
};

function parseSafeUint(text: string): number {
  const value = Number(text);
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new UpdateError("invalid_version", `Invalid numeric component in version: "${text}"`);
  }
  return value;
}

function isValidNightlyTimestamp(ts: string): boolean {
  if (ts.length !== 12 || !/^\d{12}$/.test(ts)) {
    return false;
  }
  const year = Number(ts.slice(0, 4));
  const month = Number(ts.slice(4, 6));
  const day = Number(ts.slice(6, 8));
  const hour = Number(ts.slice(8, 10));
  const minute = Number(ts.slice(10, 12));

  if (year < 2000 || month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59) {
    return false;
  }

  const probe = new Date(Date.UTC(year, month - 1, day, hour, minute));
  return (
    probe.getUTCFullYear() === year &&
    probe.getUTCMonth() === month - 1 &&
    probe.getUTCDate() === day &&
    probe.getUTCHours() === hour &&
    probe.getUTCMinutes() === minute
  );
}

export function parseVersion(input: string): ParsedVersion {
  if (typeof input !== "string" || input.length === 0 || input.length > 128) {
    throw new UpdateError("invalid_version", `Invalid version string: "${String(input)}"`);
  }

  const stableMatch = STABLE_RE.exec(input);
  if (stableMatch !== null) {
    const major = parseSafeUint(stableMatch[1] ?? "");
    const minor = parseSafeUint(stableMatch[2] ?? "");
    const patch = parseSafeUint(stableMatch[3] ?? "");
    const raw = `${major}.${minor}.${patch}`;
    return {
      raw,
      tag: `v${raw}`,
      major,
      minor,
      patch,
      channel: "stable",
      prereleaseNumber: null,
      nightlyTimestamp: null,
    };
  }

  const betaMatch = BETA_RE.exec(input);
  if (betaMatch !== null) {
    const major = parseSafeUint(betaMatch[1] ?? "");
    const minor = parseSafeUint(betaMatch[2] ?? "");
    const patch = parseSafeUint(betaMatch[3] ?? "");
    const betaNum = parseSafeUint(betaMatch[4] ?? "");
    const raw = `${major}.${minor}.${patch}-beta.${betaNum}`;
    return {
      raw,
      tag: `v${raw}`,
      major,
      minor,
      patch,
      channel: "beta",
      prereleaseNumber: betaNum,
      nightlyTimestamp: null,
    };
  }

  const nightlyMatch = NIGHTLY_RE.exec(input);
  if (nightlyMatch !== null) {
    const major = parseSafeUint(nightlyMatch[1] ?? "");
    const minor = parseSafeUint(nightlyMatch[2] ?? "");
    const patch = parseSafeUint(nightlyMatch[3] ?? "");
    const ts = nightlyMatch[4] ?? "";
    if (!isValidNightlyTimestamp(ts)) {
      throw new UpdateError(
        "invalid_version",
        `Invalid nightly UTC timestamp in version: "${input}"`,
      );
    }
    const raw = `${major}.${minor}.${patch}-nightly.${ts}`;
    return {
      raw,
      tag: `v${raw}`,
      major,
      minor,
      patch,
      channel: "nightly",
      prereleaseNumber: Number(ts),
      nightlyTimestamp: ts,
    };
  }

  throw new UpdateError(
    "invalid_version",
    `Unsupported version or tag format: "${input}" (expected vX.Y.Z, vX.Y.Z-beta.N, or vX.Y.Z-nightly.YYYYMMDDHHmm)`,
  );
}

export function tryParseVersion(input: string): ParsedVersion | null {
  try {
    return parseVersion(input);
  } catch {
    return null;
  }
}

export function channelFromTag(tagOrVersion: string): ReleaseChannel {
  return parseVersion(tagOrVersion).channel;
}

export function parseReleaseTag(tag: string): ParsedVersion {
  if (!tag.startsWith("v")) {
    throw new UpdateError("invalid_version", `Release tag must start with "v" (got "${tag}")`);
  }
  return parseVersion(tag);
}

function compareNumbers(a: number, b: number): -1 | 0 | 1 {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

export function compareVersions(a: string | ParsedVersion, b: string | ParsedVersion): -1 | 0 | 1 {
  const va = typeof a === "string" ? parseVersion(a) : a;
  const vb = typeof b === "string" ? parseVersion(b) : b;

  const maj = compareNumbers(va.major, vb.major);
  if (maj !== 0) return maj;

  const min = compareNumbers(va.minor, vb.minor);
  if (min !== 0) return min;

  const pat = compareNumbers(va.patch, vb.patch);
  if (pat !== 0) return pat;

  const chan = compareNumbers(CHANNEL_PRECEDENCE[va.channel], CHANNEL_PRECEDENCE[vb.channel]);
  if (chan !== 0) return chan;

  if (va.channel === "stable") {
    return 0;
  }

  if (va.channel === "beta") {
    return compareNumbers(va.prereleaseNumber ?? 0, vb.prereleaseNumber ?? 0);
  }

  const tsA = va.nightlyTimestamp ?? "";
  const tsB = vb.nightlyTimestamp ?? "";
  if (tsA < tsB) return -1;
  if (tsA > tsB) return 1;
  return 0;
}

export interface ShouldUpdateOptions {
  readonly allowDowngrade?: boolean;
}

export function shouldUpdate(
  currentVersion: string | ParsedVersion,
  candidateVersion: string | ParsedVersion,
  options: ShouldUpdateOptions = {},
): boolean {
  const cmp = compareVersions(candidateVersion, currentVersion);
  if (cmp > 0) {
    return true;
  }
  if (cmp === 0) {
    return false;
  }
  return options.allowDowngrade === true;
}

export function formatNightlyTag(baseVersion: string, now: Date = new Date()): string {
  const parsed = parseVersion(baseVersion);
  const yyyy = String(now.getUTCFullYear()).padStart(4, "0");
  const mm = String(now.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(now.getUTCDate()).padStart(2, "0");
  const hh = String(now.getUTCHours()).padStart(2, "0");
  const min = String(now.getUTCMinutes()).padStart(2, "0");
  return `v${parsed.major}.${parsed.minor}.${parsed.patch}-nightly.${yyyy}${mm}${dd}${hh}${min}`;
}
