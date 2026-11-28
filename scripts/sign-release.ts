// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { writeFileAtomic } from "../src/agent/state";
import { ready } from "../src/crypto";
import {
  computeFileSha256,
  formatSha256Sums,
  MANIFEST_SCHEMA_VERSION,
  parseReleaseSigningKey,
  parseReleaseTag,
  RELEASE_ASSET_NAMES,
  signManifest,
  signSha256Sums,
  type UnsignedReleaseManifest,
} from "../src/update";

export interface SignReleaseCliArgs {
  readonly tag: string;
  readonly assetsDir: string;
  readonly baseUrl: string;
  readonly outDir: string;
  readonly publishedAt: number;
}

export interface SignReleaseResult {
  readonly channel: "stable" | "beta" | "nightly";
  readonly tag: string;
  readonly version: string;
  readonly sumsPath: string;
  readonly sigPath: string;
  readonly manifestPath: string;
}

export function parseSignReleaseArgs(
  argv: readonly string[],
  now: number = Date.now(),
): SignReleaseCliArgs {
  let tag: string | undefined;
  let assetsDir: string | undefined;
  let baseUrl: string | undefined;
  let outDir: string | undefined;
  let publishedAt: number | undefined;

  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const value = argv[i + 1];
    if (flag === "--tag") {
      if (value === undefined) throw new Error("--tag requires a value");
      tag = value;
      i++;
    } else if (flag === "--assets-dir") {
      if (value === undefined) throw new Error("--assets-dir requires a value");
      assetsDir = value;
      i++;
    } else if (flag === "--base-url") {
      if (value === undefined) throw new Error("--base-url requires a value");
      baseUrl = value;
      i++;
    } else if (flag === "--out-dir") {
      if (value === undefined) throw new Error("--out-dir requires a value");
      outDir = value;
      i++;
    } else if (flag === "--published-at") {
      if (value === undefined) throw new Error("--published-at requires an integer timestamp (ms)");
      const parsed = Number(value);
      if (!Number.isSafeInteger(parsed) || parsed < 0) {
        throw new Error(`Invalid --published-at timestamp: "${value}"`);
      }
      publishedAt = parsed;
      i++;
    } else {
      throw new Error(`Unknown argument: ${String(flag)}`);
    }
  }

  if (tag === undefined || assetsDir === undefined || baseUrl === undefined) {
    throw new Error(
      "Usage: bun scripts/sign-release.ts --tag <vX.Y.Z> --assets-dir <dir> --base-url <https://...> [--out-dir <dir>] [--published-at <ms>]",
    );
  }

  let parsedBaseUrl: URL;
  try {
    parsedBaseUrl = new URL(baseUrl);
  } catch {
    throw new Error(`Invalid --base-url: "${baseUrl}"`);
  }
  if (parsedBaseUrl.protocol !== "https:") {
    throw new Error(`--base-url must use https:// (got ${parsedBaseUrl.protocol})`);
  }
  if (parsedBaseUrl.username.length > 0 || parsedBaseUrl.password.length > 0) {
    throw new Error("--base-url must not contain embedded credentials");
  }

  const resolvedAssetsDir = resolve(assetsDir);
  return {
    tag,
    assetsDir: resolvedAssetsDir,
    baseUrl: parsedBaseUrl.toString().replace(/\/+$/, ""),
    outDir: outDir !== undefined ? resolve(outDir) : resolvedAssetsDir,
    publishedAt: publishedAt ?? now,
  };
}

export async function runSignRelease(
  argv: readonly string[],
  env: Readonly<Record<string, string | undefined>> = process.env,
  now: number = Date.now(),
): Promise<SignReleaseResult> {
  await ready();

  const args = parseSignReleaseArgs(argv, now);
  const parsedTag = parseReleaseTag(args.tag);

  const rawKey = env.RELEASE_SIGNING_KEY;
  if (rawKey === undefined || rawKey.trim().length === 0) {
    throw new Error("RELEASE_SIGNING_KEY environment variable is required");
  }
  const keyPair = parseReleaseSigningKey(rawKey);

  const x64Name = RELEASE_ASSET_NAMES["linux-x64"];
  const arm64Name = RELEASE_ASSET_NAMES["linux-arm64"];
  const x64Path = join(args.assetsDir, x64Name);
  const arm64Path = join(args.assetsDir, arm64Name);

  if (!existsSync(x64Path)) {
    throw new Error(`Missing release asset: ${x64Path}`);
  }
  if (!existsSync(arm64Path)) {
    throw new Error(`Missing release asset: ${arm64Path}`);
  }

  const [x64Digest, arm64Digest] = await Promise.all([
    computeFileSha256(x64Path),
    computeFileSha256(arm64Path),
  ]);

  const sumsContent = formatSha256Sums([
    { sha256: x64Digest.sha256, filename: x64Name },
    { sha256: arm64Digest.sha256, filename: arm64Name },
  ]);
  const sumsSig = signSha256Sums(sumsContent, keyPair.secretKey);

  const unsignedManifest: UnsignedReleaseManifest = {
    v: MANIFEST_SCHEMA_VERSION,
    channel: parsedTag.channel,
    version: parsedTag.raw,
    tag: parsedTag.tag,
    published_at: args.publishedAt,
    assets: {
      "linux-x64": {
        url: `${args.baseUrl}/${x64Name}`,
        sha256: x64Digest.sha256,
        size: x64Digest.size,
      },
      "linux-arm64": {
        url: `${args.baseUrl}/${arm64Name}`,
        sha256: arm64Digest.sha256,
        size: arm64Digest.size,
      },
    },
  };
  const signedManifest = signManifest(unsignedManifest, keyPair.secretKey);

  const sumsPath = join(args.outDir, "SHA256SUMS");
  const sigPath = join(args.outDir, "SHA256SUMS.sig");
  const manifestPath = join(args.outDir, `${parsedTag.channel}.json`);

  writeFileAtomic(sumsPath, sumsContent, { mode: 0o644, dirMode: 0o755 });
  writeFileAtomic(sigPath, `${sumsSig}\n`, { mode: 0o644, dirMode: 0o755 });
  writeFileAtomic(manifestPath, `${JSON.stringify(signedManifest, null, 2)}\n`, {
    mode: 0o644,
    dirMode: 0o755,
  });

  return {
    channel: parsedTag.channel,
    tag: parsedTag.tag,
    version: parsedTag.raw,
    sumsPath,
    sigPath,
    manifestPath,
  };
}

if (import.meta.main) {
  try {
    const result = await runSignRelease(process.argv.slice(2));
    process.stdout.write(
      `Signed ${result.tag} (${result.channel}):\n  ${result.sumsPath}\n  ${result.sigPath}\n  ${result.manifestPath}\n`,
    );
  } catch (err) {
    process.stderr.write(`Error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  }
}
