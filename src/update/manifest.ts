// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { basename } from "node:path";
import { z } from "zod";
import {
  canonicalize,
  fromBase64Url,
  type PublicKey,
  ready,
  type SecretKey,
  SIGNATURE_BYTES,
  SIGNING_PUBLIC_KEY_BYTES,
  SIGNING_SECRET_KEY_BYTES,
  SIGNING_SEED_BYTES,
  type SigningKeyPair,
  sign,
  signingKeyPairFromSeed,
  toBase64Url,
  verify,
} from "../crypto";
import { base64UrlSchema } from "../protocol";
import {
  parseReleaseTag,
  parseVersion,
  type ReleaseChannel,
  releaseChannelSchema,
} from "./channels";
import { UpdateError } from "./errors";
import { getReleasePublicKey } from "./release-key";

const utf8Encoder = new TextEncoder();

function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) {
    total += part.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export const MANIFEST_SCHEMA_VERSION = 1 as const;
export const DOMAIN_RELEASE_MANIFEST = utf8Encoder.encode("TEGRA_RELEASE_MANIFEST_V1\0");
export const DOMAIN_SHA256SUMS = utf8Encoder.encode("TEGRA_SHA256SUMS_V1\0");

export const SUPPORTED_RELEASE_ARCHES = ["linux-x64", "linux-arm64"] as const;
export type ReleaseArch = (typeof SUPPORTED_RELEASE_ARCHES)[number];

export const RELEASE_ASSET_NAMES: Readonly<Record<ReleaseArch, string>> = {
  "linux-x64": "tegrad-linux-x64",
  "linux-arm64": "tegrad-linux-arm64",
};

const sha256HexSchema = z.string().regex(/^[0-9a-f]{64}$/);

const httpsUrlSchema = z.string().refine(
  (value) => {
    try {
      const parsed = new URL(value);
      return (
        parsed.protocol === "https:" &&
        parsed.username.length === 0 &&
        parsed.password.length === 0 &&
        parsed.hostname.length > 0
      );
    } catch {
      return false;
    }
  },
  { message: "Asset URL must be a valid https:// URL without embedded credentials" },
);

export const releaseAssetSchema = z
  .object({
    url: httpsUrlSchema,
    sha256: sha256HexSchema,
    size: z.number().int().positive(),
  })
  .strict();

export const unsignedReleaseManifestSchema = z
  .object({
    v: z.literal(MANIFEST_SCHEMA_VERSION),
    channel: releaseChannelSchema,
    version: z.string().min(1),
    tag: z.string().min(1),
    published_at: z.number().int().nonnegative(),
    assets: z
      .object({
        "linux-x64": releaseAssetSchema,
        "linux-arm64": releaseAssetSchema,
      })
      .strict(),
  })
  .strict();

export const releaseManifestSchema = unsignedReleaseManifestSchema
  .extend({
    sig: base64UrlSchema,
  })
  .strict();

export type ReleaseAsset = z.infer<typeof releaseAssetSchema>;
export type UnsignedReleaseManifest = z.infer<typeof unsignedReleaseManifestSchema>;
export type ReleaseManifest = z.infer<typeof releaseManifestSchema>;

export function resolveReleaseArch(
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch,
): ReleaseArch {
  if (platform !== "linux") {
    throw new UpdateError("unsupported_arch", `Auto-update only supports Linux (got ${platform})`);
  }
  if (arch === "x64") {
    return "linux-x64";
  }
  if (arch === "arm64") {
    return "linux-arm64";
  }
  throw new UpdateError("unsupported_arch", `Unsupported Linux architecture: ${arch}`);
}

export function archFromAssetName(assetName: string): ReleaseArch | null {
  if (assetName === RELEASE_ASSET_NAMES["linux-x64"]) return "linux-x64";
  if (assetName === RELEASE_ASSET_NAMES["linux-arm64"]) return "linux-arm64";
  return null;
}

function assertManifestSemantics(manifest: UnsignedReleaseManifest): void {
  const parsedVersion = parseVersion(manifest.version);
  const parsedTag = parseReleaseTag(manifest.tag);
  if (manifest.version !== parsedVersion.raw) {
    throw new UpdateError(
      "invalid_manifest",
      `Manifest version must be canonical without leading "v" (got "${manifest.version}")`,
    );
  }
  if (parsedTag.raw !== parsedVersion.raw || manifest.tag !== parsedVersion.tag) {
    throw new UpdateError(
      "invalid_manifest",
      `Manifest tag "${manifest.tag}" does not match version "${manifest.version}"`,
    );
  }
  if (parsedVersion.channel !== manifest.channel) {
    throw new UpdateError(
      "channel_mismatch",
      `Manifest channel "${manifest.channel}" does not match version "${manifest.version}" (${parsedVersion.channel})`,
    );
  }
}

export function manifestSigningPayload(unsigned: UnsignedReleaseManifest): Uint8Array {
  return concatBytes(DOMAIN_RELEASE_MANIFEST, canonicalize(unsigned));
}

export function sha256SumsSigningPayload(sumsContent: string | Uint8Array): Uint8Array {
  const bytes = typeof sumsContent === "string" ? utf8Encoder.encode(sumsContent) : sumsContent;
  return concatBytes(DOMAIN_SHA256SUMS, bytes);
}

export function parseReleaseSigningKey(rawBase64Url: string): SigningKeyPair {
  const trimmed = rawBase64Url.trim();
  let bytes: Uint8Array;
  try {
    bytes = fromBase64Url(trimmed);
  } catch {
    throw new UpdateError("bad_manifest_signature", "Invalid base64url encoding for signing key");
  }

  if (bytes.length === SIGNING_SEED_BYTES) {
    return signingKeyPairFromSeed(bytes);
  }
  if (bytes.length === SIGNING_SECRET_KEY_BYTES) {
    const publicKey = bytes.subarray(
      SIGNING_SECRET_KEY_BYTES - SIGNING_PUBLIC_KEY_BYTES,
      SIGNING_SECRET_KEY_BYTES,
    );
    return { publicKey, secretKey: bytes };
  }
  throw new UpdateError(
    "bad_manifest_signature",
    `Signing key must be ${SIGNING_SEED_BYTES} bytes (seed) or ${SIGNING_SECRET_KEY_BYTES} bytes (secret key)`,
  );
}

export function signManifest(
  unsigned: UnsignedReleaseManifest,
  secretKey: SecretKey,
): ReleaseManifest {
  const parsed = unsignedReleaseManifestSchema.safeParse(unsigned);
  if (!parsed.success) {
    throw new UpdateError("invalid_manifest", "Manifest failed schema validation before signing");
  }
  assertManifestSemantics(parsed.data);

  const payload = manifestSigningPayload(parsed.data);
  const sigBytes = sign(payload, secretKey);
  return {
    ...parsed.data,
    sig: toBase64Url(sigBytes),
  };
}

export interface VerifyManifestOptions {
  readonly publicKey?: PublicKey;
  readonly expectedChannel?: ReleaseChannel;
}

export function verifyManifest(raw: unknown, options: VerifyManifestOptions = {}): ReleaseManifest {
  const parsed = releaseManifestSchema.safeParse(raw);
  if (!parsed.success) {
    throw new UpdateError("invalid_manifest", "Release manifest failed schema validation");
  }

  const publicKey = options.publicKey ?? getReleasePublicKey();
  const { sig, ...unsigned } = parsed.data;

  let sigBytes: Uint8Array;
  try {
    sigBytes = fromBase64Url(sig);
  } catch {
    throw new UpdateError("bad_manifest_signature", "Invalid base64url signature in manifest");
  }
  if (sigBytes.length !== SIGNATURE_BYTES) {
    throw new UpdateError("bad_manifest_signature", "Invalid signature length in manifest");
  }

  const payload = manifestSigningPayload(unsigned);
  if (!verify(payload, sigBytes, publicKey)) {
    throw new UpdateError(
      "bad_manifest_signature",
      "Ed25519 signature verification failed for manifest",
    );
  }

  assertManifestSemantics(unsigned);

  if (options.expectedChannel !== undefined && parsed.data.channel !== options.expectedChannel) {
    throw new UpdateError(
      "channel_mismatch",
      `Expected manifest for channel "${options.expectedChannel}", got "${parsed.data.channel}"`,
    );
  }

  return parsed.data;
}

export function signSha256Sums(sumsContent: string | Uint8Array, secretKey: SecretKey): string {
  const payload = sha256SumsSigningPayload(sumsContent);
  return toBase64Url(sign(payload, secretKey));
}

export function verifySha256Sums(
  sumsContent: string | Uint8Array,
  signatureBase64Url: string,
  publicKey: PublicKey = getReleasePublicKey(),
): boolean {
  const trimmed = signatureBase64Url.trim();
  let sigBytes: Uint8Array;
  try {
    sigBytes = fromBase64Url(trimmed);
  } catch {
    return false;
  }
  if (sigBytes.length !== SIGNATURE_BYTES) {
    return false;
  }
  const payload = sha256SumsSigningPayload(sumsContent);
  return verify(payload, sigBytes, publicKey);
}

export function parseSha256Sums(content: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.length === 0) continue;
    const match = /^([0-9a-f]{64})[ \t]+\*?([^\s/\\]+)$/.exec(line);
    if (match === null) {
      throw new UpdateError("invalid_manifest", `Malformed line in SHA256SUMS: "${line}"`);
    }
    const sha256 = match[1] ?? "";
    const filename = match[2] ?? "";
    const existing = map.get(filename);
    if (existing !== undefined && existing !== sha256) {
      throw new UpdateError(
        "invalid_manifest",
        `Conflicting duplicate SHA256SUMS entries for "${filename}"`,
      );
    }
    map.set(filename, sha256);
  }
  return map;
}

export function formatSha256Sums(
  entries: readonly { readonly sha256: string; readonly filename: string }[],
): string {
  const sorted = [...entries].sort((a, b) =>
    a.filename < b.filename ? -1 : a.filename > b.filename ? 1 : 0,
  );
  return `${sorted.map((entry) => `${entry.sha256}  ${entry.filename}`).join("\n")}\n`;
}

export function computeBytesSha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function computeFileSha256(
  filePath: string,
): Promise<{ readonly sha256: string; readonly size: number }> {
  return new Promise((resolve, reject) => {
    const hasher = createHash("sha256");
    let size = 0;
    const stream = createReadStream(filePath);

    stream.on("data", (chunk: string | Buffer) => {
      const buf = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
      size += buf.byteLength;
      hasher.update(buf);
    });
    stream.on("error", (err) => {
      reject(err);
    });
    stream.on("end", () => {
      resolve({ sha256: hasher.digest("hex"), size });
    });
  });
}

export interface VerifyReleaseBinaryOptions {
  readonly binaryPath: string;
  readonly expectedAssetName?: string;
  readonly arch?: ReleaseArch;
  readonly sha256?: string;
  readonly manifestContent?: string | Uint8Array | unknown;
  readonly sha256SumsContent?: string | Uint8Array;
  readonly sha256SumsSig?: string;
  readonly publicKey?: PublicKey;
  readonly expectedChannel?: ReleaseChannel;
}

export type VerifyReleaseBinaryResult =
  | {
      readonly ok: true;
      readonly mode: "manifest";
      readonly sha256: string;
      readonly size: number;
      readonly arch: ReleaseArch;
      readonly manifest: ReleaseManifest;
    }
  | {
      readonly ok: true;
      readonly mode: "sums";
      readonly sha256: string;
      readonly size: number;
      readonly assetName: string;
    };

export async function verifyReleaseBinary(
  options: VerifyReleaseBinaryOptions,
): Promise<VerifyReleaseBinaryResult> {
  await ready();
  const publicKey = options.publicKey ?? getReleasePublicKey();

  if (options.manifestContent !== undefined) {
    let rawManifest: unknown;
    if (typeof options.manifestContent === "string") {
      try {
        rawManifest = JSON.parse(options.manifestContent) as unknown;
      } catch {
        throw new UpdateError("invalid_manifest", "Manifest content is not valid JSON");
      }
    } else if (options.manifestContent instanceof Uint8Array) {
      try {
        rawManifest = JSON.parse(new TextDecoder().decode(options.manifestContent)) as unknown;
      } catch {
        throw new UpdateError("invalid_manifest", "Manifest content is not valid JSON");
      }
    } else {
      rawManifest = options.manifestContent;
    }

    const manifest = verifyManifest(rawManifest, {
      publicKey,
      ...(options.expectedChannel !== undefined
        ? { expectedChannel: options.expectedChannel }
        : {}),
    });

    const archFromName =
      options.expectedAssetName !== undefined ? archFromAssetName(options.expectedAssetName) : null;
    const arch = options.arch ?? archFromName ?? resolveReleaseArch();
    const asset = manifest.assets[arch];
    const { sha256, size } = await computeFileSha256(options.binaryPath);

    if (size !== asset.size) {
      throw new UpdateError(
        "size_mismatch",
        `Binary size mismatch for ${arch}: expected ${asset.size} bytes, got ${size} bytes`,
      );
    }
    if (sha256 !== asset.sha256) {
      throw new UpdateError(
        "hash_mismatch",
        `Binary SHA-256 mismatch for ${arch}: expected ${asset.sha256}, got ${sha256}`,
      );
    }
    if (options.sha256 !== undefined && sha256 !== options.sha256.toLowerCase()) {
      throw new UpdateError(
        "hash_mismatch",
        `Binary SHA-256 mismatch: expected ${options.sha256}, got ${sha256}`,
      );
    }

    return {
      ok: true,
      mode: "manifest",
      sha256,
      size,
      arch,
      manifest,
    };
  }

  if (options.sha256SumsContent !== undefined && options.sha256SumsSig !== undefined) {
    if (!verifySha256Sums(options.sha256SumsContent, options.sha256SumsSig, publicKey)) {
      throw new UpdateError(
        "bad_sums_signature",
        "Ed25519 signature verification failed for SHA256SUMS",
      );
    }

    const text =
      typeof options.sha256SumsContent === "string"
        ? options.sha256SumsContent
        : new TextDecoder().decode(options.sha256SumsContent);
    const sums = parseSha256Sums(text);
    const assetName = options.expectedAssetName ?? basename(options.binaryPath);
    const expectedHash = sums.get(assetName);
    if (expectedHash === undefined) {
      throw new UpdateError(
        "checksum_not_found",
        `Asset "${assetName}" not found in verified SHA256SUMS`,
      );
    }

    const { sha256, size } = await computeFileSha256(options.binaryPath);
    if (sha256 !== expectedHash) {
      throw new UpdateError(
        "hash_mismatch",
        `Binary SHA-256 mismatch for ${assetName}: expected ${expectedHash}, got ${sha256}`,
      );
    }
    if (options.sha256 !== undefined && sha256 !== options.sha256.toLowerCase()) {
      throw new UpdateError(
        "hash_mismatch",
        `Binary SHA-256 mismatch: expected ${options.sha256}, got ${sha256}`,
      );
    }

    return {
      ok: true,
      mode: "sums",
      sha256,
      size,
      assetName,
    };
  }

  throw new UpdateError(
    "invalid_manifest",
    "Verification requires either manifestContent or both sha256SumsContent and sha256SumsSig",
  );
}
