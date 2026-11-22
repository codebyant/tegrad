// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { randomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { z } from "zod";
import { type RunFixedOptions, type RunFixedResult, runFixed } from "../agent/exec";
import { ProtocolError } from "../protocol";
import {
  DEFAULT_MAX_BINARY_BYTES,
  downloadVerifiedFile,
  type FetchLike,
  fetchJsonWithAllowlist,
} from "./download";

export type JavaMajor = 8 | 16 | 17 | 21;

export type RunFixedLike = (
  command: string,
  args: readonly string[],
  options?: RunFixedOptions,
) => Promise<RunFixedResult>;

export const ADOPTIUM_ALLOWED_HOSTS: ReadonlySet<string> = new Set([
  "api.adoptium.net",
  "github.com",
  "objects.githubusercontent.com",
  "release-assets.githubusercontent.com",
]);

const RUNTIME_DIR_MODE = 0o750;
const RUNTIME_BIN_MODE = 0o750;

const adoptiumAssetSchema = z.object({
  binary: z.object({
    package: z.object({
      link: z.string().min(1),
      checksum: z.string().min(1),
      size: z.number().int().positive().optional(),
    }),
  }),
});

const adoptiumAssetsResponseSchema = z.array(adoptiumAssetSchema);

const STANDARD_MC_VERSION_REGEX = /^(\d+)\.(\d+)(?:\.(\d+))?(?:[-+].*)?$/;
const SNAPSHOT_MC_VERSION_REGEX = /^(\d{2})w(\d{2})[a-z]$/i;

function isPosix(platform: NodeJS.Platform = process.platform): boolean {
  return platform !== "win32";
}

export function selectJavaMajor(minecraftVersion: string): JavaMajor {
  const trimmed = minecraftVersion.trim();

  const stdMatch = STANDARD_MC_VERSION_REGEX.exec(trimmed);
  if (stdMatch !== null) {
    const major = Number(stdMatch[1]);
    const minor = Number(stdMatch[2]);
    const patch = stdMatch[3] !== undefined ? Number(stdMatch[3]) : 0;

    if (major >= 2) {
      return 21;
    }
    if (major === 1) {
      if (minor <= 16) {
        return 8;
      }
      if (minor === 17) {
        return 16;
      }
      if (minor <= 19) {
        return 17;
      }
      if (minor === 20) {
        return patch >= 5 ? 21 : 17;
      }
      return 21;
    }
  }

  const snapMatch = SNAPSHOT_MC_VERSION_REGEX.exec(trimmed);
  if (snapMatch !== null) {
    const year = Number(snapMatch[1]);
    const week = Number(snapMatch[2]);
    if (year > 24 || (year === 24 && week >= 14)) {
      return 21;
    }
    if (year > 21 || (year === 21 && week >= 37)) {
      return 17;
    }
    if (year === 21 && week >= 19) {
      return 16;
    }
    return 8;
  }

  throw new ProtocolError(
    "invalid_body",
    `Unsupported Minecraft version format for Java selection: ${minecraftVersion}`,
  );
}

export function resolveAdoptiumArch(nodeArch: string = process.arch): "x64" | "aarch64" {
  if (nodeArch === "arm64") {
    return "aarch64";
  }
  return "x64";
}

export function getRuntimeJavaDir(serversDir: string, major: JavaMajor): string {
  return join(resolve(serversDir), ".runtime", "java", String(major));
}

export function getJavaBinPath(
  serversDir: string,
  major: JavaMajor,
  platform: NodeJS.Platform = process.platform,
): string {
  const binName = platform === "win32" ? "java.exe" : "java";
  return join(getRuntimeJavaDir(serversDir, major), "bin", binName);
}

function findExtractedJavaRoot(extractDir: string, binName: string): string | null {
  if (existsSync(join(extractDir, "bin", binName))) {
    return extractDir;
  }
  const entries = readdirSync(extractDir, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }
    const candidate = join(extractDir, entry.name);
    if (existsSync(join(candidate, "bin", binName))) {
      return candidate;
    }
  }
  return null;
}

function applyRuntimePermissions(dirPath: string): void {
  if (!isPosix()) {
    return;
  }
  chmodSync(dirPath, RUNTIME_DIR_MODE);
  const binDir = join(dirPath, "bin");
  if (existsSync(binDir)) {
    chmodSync(binDir, RUNTIME_DIR_MODE);
    for (const entry of readdirSync(binDir, { withFileTypes: true })) {
      const fullPath = join(binDir, entry.name);
      if (entry.isFile()) {
        chmodSync(fullPath, RUNTIME_BIN_MODE);
      }
    }
  }
}

export interface EnsureJavaRuntimeOptions {
  readonly serversDir: string;
  readonly minecraftVersion: string;
  readonly arch?: "x64" | "aarch64";
  readonly fetchImpl?: FetchLike;
  readonly runFixedImpl?: RunFixedLike;
  readonly maxBytes?: number;
  readonly platform?: NodeJS.Platform;
}

export interface ManagedJavaRuntime {
  readonly major: JavaMajor;
  readonly javaDir: string;
  readonly javaBin: string;
}

async function queryAdoptiumAsset(
  major: JavaMajor,
  arch: "x64" | "aarch64",
  fetchImpl?: FetchLike,
): Promise<{ readonly link: string; readonly checksum: string }> {
  const imageTypes: readonly ("jre" | "jdk")[] = ["jre", "jdk"];
  let lastError: unknown;

  for (const imageType of imageTypes) {
    const url = `https://api.adoptium.net/v3/assets/latest/${major}/hotspot?architecture=${arch}&image_type=${imageType}&os=linux&vendor=eclipse`;
    try {
      const assets = await fetchJsonWithAllowlist(url, adoptiumAssetsResponseSchema, {
        allowedHosts: ADOPTIUM_ALLOWED_HOSTS,
        ...(fetchImpl !== undefined ? { fetchImpl } : {}),
      });
      const first = assets[0];
      if (first !== undefined) {
        return {
          link: first.binary.package.link,
          checksum: first.binary.package.checksum,
        };
      }
    } catch (err) {
      lastError = err;
    }
  }

  if (lastError instanceof ProtocolError) {
    throw lastError;
  }
  throw new ProtocolError("download_failed", `No Adoptium Java ${major} runtime asset available`);
}

export async function ensureJavaRuntime(
  options: EnsureJavaRuntimeOptions,
): Promise<ManagedJavaRuntime> {
  const major = selectJavaMajor(options.minecraftVersion);
  const platform = options.platform ?? process.platform;
  const binName = platform === "win32" ? "java.exe" : "java";
  const javaDir = getRuntimeJavaDir(options.serversDir, major);
  const javaBin = join(javaDir, "bin", binName);

  if (existsSync(javaBin) && statSync(javaBin).isFile()) {
    return { major, javaDir, javaBin };
  }

  const arch = options.arch ?? resolveAdoptiumArch();
  const asset = await queryAdoptiumAsset(major, arch, options.fetchImpl);

  const runtimeRoot = join(resolve(options.serversDir), ".runtime", "java");
  mkdirSync(runtimeRoot, { recursive: true, mode: RUNTIME_DIR_MODE });
  if (isPosix(platform)) {
    chmodSync(runtimeRoot, RUNTIME_DIR_MODE);
  }

  const suffix = randomBytes(8).toString("hex");
  const archivePath = join(runtimeRoot, `.tmp-java-${major}-${suffix}.tar.gz`);
  const extractDir = join(runtimeRoot, `.tmp-extract-${major}-${suffix}`);
  const runCmd: RunFixedLike = options.runFixedImpl ?? runFixed;

  try {
    await downloadVerifiedFile({
      url: asset.link,
      destPath: archivePath,
      allowedHosts: ADOPTIUM_ALLOWED_HOSTS,
      expectedHash: {
        algorithm: "sha256",
        hex: asset.checksum,
      },
      maxBytes: options.maxBytes ?? DEFAULT_MAX_BINARY_BYTES,
      fileMode: 0o640,
      dirMode: RUNTIME_DIR_MODE,
      ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
    });

    mkdirSync(extractDir, { recursive: true, mode: RUNTIME_DIR_MODE });
    const extractResult = await runCmd("tar", ["-xzf", archivePath, "-C", extractDir], {
      timeoutMs: 120_000,
    });
    if (extractResult.timedOut || extractResult.code !== 0) {
      throw new ProtocolError(
        "download_failed",
        `Failed to extract Java ${major} runtime archive (exit ${extractResult.code})`,
      );
    }

    const extractedRoot = findExtractedJavaRoot(extractDir, binName);
    if (extractedRoot === null) {
      throw new ProtocolError(
        "download_failed",
        `Extracted Java ${major} archive is missing bin/${binName}`,
      );
    }

    if (existsSync(javaDir)) {
      rmSync(javaDir, { recursive: true, force: true });
    }
    renameSync(extractedRoot, javaDir);
    applyRuntimePermissions(javaDir);

    return { major, javaDir, javaBin };
  } finally {
    if (existsSync(archivePath)) {
      rmSync(archivePath, { force: true });
    }
    if (existsSync(extractDir)) {
      rmSync(extractDir, { recursive: true, force: true });
    }
  }
}
