// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { randomBytes } from "node:crypto";
import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { runFixed } from "../agent/exec";
import { ProtocolError, type ServerLoader } from "../protocol";
import {
  DEFAULT_MAX_BINARY_BYTES,
  downloadVerifiedFile,
  type FetchLike,
  fetchJsonWithAllowlist,
  fetchSidecarHash,
  fetchTextWithAllowlist,
  type HashAlgorithm,
} from "./download";
import { resolveServerSubpath } from "./id";
import type { RunFixedLike } from "./java";
import type { ServerLaunchTarget } from "./start-script";

export const LOADER_ALLOWED_HOSTS: ReadonlySet<string> = new Set([
  "piston-meta.mojang.com",
  "launchermeta.mojang.com",
  "piston-data.mojang.com",
  "launcher.mojang.com",
  "libraries.minecraft.net",
  "meta.fabricmc.net",
  "maven.fabricmc.net",
  "meta.quiltmc.org",
  "maven.quiltmc.org",
  "maven.minecraftforge.net",
  "files.minecraftforge.net",
  "maven.neoforged.net",
]);

const mojangManifestSchema = z.object({
  versions: z.array(
    z.object({
      id: z.string().min(1),
      url: z.string().min(1),
    }),
  ),
});

const mojangVersionPackageSchema = z.object({
  downloads: z.object({
    server: z
      .object({
        sha1: z.string().min(1),
        size: z.number().int().positive().optional(),
        url: z.string().min(1),
      })
      .optional(),
  }),
});

const fabricGameVersionsSchema = z.array(
  z.object({
    version: z.string().min(1),
    stable: z.boolean().optional(),
  }),
);

const fabricLoaderVersionsSchema = z.array(
  z.object({
    version: z.string().min(1),
    stable: z.boolean().optional(),
  }),
);

const fabricInstallerVersionsSchema = z.array(
  z.object({
    version: z.string().min(1),
    url: z.string().min(1),
    stable: z.boolean().optional(),
  }),
);

const forgePromotionsSchema = z.object({
  promos: z.record(z.string(), z.string()),
});

const neoforgeVersionsSchema = z.object({
  versions: z.array(z.string().min(1)),
});

export interface InstallLoaderOptions {
  readonly serverDir: string;
  readonly minecraftVersion: string;
  readonly loader: ServerLoader;
  readonly loaderVersion?: string;
  readonly javaBin: string;
  readonly fetchImpl?: FetchLike;
  readonly runFixedImpl?: RunFixedLike;
  readonly maxBytes?: number;
}

export interface LoaderInstallResult {
  readonly loader: ServerLoader;
  readonly minecraftVersion: string;
  readonly loaderVersion: string | null;
  readonly launchTarget: ServerLaunchTarget;
}

async function fetchMavenChecksum(
  artifactUrl: string,
  fetchImpl?: FetchLike,
): Promise<{ readonly algorithm: HashAlgorithm; readonly hex: string }> {
  const opts = {
    allowedHosts: LOADER_ALLOWED_HOSTS,
    ...(fetchImpl !== undefined ? { fetchImpl } : {}),
  };

  try {
    const hex = await fetchSidecarHash(`${artifactUrl}.sha256`, "sha256", opts);
    return { algorithm: "sha256", hex };
  } catch {
    const hex = await fetchSidecarHash(`${artifactUrl}.sha1`, "sha1", opts);
    return { algorithm: "sha1", hex };
  }
}

async function installVanilla(options: InstallLoaderOptions): Promise<LoaderInstallResult> {
  const fetchOpts = {
    allowedHosts: LOADER_ALLOWED_HOSTS,
    ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
  };

  const manifest = await fetchJsonWithAllowlist(
    "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json",
    mojangManifestSchema,
    fetchOpts,
  );

  const versionEntry = manifest.versions.find((v) => v.id === options.minecraftVersion);
  if (!versionEntry) {
    throw new ProtocolError(
      "download_failed",
      `Minecraft version not found in official Mojang manifest: ${options.minecraftVersion}`,
    );
  }

  const versionPkg = await fetchJsonWithAllowlist(
    versionEntry.url,
    mojangVersionPackageSchema,
    fetchOpts,
  );

  const serverDownload = versionPkg.downloads.server;
  if (!serverDownload) {
    throw new ProtocolError(
      "download_failed",
      `No official server JAR available for Minecraft ${versionEntry.id}`,
    );
  }

  const destPath = resolveServerSubpath(options.serverDir, "server.jar");
  await downloadVerifiedFile({
    url: serverDownload.url,
    destPath,
    expectedHash: {
      algorithm: "sha1",
      hex: serverDownload.sha1,
    },
    maxBytes: options.maxBytes ?? DEFAULT_MAX_BINARY_BYTES,
    ...fetchOpts,
  });

  return {
    loader: "vanilla",
    minecraftVersion: versionEntry.id,
    loaderVersion: null,
    launchTarget: {
      kind: "jar",
      jar_relative_path: "server.jar",
    },
  };
}

async function installFabric(options: InstallLoaderOptions): Promise<LoaderInstallResult> {
  const fetchOpts = {
    allowedHosts: LOADER_ALLOWED_HOSTS,
    ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
  };
  const runCmd: RunFixedLike = options.runFixedImpl ?? runFixed;

  const gameVersions = await fetchJsonWithAllowlist(
    "https://meta.fabricmc.net/v2/versions/game",
    fabricGameVersionsSchema,
    fetchOpts,
  );
  const matchedGame = gameVersions.find((v) => v.version === options.minecraftVersion);
  if (!matchedGame) {
    throw new ProtocolError(
      "download_failed",
      `Minecraft version not supported by Fabric: ${options.minecraftVersion}`,
    );
  }

  const loaderVersions = await fetchJsonWithAllowlist(
    "https://meta.fabricmc.net/v2/versions/loader",
    fabricLoaderVersionsSchema,
    fetchOpts,
  );
  const matchedLoader =
    options.loaderVersion !== undefined
      ? loaderVersions.find((v) => v.version === options.loaderVersion)
      : (loaderVersions.find((v) => v.stable === true) ?? loaderVersions[0]);
  if (!matchedLoader) {
    throw new ProtocolError(
      "download_failed",
      `Fabric loader version not found: ${options.loaderVersion ?? "latest"}`,
    );
  }

  const installers = await fetchJsonWithAllowlist(
    "https://meta.fabricmc.net/v2/versions/installer",
    fabricInstallerVersionsSchema,
    fetchOpts,
  );
  const installer = installers.find((v) => v.stable === true) ?? installers[0];
  if (!installer) {
    throw new ProtocolError("download_failed", "No Fabric installer available");
  }

  const expectedHash = await fetchMavenChecksum(installer.url, options.fetchImpl);
  const installerPath = join(
    options.serverDir,
    `.tmp-fabric-installer-${randomBytes(6).toString("hex")}.jar`,
  );

  try {
    await downloadVerifiedFile({
      url: installer.url,
      destPath: installerPath,
      expectedHash,
      maxBytes: options.maxBytes ?? DEFAULT_MAX_BINARY_BYTES,
      ...fetchOpts,
    });

    const result = await runCmd(
      options.javaBin,
      [
        "-jar",
        installerPath,
        "server",
        "-mcversion",
        matchedGame.version,
        "-loader",
        matchedLoader.version,
        "-downloadMinecraft",
        "-dir",
        options.serverDir,
      ],
      { timeoutMs: 300_000 },
    );

    if (result.timedOut || result.code !== 0) {
      throw new ProtocolError(
        "download_failed",
        `Fabric server installer failed (exit ${result.code})`,
      );
    }
  } finally {
    if (existsSync(installerPath)) {
      rmSync(installerPath, { force: true });
    }
  }

  const launchJar = existsSync(join(options.serverDir, "fabric-server-launch.jar"))
    ? "fabric-server-launch.jar"
    : "server.jar";

  return {
    loader: "fabric",
    minecraftVersion: matchedGame.version,
    loaderVersion: matchedLoader.version,
    launchTarget: {
      kind: "jar",
      jar_relative_path: launchJar,
    },
  };
}

async function installQuilt(options: InstallLoaderOptions): Promise<LoaderInstallResult> {
  const fetchOpts = {
    allowedHosts: LOADER_ALLOWED_HOSTS,
    ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
  };
  const runCmd: RunFixedLike = options.runFixedImpl ?? runFixed;

  const gameVersions = await fetchJsonWithAllowlist(
    "https://meta.quiltmc.org/v3/versions/game",
    fabricGameVersionsSchema,
    fetchOpts,
  );
  const matchedGame = gameVersions.find((v) => v.version === options.minecraftVersion);
  if (!matchedGame) {
    throw new ProtocolError(
      "download_failed",
      `Minecraft version not supported by Quilt: ${options.minecraftVersion}`,
    );
  }

  const loaderVersions = await fetchJsonWithAllowlist(
    "https://meta.quiltmc.org/v3/versions/loader",
    fabricLoaderVersionsSchema,
    fetchOpts,
  );
  const matchedLoader =
    options.loaderVersion !== undefined
      ? loaderVersions.find((v) => v.version === options.loaderVersion)
      : (loaderVersions.find((v) => !v.version.includes("beta")) ?? loaderVersions[0]);
  if (!matchedLoader) {
    throw new ProtocolError(
      "download_failed",
      `Quilt loader version not found: ${options.loaderVersion ?? "latest"}`,
    );
  }

  const installers = await fetchJsonWithAllowlist(
    "https://meta.quiltmc.org/v3/versions/installer",
    fabricInstallerVersionsSchema,
    fetchOpts,
  );
  const installer = installers[0];
  if (!installer) {
    throw new ProtocolError("download_failed", "No Quilt installer available");
  }

  const expectedHash = await fetchMavenChecksum(installer.url, options.fetchImpl);
  const installerPath = join(
    options.serverDir,
    `.tmp-quilt-installer-${randomBytes(6).toString("hex")}.jar`,
  );

  try {
    await downloadVerifiedFile({
      url: installer.url,
      destPath: installerPath,
      expectedHash,
      maxBytes: options.maxBytes ?? DEFAULT_MAX_BINARY_BYTES,
      ...fetchOpts,
    });

    const result = await runCmd(
      options.javaBin,
      [
        "-jar",
        installerPath,
        "install",
        "server",
        matchedGame.version,
        matchedLoader.version,
        "--download-server",
        `--install-dir=${options.serverDir}`,
      ],
      { timeoutMs: 300_000 },
    );

    if (result.timedOut || result.code !== 0) {
      throw new ProtocolError(
        "download_failed",
        `Quilt server installer failed (exit ${result.code})`,
      );
    }
  } finally {
    if (existsSync(installerPath)) {
      rmSync(installerPath, { force: true });
    }
  }

  const launchJar = existsSync(join(options.serverDir, "quilt-server-launch.jar"))
    ? "quilt-server-launch.jar"
    : "server.jar";

  return {
    loader: "quilt",
    minecraftVersion: matchedGame.version,
    loaderVersion: matchedLoader.version,
    launchTarget: {
      kind: "jar",
      jar_relative_path: launchJar,
    },
  };
}

function parseMavenMetadataVersions(xml: string): string[] {
  const versions: string[] = [];
  const regex = /<version>([^<]+)<\/version>/g;
  let match = regex.exec(xml);
  while (match !== null) {
    const val = match[1]?.trim();
    if (val) {
      versions.push(val);
    }
    match = regex.exec(xml);
  }
  return versions;
}

async function resolveForgeFullVersion(
  minecraftVersion: string,
  loaderVersion: string | undefined,
  fetchImpl?: FetchLike,
): Promise<{ readonly fullVersion: string; readonly forgeVersion: string }> {
  const fetchOpts = {
    allowedHosts: LOADER_ALLOWED_HOSTS,
    ...(fetchImpl !== undefined ? { fetchImpl } : {}),
  };

  if (loaderVersion !== undefined) {
    const metadataXml = await fetchTextWithAllowlist(
      "https://maven.minecraftforge.net/net/minecraftforge/forge/maven-metadata.xml",
      fetchOpts,
    );
    const available = parseMavenMetadataVersions(metadataXml);
    const candidate = loaderVersion.startsWith(`${minecraftVersion}-`)
      ? loaderVersion
      : `${minecraftVersion}-${loaderVersion}`;
    const exact = available.find((v) => v === candidate);
    if (!exact) {
      throw new ProtocolError(
        "download_failed",
        `Forge version not found in official Maven metadata: ${candidate}`,
      );
    }
    const forgeOnly = exact.startsWith(`${minecraftVersion}-`)
      ? exact.slice(minecraftVersion.length + 1)
      : exact;
    return { fullVersion: exact, forgeVersion: forgeOnly };
  }

  const promos = await fetchJsonWithAllowlist(
    "https://files.minecraftforge.net/net/minecraftforge/forge/promotions_slim.json",
    forgePromotionsSchema,
    fetchOpts,
  );
  const recommended = promos.promos[`${minecraftVersion}-recommended`];
  const latest = promos.promos[`${minecraftVersion}-latest`];
  const chosen = recommended ?? latest;
  if (!chosen) {
    throw new ProtocolError(
      "download_failed",
      `No Forge build available for Minecraft ${minecraftVersion}`,
    );
  }
  return {
    fullVersion: `${minecraftVersion}-${chosen}`,
    forgeVersion: chosen,
  };
}

async function installForge(options: InstallLoaderOptions): Promise<LoaderInstallResult> {
  const fetchOpts = {
    allowedHosts: LOADER_ALLOWED_HOSTS,
    ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
  };
  const runCmd: RunFixedLike = options.runFixedImpl ?? runFixed;

  const { fullVersion, forgeVersion } = await resolveForgeFullVersion(
    options.minecraftVersion,
    options.loaderVersion,
    options.fetchImpl,
  );

  const installerUrl = `https://maven.minecraftforge.net/net/minecraftforge/forge/${fullVersion}/forge-${fullVersion}-installer.jar`;
  const expectedHash = await fetchMavenChecksum(installerUrl, options.fetchImpl);
  const installerPath = join(
    options.serverDir,
    `.tmp-forge-installer-${randomBytes(6).toString("hex")}.jar`,
  );

  try {
    await downloadVerifiedFile({
      url: installerUrl,
      destPath: installerPath,
      expectedHash,
      maxBytes: options.maxBytes ?? DEFAULT_MAX_BINARY_BYTES,
      ...fetchOpts,
    });

    const result = await runCmd(
      options.javaBin,
      ["-jar", installerPath, "--installServer", options.serverDir],
      { timeoutMs: 300_000 },
    );

    if (result.timedOut || result.code !== 0) {
      throw new ProtocolError(
        "download_failed",
        `Forge server installer failed (exit ${result.code})`,
      );
    }
  } finally {
    if (existsSync(installerPath)) {
      rmSync(installerPath, { force: true });
    }
  }

  const unixArgsRel = `libraries/net/minecraftforge/forge/${fullVersion}/unix_args.txt`;
  const unixArgsAbs = resolveServerSubpath(options.serverDir, unixArgsRel);
  if (existsSync(unixArgsAbs)) {
    return {
      loader: "forge",
      minecraftVersion: options.minecraftVersion,
      loaderVersion: forgeVersion,
      launchTarget: {
        kind: "args_file",
        args_file_relative_path: unixArgsRel,
      },
    };
  }

  const legacyJar = `forge-${fullVersion}.jar`;
  const launchJar = existsSync(join(options.serverDir, legacyJar)) ? legacyJar : "server.jar";
  return {
    loader: "forge",
    minecraftVersion: options.minecraftVersion,
    loaderVersion: forgeVersion,
    launchTarget: {
      kind: "jar",
      jar_relative_path: launchJar,
    },
  };
}

function neoForgePrefixForMinecraft(minecraftVersion: string): string | null {
  const match = /^1\.(\d+)(?:\.(\d+))?$/.exec(minecraftVersion.trim());
  if (!match) {
    return null;
  }
  const minor = match[1];
  const patch = match[2] ?? "0";
  return `${minor}.${patch}.`;
}

async function installNeoForge(options: InstallLoaderOptions): Promise<LoaderInstallResult> {
  const fetchOpts = {
    allowedHosts: LOADER_ALLOWED_HOSTS,
    ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
  };
  const runCmd: RunFixedLike = options.runFixedImpl ?? runFixed;

  const versionsData = await fetchJsonWithAllowlist(
    "https://maven.neoforged.net/api/maven/versions/releases/net/neoforged/neoforge",
    neoforgeVersionsSchema,
    fetchOpts,
  );

  let exactVersion: string | undefined;
  if (options.loaderVersion !== undefined) {
    exactVersion = versionsData.versions.find((v) => v === options.loaderVersion);
  } else {
    const prefix = neoForgePrefixForMinecraft(options.minecraftVersion);
    if (prefix !== null) {
      const matching = versionsData.versions.filter((v) => v.startsWith(prefix));
      exactVersion = matching[matching.length - 1];
    }
  }

  if (!exactVersion) {
    throw new ProtocolError(
      "download_failed",
      `NeoForge version not found for Minecraft ${options.minecraftVersion}`,
    );
  }

  const installerUrl = `https://maven.neoforged.net/releases/net/neoforged/neoforge/${exactVersion}/neoforge-${exactVersion}-installer.jar`;
  const expectedHash = await fetchMavenChecksum(installerUrl, options.fetchImpl);
  const installerPath = join(
    options.serverDir,
    `.tmp-neoforge-installer-${randomBytes(6).toString("hex")}.jar`,
  );

  try {
    await downloadVerifiedFile({
      url: installerUrl,
      destPath: installerPath,
      expectedHash,
      maxBytes: options.maxBytes ?? DEFAULT_MAX_BINARY_BYTES,
      ...fetchOpts,
    });

    const result = await runCmd(
      options.javaBin,
      ["-jar", installerPath, "--installServer", options.serverDir],
      { timeoutMs: 300_000 },
    );

    if (result.timedOut || result.code !== 0) {
      throw new ProtocolError(
        "download_failed",
        `NeoForge server installer failed (exit ${result.code})`,
      );
    }
  } finally {
    if (existsSync(installerPath)) {
      rmSync(installerPath, { force: true });
    }
  }

  const unixArgsRel = `libraries/net/neoforged/neoforge/${exactVersion}/unix_args.txt`;
  resolveServerSubpath(options.serverDir, unixArgsRel);

  return {
    loader: "neoforge",
    minecraftVersion: options.minecraftVersion,
    loaderVersion: exactVersion,
    launchTarget: {
      kind: "args_file",
      args_file_relative_path: unixArgsRel,
    },
  };
}

export async function installServerLoader(
  options: InstallLoaderOptions,
): Promise<LoaderInstallResult> {
  switch (options.loader) {
    case "vanilla":
      return installVanilla(options);
    case "fabric":
      return installFabric(options);
    case "quilt":
      return installQuilt(options);
    case "forge":
      return installForge(options);
    case "neoforge":
      return installNeoForge(options);
  }
}
