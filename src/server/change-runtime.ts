// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync } from "node:fs";
import { join } from "node:path";
import type { Logger } from "../agent/logger";
import { writeFileAtomic } from "../agent/state";
import {
  ProtocolError,
  type ServerChangeRuntimeBody,
  serverChangeRuntimeBodySchema,
} from "../protocol";
import type { FetchLike } from "./download";
import { assertValidServerId, resolveServerDir, resolveServerSubpath } from "./id";
import { ensureJavaRuntime, type RunFixedLike, selectJavaMajor } from "./java";
import { assertSafeVersionToken, installServerLoader } from "./loaders";
import {
  assertServerPathsUsable,
  finalizeServerPath,
  type PermissionContext,
  SERVER_DIR_MODE,
  SERVER_EXEC_MODE,
  SERVER_FILE_MODE,
  SERVER_TREE_PLAN,
  secureTree,
} from "./permissions";
import {
  getEffectiveLaunchTarget,
  readServerMetadata,
  SERVER_METADATA_FILE,
  type ServerMetadata,
  writeServerMetadata,
} from "./registry";
import { writeStartScript } from "./start-script";
import { getUnitStatus, isUnitStopped } from "./systemd";

const PROTECTED_USER_PATHS: ReadonlySet<string> = new Set([
  "mods",
  "config",
  "world",
  "world_nether",
  "world_the_end",
  "logs",
  "server.properties",
  "eula.txt",
  "tegrad-server.json",
  "start.sh",
  "whitelist.json",
  "ops.json",
  "banned-players.json",
  "banned-ips.json",
  "usercache.json",
  "permissions.json",
]);

const KNOWN_OLD_RUNTIME_NAMES: ReadonlySet<string> = new Set([
  "libraries",
  ".fabric",
  ".quilt",
  "server.jar",
  "fabric-server-launch.jar",
  "fabric-server-launcher.properties",
  "quilt-server-launch.jar",
  "run.sh",
  "run.bat",
  "user_jvm_args.txt",
]);

const OLD_RUNTIME_JAR_PATTERNS: readonly RegExp[] = [
  /^(?:forge|neoforge)-.+\.jar$/i,
  /^minecraft_server\..+\.jar$/i,
];

function isRemovableOldRuntimeEntry(name: string, previousJarTopSegment: string | null): boolean {
  if (PROTECTED_USER_PATHS.has(name) || name.startsWith(".tmp-")) {
    return false;
  }
  if (KNOWN_OLD_RUNTIME_NAMES.has(name) || name === previousJarTopSegment) {
    return true;
  }
  return OLD_RUNTIME_JAR_PATTERNS.some((pattern) => pattern.test(name));
}

function collectPreviousJarInfo(existing: ServerMetadata): {
  readonly topSegment: string | null;
  readonly nestedRelPath: string | null;
} {
  const target = getEffectiveLaunchTarget(existing);
  if (target.kind !== "jar") {
    return { topSegment: null, nestedRelPath: null };
  }
  const rel = target.jar_relative_path;
  if (!rel.includes("/")) {
    return { topSegment: rel, nestedRelPath: null };
  }
  const firstSegment = rel.split("/")[0] ?? "";
  if (firstSegment === "libraries" || PROTECTED_USER_PATHS.has(firstSegment)) {
    return { topSegment: null, nestedRelPath: null };
  }
  return { topSegment: null, nestedRelPath: rel };
}

export interface ChangeServerRuntimeDeps {
  readonly serversDir: string;
  readonly platform: NodeJS.Platform;
  readonly permissionContext: PermissionContext;
  readonly fetchImpl?: FetchLike;
  readonly runFixedImpl?: RunFixedLike;
  readonly backupBeforeChange?: (serverId: string) => Promise<void>;
  readonly logger?: Logger;
}

export async function changeServerRuntime(
  params: ServerChangeRuntimeBody,
  deps: ChangeServerRuntimeDeps,
): Promise<ServerMetadata> {
  const validId = assertValidServerId(params.server_id);
  const parsed = serverChangeRuntimeBodySchema.safeParse(params);
  if (!parsed.success) {
    throw new ProtocolError("invalid_body", "Invalid server.change_runtime parameters");
  }

  const existing = readServerMetadata(deps.serversDir, validId);
  const serverDir = resolveServerDir(deps.serversDir, validId);

  // Validate version tokens and Java mapping before checking backup or staging.
  selectJavaMajor(parsed.data.minecraft_version);
  assertSafeVersionToken(parsed.data.minecraft_version, "Minecraft");
  if (parsed.data.loader_version !== undefined) {
    assertSafeVersionToken(parsed.data.loader_version, "loader");
  }

  const status = await getUnitStatus(validId, deps.runFixedImpl);
  if (!isUnitStopped(status)) {
    throw new ProtocolError(
      "server_running",
      `Server must be stopped before changing runtime: ${validId}`,
    );
  }

  if (parsed.data.backup_before === true) {
    if (deps.backupBeforeChange === undefined) {
      throw new ProtocolError("backup_failed", "Local backup hook is not configured");
    }
    await deps.backupBeforeChange(validId);
  }

  const javaRuntime = await ensureJavaRuntime({
    serversDir: deps.serversDir,
    minecraftVersion: parsed.data.minecraft_version,
    platform: deps.platform,
    ...(deps.fetchImpl !== undefined ? { fetchImpl: deps.fetchImpl } : {}),
    ...(deps.runFixedImpl !== undefined ? { runFixedImpl: deps.runFixedImpl } : {}),
    permissions: deps.permissionContext,
  });

  const suffix = randomBytes(6).toString("hex");
  const stagingDir = join(serverDir, `.tmp-runtime-${suffix}`);
  const oldRuntimeDir = join(serverDir, `.tmp-runtime-old-${suffix}`);
  mkdirSync(stagingDir, { recursive: true, mode: SERVER_DIR_MODE });

  try {
    const loaderResult = await installServerLoader({
      serverDir: stagingDir,
      minecraftVersion: parsed.data.minecraft_version,
      loader: parsed.data.loader,
      javaBin: javaRuntime.javaBin,
      ...(parsed.data.loader_version !== undefined
        ? { loaderVersion: parsed.data.loader_version }
        : {}),
      ...(deps.fetchImpl !== undefined ? { fetchImpl: deps.fetchImpl } : {}),
      ...(deps.runFixedImpl !== undefined ? { runFixedImpl: deps.runFixedImpl } : {}),
    });

    const stagedNames = readdirSync(stagingDir).filter(
      (name) => !name.startsWith(".tmp-") && !PROTECTED_USER_PATHS.has(name),
    );
    const { topSegment: prevJarTopSegment, nestedRelPath: prevNestedJar } =
      collectPreviousJarInfo(existing);

    const existingNames = readdirSync(serverDir);
    const entriesToDisplace = new Set<string>();
    for (const name of existingNames) {
      if (stagedNames.includes(name) || isRemovableOldRuntimeEntry(name, prevJarTopSegment)) {
        if (!PROTECTED_USER_PATHS.has(name) && !name.startsWith(".tmp-")) {
          entriesToDisplace.add(name);
        }
      }
    }

    mkdirSync(oldRuntimeDir, { recursive: true, mode: SERVER_DIR_MODE });
    const startScriptPath = resolveServerSubpath(serverDir, "start.sh");
    const metadataPath = resolveServerSubpath(serverDir, SERVER_METADATA_FILE);
    const prevStartScript = existsSync(startScriptPath)
      ? readFileSync(startScriptPath, "utf8")
      : null;
    const prevMetaRaw = readFileSync(metadataPath, "utf8");

    const movedOld: string[] = [];
    const movedNew: string[] = [];
    let wroteStartScript = false;
    let wroteMetadata = false;

    const updated: ServerMetadata = {
      ...existing,
      minecraft_version: loaderResult.minecraftVersion,
      loader: loaderResult.loader,
      loader_version: loaderResult.loaderVersion,
      launch_target: loaderResult.launchTarget,
    };

    try {
      for (const name of entriesToDisplace) {
        const src = join(serverDir, name);
        if (existsSync(src)) {
          renameSync(src, join(oldRuntimeDir, name));
          movedOld.push(name);
        }
      }

      for (const name of stagedNames) {
        renameSync(join(stagingDir, name), join(serverDir, name));
        movedNew.push(name);
      }

      writeStartScript(serverDir, {
        javaBin: javaRuntime.javaBin,
        memoryMb: updated.memory_mb,
        jvmArgs: updated.jvm_args,
        launchTarget: loaderResult.launchTarget,
        permissions: deps.permissionContext,
      });
      wroteStartScript = true;

      writeServerMetadata(deps.serversDir, updated, deps.permissionContext);
      wroteMetadata = true;

      secureTree(serverDir, SERVER_TREE_PLAN, deps.permissionContext);

      const targetRelPath =
        loaderResult.launchTarget.kind === "jar"
          ? loaderResult.launchTarget.jar_relative_path
          : loaderResult.launchTarget.args_file_relative_path;
      assertServerPathsUsable(
        [
          { path: startScriptPath, executable: true },
          { path: join(serverDir, targetRelPath), executable: false },
          { path: javaRuntime.javaBin, executable: true },
        ],
        deps.permissionContext,
      );
    } catch (err) {
      for (const name of movedNew) {
        rmSync(join(serverDir, name), { recursive: true, force: true });
      }
      for (const name of movedOld) {
        const backupEntry = join(oldRuntimeDir, name);
        if (existsSync(backupEntry)) {
          renameSync(backupEntry, join(serverDir, name));
        }
      }
      if (wroteStartScript) {
        if (prevStartScript !== null) {
          writeFileAtomic(startScriptPath, prevStartScript, {
            mode: SERVER_EXEC_MODE,
            dirMode: SERVER_DIR_MODE,
          });
          finalizeServerPath(startScriptPath, SERVER_EXEC_MODE, deps.permissionContext);
        } else {
          rmSync(startScriptPath, { force: true });
        }
      }
      if (wroteMetadata) {
        writeFileAtomic(metadataPath, prevMetaRaw, {
          mode: SERVER_FILE_MODE,
          dirMode: SERVER_DIR_MODE,
        });
        finalizeServerPath(metadataPath, SERVER_FILE_MODE, deps.permissionContext);
      }
      throw err;
    }

    if (
      prevNestedJar !== null &&
      (loaderResult.launchTarget.kind !== "jar" ||
        loaderResult.launchTarget.jar_relative_path !== prevNestedJar)
    ) {
      const nestedAbs = resolveServerSubpath(serverDir, prevNestedJar);
      if (existsSync(nestedAbs)) {
        rmSync(nestedAbs, { force: true });
      }
    }

    deps.logger?.info("Changed Minecraft server runtime", {
      serverId: validId,
      loader: updated.loader,
      minecraftVersion: updated.minecraft_version,
      loaderVersion: updated.loader_version,
    });

    return updated;
  } finally {
    rmSync(stagingDir, { recursive: true, force: true });
    rmSync(oldRuntimeDir, { recursive: true, force: true });
  }
}
