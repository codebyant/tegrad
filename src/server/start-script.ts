// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { writeFileAtomic } from "../agent/state";
import {
  MAX_JVM_ARGS,
  MAX_SERVER_MEMORY_MB,
  MIN_SERVER_MEMORY_MB,
  ProtocolError,
} from "../protocol";
import { resolveServerSubpath } from "./id";
import {
  finalizeServerPath,
  type PermissionContext,
  SERVER_DIR_MODE,
  SERVER_EXEC_MODE,
} from "./permissions";

export const MAX_JVM_ARG_LENGTH = 256;

const FORBIDDEN_CHARS_REGEX = /[\s\0'"`;|&$\\()<>]/;
const XSS_REGEX = /^-Xss[1-9][0-9]{0,5}[kKmM]$/;
const XX_BOOL_REGEX = /^-XX:[+-]([A-Za-z][A-Za-z0-9]*)$/;
const XX_VALUE_REGEX = /^-XX:([A-Za-z][A-Za-z0-9]*)=([0-9]+[kKmMgG]?)$/;
const SYS_PROP_REGEX = /^-D([a-zA-Z0-9_.-]{1,64})=([a-zA-Z0-9_.:/-]{1,128})$/;

const SAFE_JAR_RELATIVE_PATH_REGEX =
  /^[a-zA-Z0-9][a-zA-Z0-9._+-]*(?:\/[a-zA-Z0-9][a-zA-Z0-9._+-]*)*\.jar$/;
const SAFE_ARGS_FILE_RELATIVE_PATH_REGEX =
  /^libraries\/net\/(?:minecraftforge\/forge|neoforged\/neoforge)\/[a-zA-Z0-9._+-]+\/unix_args\.txt$/;

export const ALLOWED_XX_BOOLEAN_FLAGS: ReadonlySet<string> = new Set([
  "UseG1GC",
  "UseZGC",
  "ZGenerational",
  "ParallelRefProcEnabled",
  "UnlockExperimentalVMOptions",
  "ExplicitGCInvokesConcurrent",
  "AlwaysPreTouch",
  "UseStringDeduplication",
  "DisableExplicitGC",
  "PerfDisableSharedMem",
  "UseNUMA",
  "UseLargePages",
  "UseCompressedOops",
  "OptimizeStringConcat",
  "UseParallelGC",
  "UseSerialGC",
  "AlwaysActAsServerClassMachine",
]);

export const ALLOWED_XX_VALUE_KEYS: ReadonlySet<string> = new Set([
  "MaxGCPauseMillis",
  "G1NewSizePercent",
  "G1MaxNewSizePercent",
  "G1HeapRegionSize",
  "G1ReservePercent",
  "G1HeapWastePercent",
  "G1MixedGCCountTarget",
  "InitiatingHeapOccupancyPercent",
  "G1MixedGCLiveThresholdPercent",
  "G1RSetUpdatingPauseTimePercent",
  "SurvivorRatio",
  "MaxTenuringThreshold",
  "ActiveProcessorCount",
  "ParallelGCThreads",
  "ConcGCThreads",
  "NewRatio",
  "SoftRefLRUPolicyMSPerMB",
]);

const BLOCKED_EXACT_OR_PREFIX_FLAGS: readonly string[] = [
  "-javaagent",
  "-agentlib",
  "-agentpath",
  "-cp",
  "-classpath",
  "--class-path",
  "-jar",
  "-p",
  "--module-path",
  "--upgrade-module-path",
  "--patch-module",
  "--add-opens",
  "--add-exports",
  "--add-reads",
  "--add-modules",
  "-XX:OnOutOfMemoryError",
  "-XX:OnError",
  "-XX:ErrorFile",
  "-XX:HeapDumpPath",
  "-XX:LogFile",
  "-XX:CompileCommandFile",
  "-XX:SharedArchiveFile",
  "-Xbootclasspath",
  "-Xlog",
  "-Xms",
  "-Xmx",
];

const BLOCKED_SYSTEM_PROPERTY_PREFIXES: readonly string[] = [
  "java.security.",
  "java.rmi.",
  "java.naming.",
  "java.util.logging.",
  "java.protocol.",
  "java.net.",
  "com.sun.",
  "javax.",
  "sun.",
  "jdk.",
  "org.apache.logging.log4j.",
  "log4j.",
  "log4j2.",
  "logback.",
  "http.",
  "https.",
  "ftp.",
  "socks",
];

const BLOCKED_SYSTEM_PROPERTY_NAMES: ReadonlySet<string> = new Set([
  "jdk.serialfilter",
  "java.library.path",
  "java.class.path",
  "java.ext.dirs",
  "java.endorsed.dirs",
  "user.dir",
  "user.home",
  "java.io.tmpdir",
  "java.security.manager",
  "java.security.policy",
]);

export type ServerLaunchTarget =
  | { readonly kind: "jar"; readonly jar_relative_path: string }
  | { readonly kind: "args_file"; readonly args_file_relative_path: string };

export function validateSingleJvmArg(arg: string): string {
  if (arg.length === 0 || arg.length > MAX_JVM_ARG_LENGTH) {
    throw new ProtocolError("invalid_jvm_args", "JVM argument length out of range");
  }

  if (FORBIDDEN_CHARS_REGEX.test(arg)) {
    throw new ProtocolError("invalid_jvm_args", "JVM argument contains forbidden characters");
  }

  if (arg.startsWith("@")) {
    throw new ProtocolError("invalid_jvm_args", "JVM argument files (@file) are not allowed");
  }

  const lower = arg.toLowerCase();
  for (const blocked of BLOCKED_EXACT_OR_PREFIX_FLAGS) {
    const blockedLower = blocked.toLowerCase();
    if (
      lower === blockedLower ||
      lower.startsWith(`${blockedLower}:`) ||
      lower.startsWith(`${blockedLower}=`) ||
      (blockedLower === "-xms" && lower.startsWith("-xms")) ||
      (blockedLower === "-xmx" && lower.startsWith("-xmx")) ||
      (blockedLower === "-xbootclasspath" && lower.startsWith("-xbootclasspath"))
    ) {
      throw new ProtocolError("invalid_jvm_args", `JVM flag is not permitted: ${blocked}`);
    }
  }

  if (XSS_REGEX.test(arg)) {
    return arg;
  }

  const boolMatch = XX_BOOL_REGEX.exec(arg);
  if (boolMatch !== null) {
    const flagName = boolMatch[1] ?? "";
    if (!ALLOWED_XX_BOOLEAN_FLAGS.has(flagName)) {
      throw new ProtocolError(
        "invalid_jvm_args",
        `JVM boolean flag is not allowlisted: ${flagName}`,
      );
    }
    return arg;
  }

  const valueMatch = XX_VALUE_REGEX.exec(arg);
  if (valueMatch !== null) {
    const key = valueMatch[1] ?? "";
    if (!ALLOWED_XX_VALUE_KEYS.has(key)) {
      throw new ProtocolError("invalid_jvm_args", `JVM value flag is not allowlisted: ${key}`);
    }
    return arg;
  }

  const propMatch = SYS_PROP_REGEX.exec(arg);
  if (propMatch !== null) {
    const name = propMatch[1] ?? "";
    const value = propMatch[2] ?? "";
    const nameLower = name.toLowerCase();

    if (value.includes("..")) {
      throw new ProtocolError("invalid_jvm_args", "System property value must not contain '..'");
    }

    if (nameLower === "log4j2.formatmsgnolookups") {
      if (value !== "true") {
        throw new ProtocolError(
          "invalid_jvm_args",
          "log4j2.formatMsgNoLookups may only be set to true",
        );
      }
      return arg;
    }

    if (BLOCKED_SYSTEM_PROPERTY_NAMES.has(nameLower)) {
      throw new ProtocolError("invalid_jvm_args", `System property is blocked: ${name}`);
    }

    for (const prefix of BLOCKED_SYSTEM_PROPERTY_PREFIXES) {
      if (nameLower.startsWith(prefix)) {
        throw new ProtocolError(
          "invalid_jvm_args",
          `System property namespace is blocked: ${name}`,
        );
      }
    }

    return arg;
  }

  throw new ProtocolError("invalid_jvm_args", "JVM argument is not in the allowlist");
}

export function validateJvmArgs(args: readonly string[]): readonly string[] {
  if (args.length > MAX_JVM_ARGS) {
    throw new ProtocolError("invalid_jvm_args", `Too many JVM arguments (max ${MAX_JVM_ARGS})`);
  }
  return args.map((arg) => validateSingleJvmArg(arg));
}

export function posixSingleQuote(value: string): string {
  if (/[\r\n\0]/.test(value)) {
    throw new ProtocolError("invalid_body", "Shell token must not contain CR, LF, or NUL");
  }
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function joinPosixPath(baseDir: string, relativePath: string): string {
  const normalizedBase = baseDir.replaceAll("\\", "/").replace(/\/+$/, "");
  const normalizedRel = relativePath.replaceAll("\\", "/").replace(/^\/+/, "");
  return `${normalizedBase}/${normalizedRel}`;
}

export function validateLaunchTarget(target: ServerLaunchTarget): ServerLaunchTarget {
  if (target.kind === "jar") {
    if (
      target.jar_relative_path.includes("..") ||
      !SAFE_JAR_RELATIVE_PATH_REGEX.test(target.jar_relative_path)
    ) {
      throw new ProtocolError("invalid_body", "Invalid server JAR launch target path");
    }
    return target;
  }

  if (
    target.args_file_relative_path.includes("..") ||
    !SAFE_ARGS_FILE_RELATIVE_PATH_REGEX.test(target.args_file_relative_path)
  ) {
    throw new ProtocolError("invalid_body", "Invalid server args file launch target path");
  }
  return target;
}

export interface RenderStartScriptParams {
  readonly javaBin: string;
  readonly memoryMb: number;
  readonly jvmArgs: readonly string[];
  readonly serverDir: string;
  readonly launchTarget: ServerLaunchTarget;
}

export function renderStartScript(params: RenderStartScriptParams): string {
  if (
    !Number.isInteger(params.memoryMb) ||
    params.memoryMb < MIN_SERVER_MEMORY_MB ||
    params.memoryMb > MAX_SERVER_MEMORY_MB
  ) {
    throw new ProtocolError("invalid_body", "Invalid server memory_mb");
  }

  if (params.javaBin.trim().length === 0 || /[\r\n\0]/.test(params.javaBin)) {
    throw new ProtocolError("invalid_body", "Invalid java binary path");
  }

  if (params.serverDir.trim().length === 0 || /[\r\n\0]/.test(params.serverDir)) {
    throw new ProtocolError("invalid_body", "Invalid server directory path");
  }

  const safeJvmArgs = validateJvmArgs(params.jvmArgs);
  const safeTarget = validateLaunchTarget(params.launchTarget);

  const tokens: string[] = [
    posixSingleQuote(params.javaBin),
    `-Xms${params.memoryMb}M`,
    `-Xmx${params.memoryMb}M`,
    ...safeJvmArgs.map((arg) => posixSingleQuote(arg)),
  ];

  if (safeTarget.kind === "jar") {
    const fullJarPath = joinPosixPath(params.serverDir, safeTarget.jar_relative_path);
    tokens.push("-jar", posixSingleQuote(fullJarPath), "nogui");
  } else {
    tokens.push(posixSingleQuote(`@${safeTarget.args_file_relative_path}`), "nogui");
  }

  return `#!/bin/sh\nset -eu\nexec ${tokens.join(" ")}\n`;
}

export function writeStartScript(
  serverDir: string,
  params: Omit<RenderStartScriptParams, "serverDir"> & {
    readonly scriptServerDir?: string;
    readonly permissions?: PermissionContext;
  },
): string {
  const safeTarget = validateLaunchTarget(params.launchTarget);
  resolveServerSubpath(
    serverDir,
    safeTarget.kind === "jar" ? safeTarget.jar_relative_path : safeTarget.args_file_relative_path,
  );
  const script = renderStartScript({
    javaBin: params.javaBin,
    memoryMb: params.memoryMb,
    jvmArgs: params.jvmArgs,
    serverDir: params.scriptServerDir ?? serverDir,
    launchTarget: safeTarget,
  });
  const startScriptPath = resolveServerSubpath(serverDir, "start.sh");
  writeFileAtomic(startScriptPath, script, {
    mode: SERVER_EXEC_MODE,
    dirMode: SERVER_DIR_MODE,
  });
  if (params.permissions !== undefined) {
    finalizeServerPath(startScriptPath, SERVER_EXEC_MODE, params.permissions);
  }
  return startScriptPath;
}
