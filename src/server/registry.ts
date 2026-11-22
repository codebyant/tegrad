// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { writeFileAtomic } from "../agent/state";
import {
  MAX_JVM_ARGS,
  ProtocolError,
  SERVER_ID_REGEX,
  serverIdSchema,
  serverLoaderSchema,
  serverMemoryMbSchema,
  serverPortSchema,
} from "../protocol";
import { resolveServerDir } from "./id";
import type { ServerLaunchTarget } from "./start-script";

export const SERVER_METADATA_FILE = "tegrad-server.json";
export const EULA_FILE = "eula.txt";
export const SERVER_PROPERTIES_FILE = "server.properties";

const SERVER_FILE_MODE = 0o640;
const SERVER_DIR_MODE = 0o750;

export const serverLaunchTargetSchema = z.discriminatedUnion("kind", [
  z
    .object({
      kind: z.literal("jar"),
      jar_relative_path: z.string().min(1),
    })
    .strict(),
  z
    .object({
      kind: z.literal("args_file"),
      args_file_relative_path: z.string().min(1),
    })
    .strict(),
]);

export const serverMetadataSchema = z
  .object({
    v: z.literal(1),
    id: serverIdSchema,
    name: z.string().trim().min(1).max(128),
    minecraft_version: z.string().min(1).max(64),
    loader: serverLoaderSchema,
    loader_version: z.string().min(1).max(64).nullable(),
    memory_mb: serverMemoryMbSchema,
    jvm_args: z.array(z.string()).max(MAX_JVM_ARGS),
    port: serverPortSchema,
    created_at: z.number().int().nonnegative(),
    launch_target: serverLaunchTargetSchema.optional(),
  })
  .strict();

export type ServerMetadata = z.infer<typeof serverMetadataSchema>;

export function getEffectiveLaunchTarget(meta: ServerMetadata): ServerLaunchTarget {
  return (
    meta.launch_target ?? {
      kind: "jar",
      jar_relative_path: "server.jar",
    }
  );
}

export function writeServerMetadata(serversDir: string, metadata: ServerMetadata): void {
  const parsed = serverMetadataSchema.safeParse(metadata);
  if (!parsed.success) {
    throw new ProtocolError("invalid_body", "Invalid server metadata");
  }
  const serverDir = resolveServerDir(serversDir, parsed.data.id);
  const metadataPath = join(serverDir, SERVER_METADATA_FILE);
  const payload = `${JSON.stringify(parsed.data, null, 2)}\n`;
  writeFileAtomic(metadataPath, payload, {
    mode: SERVER_FILE_MODE,
    dirMode: SERVER_DIR_MODE,
  });
}

export function readServerMetadata(serversDir: string, id: string): ServerMetadata {
  const serverDir = resolveServerDir(serversDir, id);
  const metadataPath = join(serverDir, SERVER_METADATA_FILE);
  if (!existsSync(metadataPath)) {
    throw new ProtocolError("server_not_found", `Server not found: ${id}`);
  }

  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(metadataPath, "utf8")) as unknown;
  } catch {
    throw new ProtocolError("invalid_format", `Corrupt metadata for server: ${id}`);
  }

  const parsed = serverMetadataSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ProtocolError("invalid_format", `Invalid metadata schema for server: ${id}`);
  }

  if (parsed.data.id !== id) {
    throw new ProtocolError("invalid_format", `Server metadata id mismatch for ${id}`);
  }

  return parsed.data;
}

export function listServerMetadata(serversDir: string): ServerMetadata[] {
  if (!existsSync(serversDir)) {
    return [];
  }

  const entries = readdirSync(serversDir, { withFileTypes: true });
  const result: ServerMetadata[] = [];

  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }
    if (!SERVER_ID_REGEX.test(entry.name)) {
      continue;
    }
    const serverDir = resolveServerDir(serversDir, entry.name);
    const metadataPath = join(serverDir, SERVER_METADATA_FILE);
    if (!existsSync(metadataPath)) {
      continue;
    }
    result.push(readServerMetadata(serversDir, entry.name));
  }

  result.sort((a, b) => a.id.localeCompare(b.id));
  return result;
}

export function writeEulaFile(serverDir: string, accepted: boolean): void {
  const eulaPath = join(serverDir, EULA_FILE);
  const content = accepted ? "eula=true\n" : "eula=false\n";
  writeFileAtomic(eulaPath, content, {
    mode: SERVER_FILE_MODE,
    dirMode: SERVER_DIR_MODE,
  });
}

export function isEulaAccepted(serverDir: string): boolean {
  const eulaPath = join(serverDir, EULA_FILE);
  if (!existsSync(eulaPath)) {
    return false;
  }

  let content: string;
  try {
    content = readFileSync(eulaPath, "utf8");
  } catch {
    return false;
  }

  for (const rawLine of content.split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (trimmed.length === 0 || trimmed.startsWith("#")) {
      continue;
    }
    const eqIndex = trimmed.indexOf("=");
    if (eqIndex === -1) {
      continue;
    }
    const key = trimmed.slice(0, eqIndex).trim().toLowerCase();
    const val = trimmed
      .slice(eqIndex + 1)
      .trim()
      .toLowerCase();
    if (key === "eula") {
      return val === "true";
    }
  }

  return false;
}

export interface UpdateServerPropertiesOptions {
  readonly port: number;
  readonly forceOnlineMode?: boolean;
}

export function writeServerProperties(
  serverDir: string,
  options: UpdateServerPropertiesOptions,
): void {
  const propsPath = join(serverDir, SERVER_PROPERTIES_FILE);
  const lines: string[] = [];

  if (existsSync(propsPath)) {
    const existing = readFileSync(propsPath, "utf8");
    for (const line of existing.split(/\r?\n/)) {
      if (line.length > 0) {
        lines.push(line);
      }
    }
  }

  let sawPort = false;
  let sawOnlineMode = false;
  let sawRcon = false;

  const updated = lines.map((line) => {
    const trimmed = line.trim();
    if (trimmed.startsWith("#")) {
      return line;
    }
    const eqIndex = trimmed.indexOf("=");
    if (eqIndex === -1) {
      return line;
    }
    const key = trimmed.slice(0, eqIndex).trim();
    if (key === "server-port") {
      sawPort = true;
      return `server-port=${options.port}`;
    }
    if (key === "online-mode") {
      sawOnlineMode = true;
      return options.forceOnlineMode ? "online-mode=true" : line;
    }
    if (key === "enable-rcon") {
      sawRcon = true;
      return "enable-rcon=false";
    }
    return line;
  });

  if (!sawPort) {
    updated.push(`server-port=${options.port}`);
  }
  if (!sawOnlineMode) {
    updated.push("online-mode=true");
  }
  if (!sawRcon) {
    updated.push("enable-rcon=false");
  }

  writeFileAtomic(propsPath, `${updated.join("\n")}\n`, {
    mode: SERVER_FILE_MODE,
    dirMode: SERVER_DIR_MODE,
  });
}
