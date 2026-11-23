// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
import { type CommandRegistry, defineCommand } from "../registry";
import { sha256HexSchema } from "./files";
import { serverIdSchema, serverLoaderSchema } from "./server";

export const SHA1_HEX_PATTERN = /^[0-9a-f]{40}$/i;
export const SHA512_HEX_PATTERN = /^[0-9a-f]{128}$/i;

export const sha1HexSchema = z
  .string()
  .regex(SHA1_HEX_PATTERN, "Expected 40 hex characters")
  .transform((v) => v.toLowerCase());

export const sha512HexSchema = z
  .string()
  .regex(SHA512_HEX_PATTERN, "Expected 128 hex characters")
  .transform((v) => v.toLowerCase());

export const modSourceSchema = z.enum(["modrinth", "curseforge", "tegra", "local"]);
export type ModSource = z.infer<typeof modSourceSchema>;

export const modLayerSchema = z.enum(["origin", "user"]);
export type ModLayer = z.infer<typeof modLayerSchema>;

const MOD_UNSAFE_UNICODE_REGEX = /(?:\p{Cc}|\p{Cf}|\u034F|\u180E|\u2028|\u2029|\u3164|\uFFA0)/u;
const MOD_ENCODED_TRAVERSAL_REGEX = /%(?:2f|5c|00)/i;
const MOD_RESERVED_WINDOWS_REGEX =
  /^(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³]|CONIN\$|CONOUT\$|CLOCK\$)\s*(?:\.|$)/i;
const MOD_FORBIDDEN_NAMES = new Set([".runtime", ".tegrad-uploads"]);

export const modFileNameSchema = z
  .string()
  .min(1)
  .max(255)
  .refine(
    (name) => {
      if (
        name.includes("/") ||
        name.includes("\\") ||
        name.includes("\0") ||
        name.includes(":") ||
        name === "." ||
        name === ".." ||
        name.endsWith(".") ||
        name.endsWith(" ")
      ) {
        return false;
      }
      if (MOD_UNSAFE_UNICODE_REGEX.test(name) || name.normalize("NFC") !== name) {
        return false;
      }
      if (MOD_ENCODED_TRAVERSAL_REGEX.test(name) || MOD_RESERVED_WINDOWS_REGEX.test(name)) {
        return false;
      }
      const lower = name.toLowerCase();
      if (MOD_FORBIDDEN_NAMES.has(lower) || lower.startsWith(".tmp-upload-")) {
        return false;
      }
      return new TextEncoder().encode(name).byteLength <= 255;
    },
    { message: "Mod filename must be a single safe filename" },
  );

export const serverModEntrySchema = z
  .object({
    file: modFileNameSchema,
    source: modSourceSchema,
    project_id: z.string().min(1).max(128).optional(),
    version_id: z.string().min(1).max(128).optional(),
    sha1: sha1HexSchema.optional(),
    sha256: sha256HexSchema.optional(),
    sha512: sha512HexSchema.optional(),
    layer: modLayerSchema,
  })
  .strict();

export type ServerModEntry = z.infer<typeof serverModEntrySchema>;

export const serverOriginSchema = z
  .discriminatedUnion("kind", [
    z
      .object({
        kind: z.literal("modpack"),
        source: modSourceSchema,
        modpack_id: z.string().min(1).max(128),
        version_id: z.string().min(1).max(128),
      })
      .strict(),
    z
      .object({
        kind: z.literal("local"),
        note: z.string().max(512).optional(),
      })
      .strict(),
  ])
  .nullable();

export type ServerOrigin = z.infer<typeof serverOriginSchema>;

export const serverOriginSyncStateSchema = z
  .object({
    excluded_mod_keys: z.array(z.string().min(1).max(256)).max(4000),
    synced_mod_keys: z.array(z.string().min(1).max(256)).max(4000),
    removed_origin_files: z.array(z.string().min(1).max(1024)).max(5000).optional(),
    synced_files: z.array(z.string().min(1).max(1024)).max(5000).optional(),
    last_synced_at: z.string().nullable().optional(),
    last_synced_version_id: z.string().min(1).max(128).nullable().optional(),
  })
  .strict();

export type ServerOriginSyncState = z.infer<typeof serverOriginSyncStateSchema>;

export const modEnvironmentInfoSchema = z
  .object({
    client: z.enum(["required", "optional", "unsupported", "unknown"]).optional(),
    server: z.enum(["required", "optional", "unsupported", "unknown"]).optional(),
  })
  .strict();

export type ModEnvironmentInfo = z.infer<typeof modEnvironmentInfoSchema>;

export const originPlanModInputSchema = z
  .object({
    key: z.string().min(1).max(256),
    file: modFileNameSchema,
    name: z.string().min(1).max(256).optional(),
    enabled: z.boolean().optional(),
    source: modSourceSchema.optional(),
    project_id: z.string().min(1).max(128).optional(),
    version_id: z.string().min(1).max(128).optional(),
    url: z.string().url().max(2048).optional(),
    sha1: sha1HexSchema.optional(),
    sha256: sha256HexSchema.optional(),
    sha512: sha512HexSchema.optional(),
    environment: modEnvironmentInfoSchema.optional(),
  })
  .strict();

export type OriginPlanModInput = z.infer<typeof originPlanModInputSchema>;

export const originPlanFileInputSchema = z
  .object({
    path: z.string().min(1).max(1024),
    sha1: sha1HexSchema,
    sha256: sha256HexSchema.optional(),
    size_bytes: z.number().int().nonnegative(),
    url: z.string().url().max(2048).optional(),
    content_base64: z.string().optional(),
  })
  .strict();

export type OriginPlanFileInput = z.infer<typeof originPlanFileInputSchema>;

export const serverModsListBodySchema = z
  .object({
    server_id: serverIdSchema,
  })
  .strict();

export const serverModsInstallBodySchema = z
  .object({
    server_id: serverIdSchema,
    file: modFileNameSchema,
    url: z.string().url().max(2048),
    source: modSourceSchema,
    project_id: z.string().min(1).max(128).optional(),
    version_id: z.string().min(1).max(128).optional(),
    sha1: sha1HexSchema.optional(),
    sha256: sha256HexSchema.optional(),
    sha512: sha512HexSchema.optional(),
  })
  .strict();

export const serverModsRemoveBodySchema = z
  .object({
    server_id: serverIdSchema,
    file: modFileNameSchema,
  })
  .strict();

export const serverOriginPlanBodySchema = z
  .object({
    server_id: serverIdSchema,
    to_version_id: z.string().min(1).max(128),
    source: modSourceSchema.optional(),
    modpack_id: z.string().min(1).max(128).optional(),
    minecraft_version: z.string().min(1).max(64).optional(),
    loader: serverLoaderSchema.optional(),
    loader_version: z.string().min(1).max(64).nullable().optional(),
    mods: z.array(originPlanModInputSchema).max(2000),
    files: z.array(originPlanFileInputSchema).max(5000).optional(),
  })
  .strict();

export const serverOriginApplyBodySchema = z
  .object({
    server_id: serverIdSchema,
    plan_id: z.string().min(1).max(128),
    selected_mod_keys: z.array(z.string().min(1).max(256)).max(2000).optional(),
    selected_file_paths: z.array(z.string().min(1).max(1024)).max(5000).optional(),
  })
  .strict();

export const serverOriginUnlinkBodySchema = z
  .object({
    server_id: serverIdSchema,
  })
  .strict();

/** 32-byte symmetric key in base64url (no padding) for blobs in the chunked TGB1 format. */
export const blobKeySchema = z
  .string()
  .regex(/^[A-Za-z0-9_-]{43}$/, "Expected a 32-byte key in base64url");

export const WORLD_NAME_REGEX = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
/** Folder names that hold server content other than a world. */
export const RESERVED_WORLD_NAMES: ReadonlySet<string> = new Set([
  "mods",
  "config",
  "defaultconfigs",
  "logs",
  "libraries",
  "plugins",
  "versions",
  "crash-reports",
  "resourcepacks",
  "datapacks",
  "kubejs",
  "scripts",
]);

export const worldNameSchema = z
  .string()
  .regex(WORLD_NAME_REGEX, "Invalid world name")
  .refine((name) => !name.includes("..") && !RESERVED_WORLD_NAMES.has(name.toLowerCase()), {
    message: "Reserved or unsafe world name",
  });

export const serverWorldImportBodySchema = z
  .object({
    server_id: serverIdSchema,
    world_name: worldNameSchema,
    url: z.string().url().max(2048),
    sha256: sha256HexSchema,
    key: blobKeySchema,
  })
  .strict();
export type ServerWorldImportBody = z.infer<typeof serverWorldImportBodySchema>;

export const serverDeployServerpackBodySchema = z
  .object({
    server_id: serverIdSchema,
    url: z.string().url().max(2048),
    sha256: sha256HexSchema.optional(),
    sha512: sha512HexSchema.optional(),
    sha1: sha1HexSchema.optional(),
    origin: serverOriginSchema.optional(),
    /** When present, the downloaded blob is encrypted in the TGB1 chunked format with this key. */
    key: blobKeySchema.optional(),
  })
  .strict();

export type ServerModsListBody = z.infer<typeof serverModsListBodySchema>;
export type ServerModsInstallBody = z.infer<typeof serverModsInstallBodySchema>;
export type ServerModsRemoveBody = z.infer<typeof serverModsRemoveBodySchema>;
export type ServerOriginPlanBody = z.infer<typeof serverOriginPlanBodySchema>;
export type ServerOriginApplyBody = z.infer<typeof serverOriginApplyBodySchema>;
export type ServerOriginUnlinkBody = z.infer<typeof serverOriginUnlinkBodySchema>;
export type ServerDeployServerpackBody = z.infer<typeof serverDeployServerpackBodySchema>;

export const serverModsListCommand = defineCommand({
  type: "server.mods.list",
  sensitive: false,
  minRole: "viewer",
  body: serverModsListBodySchema,
});

export const serverModsInstallCommand = defineCommand({
  type: "server.mods.install",
  sensitive: false,
  minRole: "editor",
  body: serverModsInstallBodySchema,
});

export const serverModsRemoveCommand = defineCommand({
  type: "server.mods.remove",
  sensitive: false,
  minRole: "editor",
  body: serverModsRemoveBodySchema,
});

export const serverOriginPlanCommand = defineCommand({
  type: "server.origin.plan",
  sensitive: false,
  minRole: "editor",
  body: serverOriginPlanBodySchema,
});

export const serverOriginApplyCommand = defineCommand({
  type: "server.origin.apply",
  sensitive: true,
  minRole: "editor",
  body: serverOriginApplyBodySchema,
});

export const serverOriginUnlinkCommand = defineCommand({
  type: "server.origin.unlink",
  sensitive: false,
  minRole: "editor",
  body: serverOriginUnlinkBodySchema,
});

export const serverDeployServerpackCommand = defineCommand({
  type: "server.deploy.serverpack",
  sensitive: true,
  minRole: "editor",
  body: serverDeployServerpackBodySchema,
});

export const serverWorldImportCommand = defineCommand({
  type: "server.world.import",
  sensitive: false,
  minRole: "editor",
  body: serverWorldImportBodySchema,
});

export const STATE_COMMANDS = [
  serverModsListCommand,
  serverModsInstallCommand,
  serverModsRemoveCommand,
  serverOriginPlanCommand,
  serverOriginApplyCommand,
  serverOriginUnlinkCommand,
  serverDeployServerpackCommand,
  serverWorldImportCommand,
] as const;

export function registerStateCommands(registry: CommandRegistry): CommandRegistry {
  return registry.registerAll(STATE_COMMANDS);
}
