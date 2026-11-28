import { z } from "zod";
import { type CommandRegistry } from "../registry";
export declare const SHA1_HEX_PATTERN: RegExp;
export declare const SHA512_HEX_PATTERN: RegExp;
export declare const sha1HexSchema: z.ZodPipe<z.ZodString, z.ZodTransform<string, string>>;
export declare const sha512HexSchema: z.ZodPipe<z.ZodString, z.ZodTransform<string, string>>;
export declare const modSourceSchema: z.ZodEnum<{
    curseforge: "curseforge";
    local: "local";
    modrinth: "modrinth";
    tegra: "tegra";
}>;
export type ModSource = z.infer<typeof modSourceSchema>;
export declare const modLayerSchema: z.ZodEnum<{
    origin: "origin";
    user: "user";
}>;
export type ModLayer = z.infer<typeof modLayerSchema>;
export declare const modFileNameSchema: z.ZodString;
export declare const serverModEntrySchema: z.ZodObject<{
    file: z.ZodString;
    source: z.ZodEnum<{
        curseforge: "curseforge";
        local: "local";
        modrinth: "modrinth";
        tegra: "tegra";
    }>;
    project_id: z.ZodOptional<z.ZodString>;
    version_id: z.ZodOptional<z.ZodString>;
    sha1: z.ZodOptional<z.ZodPipe<z.ZodString, z.ZodTransform<string, string>>>;
    sha256: z.ZodOptional<z.ZodString>;
    sha512: z.ZodOptional<z.ZodPipe<z.ZodString, z.ZodTransform<string, string>>>;
    layer: z.ZodEnum<{
        origin: "origin";
        user: "user";
    }>;
}, z.core.$strict>;
export type ServerModEntry = z.infer<typeof serverModEntrySchema>;
export declare const serverOriginSchema: z.ZodNullable<z.ZodDiscriminatedUnion<[z.ZodObject<{
    kind: z.ZodLiteral<"modpack">;
    source: z.ZodEnum<{
        curseforge: "curseforge";
        local: "local";
        modrinth: "modrinth";
        tegra: "tegra";
    }>;
    modpack_id: z.ZodString;
    version_id: z.ZodString;
    modpack_name: z.ZodOptional<z.ZodString>;
}, z.core.$strict>, z.ZodObject<{
    kind: z.ZodLiteral<"local">;
    note: z.ZodOptional<z.ZodString>;
}, z.core.$strict>], "kind">>;
export type ServerOrigin = z.infer<typeof serverOriginSchema>;
export declare const serverOriginSyncStateSchema: z.ZodObject<{
    excluded_mod_keys: z.ZodArray<z.ZodString>;
    synced_mod_keys: z.ZodArray<z.ZodString>;
    removed_origin_files: z.ZodOptional<z.ZodArray<z.ZodString>>;
    synced_files: z.ZodOptional<z.ZodArray<z.ZodString>>;
    last_synced_at: z.ZodOptional<z.ZodNullable<z.ZodString>>;
    last_synced_version_id: z.ZodOptional<z.ZodNullable<z.ZodString>>;
}, z.core.$strict>;
export type ServerOriginSyncState = z.infer<typeof serverOriginSyncStateSchema>;
export declare const modEnvironmentInfoSchema: z.ZodObject<{
    client: z.ZodOptional<z.ZodEnum<{
        optional: "optional";
        required: "required";
        unknown: "unknown";
        unsupported: "unsupported";
    }>>;
    server: z.ZodOptional<z.ZodEnum<{
        optional: "optional";
        required: "required";
        unknown: "unknown";
        unsupported: "unsupported";
    }>>;
}, z.core.$strict>;
export type ModEnvironmentInfo = z.infer<typeof modEnvironmentInfoSchema>;
export declare const originPlanModInputSchema: z.ZodObject<{
    key: z.ZodString;
    file: z.ZodString;
    name: z.ZodOptional<z.ZodString>;
    enabled: z.ZodOptional<z.ZodBoolean>;
    source: z.ZodOptional<z.ZodEnum<{
        curseforge: "curseforge";
        local: "local";
        modrinth: "modrinth";
        tegra: "tegra";
    }>>;
    project_id: z.ZodOptional<z.ZodString>;
    version_id: z.ZodOptional<z.ZodString>;
    url: z.ZodOptional<z.ZodString>;
    sha1: z.ZodOptional<z.ZodPipe<z.ZodString, z.ZodTransform<string, string>>>;
    sha256: z.ZodOptional<z.ZodString>;
    sha512: z.ZodOptional<z.ZodPipe<z.ZodString, z.ZodTransform<string, string>>>;
    environment: z.ZodOptional<z.ZodObject<{
        client: z.ZodOptional<z.ZodEnum<{
            optional: "optional";
            required: "required";
            unknown: "unknown";
            unsupported: "unsupported";
        }>>;
        server: z.ZodOptional<z.ZodEnum<{
            optional: "optional";
            required: "required";
            unknown: "unknown";
            unsupported: "unsupported";
        }>>;
    }, z.core.$strict>>;
}, z.core.$strict>;
export type OriginPlanModInput = z.infer<typeof originPlanModInputSchema>;
export declare const originPlanFileInputSchema: z.ZodObject<{
    path: z.ZodString;
    sha1: z.ZodPipe<z.ZodString, z.ZodTransform<string, string>>;
    sha256: z.ZodOptional<z.ZodString>;
    size_bytes: z.ZodNumber;
    url: z.ZodOptional<z.ZodString>;
    content_base64: z.ZodOptional<z.ZodString>;
}, z.core.$strict>;
export type OriginPlanFileInput = z.infer<typeof originPlanFileInputSchema>;
export declare const serverModsListBodySchema: z.ZodObject<{
    server_id: z.ZodString;
}, z.core.$strict>;
export declare const serverModsInstallBodySchema: z.ZodObject<{
    server_id: z.ZodString;
    file: z.ZodString;
    url: z.ZodString;
    source: z.ZodEnum<{
        curseforge: "curseforge";
        local: "local";
        modrinth: "modrinth";
        tegra: "tegra";
    }>;
    project_id: z.ZodOptional<z.ZodString>;
    version_id: z.ZodOptional<z.ZodString>;
    sha1: z.ZodOptional<z.ZodPipe<z.ZodString, z.ZodTransform<string, string>>>;
    sha256: z.ZodOptional<z.ZodString>;
    sha512: z.ZodOptional<z.ZodPipe<z.ZodString, z.ZodTransform<string, string>>>;
}, z.core.$strict>;
export declare const serverModsRemoveBodySchema: z.ZodObject<{
    server_id: z.ZodString;
    file: z.ZodString;
}, z.core.$strict>;
export declare const serverOriginPlanBodySchema: z.ZodObject<{
    server_id: z.ZodString;
    to_version_id: z.ZodString;
    source: z.ZodOptional<z.ZodEnum<{
        curseforge: "curseforge";
        local: "local";
        modrinth: "modrinth";
        tegra: "tegra";
    }>>;
    modpack_id: z.ZodOptional<z.ZodString>;
    minecraft_version: z.ZodOptional<z.ZodString>;
    loader: z.ZodOptional<z.ZodEnum<{
        fabric: "fabric";
        forge: "forge";
        neoforge: "neoforge";
        quilt: "quilt";
        vanilla: "vanilla";
    }>>;
    loader_version: z.ZodOptional<z.ZodNullable<z.ZodString>>;
    mods: z.ZodArray<z.ZodObject<{
        key: z.ZodString;
        file: z.ZodString;
        name: z.ZodOptional<z.ZodString>;
        enabled: z.ZodOptional<z.ZodBoolean>;
        source: z.ZodOptional<z.ZodEnum<{
            curseforge: "curseforge";
            local: "local";
            modrinth: "modrinth";
            tegra: "tegra";
        }>>;
        project_id: z.ZodOptional<z.ZodString>;
        version_id: z.ZodOptional<z.ZodString>;
        url: z.ZodOptional<z.ZodString>;
        sha1: z.ZodOptional<z.ZodPipe<z.ZodString, z.ZodTransform<string, string>>>;
        sha256: z.ZodOptional<z.ZodString>;
        sha512: z.ZodOptional<z.ZodPipe<z.ZodString, z.ZodTransform<string, string>>>;
        environment: z.ZodOptional<z.ZodObject<{
            client: z.ZodOptional<z.ZodEnum<{
                optional: "optional";
                required: "required";
                unknown: "unknown";
                unsupported: "unsupported";
            }>>;
            server: z.ZodOptional<z.ZodEnum<{
                optional: "optional";
                required: "required";
                unknown: "unknown";
                unsupported: "unsupported";
            }>>;
        }, z.core.$strict>>;
    }, z.core.$strict>>;
    files: z.ZodOptional<z.ZodArray<z.ZodObject<{
        path: z.ZodString;
        sha1: z.ZodPipe<z.ZodString, z.ZodTransform<string, string>>;
        sha256: z.ZodOptional<z.ZodString>;
        size_bytes: z.ZodNumber;
        url: z.ZodOptional<z.ZodString>;
        content_base64: z.ZodOptional<z.ZodString>;
    }, z.core.$strict>>>;
}, z.core.$strict>;
export declare const serverOriginApplyBodySchema: z.ZodObject<{
    server_id: z.ZodString;
    plan_id: z.ZodString;
    selected_mod_keys: z.ZodOptional<z.ZodArray<z.ZodString>>;
    selected_file_paths: z.ZodOptional<z.ZodArray<z.ZodString>>;
}, z.core.$strict>;
export declare const serverOriginUnlinkBodySchema: z.ZodObject<{
    server_id: z.ZodString;
}, z.core.$strict>;
/** 32-byte symmetric key in base64url (no padding) for blobs in the chunked TGB1 format. */
export declare const blobKeySchema: z.ZodString;
export declare const WORLD_NAME_REGEX: RegExp;
/** Folder names that hold server content other than a world. */
export declare const RESERVED_WORLD_NAMES: ReadonlySet<string>;
export declare const worldNameSchema: z.ZodString;
export declare const serverWorldImportBodySchema: z.ZodObject<{
    server_id: z.ZodString;
    world_name: z.ZodString;
    url: z.ZodString;
    sha256: z.ZodString;
    key: z.ZodString;
}, z.core.$strict>;
export type ServerWorldImportBody = z.infer<typeof serverWorldImportBodySchema>;
export declare const serverDeployServerpackBodySchema: z.ZodObject<{
    server_id: z.ZodString;
    url: z.ZodString;
    sha256: z.ZodOptional<z.ZodString>;
    sha512: z.ZodOptional<z.ZodPipe<z.ZodString, z.ZodTransform<string, string>>>;
    sha1: z.ZodOptional<z.ZodPipe<z.ZodString, z.ZodTransform<string, string>>>;
    origin: z.ZodOptional<z.ZodNullable<z.ZodDiscriminatedUnion<[z.ZodObject<{
        kind: z.ZodLiteral<"modpack">;
        source: z.ZodEnum<{
            curseforge: "curseforge";
            local: "local";
            modrinth: "modrinth";
            tegra: "tegra";
        }>;
        modpack_id: z.ZodString;
        version_id: z.ZodString;
        modpack_name: z.ZodOptional<z.ZodString>;
    }, z.core.$strict>, z.ZodObject<{
        kind: z.ZodLiteral<"local">;
        note: z.ZodOptional<z.ZodString>;
    }, z.core.$strict>], "kind">>>;
    key: z.ZodOptional<z.ZodString>;
}, z.core.$strict>;
export type ServerModsListBody = z.infer<typeof serverModsListBodySchema>;
export type ServerModsInstallBody = z.infer<typeof serverModsInstallBodySchema>;
export type ServerModsRemoveBody = z.infer<typeof serverModsRemoveBodySchema>;
export type ServerOriginPlanBody = z.infer<typeof serverOriginPlanBodySchema>;
export type ServerOriginApplyBody = z.infer<typeof serverOriginApplyBodySchema>;
export type ServerOriginUnlinkBody = z.infer<typeof serverOriginUnlinkBodySchema>;
export type ServerDeployServerpackBody = z.infer<typeof serverDeployServerpackBodySchema>;
export declare const serverModsListCommand: import("..").CommandDefinition<"server.mods.list", {
    server_id: string;
}>;
export declare const serverModsInstallCommand: import("..").CommandDefinition<"server.mods.install", {
    server_id: string;
    file: string;
    url: string;
    source: "curseforge" | "local" | "modrinth" | "tegra";
    project_id?: string | undefined;
    version_id?: string | undefined;
    sha1?: string | undefined;
    sha256?: string | undefined;
    sha512?: string | undefined;
}>;
export declare const serverModsRemoveCommand: import("..").CommandDefinition<"server.mods.remove", {
    server_id: string;
    file: string;
}>;
export declare const serverOriginPlanCommand: import("..").CommandDefinition<"server.origin.plan", {
    server_id: string;
    to_version_id: string;
    source?: "curseforge" | "local" | "modrinth" | "tegra" | undefined;
    modpack_id?: string | undefined;
    minecraft_version?: string | undefined;
    loader?: "fabric" | "forge" | "neoforge" | "quilt" | "vanilla" | undefined;
    loader_version?: string | null | undefined;
    mods: {
        key: string;
        file: string;
        name?: string | undefined;
        enabled?: boolean | undefined;
        source?: "curseforge" | "local" | "modrinth" | "tegra" | undefined;
        project_id?: string | undefined;
        version_id?: string | undefined;
        url?: string | undefined;
        sha1?: string | undefined;
        sha256?: string | undefined;
        sha512?: string | undefined;
        environment?: {
            client?: "optional" | "required" | "unknown" | "unsupported" | undefined;
            server?: "optional" | "required" | "unknown" | "unsupported" | undefined;
        } | undefined;
    }[];
    files?: {
        path: string;
        sha1: string;
        sha256?: string | undefined;
        size_bytes: number;
        url?: string | undefined;
        content_base64?: string | undefined;
    }[] | undefined;
}>;
export declare const serverOriginApplyCommand: import("..").CommandDefinition<"server.origin.apply", {
    server_id: string;
    plan_id: string;
    selected_mod_keys?: string[] | undefined;
    selected_file_paths?: string[] | undefined;
}>;
export declare const serverOriginUnlinkCommand: import("..").CommandDefinition<"server.origin.unlink", {
    server_id: string;
}>;
export declare const serverDeployServerpackCommand: import("..").CommandDefinition<"server.deploy.serverpack", {
    server_id: string;
    url: string;
    sha256?: string | undefined;
    sha512?: string | undefined;
    sha1?: string | undefined;
    origin?: {
        kind: "modpack";
        source: "curseforge" | "local" | "modrinth" | "tegra";
        modpack_id: string;
        version_id: string;
        modpack_name?: string | undefined;
    } | {
        kind: "local";
        note?: string | undefined;
    } | null | undefined;
    key?: string | undefined;
}>;
export declare const serverWorldImportCommand: import("..").CommandDefinition<"server.world.import", {
    server_id: string;
    world_name: string;
    url: string;
    sha256: string;
    key: string;
}>;
export declare const STATE_COMMANDS: readonly [import("..").CommandDefinition<"server.mods.list", {
    server_id: string;
}>, import("..").CommandDefinition<"server.mods.install", {
    server_id: string;
    file: string;
    url: string;
    source: "curseforge" | "local" | "modrinth" | "tegra";
    project_id?: string | undefined;
    version_id?: string | undefined;
    sha1?: string | undefined;
    sha256?: string | undefined;
    sha512?: string | undefined;
}>, import("..").CommandDefinition<"server.mods.remove", {
    server_id: string;
    file: string;
}>, import("..").CommandDefinition<"server.origin.plan", {
    server_id: string;
    to_version_id: string;
    source?: "curseforge" | "local" | "modrinth" | "tegra" | undefined;
    modpack_id?: string | undefined;
    minecraft_version?: string | undefined;
    loader?: "fabric" | "forge" | "neoforge" | "quilt" | "vanilla" | undefined;
    loader_version?: string | null | undefined;
    mods: {
        key: string;
        file: string;
        name?: string | undefined;
        enabled?: boolean | undefined;
        source?: "curseforge" | "local" | "modrinth" | "tegra" | undefined;
        project_id?: string | undefined;
        version_id?: string | undefined;
        url?: string | undefined;
        sha1?: string | undefined;
        sha256?: string | undefined;
        sha512?: string | undefined;
        environment?: {
            client?: "optional" | "required" | "unknown" | "unsupported" | undefined;
            server?: "optional" | "required" | "unknown" | "unsupported" | undefined;
        } | undefined;
    }[];
    files?: {
        path: string;
        sha1: string;
        sha256?: string | undefined;
        size_bytes: number;
        url?: string | undefined;
        content_base64?: string | undefined;
    }[] | undefined;
}>, import("..").CommandDefinition<"server.origin.apply", {
    server_id: string;
    plan_id: string;
    selected_mod_keys?: string[] | undefined;
    selected_file_paths?: string[] | undefined;
}>, import("..").CommandDefinition<"server.origin.unlink", {
    server_id: string;
}>, import("..").CommandDefinition<"server.deploy.serverpack", {
    server_id: string;
    url: string;
    sha256?: string | undefined;
    sha512?: string | undefined;
    sha1?: string | undefined;
    origin?: {
        kind: "modpack";
        source: "curseforge" | "local" | "modrinth" | "tegra";
        modpack_id: string;
        version_id: string;
        modpack_name?: string | undefined;
    } | {
        kind: "local";
        note?: string | undefined;
    } | null | undefined;
    key?: string | undefined;
}>, import("..").CommandDefinition<"server.world.import", {
    server_id: string;
    world_name: string;
    url: string;
    sha256: string;
    key: string;
}>];
export declare function registerStateCommands(registry: CommandRegistry): CommandRegistry;
