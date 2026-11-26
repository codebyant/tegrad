import { z } from "zod";
import { type CommandRegistry } from "../registry";
export declare const MODPACK_SOURCES: readonly ["tegra", "modrinth", "curseforge"];
export declare const modpackSourceSchema: z.ZodEnum<{
    curseforge: "curseforge";
    modrinth: "modrinth";
    tegra: "tegra";
}>;
export type ModpackSource = z.infer<typeof modpackSourceSchema>;
export declare const MODPACK_INSTALL_PHASES: readonly ["resolving", "downloading", "extracting", "overrides", "finalizing"];
export declare const modpackInstallPhaseSchema: z.ZodEnum<{
    downloading: "downloading";
    extracting: "extracting";
    finalizing: "finalizing";
    overrides: "overrides";
    resolving: "resolving";
}>;
export type ModpackInstallPhase = z.infer<typeof modpackInstallPhaseSchema>;
export declare const MODPACK_INSTALL_JOB_STATES: readonly ["running", "completed", "failed", "cancelled"];
export declare const modpackInstallJobStateSchema: z.ZodEnum<{
    cancelled: "cancelled";
    completed: "completed";
    failed: "failed";
    running: "running";
}>;
export type ModpackInstallJobState = z.infer<typeof modpackInstallJobStateSchema>;
export declare const MODPACK_INSTALL_ERROR_CODES: readonly ["pack_unavailable", "host_not_allowed", "hash_mismatch", "too_large", "install_in_progress", "server_running", "api_unavailable", "io_error", "cancelled"];
export declare const modpackInstallErrorCodeSchema: z.ZodEnum<{
    api_unavailable: "api_unavailable";
    cancelled: "cancelled";
    hash_mismatch: "hash_mismatch";
    host_not_allowed: "host_not_allowed";
    install_in_progress: "install_in_progress";
    io_error: "io_error";
    pack_unavailable: "pack_unavailable";
    server_running: "server_running";
    too_large: "too_large";
}>;
export type ModpackInstallErrorCode = z.infer<typeof modpackInstallErrorCodeSchema>;
export declare const modpackInstallSkippedItemSchema: z.ZodObject<{
    name: z.ZodString;
    reason: z.ZodString;
}, z.core.$strict>;
export type ModpackInstallSkippedItem = z.infer<typeof modpackInstallSkippedItemSchema>;
export declare const serverInstallModpackBodySchema: z.ZodObject<{
    server_id: z.ZodString;
    source: z.ZodEnum<{
        curseforge: "curseforge";
        modrinth: "modrinth";
        tegra: "tegra";
    }>;
    modpack_id: z.ZodString;
    version_id: z.ZodString;
    modpack_name: z.ZodOptional<z.ZodString>;
    version_label: z.ZodOptional<z.ZodString>;
}, z.core.$strict>;
export type ServerInstallModpackBody = z.infer<typeof serverInstallModpackBodySchema>;
export declare const serverInstallModpackStatusBodySchema: z.ZodObject<{
    server_id: z.ZodString;
}, z.core.$strict>;
export type ServerInstallModpackStatusBody = z.infer<typeof serverInstallModpackStatusBodySchema>;
export declare const serverInstallModpackCancelBodySchema: z.ZodObject<{
    server_id: z.ZodString;
    job_id: z.ZodOptional<z.ZodString>;
}, z.core.$strict>;
export type ServerInstallModpackCancelBody = z.infer<typeof serverInstallModpackCancelBodySchema>;
export declare const serverInstallModpackAcceptedEventSchema: z.ZodObject<{
    job_id: z.ZodString;
    server_id: z.ZodString;
}, z.core.$strict>;
export type ServerInstallModpackAcceptedEvent = z.infer<typeof serverInstallModpackAcceptedEventSchema>;
export declare const serverInstallModpackProgressEventSchema: z.ZodObject<{
    job_id: z.ZodString;
    server_id: z.ZodString;
    phase: z.ZodEnum<{
        downloading: "downloading";
        extracting: "extracting";
        finalizing: "finalizing";
        overrides: "overrides";
        resolving: "resolving";
    }>;
    done: z.ZodNumber;
    total: z.ZodNumber;
    current: z.ZodOptional<z.ZodString>;
}, z.core.$strict>;
export type ServerInstallModpackProgressEvent = z.infer<typeof serverInstallModpackProgressEventSchema>;
export declare const serverInstallModpackResultEventSchema: z.ZodObject<{
    job_id: z.ZodString;
    server_id: z.ZodString;
    ok: z.ZodBoolean;
    installed: z.ZodNumber;
    skipped: z.ZodArray<z.ZodObject<{
        name: z.ZodString;
        reason: z.ZodString;
    }, z.core.$strict>>;
    error_code: z.ZodOptional<z.ZodEnum<{
        api_unavailable: "api_unavailable";
        cancelled: "cancelled";
        hash_mismatch: "hash_mismatch";
        host_not_allowed: "host_not_allowed";
        install_in_progress: "install_in_progress";
        io_error: "io_error";
        pack_unavailable: "pack_unavailable";
        server_running: "server_running";
        too_large: "too_large";
    }>>;
}, z.core.$strict>;
export type ServerInstallModpackResultEvent = z.infer<typeof serverInstallModpackResultEventSchema>;
export declare const modpackInstallJobStatusSchema: z.ZodObject<{
    job_id: z.ZodString;
    server_id: z.ZodString;
    source: z.ZodEnum<{
        curseforge: "curseforge";
        modrinth: "modrinth";
        tegra: "tegra";
    }>;
    modpack_id: z.ZodString;
    version_id: z.ZodString;
    modpack_name: z.ZodOptional<z.ZodString>;
    version_label: z.ZodOptional<z.ZodString>;
    status: z.ZodEnum<{
        cancelled: "cancelled";
        completed: "completed";
        failed: "failed";
        running: "running";
    }>;
    phase: z.ZodEnum<{
        downloading: "downloading";
        extracting: "extracting";
        finalizing: "finalizing";
        overrides: "overrides";
        resolving: "resolving";
    }>;
    done: z.ZodNumber;
    total: z.ZodNumber;
    current: z.ZodOptional<z.ZodString>;
    installed: z.ZodNumber;
    skipped: z.ZodArray<z.ZodObject<{
        name: z.ZodString;
        reason: z.ZodString;
    }, z.core.$strict>>;
    error_code: z.ZodOptional<z.ZodEnum<{
        api_unavailable: "api_unavailable";
        cancelled: "cancelled";
        hash_mismatch: "hash_mismatch";
        host_not_allowed: "host_not_allowed";
        install_in_progress: "install_in_progress";
        io_error: "io_error";
        pack_unavailable: "pack_unavailable";
        server_running: "server_running";
        too_large: "too_large";
    }>>;
    started_at: z.ZodNumber;
    updated_at: z.ZodNumber;
    finished_at: z.ZodOptional<z.ZodNumber>;
}, z.core.$strict>;
export type ModpackInstallJobStatus = z.infer<typeof modpackInstallJobStatusSchema>;
export declare const serverInstallModpackStatusResultSchema: z.ZodObject<{
    server_id: z.ZodString;
    job: z.ZodNullable<z.ZodObject<{
        job_id: z.ZodString;
        server_id: z.ZodString;
        source: z.ZodEnum<{
            curseforge: "curseforge";
            modrinth: "modrinth";
            tegra: "tegra";
        }>;
        modpack_id: z.ZodString;
        version_id: z.ZodString;
        modpack_name: z.ZodOptional<z.ZodString>;
        version_label: z.ZodOptional<z.ZodString>;
        status: z.ZodEnum<{
            cancelled: "cancelled";
            completed: "completed";
            failed: "failed";
            running: "running";
        }>;
        phase: z.ZodEnum<{
            downloading: "downloading";
            extracting: "extracting";
            finalizing: "finalizing";
            overrides: "overrides";
            resolving: "resolving";
        }>;
        done: z.ZodNumber;
        total: z.ZodNumber;
        current: z.ZodOptional<z.ZodString>;
        installed: z.ZodNumber;
        skipped: z.ZodArray<z.ZodObject<{
            name: z.ZodString;
            reason: z.ZodString;
        }, z.core.$strict>>;
        error_code: z.ZodOptional<z.ZodEnum<{
            api_unavailable: "api_unavailable";
            cancelled: "cancelled";
            hash_mismatch: "hash_mismatch";
            host_not_allowed: "host_not_allowed";
            install_in_progress: "install_in_progress";
            io_error: "io_error";
            pack_unavailable: "pack_unavailable";
            server_running: "server_running";
            too_large: "too_large";
        }>>;
        started_at: z.ZodNumber;
        updated_at: z.ZodNumber;
        finished_at: z.ZodOptional<z.ZodNumber>;
    }, z.core.$strict>>;
}, z.core.$strict>;
export type ServerInstallModpackStatusResult = z.infer<typeof serverInstallModpackStatusResultSchema>;
export declare const serverInstallModpackCommand: import("..").CommandDefinition<"server.install_modpack", {
    server_id: string;
    source: "curseforge" | "modrinth" | "tegra";
    modpack_id: string;
    version_id: string;
    modpack_name?: string | undefined;
    version_label?: string | undefined;
}>;
export declare const serverInstallModpackStatusCommand: import("..").CommandDefinition<"server.install_modpack.status", {
    server_id: string;
}>;
export declare const serverInstallModpackCancelCommand: import("..").CommandDefinition<"server.install_modpack.cancel", {
    server_id: string;
    job_id?: string | undefined;
}>;
export declare const MODPACK_COMMANDS: readonly [import("..").CommandDefinition<"server.install_modpack", {
    server_id: string;
    source: "curseforge" | "modrinth" | "tegra";
    modpack_id: string;
    version_id: string;
    modpack_name?: string | undefined;
    version_label?: string | undefined;
}>, import("..").CommandDefinition<"server.install_modpack.status", {
    server_id: string;
}>, import("..").CommandDefinition<"server.install_modpack.cancel", {
    server_id: string;
    job_id?: string | undefined;
}>];
export declare function registerModpackCommands(registry: CommandRegistry): CommandRegistry;
