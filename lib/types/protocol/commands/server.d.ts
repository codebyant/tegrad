import { z } from "zod";
import { type CommandRegistry } from "../registry";
export declare const SERVER_ID_REGEX: RegExp;
export declare const DEFAULT_SERVER_PORT = 25565;
export declare const MAX_CONSOLE_LINE_LENGTH = 1024;
export declare const MIN_SERVER_MEMORY_MB = 512;
export declare const MAX_SERVER_MEMORY_MB = 1048576;
export declare const MAX_JVM_ARGS = 64;
export declare const serverIdSchema: z.ZodString;
export declare const serverLoaderSchema: z.ZodEnum<{
    fabric: "fabric";
    forge: "forge";
    neoforge: "neoforge";
    quilt: "quilt";
    vanilla: "vanilla";
}>;
export type ServerLoader = z.infer<typeof serverLoaderSchema>;
export declare const serverPortSchema: z.ZodNumber;
export declare const serverMemoryMbSchema: z.ZodNumber;
export declare const consoleLineSchema: z.ZodString;
export declare const serverCreateBodySchema: z.ZodObject<{
    server_id: z.ZodString;
    name: z.ZodString;
    minecraft_version: z.ZodString;
    loader: z.ZodEnum<{
        fabric: "fabric";
        forge: "forge";
        neoforge: "neoforge";
        quilt: "quilt";
        vanilla: "vanilla";
    }>;
    loader_version: z.ZodOptional<z.ZodString>;
    memory_mb: z.ZodNumber;
    jvm_args: z.ZodOptional<z.ZodArray<z.ZodString>>;
    port: z.ZodOptional<z.ZodNumber>;
    eula_accepted: z.ZodBoolean;
}, z.core.$strict>;
export declare const serverUpdateSettingsBodySchema: z.ZodObject<{
    server_id: z.ZodString;
    memory_mb: z.ZodOptional<z.ZodNumber>;
    jvm_args: z.ZodOptional<z.ZodArray<z.ZodString>>;
    port: z.ZodOptional<z.ZodNumber>;
    eula_accepted: z.ZodOptional<z.ZodBoolean>;
}, z.core.$strict>;
export declare const serverConsoleSendBodySchema: z.ZodObject<{
    server_id: z.ZodString;
    line: z.ZodString;
}, z.core.$strict>;
export declare const serverConsoleSubscribeBodySchema: z.ZodObject<{
    server_id: z.ZodString;
    from_offset: z.ZodOptional<z.ZodNumber>;
}, z.core.$strict>;
export type ServerCreateBody = z.infer<typeof serverCreateBodySchema>;
export type ServerUpdateSettingsBody = z.infer<typeof serverUpdateSettingsBodySchema>;
export type ServerConsoleSendBody = z.infer<typeof serverConsoleSendBodySchema>;
export type ServerConsoleSubscribeBody = z.infer<typeof serverConsoleSubscribeBodySchema>;
export declare const serverCreateCommand: import("..").CommandDefinition<"server.create", {
    server_id: string;
    name: string;
    minecraft_version: string;
    loader: "fabric" | "forge" | "neoforge" | "quilt" | "vanilla";
    loader_version?: string | undefined;
    memory_mb: number;
    jvm_args?: string[] | undefined;
    port?: number | undefined;
    eula_accepted: boolean;
}>;
export declare const serverRestartCommand: import("..").CommandDefinition<"server.restart", {
    server_id: string;
}>;
export declare const serverStatusCommand: import("..").CommandDefinition<"server.status", {
    server_id: string;
}>;
export declare const serverListCommand: import("..").CommandDefinition<"server.list", Record<string, never>>;
export declare const serverUpdateSettingsCommand: import("..").CommandDefinition<"server.update_settings", {
    server_id: string;
    memory_mb?: number | undefined;
    jvm_args?: string[] | undefined;
    port?: number | undefined;
    eula_accepted?: boolean | undefined;
}>;
export declare const serverConsoleSendCommand: import("..").CommandDefinition<"server.console.send", {
    server_id: string;
    line: string;
}>;
export declare const serverConsoleSubscribeCommand: import("..").CommandDefinition<"server.console.subscribe", {
    server_id: string;
    from_offset?: number | undefined;
}>;
export declare const serverConsoleUnsubscribeCommand: import("..").CommandDefinition<"server.console.unsubscribe", {
    server_id: string;
}>;
export declare const SERVER_COMMANDS: readonly [import("..").CommandDefinition<"server.create", {
    server_id: string;
    name: string;
    minecraft_version: string;
    loader: "fabric" | "forge" | "neoforge" | "quilt" | "vanilla";
    loader_version?: string | undefined;
    memory_mb: number;
    jvm_args?: string[] | undefined;
    port?: number | undefined;
    eula_accepted: boolean;
}>, import("..").CommandDefinition<"server.restart", {
    server_id: string;
}>, import("..").CommandDefinition<"server.status", {
    server_id: string;
}>, import("..").CommandDefinition<"server.list", Record<string, never>>, import("..").CommandDefinition<"server.update_settings", {
    server_id: string;
    memory_mb?: number | undefined;
    jvm_args?: string[] | undefined;
    port?: number | undefined;
    eula_accepted?: boolean | undefined;
}>, import("..").CommandDefinition<"server.console.send", {
    server_id: string;
    line: string;
}>, import("..").CommandDefinition<"server.console.subscribe", {
    server_id: string;
    from_offset?: number | undefined;
}>, import("..").CommandDefinition<"server.console.unsubscribe", {
    server_id: string;
}>];
export declare function registerServerCommands(registry: CommandRegistry): CommandRegistry;
