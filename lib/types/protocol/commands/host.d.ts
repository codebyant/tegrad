import { z } from "zod";
import { type CommandRegistry } from "../registry";
export declare const hostInfoBodySchema: z.ZodObject<{}, z.core.$strict>;
export type HostInfoBody = z.infer<typeof hostInfoBodySchema>;
export declare const hostInfoResultSchema: z.ZodObject<{
    memory_total_mb: z.ZodNumber;
    memory_available_mb: z.ZodNumber;
    cpu_count: z.ZodNumber;
    reserved_memory_mb: z.ZodNumber;
    addresses: z.ZodOptional<z.ZodArray<z.ZodString>>;
}, z.core.$strip>;
export type HostInfoResult = z.infer<typeof hostInfoResultSchema>;
export declare const hostInfoCommand: import("..").CommandDefinition<"host.info", Record<string, never>>;
export declare const HOST_COMMANDS: readonly [import("..").CommandDefinition<"host.info", Record<string, never>>];
export declare function registerHostCommands(registry: CommandRegistry): CommandRegistry;
