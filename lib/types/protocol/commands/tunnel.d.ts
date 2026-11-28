import { z } from "zod";
import { type CommandRegistry } from "../registry";
export declare const PLAYIT_SECRET_KEY_REGEX: RegExp;
export declare const playitSecretKeySchema: z.ZodString;
export declare const tunnelPlayitSetKeyBodySchema: z.ZodObject<{
    secret_key: z.ZodString;
}, z.core.$strict>;
export type TunnelPlayitSetKeyBody = z.infer<typeof tunnelPlayitSetKeyBodySchema>;
export declare const tunnelPlayitSetKeyCommand: import("..").CommandDefinition<"tunnel.playit.set_key", {
    secret_key: string;
}>;
export declare const tunnelPlayitStartCommand: import("..").CommandDefinition<"tunnel.playit.start", Record<string, never>>;
export declare const tunnelPlayitStopCommand: import("..").CommandDefinition<"tunnel.playit.stop", Record<string, never>>;
export declare const tunnelPlayitStatusCommand: import("..").CommandDefinition<"tunnel.playit.status", Record<string, never>>;
export declare const TUNNEL_COMMANDS: readonly [import("..").CommandDefinition<"tunnel.playit.set_key", {
    secret_key: string;
}>, import("..").CommandDefinition<"tunnel.playit.start", Record<string, never>>, import("..").CommandDefinition<"tunnel.playit.stop", Record<string, never>>, import("..").CommandDefinition<"tunnel.playit.status", Record<string, never>>];
export declare function registerTunnelCommands(registry: CommandRegistry): CommandRegistry;
