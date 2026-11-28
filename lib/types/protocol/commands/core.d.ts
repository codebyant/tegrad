import { CommandRegistry } from "../registry";
export declare const agentPingCommand: import("..").CommandDefinition<"agent.ping", Record<string, never>>;
export declare const serverStartCommand: import("..").CommandDefinition<"server.start", {
    server_id: string;
}>;
export declare const serverStopCommand: import("..").CommandDefinition<"server.stop", {
    server_id: string;
}>;
export declare const serverDeleteCommand: import("..").CommandDefinition<"server.delete", {
    server_id: string;
}>;
export declare const CORE_COMMANDS: readonly [import("..").CommandDefinition<"agent.ping", Record<string, never>>, import("..").CommandDefinition<"server.start", {
    server_id: string;
}>, import("..").CommandDefinition<"server.stop", {
    server_id: string;
}>, import("..").CommandDefinition<"server.delete", {
    server_id: string;
}>];
export declare function registerCoreCommands(registry: CommandRegistry): CommandRegistry;
export declare function createCoreRegistry(): CommandRegistry;
