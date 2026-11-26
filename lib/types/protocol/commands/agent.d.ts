import { z } from "zod";
import { type CommandRegistry } from "../registry";
export declare const SUBSCRIPTION_TOPICS: readonly ["server.status", "server.backup"];
export declare const subscriptionTopicSchema: z.ZodEnum<{
    "server.backup": "server.backup";
    "server.status": "server.status";
}>;
export type SubscriptionTopic = z.infer<typeof subscriptionTopicSchema>;
export declare const SERVER_STATES: readonly ["stopped", "starting", "running", "stopping", "crashed"];
export declare const serverStateSchema: z.ZodEnum<{
    crashed: "crashed";
    running: "running";
    starting: "starting";
    stopped: "stopped";
    stopping: "stopping";
}>;
export type ServerState = z.infer<typeof serverStateSchema>;
export declare const serverStatusChangedSchema: z.ZodObject<{
    server_id: z.ZodString;
    state: z.ZodEnum<{
        crashed: "crashed";
        running: "running";
        starting: "starting";
        stopped: "stopped";
        stopping: "stopping";
    }>;
    at: z.ZodNumber;
}, z.core.$strip>;
export type ServerStatusChanged = z.infer<typeof serverStatusChangedSchema>;
export declare const agentSubscribeBodySchema: z.ZodObject<{
    topics: z.ZodArray<z.ZodEnum<{
        "server.backup": "server.backup";
        "server.status": "server.status";
    }>>;
}, z.core.$strict>;
export type AgentSubscribeBody = z.infer<typeof agentSubscribeBodySchema>;
export declare const agentMembersSetBodySchema: z.ZodObject<{
    grant: z.ZodObject<{
        v: z.ZodLiteral<1>;
        kind: z.ZodLiteral<"server-role">;
        account_key: z.ZodString;
        agent: z.ZodString;
        servers: z.ZodUnion<readonly [z.ZodLiteral<"*">, z.ZodArray<z.ZodString>]>;
        role: z.ZodEnum<{
            admin: "admin";
            editor: "editor";
            operator: "operator";
            viewer: "viewer";
        }>;
        issued_at: z.ZodNumber;
        expires_at: z.ZodOptional<z.ZodNumber>;
        sig: z.ZodString;
    }, z.core.$strict>;
}, z.core.$strict>;
export type AgentMembersSetBody = z.infer<typeof agentMembersSetBodySchema>;
export declare const agentMembersRevokeBodySchema: z.ZodObject<{
    account: z.ZodString;
    servers: z.ZodOptional<z.ZodArray<z.ZodString>>;
}, z.core.$strict>;
export type AgentMembersRevokeBody = z.infer<typeof agentMembersRevokeBodySchema>;
export declare const agentSubscribeCommand: import("..").CommandDefinition<"agent.subscribe", {
    topics: ("server.backup" | "server.status")[];
}>;
export declare const agentUnsubscribeCommand: import("..").CommandDefinition<"agent.unsubscribe", {
    topics: ("server.backup" | "server.status")[];
}>;
export declare const agentMembersSetCommand: import("..").CommandDefinition<"agent.members.set", {
    grant: {
        v: 1;
        kind: "server-role";
        account_key: string;
        agent: string;
        servers: "*" | string[];
        role: "admin" | "editor" | "operator" | "viewer";
        issued_at: number;
        expires_at?: number | undefined;
        sig: string;
    };
}>;
export declare const agentMembersRevokeCommand: import("..").CommandDefinition<"agent.members.revoke", {
    account: string;
    servers?: string[] | undefined;
}>;
export declare const AGENT_COMMANDS: readonly [import("..").CommandDefinition<"agent.subscribe", {
    topics: ("server.backup" | "server.status")[];
}>, import("..").CommandDefinition<"agent.unsubscribe", {
    topics: ("server.backup" | "server.status")[];
}>, import("..").CommandDefinition<"agent.members.set", {
    grant: {
        v: 1;
        kind: "server-role";
        account_key: string;
        agent: string;
        servers: "*" | string[];
        role: "admin" | "editor" | "operator" | "viewer";
        issued_at: number;
        expires_at?: number | undefined;
        sig: string;
    };
}>, import("..").CommandDefinition<"agent.members.revoke", {
    account: string;
    servers?: string[] | undefined;
}>];
export declare function registerAgentCommands(registry: CommandRegistry): CommandRegistry;
