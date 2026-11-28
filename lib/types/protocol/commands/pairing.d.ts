import { type CommandRegistry } from "../registry";
export declare const agentRevocationsSetCommand: import("..").CommandDefinition<"agent.revocations.set", {
    list: {
        v: 1;
        account: string;
        issued_at: number;
        revoked: string[];
        sig: string;
    };
}>;
export declare const PAIRING_COMMANDS: readonly [import("..").CommandDefinition<"agent.revocations.set", {
    list: {
        v: 1;
        account: string;
        issued_at: number;
        revoked: string[];
        sig: string;
    };
}>];
export declare function registerPairingCommands(registry: CommandRegistry): CommandRegistry;
