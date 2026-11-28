import type { z } from "zod";
import type { Role } from "./roles";
/**
 * What a command needs from its signer, split by the sandbox boundary:
 * - `session`: stays inside the server folder; any valid session key.
 * - `sudo`: leaves the folder (restore a backup, delete a server, tunnel keys); an
 *   elevated session (short lived, see `MAX_ELEVATED_SESSION_MS`) or the account key.
 * - `account`: recovery and access (delete a backup, members); the account key only.
 */
export type CommandLevel = "session" | "sudo" | "account";
export interface CommandDefinition<TType extends string = string, TBody = unknown> {
    readonly type: TType;
    readonly level: CommandLevel;
    /** `level !== "session"`. Kept for launchers that only know this flag. */
    readonly sensitive: boolean;
    readonly minRole: Role;
    readonly body: z.ZodType<TBody>;
}
export declare function defineCommand<TType extends string, TBody>(definition: {
    readonly type: TType;
    readonly level: CommandLevel;
    readonly minRole: Role;
    readonly body: z.ZodType<TBody>;
}): CommandDefinition<TType, TBody>;
export declare class CommandRegistry {
    #private;
    register(definition: CommandDefinition): this;
    registerAll(definitions: readonly CommandDefinition[]): this;
    get(type: string): CommandDefinition | undefined;
    has(type: string): boolean;
    types(): string[];
}
