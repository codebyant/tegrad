import type { z } from "zod";
export interface CommandDefinition<TType extends string = string, TBody = unknown> {
    readonly type: TType;
    readonly sensitive: boolean;
    readonly body: z.ZodType<TBody>;
}
export declare function defineCommand<TType extends string, TBody>(definition: {
    readonly type: TType;
    readonly sensitive: boolean;
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
