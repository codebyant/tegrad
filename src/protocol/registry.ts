// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import type { z } from "zod";

export interface CommandDefinition<TType extends string = string, TBody = unknown> {
  readonly type: TType;
  readonly sensitive: boolean;
  readonly body: z.ZodType<TBody>;
}

export function defineCommand<TType extends string, TBody>(definition: {
  readonly type: TType;
  readonly sensitive: boolean;
  readonly body: z.ZodType<TBody>;
}): CommandDefinition<TType, TBody> {
  return {
    type: definition.type,
    sensitive: definition.sensitive,
    body: definition.body,
  };
}

export class CommandRegistry {
  readonly #commands = new Map<string, CommandDefinition>();

  register(definition: CommandDefinition): this {
    if (this.#commands.has(definition.type)) {
      throw new Error(`Command already registered: ${definition.type}`);
    }
    this.#commands.set(definition.type, definition);
    return this;
  }

  registerAll(definitions: readonly CommandDefinition[]): this {
    for (const definition of definitions) {
      this.register(definition);
    }
    return this;
  }

  get(type: string): CommandDefinition | undefined {
    return this.#commands.get(type);
  }

  has(type: string): boolean {
    return this.#commands.has(type);
  }

  types(): string[] {
    return [...this.#commands.keys()];
  }
}
