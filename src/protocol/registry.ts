// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

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

export function defineCommand<TType extends string, TBody>(definition: {
  readonly type: TType;
  readonly level: CommandLevel;
  readonly minRole: Role;
  readonly body: z.ZodType<TBody>;
}): CommandDefinition<TType, TBody> {
  return {
    type: definition.type,
    level: definition.level,
    sensitive: definition.level !== "session",
    minRole: definition.minRole,
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
