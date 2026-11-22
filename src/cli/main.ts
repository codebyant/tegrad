// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { existsSync } from "node:fs";
import {
  getStatePaths,
  loadIdentityIfExists,
  loadOrCreateIdentity,
  loadTrust,
  resolveStateDir,
} from "../agent";
import { fingerprint } from "../crypto";
import { versionLine } from "../version";
import { formatUsage, parseCliArgs } from "./args";
import { runAgentLoop } from "./run";

export interface CliDependencies {
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly stdout?: (text: string) => void;
  readonly stderr?: (text: string) => void;
  readonly runAgent?: (
    stateDir: string,
    env: Readonly<Record<string, string | undefined>>,
  ) => Promise<number>;
}

export async function runCli(argv: readonly string[], deps: CliDependencies = {}): Promise<number> {
  const env = deps.env ?? process.env;
  const stdout = deps.stdout ?? ((text: string) => process.stdout.write(text));
  const stderr = deps.stderr ?? ((text: string) => process.stderr.write(text));
  const parsed = parseCliArgs(argv);

  switch (parsed.kind) {
    case "version": {
      stdout(`${versionLine()}\n`);
      return 0;
    }

    case "help": {
      stdout(formatUsage(versionLine()));
      return 0;
    }

    case "link": {
      stderr("not implemented\n");
      return 2;
    }

    case "unknown": {
      stderr(`Unknown command: ${parsed.token}\n\n${formatUsage(versionLine())}`);
      return 2;
    }

    case "identity": {
      try {
        const stateDir = resolveStateDir(env);
        const keyPair = await loadOrCreateIdentity(stateDir);
        stdout(`${fingerprint(keyPair.publicKey)}\n`);
        return 0;
      } catch (err) {
        stderr(`${err instanceof Error ? err.message : String(err)}\n`);
        return 1;
      }
    }

    case "status": {
      try {
        const stateDir = resolveStateDir(env);
        const paths = getStatePaths(stateDir);
        const identity = await loadIdentityIfExists(stateDir);
        const hasConfig = existsSync(paths.configPath);
        const trustedKeys = await loadTrust(stateDir);

        const lines = [
          `state_dir: ${stateDir}`,
          `fingerprint: ${identity ? fingerprint(identity.publicKey) : "not initialized"}`,
          `config: ${hasConfig ? "present" : "missing"}`,
          `trusted_accounts: ${trustedKeys.length}`,
        ];
        stdout(`${lines.join("\n")}\n`);
        return 0;
      } catch (err) {
        stderr(`${err instanceof Error ? err.message : String(err)}\n`);
        return 1;
      }
    }

    case "run": {
      try {
        const stateDir = resolveStateDir(env);
        if (deps.runAgent) {
          return await deps.runAgent(stateDir, env);
        }
        return await runAgentLoop({ stateDir, env });
      } catch (err) {
        stderr(`${err instanceof Error ? err.message : String(err)}\n`);
        return 1;
      }
    }
  }
}
