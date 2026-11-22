// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { existsSync } from "node:fs";
import {
  type FetchLike,
  getStatePaths,
  type Logger,
  loadIdentityIfExists,
  loadOrCreateIdentity,
  loadRevocations,
  loadTrust,
  type RunPairingFlowOptions,
  resolveStateDir,
  runPairingFlow,
} from "../agent";
import { fingerprint } from "../crypto";
import { versionLine } from "../version";
import { formatUsage, parseCliArgs } from "./args";
import { type DoctorOptions, runDoctor } from "./doctor";
import { assertNotRoot, runAgentLoop } from "./run";

export interface CliDependencies {
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly stdout?: (text: string) => void;
  readonly stderr?: (text: string) => void;
  readonly geteuid?: () => number;
  readonly doctorOptions?: Omit<DoctorOptions, "env" | "stdout">;
  readonly runAgent?: (
    stateDir: string,
    env: Readonly<Record<string, string | undefined>>,
  ) => Promise<number>;
  readonly linkOptions?: Omit<
    RunPairingFlowOptions,
    "stateDir" | "env" | "add" | "reset" | "yes" | "allowUnverified" | "stdout" | "stderr"
  > & {
    readonly fetch?: FetchLike;
    readonly logger?: Logger;
  };
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
      if (parsed.options.add && parsed.options.reset) {
        stderr("Cannot combine --add and --reset.\n");
        return 2;
      }
      try {
        const stateDir = resolveStateDir(env);
        return await runPairingFlow({
          ...(deps.linkOptions ?? {}),
          stateDir,
          env,
          add: parsed.options.add,
          reset: parsed.options.reset,
          yes: parsed.options.yes,
          allowUnverified: parsed.options.allowUnverified,
          stdout,
          stderr,
        });
      } catch (err) {
        stderr(`${err instanceof Error ? err.message : String(err)}\n`);
        return 1;
      }
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
        const revocations = loadRevocations(stateDir);

        const lines = [
          `state_dir: ${stateDir}`,
          `fingerprint: ${identity ? fingerprint(identity.publicKey) : "not initialized"}`,
          `config: ${hasConfig ? "present" : "missing"}`,
          `trusted_accounts: ${trustedKeys.length}`,
        ];
        for (const key of trustedKeys) {
          const accountId = fingerprint(key);
          const revokedCount = revocations.accounts[accountId]?.revoked.length ?? 0;
          lines.push(`  - ${accountId} (revoked_sessions: ${revokedCount})`);
        }
        stdout(`${lines.join("\n")}\n`);
        return 0;
      } catch (err) {
        stderr(`${err instanceof Error ? err.message : String(err)}\n`);
        return 1;
      }
    }

    case "doctor": {
      try {
        return await runDoctor({
          ...(deps.doctorOptions ?? {}),
          env,
          stdout,
        });
      } catch (err) {
        stderr(`${err instanceof Error ? err.message : String(err)}\n`);
        return 1;
      }
    }

    case "run": {
      try {
        assertNotRoot(env, deps.geteuid);
        const stateDir = resolveStateDir(env);
        if (deps.runAgent) {
          return await deps.runAgent(stateDir, env);
        }
        return await runAgentLoop({
          stateDir,
          env,
          ...(deps.geteuid !== undefined ? { geteuid: deps.geteuid } : {}),
        });
      } catch (err) {
        stderr(`${err instanceof Error ? err.message : String(err)}\n`);
        return 1;
      }
    }
  }
}
