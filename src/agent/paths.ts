// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { z } from "zod";

export const DEFAULT_LINUX_STATE_DIR = "/var/lib/tegrad";

const stateDirEnvSchema = z.object({
  TEGRAD_STATE_DIR: z.string().trim().min(1).optional(),
});

export interface StatePaths {
  readonly stateDir: string;
  readonly configPath: string;
  readonly identityPath: string;
  readonly trustPath: string;
  readonly revocationsPath: string;
  readonly replayPath: string;
  readonly updateDir: string;
}

export function resolveStateDir(
  env: Readonly<Record<string, string | undefined>> = process.env,
  platform: NodeJS.Platform = process.platform,
  homeDirectory: string = homedir(),
): string {
  const raw = env.TEGRAD_STATE_DIR;
  if (raw !== undefined && raw.trim().length > 0) {
    const parsed = stateDirEnvSchema.parse({ TEGRAD_STATE_DIR: raw });
    if (parsed.TEGRAD_STATE_DIR !== undefined) {
      return resolve(parsed.TEGRAD_STATE_DIR);
    }
  }

  if (platform === "linux") {
    return DEFAULT_LINUX_STATE_DIR;
  }

  return join(homeDirectory, ".tegrad");
}

export function getStatePaths(stateDir: string): StatePaths {
  return {
    stateDir,
    configPath: join(stateDir, "config.json"),
    identityPath: join(stateDir, "identity.json"),
    trustPath: join(stateDir, "trust.json"),
    revocationsPath: join(stateDir, "revocations.json"),
    replayPath: join(stateDir, "replay.json"),
    updateDir: join(stateDir, "update"),
  };
}
