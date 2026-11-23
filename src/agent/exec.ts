// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { accessSync, constants, statSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";

export const DEFAULT_EXEC_TIMEOUT_MS = 10_000;
export const DEFAULT_EXEC_MAX_OUTPUT_BYTES = 64 * 1024;

export interface RunFixedOptions {
  readonly timeoutMs?: number;
  readonly maxOutputBytes?: number;
}

export interface RunFixedResult {
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
  readonly truncated: boolean;
}

const commandSchema = z.string().min(1);
const argsSchema = z.array(z.string());
const optionsSchema = z.object({
  timeoutMs: z.number().int().positive().optional(),
  maxOutputBytes: z.number().int().positive().optional(),
});

function buildMinimalEnv(platform: NodeJS.Platform = process.platform): Record<string, string> {
  if (platform === "win32") {
    const env: Record<string, string> = {};
    if (process.env.PATH !== undefined) {
      env.PATH = process.env.PATH;
    } else if (process.env.Path !== undefined) {
      env.PATH = process.env.Path;
    }
    if (process.env.SystemRoot !== undefined) {
      env.SystemRoot = process.env.SystemRoot;
    }
    return env;
  }

  return {
    PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    LC_ALL: "C",
  };
}

/**
 * Resolves a bare command name against the fixed PATH we hand to the child, not the
 * caller's PATH. Spawning "systemctl" otherwise searches the parent's PATH, which can
 * contain directories the service user cannot enter (EACCES from posix_spawn).
 */
export function resolveCommandPath(
  command: string,
  platform: NodeJS.Platform = process.platform,
  searchPath: string | undefined = buildMinimalEnv(platform).PATH,
): string {
  if (platform === "win32" || command.includes("/") || searchPath === undefined) {
    return command;
  }
  for (const dir of searchPath.split(":")) {
    const candidate = join(dir, command);
    try {
      if (statSync(candidate).isFile()) {
        accessSync(candidate, constants.X_OK);
        return candidate;
      }
    } catch {
      // not here or not executable; try the next directory
    }
  }
  return command;
}

async function readStreamCapped(
  stream: ReadableStream<Uint8Array> | null,
  maxBytes: number,
): Promise<{ readonly text: string; readonly truncated: boolean }> {
  if (stream === null) {
    return { text: "", truncated: false };
  }

  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  let truncated = false;

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) {
        break;
      }
      if (value === undefined || value.byteLength === 0) {
        continue;
      }
      if (totalBytes + value.byteLength <= maxBytes) {
        chunks.push(value);
        totalBytes += value.byteLength;
      } else {
        const remaining = maxBytes - totalBytes;
        if (remaining > 0) {
          chunks.push(value.subarray(0, remaining));
          totalBytes += remaining;
        }
        truncated = true;
        await reader.cancel();
        break;
      }
    }
  } catch {
    // Stream may abort when process is killed on timeout
  } finally {
    reader.releaseLock();
  }

  const combined = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return {
    text: new TextDecoder().decode(combined),
    truncated,
  };
}

/**
 * Executes a fixed external command with argv array (never via a shell),
 * minimal environment, strict timeout, and capped stdout/stderr buffers.
 */
export async function runFixed(
  command: string,
  args: readonly string[],
  options: RunFixedOptions = {},
): Promise<RunFixedResult> {
  const validCommand = commandSchema.parse(command);
  const validArgs = argsSchema.parse(args);
  const validOptions = optionsSchema.parse(options);

  const timeoutMs = validOptions.timeoutMs ?? DEFAULT_EXEC_TIMEOUT_MS;
  const maxOutputBytes = validOptions.maxOutputBytes ?? DEFAULT_EXEC_MAX_OUTPUT_BYTES;

  const proc = Bun.spawn([resolveCommandPath(validCommand), ...validArgs], {
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
    env: buildMinimalEnv(),
  });

  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    try {
      proc.kill();
    } catch {
      // Process may have already exited
    }
  }, timeoutMs);

  try {
    const [stdoutRes, stderrRes, exitCode] = await Promise.all([
      readStreamCapped(proc.stdout, maxOutputBytes),
      readStreamCapped(proc.stderr, maxOutputBytes),
      proc.exited,
    ]);

    return {
      code: timedOut ? -1 : exitCode,
      stdout: stdoutRes.text,
      stderr: stderrRes.text,
      timedOut,
      truncated: stdoutRes.truncated || stderrRes.truncated,
    };
  } finally {
    clearTimeout(timer);
  }
}
