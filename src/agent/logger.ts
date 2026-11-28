// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";

export const logLevelSchema = z.enum(["debug", "info", "warn", "error"]);
export type LogLevel = z.infer<typeof logLevelSchema>;

const LEVEL_RANK: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

const SENSITIVE_KEY_PATTERN = /secret|key|token|password|payload/i;
const REDACTED = "[redacted]";

export type LogContext = Record<string, unknown>;

export interface Logger {
  debug(msg: string, context?: LogContext): void;
  info(msg: string, context?: LogContext): void;
  warn(msg: string, context?: LogContext): void;
  error(msg: string, context?: LogContext): void;
  child(baseContext: LogContext): Logger;
}

export interface LoggerOptions {
  readonly level?: LogLevel;
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly stdout?: (line: string) => void;
  readonly stderr?: (line: string) => void;
  readonly now?: () => number;
  readonly baseContext?: LogContext;
}

export function resolveLogLevel(
  env: Readonly<Record<string, string | undefined>> = process.env,
): LogLevel {
  const raw = env.TEGRAD_LOG_LEVEL?.trim().toLowerCase();
  if (!raw) {
    return "info";
  }
  const parsed = logLevelSchema.safeParse(raw);
  return parsed.success ? parsed.data : "info";
}

export function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY_PATTERN.test(key);
}

export function redactValue(value: unknown, seen: WeakSet<object> = new WeakSet()): unknown {
  if (value === null || value === undefined) {
    return value;
  }
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (value instanceof Uint8Array) {
    return `[Uint8Array(${value.byteLength})]`;
  }
  if (value instanceof Error) {
    return { name: value.name, message: value.message };
  }
  if (typeof value !== "object") {
    return String(value);
  }
  if (seen.has(value)) {
    return "[circular]";
  }
  seen.add(value);

  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item, seen));
  }

  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value)) {
    if (isSensitiveKey(k)) {
      out[k] = REDACTED;
    } else if (v !== undefined) {
      out[k] = redactValue(v, seen);
    }
  }
  return out;
}

export function createLogger(options: LoggerOptions = {}): Logger {
  const level = options.level ?? resolveLogLevel(options.env);
  const minRank = LEVEL_RANK[level];
  const writeStdout = options.stdout ?? ((line: string) => process.stdout.write(line));
  const writeStderr = options.stderr ?? ((line: string) => process.stderr.write(line));
  const now = options.now ?? (() => Date.now());
  const baseContext = options.baseContext;

  function emit(entryLevel: LogLevel, msg: string, context?: LogContext): void {
    if (LEVEL_RANK[entryLevel] < minRank) {
      return;
    }

    const merged: Record<string, unknown> = {};
    if (baseContext) {
      const redactedBase = redactValue(baseContext) as Record<string, unknown>;
      Object.assign(merged, redactedBase);
    }
    if (context) {
      const redactedCtx = redactValue(context) as Record<string, unknown>;
      Object.assign(merged, redactedCtx);
    }

    const record: Record<string, unknown> = {
      ...merged,
      ts: new Date(now()).toISOString(),
      level: entryLevel,
      msg,
    };

    const line = `${JSON.stringify(record)}\n`;
    if (entryLevel === "error") {
      writeStderr(line);
    } else {
      writeStdout(line);
    }
  }

  return {
    debug(msg: string, context?: LogContext): void {
      emit("debug", msg, context);
    },
    info(msg: string, context?: LogContext): void {
      emit("info", msg, context);
    },
    warn(msg: string, context?: LogContext): void {
      emit("warn", msg, context);
    },
    error(msg: string, context?: LogContext): void {
      emit("error", msg, context);
    },
    child(extraContext: LogContext): Logger {
      return createLogger({
        level,
        stdout: writeStdout,
        stderr: writeStderr,
        now,
        baseContext: { ...(baseContext ?? {}), ...extraContext },
      });
    },
  };
}
