// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { closeSync, constants, existsSync, openSync, readSync, statSync, writeSync } from "node:fs";
import { consoleLineSchema, ProtocolError } from "../protocol";
import { assertValidServerId, resolveFifoPath, resolveServerDir, resolveServerSubpath } from "./id";

export const DEFAULT_CONSOLE_POLL_MS = 100;
export const MAX_LINES_PER_EVENT = 200;
export const MAX_BYTES_PER_EVENT = 64 * 1024;
export const MAX_LINES_PER_SECOND = 1000;

export type FifoWriter = (fifoPath: string, data: string) => void;

export interface ConsoleTimerHandle {
  readonly id?: unknown;
}

export interface ConsoleTimerProvider {
  setInterval(fn: () => void, ms: number): ConsoleTimerHandle;
  clearInterval(handle: ConsoleTimerHandle): void;
}

export const defaultConsoleTimers: ConsoleTimerProvider = {
  setInterval(fn, ms) {
    const id = setInterval(fn, ms);
    return { id };
  },
  clearInterval(handle) {
    clearInterval(handle.id as ReturnType<typeof setInterval>);
  },
};

function getErrnoCode(err: unknown): string | undefined {
  if (typeof err === "object" && err !== null && "code" in err) {
    const code = (err as { code: unknown }).code;
    return typeof code === "string" ? code : undefined;
  }
  return undefined;
}

export function defaultWriteFifo(fifoPath: string, data: string): void {
  const flags = constants.O_WRONLY | (constants.O_NONBLOCK ?? 0);
  let fd: number | undefined;
  try {
    fd = openSync(fifoPath, flags);
    const buf = Buffer.from(data, "utf8");
    let written = 0;
    while (written < buf.byteLength) {
      written += writeSync(fd, buf, written, buf.byteLength - written);
    }
  } catch (err) {
    const code = getErrnoCode(err);
    if (code === "ENXIO" || code === "ENOENT") {
      throw new ProtocolError(
        "server_stopped",
        "Server is not running or console FIFO has no reader",
      );
    }
    throw new ProtocolError("systemd_error", "Failed to write to server console FIFO");
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        // ignore close failure
      }
    }
  }
}

export interface SendConsoleLineOptions {
  readonly runDir: string;
  readonly serverId: string;
  readonly line: string;
  readonly writeFifoImpl?: FifoWriter;
}

export function sendConsoleLine(options: SendConsoleLineOptions): void {
  const validId = assertValidServerId(options.serverId);
  const parsedLine = consoleLineSchema.safeParse(options.line);
  if (!parsedLine.success) {
    throw new ProtocolError(
      "invalid_body",
      "Invalid console line: must be 1..1024 chars without CR, LF, or NUL",
    );
  }

  const fifoPath = resolveFifoPath(options.runDir, validId);
  const writer = options.writeFifoImpl ?? defaultWriteFifo;
  writer(fifoPath, `${parsedLine.data}\n`);
}

export interface ConsoleLinesEvent {
  readonly server_id: string;
  readonly lines: readonly string[];
  readonly next_offset: number;
  readonly reset?: true;
  readonly truncated?: true;
}

export type ConsoleEventEmitter = (type: string, body: ConsoleLinesEvent) => void;

export interface ConsoleSubscriptionManagerOptions {
  readonly serversDir: string;
  readonly pollIntervalMs?: number;
  readonly maxLinesPerEvent?: number;
  readonly maxBytesPerEvent?: number;
  readonly maxLinesPerSecond?: number;
  readonly timers?: ConsoleTimerProvider;
  readonly now?: () => number;
}

interface ActiveSubscription {
  readonly serverId: string;
  readonly logPath: string;
  readonly sendEvent: ConsoleEventEmitter;
  readonly timer: ConsoleTimerHandle;
  offset: number;
  windowStartMs: number;
  windowLineCount: number;
}

export interface ConsoleSubscriptionManager {
  subscribe(params: {
    readonly serverId: string;
    readonly fromOffset?: number;
    readonly sendEvent: ConsoleEventEmitter;
  }): void;
  unsubscribe(serverId: string): void;
  pollOnce(serverId: string): void;
  hasSubscription(serverId: string): boolean;
  closeAll(): void;
}

export function createConsoleSubscriptionManager(
  options: ConsoleSubscriptionManagerOptions,
): ConsoleSubscriptionManager {
  const pollIntervalMs = options.pollIntervalMs ?? DEFAULT_CONSOLE_POLL_MS;
  const maxLinesPerEvent = options.maxLinesPerEvent ?? MAX_LINES_PER_EVENT;
  const maxBytesPerEvent = options.maxBytesPerEvent ?? MAX_BYTES_PER_EVENT;
  const maxLinesPerSecond = options.maxLinesPerSecond ?? MAX_LINES_PER_SECOND;
  const timers = options.timers ?? defaultConsoleTimers;
  const now = options.now ?? (() => Date.now());

  const subscriptions = new Map<string, ActiveSubscription>();

  function pollSubscription(sub: ActiveSubscription): void {
    if (!existsSync(sub.logPath)) {
      return;
    }

    let fileSize: number;
    try {
      fileSize = statSync(sub.logPath).size;
    } catch {
      return;
    }

    let reset = false;
    if (fileSize < sub.offset) {
      sub.offset = 0;
      reset = true;
    }

    const availableBytes = fileSize - sub.offset;
    if (availableBytes <= 0) {
      if (reset) {
        sub.sendEvent("server.console.lines", {
          server_id: sub.serverId,
          lines: [],
          next_offset: 0,
          reset: true,
        });
      }
      return;
    }

    const currentTime = now();
    if (currentTime - sub.windowStartMs >= 1000) {
      sub.windowStartMs = currentTime;
      sub.windowLineCount = 0;
    }

    const remainingPerSecond = maxLinesPerSecond - sub.windowLineCount;
    if (remainingPerSecond <= 0) {
      return;
    }

    const lineBudget = Math.min(maxLinesPerEvent, remainingPerSecond);
    const bytesToRead = Math.min(availableBytes, maxBytesPerEvent);
    const buffer = Buffer.allocUnsafe(bytesToRead);

    let bytesRead = 0;
    let fd: number | undefined;
    try {
      fd = openSync(sub.logPath, "r");
      bytesRead = readSync(fd, buffer, 0, bytesToRead, sub.offset);
    } catch {
      return;
    } finally {
      if (fd !== undefined) {
        try {
          closeSync(fd);
        } catch {
          // ignore close failure
        }
      }
    }

    if (bytesRead <= 0) {
      return;
    }

    const slice = buffer.subarray(0, bytesRead);
    const lines: string[] = [];
    let consumedBytes = 0;
    let lineStart = 0;
    let truncated = availableBytes > bytesToRead;

    for (let i = 0; i < slice.byteLength; i++) {
      if (slice[i] === 0x0a) {
        const lineEnd = i > lineStart && slice[i - 1] === 0x0d ? i - 1 : i;
        lines.push(slice.subarray(lineStart, lineEnd).toString("utf8"));
        consumedBytes = i + 1;
        lineStart = i + 1;

        if (lines.length >= lineBudget) {
          if (consumedBytes < slice.byteLength || availableBytes > bytesToRead) {
            truncated = true;
          }
          break;
        }
      }
    }

    // If a single line exceeds maxBytesPerEvent without any newline, flush it so the reader makes progress.
    if (lines.length === 0 && bytesRead >= maxBytesPerEvent) {
      lines.push(slice.toString("utf8"));
      consumedBytes = bytesRead;
      truncated = true;
    }

    if (lines.length === 0 && !reset) {
      return;
    }

    sub.offset += consumedBytes;
    sub.windowLineCount += lines.length;

    const event: ConsoleLinesEvent = {
      server_id: sub.serverId,
      lines,
      next_offset: sub.offset,
      ...(reset ? { reset: true as const } : {}),
      ...(truncated ? { truncated: true as const } : {}),
    };
    sub.sendEvent("server.console.lines", event);
  }

  function unsubscribe(serverId: string): void {
    const validId = assertValidServerId(serverId);
    const existing = subscriptions.get(validId);
    if (existing !== undefined) {
      timers.clearInterval(existing.timer);
      subscriptions.delete(validId);
    }
  }

  return {
    subscribe(params) {
      const validId = assertValidServerId(params.serverId);
      const serverDir = resolveServerDir(options.serversDir, validId);
      if (!existsSync(serverDir)) {
        throw new ProtocolError("server_not_found", `Server not found: ${validId}`);
      }
      const logPath = resolveServerSubpath(serverDir, "logs/console.log");

      unsubscribe(validId);

      const sub: ActiveSubscription = {
        serverId: validId,
        logPath,
        sendEvent: params.sendEvent,
        offset: params.fromOffset ?? 0,
        windowStartMs: now(),
        windowLineCount: 0,
        timer: timers.setInterval(() => {
          pollSubscription(sub);
        }, pollIntervalMs),
      };

      subscriptions.set(validId, sub);
      pollSubscription(sub);
    },

    unsubscribe,

    pollOnce(serverId: string) {
      const validId = assertValidServerId(serverId);
      const sub = subscriptions.get(validId);
      if (sub !== undefined) {
        pollSubscription(sub);
      }
    },

    hasSubscription(serverId: string) {
      const validId = assertValidServerId(serverId);
      return subscriptions.has(validId);
    },

    closeAll() {
      for (const sub of subscriptions.values()) {
        timers.clearInterval(sub.timer);
      }
      subscriptions.clear();
    },
  };
}
