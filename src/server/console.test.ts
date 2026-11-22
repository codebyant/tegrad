// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, describe, expect, test } from "bun:test";
import { appendFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ProtocolError } from "../protocol";
import {
  type ConsoleLinesEvent,
  type ConsoleTimerHandle,
  type ConsoleTimerProvider,
  createConsoleSubscriptionManager,
  defaultWriteFifo,
  sendConsoleLine,
} from "./index";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

function makeFakeTimers() {
  const callbacks = new Map<number, () => void>();
  let nextId = 1;
  const provider: ConsoleTimerProvider = {
    setInterval(fn) {
      const id = nextId++;
      callbacks.set(id, fn);
      return { id };
    },
    clearInterval(handle: ConsoleTimerHandle) {
      callbacks.delete(handle.id as number);
    },
  };
  return {
    provider,
    tickAll() {
      for (const fn of [...callbacks.values()]) {
        fn();
      }
    },
    activeCount() {
      return callbacks.size;
    },
  };
}

describe("server.console.send", () => {
  test("writes valid line terminated with LF and rejects CR, LF, NUL, empty, and >1024 chars", () => {
    const written: { path: string; data: string }[] = [];
    sendConsoleLine({
      runDir: "/run/tegrad-server",
      serverId: "srv-1",
      line: "say hello world",
      writeFifoImpl: (path, data) => written.push({ path, data }),
    });
    expect(written).toHaveLength(1);
    expect(written[0]?.data).toBe("say hello world\n");

    const invalidLines = ["", "say hi\nstop", "say hi\rstop", "say hi\0stop", "a".repeat(1025)];
    for (const line of invalidLines) {
      try {
        sendConsoleLine({
          runDir: "/run/tegrad-server",
          serverId: "srv-1",
          line,
          writeFifoImpl: () => {},
        });
        throw new Error(`Expected rejection for line: ${JSON.stringify(line)}`);
      } catch (err) {
        expect(err).toBeInstanceOf(ProtocolError);
        expect((err as ProtocolError).code).toBe("invalid_body");
      }
    }
  });

  test("maps ENOENT/ENXIO from FIFO open to server_stopped", () => {
    const missingDir = makeTempDir("tegrad-fifo-missing-");
    try {
      defaultWriteFifo(join(missingDir, "srv-1.stdin"), "stop\n");
      throw new Error("Expected server_stopped");
    } catch (err) {
      expect(err).toBeInstanceOf(ProtocolError);
      expect((err as ProtocolError).code).toBe("server_stopped");
    }
  });
});

describe("console log subscription", () => {
  test("streams new lines from offset, enforces per-event & per-second limits, and handles rotation", () => {
    const serversDir = makeTempDir("tegrad-console-");
    const logsDir = join(serversDir, "srv-1", "logs");
    mkdirSync(logsDir, { recursive: true });
    const logPath = join(logsDir, "console.log");
    writeFileSync(logPath, "line 1\nline 2\n");

    const timers = makeFakeTimers();
    let nowMs = 1_000_000;
    const manager = createConsoleSubscriptionManager({
      serversDir,
      timers: timers.provider,
      maxLinesPerEvent: 3,
      maxBytesPerEvent: 4096,
      maxLinesPerSecond: 5,
      now: () => nowMs,
    });

    const events: ConsoleLinesEvent[] = [];
    manager.subscribe({
      serverId: "srv-1",
      sendEvent: (_type, body) => events.push(body),
    });

    expect(events).toHaveLength(1);
    expect(events[0]?.lines).toEqual(["line 1", "line 2"]);
    expect(events[0]?.next_offset).toBe(Buffer.byteLength("line 1\nline 2\n"));
    expect(events[0]?.reset).toBeUndefined();

    // Append 5 more lines: per-event cap is 3, and per-second cap is 5 (already emitted 2 -> budget 3 left)
    appendFileSync(logPath, "line 3\nline 4\nline 5\nline 6\nline 7\n");
    timers.tickAll();
    expect(events).toHaveLength(2);
    expect(events[1]?.lines).toEqual(["line 3", "line 4", "line 5"]);
    expect(events[1]?.truncated).toBe(true);

    // Same second: rate limit reached (5 lines already emitted in this 1s window)
    timers.tickAll();
    expect(events).toHaveLength(2);

    // Advance clock 1 second: remaining 2 lines delivered
    nowMs += 1000;
    timers.tickAll();
    expect(events).toHaveLength(3);
    expect(events[2]?.lines).toEqual(["line 6", "line 7"]);

    // Simulate log truncation / rotation
    writeFileSync(logPath, "fresh boot\n");
    timers.tickAll();
    expect(events).toHaveLength(4);
    expect(events[3]?.reset).toBe(true);
    expect(events[3]?.lines).toEqual(["fresh boot"]);
    expect(events[3]?.next_offset).toBe(Buffer.byteLength("fresh boot\n"));

    expect(timers.activeCount()).toBe(1);
    manager.unsubscribe("srv-1");
    expect(timers.activeCount()).toBe(0);
    expect(manager.hasSubscription("srv-1")).toBe(false);
  });
});
