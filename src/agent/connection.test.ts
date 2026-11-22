// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { describe, expect, test } from "bun:test";
import { PROTOCOL_VERSION, type TransportFrame } from "../protocol";
import {
  buildConnectUrl,
  computeBackoffDelayMs,
  createAgentConnection,
  HEARTBEAT_INTERVAL_MS,
  IDLE_TIMEOUT_MS,
  MAX_INBOUND_MESSAGE_BYTES,
  MAX_OUTBOUND_QUEUE,
  STABLE_CONNECTION_MS,
  type TimerProvider,
  type WebSocketCloseEventLike,
  type WebSocketLike,
  type WebSocketMessageEventLike,
  WS_READY_STATE_CLOSED,
  WS_READY_STATE_CONNECTING,
  WS_READY_STATE_OPEN,
} from "./connection";
import { createLogger } from "./logger";

const AGENT_ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

class FakeSocket implements WebSocketLike {
  readyState: number = WS_READY_STATE_CONNECTING;
  onopen: (() => void) | null = null;
  onmessage: ((event: WebSocketMessageEventLike) => void) | null = null;
  onclose: ((event: WebSocketCloseEventLike) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  readonly sent: string[] = [];
  readonly closeCalls: { code?: number; reason?: string }[] = [];

  constructor(readonly url: string) {}

  send(data: string): void {
    if (this.readyState !== WS_READY_STATE_OPEN) {
      throw new Error("Socket not open");
    }
    this.sent.push(data);
  }

  close(code?: number, reason?: string): void {
    this.closeCalls.push({
      ...(code !== undefined ? { code } : {}),
      ...(reason !== undefined ? { reason } : {}),
    });
    if (this.readyState === WS_READY_STATE_CLOSED) {
      return;
    }
    this.readyState = WS_READY_STATE_CLOSED;
    this.onclose?.({
      ...(code !== undefined ? { code } : {}),
      ...(reason !== undefined ? { reason } : {}),
    });
  }

  triggerOpen(): void {
    this.readyState = WS_READY_STATE_OPEN;
    this.onopen?.();
  }

  triggerMessage(data: unknown): void {
    this.onmessage?.({ data });
  }

  triggerDrop(code = 1006, reason = "dropped"): void {
    this.readyState = WS_READY_STATE_CLOSED;
    this.onclose?.({ code, reason });
  }
}

interface ScheduledTimer {
  id: number;
  runAt: number;
  intervalMs: number | null;
  fn: () => void;
  cleared: boolean;
}

class FakeTimers implements TimerProvider {
  private currentTime = 1_700_000_000_000;
  private nextId = 1;
  private readonly timers = new Map<number, ScheduledTimer>();

  setTimeout(fn: () => void, ms: number): number {
    const id = this.nextId++;
    this.timers.set(id, {
      id,
      runAt: this.currentTime + ms,
      intervalMs: null,
      fn,
      cleared: false,
    });
    return id;
  }

  clearTimeout(handle: unknown): void {
    const entry = this.timers.get(handle as number);
    if (entry) {
      entry.cleared = true;
      this.timers.delete(entry.id);
    }
  }

  setInterval(fn: () => void, ms: number): number {
    const id = this.nextId++;
    this.timers.set(id, {
      id,
      runAt: this.currentTime + ms,
      intervalMs: ms,
      fn,
      cleared: false,
    });
    return id;
  }

  clearInterval(handle: unknown): void {
    this.clearTimeout(handle);
  }

  now(): number {
    return this.currentTime;
  }

  advance(ms: number): void {
    const target = this.currentTime + ms;
    while (true) {
      let next: ScheduledTimer | null = null;
      for (const t of this.timers.values()) {
        if (t.cleared || t.runAt > target) continue;
        if (next === null || t.runAt < next.runAt) {
          next = t;
        }
      }
      if (next === null) {
        break;
      }
      this.currentTime = next.runAt;
      if (next.intervalMs !== null) {
        next.runAt += next.intervalMs;
      } else {
        this.timers.delete(next.id);
      }
      next.fn();
    }
    this.currentTime = target;
  }

  activeCount(): number {
    return this.timers.size;
  }
}

function makeLogger(logs: string[] = []) {
  return createLogger({
    level: "debug",
    stdout: (line) => logs.push(line),
    stderr: (line) => logs.push(line),
  });
}

function makePingFrame(ts: number): TransportFrame {
  return {
    v: PROTOCOL_VERSION,
    kind: "ping",
    route: { agent: AGENT_ID },
    body: { ts },
  };
}

async function flushMicrotasks(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}

describe("connection", () => {
  test("buildConnectUrl converts https/http to wss/ws with agent query param", () => {
    expect(buildConnectUrl("https://api.tegra.example", AGENT_ID)).toBe(
      `wss://api.tegra.example/agents/connect?agent=${AGENT_ID}`,
    );
    expect(buildConnectUrl("http://127.0.0.1:8080/v1/", AGENT_ID)).toBe(
      `ws://127.0.0.1:8080/v1/agents/connect?agent=${AGENT_ID}`,
    );
  });

  test("computeBackoffDelayMs scales exponentially with jitter within range and caps at 60s", () => {
    expect(computeBackoffDelayMs(0, () => 0)).toBe(800);
    expect(computeBackoffDelayMs(0, () => 0.5)).toBe(1000);
    expect(computeBackoffDelayMs(0, () => 1)).toBe(1200);
    expect(computeBackoffDelayMs(1, () => 0.5)).toBe(2000);
    expect(computeBackoffDelayMs(2, () => 0.5)).toBe(4000);
    expect(computeBackoffDelayMs(10, () => 1)).toBe(60_000);
  });

  test("reconnects with exponential backoff and resets backoff after stable connection", async () => {
    const timers = new FakeTimers();
    const sockets: FakeSocket[] = [];
    const conn = createAgentConnection({
      apiUrl: "https://api.tegra.example",
      agentId: AGENT_ID,
      logger: makeLogger(),
      onFrame: () => {},
      webSocketFactory: (url) => {
        const ws = new FakeSocket(url);
        sockets.push(ws);
        return ws;
      },
      timers,
      random: () => 0.5, // exact base backoff: 1000, 2000, 4000...
    });

    conn.start();
    expect(sockets.length).toBe(1);

    // Drop #1 -> reconnect after 1000ms
    sockets[0]?.triggerDrop();
    timers.advance(999);
    expect(sockets.length).toBe(1);
    timers.advance(1);
    expect(sockets.length).toBe(2);

    // Drop #2 -> reconnect after 2000ms
    sockets[1]?.triggerDrop();
    timers.advance(1999);
    expect(sockets.length).toBe(2);
    timers.advance(1);
    expect(sockets.length).toBe(3);

    // Connect and stay stable for 30s -> backoff resets to 1000ms
    sockets[2]?.triggerOpen();
    await flushMicrotasks();
    timers.advance(STABLE_CONNECTION_MS);

    sockets[2]?.triggerDrop();
    timers.advance(999);
    expect(sockets.length).toBe(3);
    timers.advance(1);
    expect(sockets.length).toBe(4);

    conn.stop();
    expect(timers.activeCount()).toBe(0);
  });

  test("sends heartbeat pings every 25s and reconnects after 75s without inbound traffic", async () => {
    const timers = new FakeTimers();
    const sockets: FakeSocket[] = [];
    const received: TransportFrame[] = [];

    const conn = createAgentConnection({
      apiUrl: "https://api.tegra.example",
      agentId: AGENT_ID,
      logger: makeLogger(),
      onFrame: (frame) => received.push(frame),
      webSocketFactory: (url) => {
        const ws = new FakeSocket(url);
        sockets.push(ws);
        return ws;
      },
      timers,
      random: () => 0.5,
    });

    conn.start();
    sockets[0]?.triggerOpen();
    await flushMicrotasks();

    timers.advance(HEARTBEAT_INTERVAL_MS);
    expect(sockets[0]?.sent.length).toBe(1);
    const ping = JSON.parse(sockets[0]?.sent[0] ?? "") as TransportFrame;
    expect(ping.kind).toBe("ping");

    // Advance remaining time up to 75s with no inbound frames -> connection torn down
    timers.advance(IDLE_TIMEOUT_MS - HEARTBEAT_INTERVAL_MS);
    expect(sockets[0]?.readyState).toBe(WS_READY_STATE_CLOSED);

    // After backoff (1000ms), reconnects
    timers.advance(1000);
    expect(sockets.length).toBe(2);

    // Inbound traffic resets idle timer
    sockets[1]?.triggerOpen();
    await flushMicrotasks();
    timers.advance(50_000);
    sockets[1]?.triggerMessage(JSON.stringify(makePingFrame(timers.now())));
    expect(received.length).toBe(1);
    timers.advance(50_000);
    expect(sockets[1]?.readyState).toBe(WS_READY_STATE_OPEN);

    conn.stop();
  });

  test("discards invalid frames and oversized messages without dropping the connection", async () => {
    const timers = new FakeTimers();
    const sockets: FakeSocket[] = [];
    const received: TransportFrame[] = [];
    const logs: string[] = [];

    const conn = createAgentConnection({
      apiUrl: "https://api.tegra.example",
      agentId: AGENT_ID,
      logger: makeLogger(logs),
      onFrame: (frame) => received.push(frame),
      webSocketFactory: (url) => {
        const ws = new FakeSocket(url);
        sockets.push(ws);
        return ws;
      },
      timers,
    });

    conn.start();
    sockets[0]?.triggerOpen();
    await flushMicrotasks();

    // Bad JSON
    sockets[0]?.triggerMessage("{broken");
    // Valid JSON, invalid TransportFrame
    sockets[0]?.triggerMessage(JSON.stringify({ kind: "unknown" }));
    // Oversized message (> 1 MiB)
    sockets[0]?.triggerMessage("x".repeat(MAX_INBOUND_MESSAGE_BYTES + 1));

    expect(received.length).toBe(0);
    expect(conn.isConnected()).toBe(true);
    expect(logs.filter((l) => l.includes('"level":"warn"')).length).toBe(3);

    // Connection still accepts valid frames afterwards
    sockets[0]?.triggerMessage(JSON.stringify(makePingFrame(timers.now())));
    expect(received.length).toBe(1);

    conn.stop();
  });

  test("queues outbound frames while disconnected up to 256 and flushes after authenticate on reconnect", async () => {
    const timers = new FakeTimers();
    const sockets: FakeSocket[] = [];
    let authCalls = 0;

    const conn = createAgentConnection({
      apiUrl: "https://api.tegra.example",
      agentId: AGENT_ID,
      logger: makeLogger(),
      onFrame: () => {},
      authenticate: async () => {
        authCalls++;
      },
      webSocketFactory: (url) => {
        const ws = new FakeSocket(url);
        sockets.push(ws);
        return ws;
      },
      timers,
    });

    // Send 260 frames while disconnected -> oldest 4 discarded, 256 kept
    for (let i = 1; i <= MAX_OUTBOUND_QUEUE + 4; i++) {
      expect(conn.send(makePingFrame(i))).toBe(false);
    }
    expect(conn.getQueuedCount()).toBe(MAX_OUTBOUND_QUEUE);

    conn.start();
    sockets[0]?.triggerOpen();
    await flushMicrotasks();

    expect(authCalls).toBe(1);
    expect(conn.getQueuedCount()).toBe(0);
    expect(sockets[0]?.sent.length).toBe(MAX_OUTBOUND_QUEUE);

    const firstFlushed = JSON.parse(sockets[0]?.sent[0] ?? "") as Extract<
      TransportFrame,
      { kind: "ping" }
    >;
    const lastFlushed = JSON.parse(sockets[0]?.sent[MAX_OUTBOUND_QUEUE - 1] ?? "") as Extract<
      TransportFrame,
      { kind: "ping" }
    >;

    expect(firstFlushed.body.ts).toBe(5);
    expect(lastFlushed.body.ts).toBe(MAX_OUTBOUND_QUEUE + 4);

    conn.stop();
  });
});
