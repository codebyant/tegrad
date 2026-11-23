// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import {
  type HelloFrame,
  type KeyId,
  PROTOCOL_VERSION,
  type TransportFrame,
  transportFrameSchema,
} from "../protocol";
import type { Logger } from "./logger";

export const AGENT_CONNECT_PATH = "/v1/agents/connect";
export const MAX_INBOUND_MESSAGE_BYTES = 1024 * 1024;
export const MAX_OUTBOUND_QUEUE = 256;
export const INITIAL_BACKOFF_MS = 1_000;
export const MAX_BACKOFF_MS = 60_000;
export const STABLE_CONNECTION_MS = 30_000;
export const HEARTBEAT_INTERVAL_MS = 25_000;
export const IDLE_TIMEOUT_MS = 75_000;
export const HELLO_TIMEOUT_MS = 10_000;
/** After this many failed attempts in a row, connection errors are logged at debug level. */
export const QUIET_AFTER_FAILED_ATTEMPTS = 3;

export const WS_READY_STATE_CONNECTING = 0;
export const WS_READY_STATE_OPEN = 1;
export const WS_READY_STATE_CLOSING = 2;
export const WS_READY_STATE_CLOSED = 3;

export interface WebSocketMessageEventLike {
  readonly data: unknown;
}

export interface WebSocketCloseEventLike {
  readonly code?: number;
  readonly reason?: string;
}

export interface WebSocketLike {
  readonly readyState: number;
  onopen: (() => void) | null;
  onmessage: ((event: WebSocketMessageEventLike) => void) | null;
  onclose: ((event: WebSocketCloseEventLike) => void) | null;
  onerror: ((event: unknown) => void) | null;
  send(data: string): void;
  close(code?: number, reason?: string): void;
}

export type WebSocketFactory = (url: string) => WebSocketLike;

export type TimerHandle = unknown;

export interface TimerProvider {
  setTimeout(fn: () => void, ms: number): TimerHandle;
  clearTimeout(handle: TimerHandle): void;
  setInterval(fn: () => void, ms: number): TimerHandle;
  clearInterval(handle: TimerHandle): void;
  now(): number;
}

export const defaultTimers: TimerProvider = {
  setTimeout: (fn, ms) => setTimeout(fn, ms),
  clearTimeout: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
  setInterval: (fn, ms) => setInterval(fn, ms),
  clearInterval: (handle) => clearInterval(handle as ReturnType<typeof setInterval>),
  now: () => Date.now(),
};

export function createDefaultWebSocket(url: string): WebSocketLike {
  const ws = new WebSocket(url);
  const adapter: WebSocketLike = {
    get readyState() {
      return ws.readyState;
    },
    onopen: null,
    onmessage: null,
    onclose: null,
    onerror: null,
    send(data: string) {
      ws.send(data);
    },
    close(code?: number, reason?: string) {
      ws.close(code, reason);
    },
  };

  ws.addEventListener("open", () => {
    adapter.onopen?.();
  });
  ws.addEventListener("message", (event) => {
    adapter.onmessage?.({ data: event.data });
  });
  ws.addEventListener("close", (event) => {
    adapter.onclose?.({ code: event.code, reason: event.reason });
  });
  ws.addEventListener("error", (event) => {
    adapter.onerror?.(event);
  });

  return adapter;
}

export function buildConnectUrl(apiUrl: string, agentId: KeyId): string {
  const url = new URL(apiUrl);
  if (url.protocol === "https:") {
    url.protocol = "wss:";
  } else if (url.protocol === "http:") {
    url.protocol = "ws:";
  } else {
    throw new Error(`Unsupported api_url protocol: ${url.protocol}`);
  }

  const basePath = url.pathname.replace(/\/+$/, "");
  url.pathname = `${basePath}${AGENT_CONNECT_PATH}`;
  url.search = "";
  url.searchParams.set("agent", agentId);
  return url.toString();
}

export function computeBackoffDelayMs(attempt: number, random: () => number = Math.random): number {
  const base = Math.min(INITIAL_BACKOFF_MS * 2 ** Math.max(0, attempt), MAX_BACKOFF_MS);
  const clampedRandom = Math.min(1, Math.max(0, random()));
  const jittered = Math.round(base * (0.8 + clampedRandom * 0.4));
  return Math.min(MAX_BACKOFF_MS, jittered);
}

export interface AgentConnectionOptions {
  readonly apiUrl: string;
  readonly agentId: KeyId;
  readonly logger: Logger;
  readonly onFrame: (frame: TransportFrame) => void;
  readonly authenticate?: (socket: WebSocketLike) => void | Promise<void>;
  /**
   * Answers the control server's `hello` challenge with a signed `auth` frame.
   * When set, the connection only counts as authenticated (and only flushes
   * queued frames) after the `auth` frame was sent; without a `hello` within
   * `helloTimeoutMs` it reconnects.
   */
  readonly answerHello?: (hello: HelloFrame) => TransportFrame | Promise<TransportFrame>;
  readonly helloTimeoutMs?: number;
  readonly webSocketFactory?: WebSocketFactory;
  readonly timers?: TimerProvider;
  readonly random?: () => number;
  readonly maxInboundBytes?: number;
  readonly maxOutboundQueue?: number;
  readonly heartbeatIntervalMs?: number;
  readonly idleTimeoutMs?: number;
  readonly stableConnectionMs?: number;
}

export interface AgentConnection {
  start(): void;
  stop(): void;
  send(frame: TransportFrame): boolean;
  isConnected(): boolean;
  getQueuedCount(): number;
}

const utf8Encoder = new TextEncoder();

export function createAgentConnection(options: AgentConnectionOptions): AgentConnection {
  const connectUrl = buildConnectUrl(options.apiUrl, options.agentId);
  const wsFactory = options.webSocketFactory ?? createDefaultWebSocket;
  const timers = options.timers ?? defaultTimers;
  const random = options.random ?? Math.random;
  const maxInboundBytes = options.maxInboundBytes ?? MAX_INBOUND_MESSAGE_BYTES;
  const maxOutboundQueue = options.maxOutboundQueue ?? MAX_OUTBOUND_QUEUE;
  const heartbeatIntervalMs = options.heartbeatIntervalMs ?? HEARTBEAT_INTERVAL_MS;
  const idleTimeoutMs = options.idleTimeoutMs ?? IDLE_TIMEOUT_MS;
  const stableConnectionMs = options.stableConnectionMs ?? STABLE_CONNECTION_MS;
  const authenticate = options.authenticate ?? (() => {});
  const helloTimeoutMs = options.helloTimeoutMs ?? HELLO_TIMEOUT_MS;

  const outboundQueue: string[] = [];
  let running = false;
  let socket: WebSocketLike | null = null;
  let authenticated = false;
  let awaitingHello = false;
  let reconnectAttempt = 0;

  let reconnectTimer: TimerHandle | null = null;
  let stableTimer: TimerHandle | null = null;
  let heartbeatTimer: TimerHandle | null = null;
  let idleTimer: TimerHandle | null = null;
  let helloTimer: TimerHandle | null = null;

  function clearConnectionTimers(): void {
    if (helloTimer !== null) {
      timers.clearTimeout(helloTimer);
      helloTimer = null;
    }
    if (stableTimer !== null) {
      timers.clearTimeout(stableTimer);
      stableTimer = null;
    }
    if (heartbeatTimer !== null) {
      timers.clearInterval(heartbeatTimer);
      heartbeatTimer = null;
    }
    if (idleTimer !== null) {
      timers.clearTimeout(idleTimer);
      idleTimer = null;
    }
  }

  function clearReconnectTimer(): void {
    if (reconnectTimer !== null) {
      timers.clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
  }

  function resetIdleTimer(activeSocket: WebSocketLike): void {
    if (idleTimer !== null) {
      timers.clearTimeout(idleTimer);
      idleTimer = null;
    }
    idleTimer = timers.setTimeout(() => {
      if (!running || socket !== activeSocket) {
        return;
      }
      options.logger.warn("Connection idle timeout reached, reconnecting", {
        idleTimeoutMs,
      });
      detachAndReconnect(activeSocket, 4000, "idle_timeout");
    }, idleTimeoutMs);
  }

  function flushQueue(activeSocket: WebSocketLike): void {
    while (outboundQueue.length > 0) {
      if (!running || socket !== activeSocket || activeSocket.readyState !== WS_READY_STATE_OPEN) {
        return;
      }
      const next = outboundQueue.shift();
      if (next === undefined) {
        return;
      }
      try {
        activeSocket.send(next);
      } catch {
        outboundQueue.unshift(next);
        detachAndReconnect(activeSocket, 1011, "send_failed");
        return;
      }
    }
  }

  function scheduleReconnect(): void {
    if (!running || reconnectTimer !== null) {
      return;
    }
    const delayMs = computeBackoffDelayMs(reconnectAttempt, random);
    reconnectAttempt++;
    options.logger.info("Scheduling reconnect", {
      attempt: reconnectAttempt,
      delayMs,
    });
    reconnectTimer = timers.setTimeout(() => {
      reconnectTimer = null;
      if (running) {
        connect();
      }
    }, delayMs);
  }

  function detachAndReconnect(
    activeSocket: WebSocketLike,
    closeCode?: number,
    reason?: string,
  ): void {
    if (socket !== activeSocket) {
      return;
    }
    socket = null;
    authenticated = false;
    awaitingHello = false;
    clearConnectionTimers();
    activeSocket.onopen = null;
    activeSocket.onmessage = null;
    activeSocket.onclose = null;
    activeSocket.onerror = null;

    if (closeCode !== undefined) {
      try {
        activeSocket.close(closeCode, reason);
      } catch {
        // ignore close errors on dead socket
      }
    }

    if (running) {
      scheduleReconnect();
    }
  }

  function handleMessage(activeSocket: WebSocketLike, data: unknown): void {
    if (socket !== activeSocket || !running) {
      return;
    }
    if (typeof data !== "string") {
      options.logger.warn("Discarding non-text WebSocket message");
      return;
    }
    const byteLength = utf8Encoder.encode(data).byteLength;
    if (byteLength > maxInboundBytes) {
      options.logger.warn("Discarding oversized WebSocket message", {
        byteLength,
        maxInboundBytes,
      });
      return;
    }

    let raw: unknown;
    try {
      raw = JSON.parse(data) as unknown;
    } catch {
      options.logger.warn("Discarding invalid JSON WebSocket message");
      return;
    }

    const parsed = transportFrameSchema.safeParse(raw);
    if (!parsed.success) {
      options.logger.warn("Discarding invalid transport frame");
      return;
    }

    resetIdleTimer(activeSocket);

    if (parsed.data.kind === "hello") {
      if (awaitingHello && options.answerHello !== undefined) {
        void answerHello(activeSocket, parsed.data);
      } else {
        options.logger.warn("Discarding unexpected hello frame");
      }
      return;
    }
    if (parsed.data.kind === "auth") {
      options.logger.warn("Discarding unexpected auth frame");
      return;
    }
    if (awaitingHello) {
      options.logger.warn("Discarding frame received before authentication");
      return;
    }

    try {
      options.onFrame(parsed.data);
    } catch (err) {
      options.logger.error("Unhandled error in frame listener", {
        errName: err instanceof Error ? err.name : "Error",
      });
    }
  }

  function markAuthenticated(ws: WebSocketLike): void {
    awaitingHello = false;
    authenticated = true;
    options.logger.info("Connected to control server");

    stableTimer = timers.setTimeout(() => {
      if (running && socket === ws) {
        reconnectAttempt = 0;
      }
    }, stableConnectionMs);

    resetIdleTimer(ws);

    heartbeatTimer = timers.setInterval(() => {
      if (!running || socket !== ws || ws.readyState !== WS_READY_STATE_OPEN) {
        return;
      }
      const pingFrame: TransportFrame = {
        v: PROTOCOL_VERSION,
        kind: "ping",
        route: { agent: options.agentId },
        body: { ts: timers.now() },
      };
      try {
        ws.send(JSON.stringify(pingFrame));
      } catch {
        detachAndReconnect(ws, 1011, "ping_failed");
      }
    }, heartbeatIntervalMs);

    flushQueue(ws);
  }

  async function answerHello(ws: WebSocketLike, hello: HelloFrame): Promise<void> {
    if (options.answerHello === undefined) {
      return;
    }
    awaitingHello = false;
    if (helloTimer !== null) {
      timers.clearTimeout(helloTimer);
      helloTimer = null;
    }
    try {
      const authFrame = await options.answerHello(hello);
      if (!running || socket !== ws || ws.readyState !== WS_READY_STATE_OPEN) {
        return;
      }
      ws.send(JSON.stringify(transportFrameSchema.parse(authFrame)));
    } catch (err) {
      options.logger.warn("Failed to answer hello challenge", {
        errName: err instanceof Error ? err.name : "Error",
      });
      detachAndReconnect(ws, 4001, "auth_failed");
      return;
    }
    markAuthenticated(ws);
  }

  function connect(): void {
    if (!running) {
      return;
    }

    clearReconnectTimer();
    let ws: WebSocketLike;
    try {
      ws = wsFactory(connectUrl);
    } catch (err) {
      options.logger.warn("Failed to create WebSocket connection", {
        errName: err instanceof Error ? err.name : "Error",
      });
      scheduleReconnect();
      return;
    }

    socket = ws;
    authenticated = false;

    ws.onopen = () => {
      if (!running || socket !== ws) {
        return;
      }
      if (options.answerHello !== undefined) {
        awaitingHello = true;
        resetIdleTimer(ws);
        helloTimer = timers.setTimeout(() => {
          if (running && socket === ws && awaitingHello) {
            options.logger.warn("Control server did not send a hello challenge in time");
            detachAndReconnect(ws, 4002, "hello_timeout");
          }
        }, helloTimeoutMs);
      }
      void (async () => {
        try {
          await authenticate(ws);
        } catch (err) {
          options.logger.warn("Connection authentication hook failed", {
            errName: err instanceof Error ? err.name : "Error",
          });
          detachAndReconnect(ws, 4001, "auth_failed");
          return;
        }

        if (!running || socket !== ws || ws.readyState !== WS_READY_STATE_OPEN) {
          return;
        }

        if (options.answerHello === undefined) {
          markAuthenticated(ws);
        }
      })();
    };

    ws.onmessage = (event) => {
      handleMessage(ws, event.data);
    };

    ws.onerror = () => {
      if (!running || socket !== ws) {
        return;
      }
      // Repeated failures of the same outage are noise: warn for the first few, then debug.
      if (reconnectAttempt < QUIET_AFTER_FAILED_ATTEMPTS) {
        options.logger.warn("WebSocket error occurred");
      } else {
        options.logger.debug("WebSocket error occurred", { attempt: reconnectAttempt });
      }
    };

    ws.onclose = (event) => {
      if (socket !== ws) {
        return;
      }
      options.logger.info("WebSocket closed", {
        code: event.code ?? 0,
      });
      detachAndReconnect(ws);
    };
  }

  return {
    start(): void {
      if (running) {
        return;
      }
      running = true;
      connect();
    },

    stop(): void {
      if (!running) {
        return;
      }
      running = false;
      clearReconnectTimer();
      clearConnectionTimers();
      authenticated = false;
      const active = socket;
      socket = null;
      if (active) {
        active.onopen = null;
        active.onmessage = null;
        active.onclose = null;
        active.onerror = null;
        try {
          active.close(1000, "shutdown");
        } catch {
          // ignore close errors during shutdown
        }
      }
    },

    send(frame: TransportFrame): boolean {
      const validated = transportFrameSchema.parse(frame);
      const serialized = JSON.stringify(validated);

      if (
        running &&
        authenticated &&
        socket !== null &&
        socket.readyState === WS_READY_STATE_OPEN
      ) {
        try {
          socket.send(serialized);
          return true;
        } catch {
          detachAndReconnect(socket, 1011, "send_failed");
        }
      }

      if (outboundQueue.length >= maxOutboundQueue) {
        outboundQueue.shift();
      }
      outboundQueue.push(serialized);
      return false;
    },

    isConnected(): boolean {
      return (
        running && authenticated && socket !== null && socket.readyState === WS_READY_STATE_OPEN
      );
    },

    getQueuedCount(): number {
      return outboundQueue.length;
    },
  };
}
