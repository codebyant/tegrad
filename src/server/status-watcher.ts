// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import type { ServerState, ServerStatusChanged } from "../protocol";

export const DEFAULT_STATUS_POLL_INTERVAL_MS = 3_000;

/** Maps a systemd `ActiveState` to the state clients see, or null when it is not meaningful. */
export function mapUnitState(activeState: string): ServerState | null {
  switch (activeState) {
    case "active":
    case "reloading":
      return "running";
    case "activating":
      return "starting";
    case "deactivating":
      return "stopping";
    case "inactive":
      return "stopped";
    case "failed":
      return "crashed";
    default:
      return null;
  }
}

export interface StatusWatcherTimers {
  setInterval(fn: () => void, ms: number): unknown;
  clearInterval(handle: unknown): void;
}

export interface StatusWatcherOptions {
  readonly listServerIds: () => readonly string[];
  readonly getState: (serverId: string) => Promise<ServerState | null>;
  readonly emit: (change: ServerStatusChanged) => void;
  /** Polling only runs while this returns true (e.g. while someone is subscribed). */
  readonly shouldPoll?: () => boolean;
  readonly now?: () => number;
  readonly intervalMs?: number;
  readonly timers?: StatusWatcherTimers;
}

export interface ServerStatusWatcher {
  start(): void;
  stop(): void;
  /** Reads the server's state now and emits a change if it differs from the last one seen. */
  refresh(serverId: string): Promise<void>;
  /** Forgets a server that no longer exists. */
  forget(serverId: string): void;
  pollOnce(): Promise<void>;
}

const defaultTimers: StatusWatcherTimers = {
  setInterval: (fn, ms) => setInterval(fn, ms),
  clearInterval: (handle) => clearInterval(handle as ReturnType<typeof setInterval>),
};

export function createServerStatusWatcher(options: StatusWatcherOptions): ServerStatusWatcher {
  const now = options.now ?? (() => Date.now());
  const timers = options.timers ?? defaultTimers;
  const intervalMs = options.intervalMs ?? DEFAULT_STATUS_POLL_INTERVAL_MS;
  const lastStates = new Map<string, ServerState>();
  let handle: unknown = null;
  let polling = false;

  async function observe(serverId: string, emitFirst: boolean): Promise<void> {
    let state: ServerState | null;
    try {
      state = await options.getState(serverId);
    } catch {
      return;
    }
    if (state === null) {
      return;
    }
    const previous = lastStates.get(serverId);
    lastStates.set(serverId, state);
    if (previous === state || (previous === undefined && !emitFirst)) {
      return;
    }
    options.emit({ server_id: serverId, state, at: now() });
  }

  async function pollOnce(): Promise<void> {
    if (polling) {
      return;
    }
    polling = true;
    try {
      const ids = options.listServerIds();
      const known = new Set(ids);
      for (const id of lastStates.keys()) {
        if (!known.has(id)) {
          lastStates.delete(id);
        }
      }
      for (const id of ids) {
        await observe(id, false);
      }
    } finally {
      polling = false;
    }
  }

  return {
    start(): void {
      if (handle !== null) {
        return;
      }
      handle = timers.setInterval(() => {
        if (options.shouldPoll !== undefined && !options.shouldPoll()) {
          lastStates.clear();
          return;
        }
        void pollOnce();
      }, intervalMs);
    },

    stop(): void {
      if (handle !== null) {
        timers.clearInterval(handle);
        handle = null;
      }
    },

    refresh(serverId: string): Promise<void> {
      return observe(serverId, true);
    },

    forget(serverId: string): void {
      lastStates.delete(serverId);
    },

    pollOnce,
  };
}
