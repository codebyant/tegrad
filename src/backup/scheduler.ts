// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import type { Logger } from "../agent/logger";
import type { BackupScheduleConfig } from "../protocol";
import type { BackupConfigStore } from "./config";

export interface BackupTimerHandle {
  readonly id?: unknown;
}

export interface BackupTimerProvider {
  setInterval(fn: () => void, ms: number): BackupTimerHandle;
  clearInterval(handle: BackupTimerHandle): void;
}

export const defaultBackupTimers: BackupTimerProvider = {
  setInterval(fn, ms) {
    const id = setInterval(fn, ms);
    return { id };
  },
  clearInterval(handle) {
    clearInterval(handle.id as ReturnType<typeof setInterval>);
  },
};

export interface BackupSchedulerOptions {
  readonly configStore: BackupConfigStore;
  readonly runScheduledBackup: (serverId: string, retentionCount: number) => Promise<void>;
  readonly timers?: BackupTimerProvider;
  readonly logger?: Logger;
}

export interface BackupScheduler {
  start(): void;
  syncServer(serverId: string, schedule?: BackupScheduleConfig): void;
  stop(): void;
  getScheduledServerIds(): string[];
}

export function createBackupScheduler(options: BackupSchedulerOptions): BackupScheduler {
  const timers = options.timers ?? defaultBackupTimers;
  const activeTimers = new Map<string, BackupTimerHandle>();
  const inFlight = new Set<string>();

  function clearServer(serverId: string): void {
    const existing = activeTimers.get(serverId);
    if (existing !== undefined) {
      timers.clearInterval(existing);
      activeTimers.delete(serverId);
    }
  }

  function syncServer(serverId: string, schedule?: BackupScheduleConfig): void {
    clearServer(serverId);
    if (schedule === undefined || !schedule.enabled) {
      return;
    }

    const intervalMs = schedule.interval_minutes * 60_000;
    const retentionCount = schedule.retention_count;
    const handle = timers.setInterval(() => {
      if (inFlight.has(serverId)) {
        options.logger?.warn("Skipping scheduled backup because previous backup is still running", {
          serverId,
        });
        return;
      }
      inFlight.add(serverId);
      void options
        .runScheduledBackup(serverId, retentionCount)
        .catch((err: unknown) => {
          options.logger?.error("Scheduled backup failed", {
            serverId,
            errName: err instanceof Error ? err.name : "Error",
          });
        })
        .finally(() => {
          inFlight.delete(serverId);
        });
    }, intervalMs);

    activeTimers.set(serverId, handle);
  }

  function start(): void {
    for (const serverId of options.configStore.listConfiguredServerIds()) {
      const cfg = options.configStore.getServerConfig(serverId);
      syncServer(serverId, cfg.schedule);
    }
  }

  function stop(): void {
    for (const handle of activeTimers.values()) {
      timers.clearInterval(handle);
    }
    activeTimers.clear();
  }

  function getScheduledServerIds(): string[] {
    return [...activeTimers.keys()].sort();
  }

  return {
    start,
    syncServer,
    stop,
    getScheduledServerIds,
  };
}
