// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

export interface BackupHook {
  beforeChange(serverId: string): Promise<void>;
}

export const noopBackupHook: BackupHook = {
  async beforeChange(_serverId: string): Promise<void> {
    // Intentionally empty default hook.
  },
};
