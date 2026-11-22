// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

export { type BackupHook, noopBackupHook } from "./backup-hook";
export {
  buildAllowedDownloadHosts,
  DEFAULT_MAX_MOD_BYTES,
  DEFAULT_MAX_SERVERPACK_BYTES,
  DEFAULT_MOD_ALLOWED_HOSTS,
  DEFAULT_STATE_DOWNLOAD_TIMEOUT_MS,
  DEFAULT_STATE_MAX_REDIRECTS,
  type DownloadVerifiedBufferOptions,
  downloadVerifiedBuffer,
  type ExpectedHashes,
  type VerifiedDownloadResult,
  validateStateDownloadUrl,
} from "./download";
export { assertVersionLoaderUnlocked, isVersionLoaderLocked } from "./lock";
export {
  createStateManager,
  DEFAULT_MAX_STORED_PLANS,
  DEFAULT_PLAN_TTL_MS,
  type ModInstallResult,
  type ModRemoveResult,
  type ModsListResult,
  type OriginApplyResult,
  type OriginPlanResult,
  type OriginUnlinkResult,
  registerStateHandlers,
  type ServerPackDeployResult,
  type StateManager,
  type StateManagerOptions,
  type UpdateVersionLoaderParams,
} from "./manager";
export {
  buildOriginSyncChanges,
  emptyOriginSyncState,
  isClientOnly,
  isRedistributionRestricted,
  isServerContentPath,
  type ModExcludedReason,
  type ModIdentitySource,
  type ModRedistributionInfo,
  modIdentityKey,
  nextOriginSyncState,
  normalizeRelativePath,
  type OriginFileChange,
  type OriginModChange,
  type OriginSyncChanges,
  type PlanFile,
  type PlanMod,
  redistributionFromModrinthLicense,
  SERVER_PACK_MANIFEST_FILE,
  SERVER_PACK_WORLD_DIR,
  shouldCopyOnCreate,
  stripDisabledSuffix,
  worldArchivePath,
} from "./sync-plan";
