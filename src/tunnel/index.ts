// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

export {
  computeSha256Hex,
  DEFAULT_PLAYIT_DOWNLOAD_TIMEOUT_MS,
  DEFAULT_PLAYIT_MAX_BINARY_BYTES,
  type EnsurePlayitBinaryOptions,
  ensurePlayitBinary,
  getPlayitBinaryPath,
  type PinnedPlayitAsset,
  PLAYIT_RELEASE_ASSETS,
  PLAYIT_VERSION,
  type PlayitPlatform,
  resolvePlayitPlatform,
  type TunnelFetchLike,
  verifyFileSha256,
} from "./binary";
export {
  assertPlayitSecretKey,
  getPlayitKeyPath,
  hasPlayitSecretKey,
  PLAYIT_KEY_FILENAME,
  savePlayitSecretKey,
} from "./key";
export {
  buildPlayitSpawnSpec,
  createPlayitTunnelManager,
  DEFAULT_TUNNEL_STOP_TIMEOUT_MS,
  type PlayitSpawnSpec,
  type PlayitTunnelManager,
  type PlayitTunnelManagerOptions,
  type PlayitTunnelStatus,
  registerTunnelHandlers,
  type SpawnedTunnelProcess,
  type TunnelSpawnLike,
} from "./playit";
