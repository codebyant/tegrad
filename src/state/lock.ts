// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { ProtocolError } from "../protocol";
import type { ServerMetadata } from "../server/registry";

export function isVersionLoaderLocked(meta: ServerMetadata): boolean {
  return meta.origin?.kind === "modpack";
}

export function assertVersionLoaderUnlocked(meta: ServerMetadata): void {
  if (isVersionLoaderLocked(meta)) {
    throw new ProtocolError(
      "origin_locked",
      `Server "${meta.id}" is linked to a modpack origin; unlink the origin before changing Minecraft version or loader`,
    );
  }
}
