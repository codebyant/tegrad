// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { getSodium } from "./sodium";

export const HASH_BYTES = 32;

export function hash(data: Uint8Array, key?: Uint8Array): Uint8Array {
  const s = getSodium();
  if (key !== undefined) {
    if (
      key.length < s.crypto_generichash_KEYBYTES_MIN ||
      key.length > s.crypto_generichash_KEYBYTES_MAX
    ) {
      throw new RangeError(
        `Hash key must be between ${s.crypto_generichash_KEYBYTES_MIN} and ${s.crypto_generichash_KEYBYTES_MAX} bytes`,
      );
    }
    return s.crypto_generichash(HASH_BYTES, data, key);
  }
  return s.crypto_generichash(HASH_BYTES, data, null);
}
