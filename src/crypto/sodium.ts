// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import sodium from "libsodium-wrappers-sumo";

let initialized = false;

export async function ready(): Promise<void> {
  if (initialized) return;
  await sodium.ready;
  initialized = true;
}

export function getSodium(): typeof sodium {
  if (!initialized) {
    throw new Error("Crypto module is not initialized. Call await ready() first.");
  }
  return sodium;
}

export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length < 0) {
    throw new RangeError("length must be a non-negative integer");
  }
  return getSodium().randombytes_buf(length);
}

export function memzero(buffer: Uint8Array): void {
  getSodium().memzero(buffer);
}
