// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import type { KeyId } from "../protocol";

export interface CounterStore {
  next(signer: KeyId, now: number): Promise<number>;
}

export function createMemoryCounterStore(): CounterStore {
  const lastBySigner = new Map<KeyId, number>();

  return {
    async next(signer: KeyId, now: number): Promise<number> {
      if (!Number.isSafeInteger(now) || now < 0) {
        throw new RangeError("now must be a non-negative safe integer");
      }
      const prev = lastBySigner.get(signer);
      const value = prev === undefined ? now : Math.max(prev + 1, now);
      lastBySigner.set(signer, value);
      return value;
    },
  };
}
