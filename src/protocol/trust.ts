// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { fingerprint, type PublicKey, type SigningKeyPair } from "../crypto";
import type { KeyId } from "./schemas";

export interface TrustContext {
  readonly agentKeyPair: SigningKeyPair;
  isTrustedAccountKey(id: KeyId): PublicKey | null;
  isSessionRevoked(certificateId: string): boolean;
  now(): number;
  claimCommand(signer: KeyId, id: string, counter: number): boolean;
}

export interface InMemoryTrustContextOptions {
  readonly agentKeyPair: SigningKeyPair;
  readonly trustedAccountKeys: readonly PublicKey[];
  readonly revokedSessionIds?: Iterable<string>;
  readonly now?: () => number;
}

export interface InMemoryTrustContext extends TrustContext {
  revokeSession(certificateId: string): void;
  setNow(clock: () => number): void;
}

export function createInMemoryTrustContext(
  options: InMemoryTrustContextOptions,
): InMemoryTrustContext {
  const trusted = new Map<KeyId, PublicKey>();
  for (const key of options.trustedAccountKeys) {
    trusted.set(fingerprint(key), key);
  }

  const revoked = new Set<string>(options.revokedSessionIds);
  const seenIds = new Set<string>();
  const lastCounters = new Map<KeyId, number>();
  let clock = options.now ?? (() => Date.now());

  return {
    agentKeyPair: options.agentKeyPair,

    isTrustedAccountKey(id: KeyId): PublicKey | null {
      return trusted.get(id) ?? null;
    },

    isSessionRevoked(certificateId: string): boolean {
      return revoked.has(certificateId);
    },

    now(): number {
      return clock();
    },

    claimCommand(signer: KeyId, id: string, counter: number): boolean {
      if (seenIds.has(id)) {
        return false;
      }
      const prev = lastCounters.get(signer);
      if (prev !== undefined && counter <= prev) {
        return false;
      }
      seenIds.add(id);
      lastCounters.set(signer, counter);
      return true;
    },

    revokeSession(certificateId: string): void {
      revoked.add(certificateId);
    },

    setNow(nextClock: () => number): void {
      clock = nextClock;
    },
  };
}
