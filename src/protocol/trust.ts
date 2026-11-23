// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { fingerprint, type PublicKey, type SigningKeyPair } from "../crypto";
import { type MemberEntry, type Role, RoleTable } from "./roles";
import type { KeyId } from "./schemas";

export interface TrustContext {
  readonly agentKeyPair: SigningKeyPair;
  isTrustedAccountKey(id: KeyId): PublicKey | null;
  isSessionRevoked(certificateId: string): boolean;
  /**
   * Role of an account on a server (`"*"` for agent-level commands), or null
   * when the account has no access. Owners come from the trust list; other
   * roles come from accepted role grants.
   */
  roleFor(account: KeyId, serverId: string): Role | null;
  now(): number;
  claimCommand(signer: KeyId, id: string, counter: number): boolean;
}

export interface InMemoryTrustContextOptions {
  readonly agentKeyPair: SigningKeyPair;
  readonly trustedAccountKeys: readonly PublicKey[];
  readonly revokedSessionIds?: Iterable<string>;
  readonly members?: readonly MemberEntry[];
  readonly now?: () => number;
}

export interface MemberStore {
  listMembers(): readonly MemberEntry[];
  setMember(entry: MemberEntry): void;
  revokeMembers(account: KeyId, servers?: readonly string[]): number;
}

export interface InMemoryTrustContext extends TrustContext, MemberStore {
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

  const members = new RoleTable(options.members);
  const revoked = new Set<string>(options.revokedSessionIds);
  const seenIds = new Set<string>();
  const lastCounters = new Map<KeyId, number>();
  let clock = options.now ?? (() => Date.now());

  return {
    agentKeyPair: options.agentKeyPair,

    isTrustedAccountKey(id: KeyId): PublicKey | null {
      return trusted.get(id) ?? members.keyFor(id, clock());
    },

    roleFor(account: KeyId, serverId: string): Role | null {
      if (trusted.has(account)) {
        return "owner";
      }
      return members.roleFor(account, serverId, clock());
    },

    listMembers(): readonly MemberEntry[] {
      return members.entries();
    },

    setMember(entry: MemberEntry): void {
      members.set(entry);
    },

    revokeMembers(account: KeyId, servers?: readonly string[]): number {
      return members.revoke(account, servers);
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
