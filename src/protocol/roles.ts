// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
import {
  canonicalize,
  fingerprint,
  fromBase64Url,
  type PublicKey,
  SIGNING_PUBLIC_KEY_BYTES,
  type SigningKeyPair,
  sign,
  toBase64Url,
  verify,
} from "../crypto";
import {
  assertSupportedVersion,
  concatBytes,
  DOMAIN_ROLE_GRANT,
  PROTOCOL_VERSION,
} from "./domains";
import { ProtocolError } from "./errors";
import { base64UrlSchema, type KeyId, keyIdSchema } from "./schemas";

export const ROLES = ["viewer", "operator", "editor", "admin", "owner"] as const;
export type Role = (typeof ROLES)[number];
export const roleSchema = z.enum(ROLES);

export const GRANTABLE_ROLES = ["viewer", "operator", "editor", "admin"] as const;
export type GrantableRole = (typeof GRANTABLE_ROLES)[number];
export const grantableRoleSchema = z.enum(GRANTABLE_ROLES);

export const ROLE_LEVEL: Readonly<Record<Role, number>> = {
  viewer: 1,
  operator: 2,
  editor: 3,
  admin: 4,
  owner: 5,
};

export function roleAtLeast(role: Role | null | undefined, minimum: Role): boolean {
  return role !== null && role !== undefined && ROLE_LEVEL[role] >= ROLE_LEVEL[minimum];
}

export function maxRole<T extends Role>(a: T | null, b: T | null): T | null {
  if (a === null) return b;
  if (b === null) return a;
  return ROLE_LEVEL[a] >= ROLE_LEVEL[b] ? a : b;
}

export const ALL_SERVERS = "*" as const;
export const MAX_GRANT_SERVERS = 256;
export const MAX_MEMBERS = 64;

const grantServerIdSchema = z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/, "Invalid server id");

const grantServersSchema = z.union([
  z.literal(ALL_SERVERS),
  z.array(grantServerIdSchema).min(1).max(MAX_GRANT_SERVERS),
]);

export const roleGrantSchema = z
  .object({
    v: z.literal(PROTOCOL_VERSION),
    kind: z.literal("server-role"),
    account_key: base64UrlSchema,
    agent: keyIdSchema,
    servers: grantServersSchema,
    role: grantableRoleSchema,
    issued_at: z.number().int().nonnegative(),
    expires_at: z.number().int().nonnegative().optional(),
    sig: base64UrlSchema,
  })
  .strict();
export type RoleGrant = z.infer<typeof roleGrantSchema>;

export const MAX_GRANT_CLOCK_SKEW_MS = 5 * 60 * 1000;

export interface SignRoleGrantParams {
  readonly granter: SigningKeyPair;
  readonly accountPublicKey: PublicKey;
  readonly agent: KeyId;
  readonly servers: readonly string[] | typeof ALL_SERVERS;
  readonly role: GrantableRole;
  readonly issuedAt: number;
  readonly expiresAt?: number;
}

export function signRoleGrant(params: SignRoleGrantParams): RoleGrant {
  if (params.accountPublicKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new RangeError(`Account public key must be ${SIGNING_PUBLIC_KEY_BYTES} bytes`);
  }
  if (!Number.isSafeInteger(params.issuedAt) || params.issuedAt < 0) {
    throw new RangeError("issuedAt must be a non-negative safe integer");
  }
  if (
    params.expiresAt !== undefined &&
    (!Number.isSafeInteger(params.expiresAt) || params.expiresAt <= params.issuedAt)
  ) {
    throw new RangeError("expiresAt must be a safe integer after issuedAt");
  }

  const unsigned = {
    v: PROTOCOL_VERSION,
    kind: "server-role" as const,
    account_key: toBase64Url(params.accountPublicKey),
    agent: params.agent,
    servers: params.servers === ALL_SERVERS ? ALL_SERVERS : [...params.servers],
    role: params.role,
    issued_at: params.issuedAt,
    ...(params.expiresAt !== undefined ? { expires_at: params.expiresAt } : {}),
  };

  const signingInput = concatBytes(DOMAIN_ROLE_GRANT, canonicalize(unsigned));
  const signature = sign(signingInput, params.granter.secretKey);
  return roleGrantSchema.parse({ ...unsigned, sig: toBase64Url(signature) });
}

export interface VerifyRoleGrantOptions {
  readonly agent: KeyId;
  readonly now: number;
}

export interface VerifiedRoleGrant {
  readonly grant: RoleGrant;
  readonly accountPublicKey: PublicKey;
  readonly accountId: KeyId;
}

export function verifyRoleGrant(
  grant: unknown,
  granterPublicKey: PublicKey,
  options: VerifyRoleGrantOptions,
): VerifiedRoleGrant {
  assertSupportedVersion(grant);

  const parsed = roleGrantSchema.safeParse(grant);
  if (!parsed.success) {
    throw new ProtocolError("role_grant_invalid", "Malformed role grant");
  }
  const data = parsed.data;

  if (data.agent !== options.agent) {
    throw new ProtocolError("role_grant_invalid", "Role grant is addressed to a different agent");
  }
  if (data.issued_at > options.now + MAX_GRANT_CLOCK_SKEW_MS) {
    throw new ProtocolError("role_grant_invalid", "Role grant issued_at is in the future");
  }
  if (data.expires_at !== undefined && data.expires_at <= data.issued_at) {
    throw new ProtocolError("role_grant_invalid", "Role grant expiry is not after issuance");
  }
  if (data.expires_at !== undefined && options.now >= data.expires_at) {
    throw new ProtocolError("role_grant_invalid", "Role grant has expired");
  }
  if (data.servers !== ALL_SERVERS && new Set(data.servers).size !== data.servers.length) {
    throw new ProtocolError("role_grant_invalid", "Role grant lists a server more than once");
  }

  let accountPublicKey: Uint8Array;
  let signatureBytes: Uint8Array;
  try {
    accountPublicKey = fromBase64Url(data.account_key);
    signatureBytes = fromBase64Url(data.sig);
  } catch {
    throw new ProtocolError("role_grant_invalid", "Invalid base64url encoding in role grant");
  }
  if (accountPublicKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new ProtocolError("role_grant_invalid", "Invalid account key length in role grant");
  }

  const { sig: _sig, ...unsigned } = data;
  const signingInput = concatBytes(DOMAIN_ROLE_GRANT, canonicalize(unsigned));
  if (!verify(signingInput, signatureBytes, granterPublicKey)) {
    throw new ProtocolError("role_grant_invalid", "Invalid role grant signature");
  }

  return { grant: data, accountPublicKey, accountId: fingerprint(accountPublicKey) };
}

/** A role grant that an agent has accepted, as kept in its member table. */
export const memberEntrySchema = z
  .object({
    account_key: base64UrlSchema,
    account: keyIdSchema,
    granted_by: keyIdSchema,
    role: grantableRoleSchema,
    servers: grantServersSchema,
    issued_at: z.number().int().nonnegative(),
    expires_at: z.number().int().nonnegative().optional(),
  })
  .strict();
export type MemberEntry = z.infer<typeof memberEntrySchema>;

function scopeKey(servers: MemberEntry["servers"]): string {
  return servers === ALL_SERVERS ? ALL_SERVERS : [...servers].sort().join(",");
}

function isActive(entry: MemberEntry, now: number): boolean {
  return entry.expires_at === undefined || now < entry.expires_at;
}

/**
 * Member-table logic shared by the in-memory and the file-backed trust
 * contexts. Owners are not members: they come from the trust list.
 */
export class RoleTable {
  #entries: MemberEntry[];

  constructor(entries: readonly MemberEntry[] = []) {
    this.#entries = [...entries];
  }

  entries(): readonly MemberEntry[] {
    return [...this.#entries];
  }

  accountCount(): number {
    return new Set(this.#entries.map((entry) => entry.account)).size;
  }

  keyFor(account: KeyId, now: number): PublicKey | null {
    for (const entry of this.#entries) {
      if (entry.account === account && isActive(entry, now)) {
        try {
          return fromBase64Url(entry.account_key);
        } catch {
          return null;
        }
      }
    }
    return null;
  }

  /**
   * Role of `account` on `serverId`. Agent-level scope (`"*"`) resolves to the
   * highest role granted on all servers; an account that only has per-server
   * grants gets `viewer` there, which allows agent-level reads (what they
   * return is filtered per server).
   */
  roleFor(account: KeyId, serverId: string, now: number): GrantableRole | null {
    let best: GrantableRole | null = null;
    let anyActive = false;
    for (const entry of this.#entries) {
      if (entry.account !== account || !isActive(entry, now)) {
        continue;
      }
      anyActive = true;
      const covers =
        entry.servers === ALL_SERVERS ||
        (serverId !== ALL_SERVERS && entry.servers.includes(serverId));
      if (covers) {
        best = maxRole(best, entry.role);
      }
    }
    if (best === null && serverId === ALL_SERVERS && anyActive) {
      return "viewer";
    }
    return best;
  }

  set(entry: MemberEntry): void {
    const key = scopeKey(entry.servers);
    const next = this.#entries.filter(
      (existing) => !(existing.account === entry.account && scopeKey(existing.servers) === key),
    );
    next.push(entry);
    this.#entries = next;
  }

  /**
   * Removes grants of `account`. Without `servers`, all of them. With
   * `servers`, those ids are removed from per-server grants; a grant that
   * covers all servers is only removed by a revoke without `servers`.
   * Returns how many grants were changed or removed.
   */
  revoke(account: KeyId, servers?: readonly string[]): number {
    let changed = 0;
    const next: MemberEntry[] = [];
    for (const entry of this.#entries) {
      if (entry.account !== account) {
        next.push(entry);
        continue;
      }
      if (servers === undefined) {
        changed++;
        continue;
      }
      if (entry.servers === ALL_SERVERS) {
        next.push(entry);
        continue;
      }
      const remaining = entry.servers.filter((id) => !servers.includes(id));
      if (remaining.length === entry.servers.length) {
        next.push(entry);
        continue;
      }
      changed++;
      if (remaining.length > 0) {
        next.push({ ...entry, servers: remaining });
      }
    }
    this.#entries = next;
    return changed;
  }
}
