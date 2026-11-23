// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import {
  type AgentMembersRevokeBody,
  type AgentMembersSetBody,
  type GrantableRole,
  type KeyId,
  MAX_MEMBERS,
  type MemberEntry,
  type MemberStore,
  type OpenedCommand,
  ProtocolError,
  ROLE_LEVEL,
  type Role,
  roleAtLeast,
  type TrustContext,
  verifyRoleGrant,
} from "../protocol";

export interface MembersContext {
  readonly trust: TrustContext;
  readonly store: MemberStore;
  readonly agentId: KeyId;
}

function highestMemberRole(store: MemberStore, account: KeyId): GrantableRole | null {
  let best: GrantableRole | null = null;
  for (const entry of store.listMembers()) {
    if (entry.account !== account) {
      continue;
    }
    if (best === null || ROLE_LEVEL[entry.role] > ROLE_LEVEL[best]) {
      best = entry.role;
    }
  }
  return best;
}

function requireAccountSigner(opened: OpenedCommand): Role {
  if (opened.signerType !== "account" || !roleAtLeast(opened.role, "admin")) {
    throw new ProtocolError(
      "sensitive_requires_account_key",
      "Member changes must be signed directly by an admin or owner account key",
    );
  }
  return opened.role;
}

/**
 * Validates a signed role grant against the account that sent the command and
 * records it. The command's signer is the granter: the grant must be signed
 * by that same key, and the granter must outrank the role it hands out.
 */
export function applyMembersSet(
  opened: OpenedCommand,
  body: AgentMembersSetBody,
  ctx: MembersContext,
  now: number,
): MemberEntry {
  const granterRole = requireAccountSigner(opened);
  const granterKey = ctx.trust.isTrustedAccountKey(opened.accountId);
  if (granterKey === null) {
    throw new ProtocolError("untrusted_signer", "Granting account is not trusted");
  }

  const verified = verifyRoleGrant(body.grant, granterKey, { agent: ctx.agentId, now });
  const { grant } = verified;

  if (ROLE_LEVEL[grant.role] >= ROLE_LEVEL[granterRole]) {
    throw new ProtocolError(
      "role_grant_invalid",
      "A role at or above the granting account's own role cannot be granted",
    );
  }
  if (verified.accountId === opened.accountId) {
    throw new ProtocolError("role_grant_invalid", "An account cannot change its own role");
  }
  if (ctx.trust.roleFor(verified.accountId, "*") === "owner") {
    throw new ProtocolError("role_grant_invalid", "Owner accounts cannot be given a member role");
  }

  const existing = highestMemberRole(ctx.store, verified.accountId);
  if (existing !== null && ROLE_LEVEL[existing] >= ROLE_LEVEL[granterRole]) {
    throw new ProtocolError(
      "role_grant_invalid",
      "The account already holds a role at or above the granting account's own role",
    );
  }

  const known = new Set(ctx.store.listMembers().map((entry) => entry.account));
  if (!known.has(verified.accountId) && known.size >= MAX_MEMBERS) {
    throw new ProtocolError("role_grant_invalid", "Too many members");
  }

  const entry: MemberEntry = {
    account_key: grant.account_key,
    account: verified.accountId,
    granted_by: opened.accountId,
    role: grant.role,
    servers: grant.servers,
    issued_at: grant.issued_at,
    ...(grant.expires_at !== undefined ? { expires_at: grant.expires_at } : {}),
  };
  ctx.store.setMember(entry);
  return entry;
}

export function applyMembersRevoke(
  opened: OpenedCommand,
  body: AgentMembersRevokeBody,
  ctx: MembersContext,
): number {
  const revokerRole = requireAccountSigner(opened);

  if (ctx.trust.roleFor(body.account, "*") === "owner") {
    throw new ProtocolError("role_grant_invalid", "Owner accounts cannot be revoked");
  }
  const existing = highestMemberRole(ctx.store, body.account);
  if (
    existing !== null &&
    revokerRole !== "owner" &&
    ROLE_LEVEL[existing] >= ROLE_LEVEL[revokerRole]
  ) {
    throw new ProtocolError(
      "role_grant_invalid",
      "The account holds a role at or above the revoking account's own role",
    );
  }

  return ctx.store.revokeMembers(body.account, body.servers);
}
