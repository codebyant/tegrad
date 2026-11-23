// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { beforeAll, describe, expect, test } from "bun:test";
import { fingerprint, generateSigningKeyPair, ready, toBase64Url } from "../crypto";
import {
  AGENT_HTTP_HEADER_SIG,
  AGENT_HTTP_HEADER_TS,
  type CommandRegistry,
  createCoreRegistry,
  createHelloFrame,
  createInMemoryTrustContext,
  createSignedCommand,
  type GrantableRole,
  generateAgentNonce,
  type MemberEntry,
  openAgentEvent,
  openCommand,
  ProtocolError,
  type ProtocolErrorCode,
  ROLE_LEVEL,
  type Role,
  RoleTable,
  roleAtLeast,
  sealAgentMessage,
  signAgentAuth,
  signAgentRequest,
  signRoleGrant,
  signSessionCertificate,
  transportFrameSchema,
  verifyAgentAuth,
  verifyAgentRequest,
  verifyRoleGrant,
  wrapEventBody,
} from "./index";

const NOW = 1_700_000_000_000;

beforeAll(async () => {
  await ready();
});

async function expectCode(promise: Promise<unknown>, code: ProtocolErrorCode): Promise<void> {
  try {
    await promise;
  } catch (err) {
    expect(err).toBeInstanceOf(ProtocolError);
    expect((err as ProtocolError).code).toBe(code);
    return;
  }
  throw new Error(`Expected ProtocolError ${code}`);
}

function expectThrowCode(fn: () => unknown, code: ProtocolErrorCode): void {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(ProtocolError);
    expect((err as ProtocolError).code).toBe(code);
    return;
  }
  throw new Error(`Expected ProtocolError ${code}`);
}

describe("reply_to", () => {
  function setup() {
    const agent = generateSigningKeyPair();
    const account = generateSigningKeyPair();
    const session = generateSigningKeyPair();
    const registry = createCoreRegistry();
    const trust = createInMemoryTrustContext({
      agentKeyPair: agent,
      trustedAccountKeys: [account.publicKey],
      now: () => NOW,
    });
    const certificate = signSessionCertificate({
      sessionPublicKey: session.publicKey,
      accountKeyPair: account,
      notBefore: NOW - 1000,
      notAfter: NOW + 3_600_000,
    });
    return { agent, account, session, registry, trust, certificate };
  }

  test("is part of the signed header and round-trips through openCommand", async () => {
    const { agent, session, registry, trust, certificate } = setup();
    const cmd = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: session,
        session: certificate,
        counter: 1,
        now: NOW,
        replyTo: session.publicKey,
      },
      registry,
    );
    expect(cmd.header.reply_to).toBe(toBase64Url(session.publicKey));
    const opened = await openCommand(cmd, trust, registry);
    expect(opened.replyTo).toEqual(session.publicKey);
    expect(opened.signerType).toBe("session");
    expect(opened.sessionNotAfter).toBe(certificate.not_after);
  });

  test("tampering with reply_to breaks the signature", async () => {
    const { agent, session, registry, trust, certificate } = setup();
    const cmd = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: session,
        session: certificate,
        counter: 1,
        now: NOW,
        replyTo: session.publicKey,
      },
      registry,
    );
    const attacker = generateSigningKeyPair();
    const forged = {
      ...cmd,
      header: { ...cmd.header, reply_to: toBase64Url(attacker.publicKey) },
    };
    await expectCode(openCommand(forged, trust, registry), "wrong_recipient");

    // Even when the attacker's key is a valid reply_to for an account signer, the signature covers it.
    const accountCmd = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: setup().account,
        counter: 1,
        now: NOW,
      },
      registry,
    );
    await expectCode(
      openCommand(
        {
          ...accountCmd,
          header: { ...accountCmd.header, reply_to: toBase64Url(attacker.publicKey) },
        },
        trust,
        registry,
      ),
      "untrusted_signer",
    );
  });

  test("a session signer must reply to its own session key", async () => {
    const { agent, session, registry, trust, certificate } = setup();
    const other = generateSigningKeyPair();
    const cmd = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: session,
        session: certificate,
        counter: 1,
        now: NOW,
        replyTo: other.publicKey,
      },
      registry,
    );
    await expectCode(openCommand(cmd, trust, registry), "wrong_recipient");
  });

  test("an account signer may point reply_to at the active session key", async () => {
    const { agent, account, session, registry, trust } = setup();
    const cmd = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now: NOW,
        replyTo: session.publicKey,
      },
      registry,
    );
    const opened = await openCommand(cmd, trust, registry);
    expect(opened.signerType).toBe("account");
    expect(opened.replyTo).toEqual(session.publicKey);
  });

  test("rejects reply_to that is not a 32-byte key", async () => {
    const { agent, account, registry, trust } = setup();
    expect(() =>
      createSignedCommand(
        {
          type: "agent.ping",
          body: {},
          agentPublicKey: agent.publicKey,
          signer: account,
          counter: 1,
          now: NOW,
          replyTo: new Uint8Array(8),
        },
        registry,
      ),
    ).toThrow(RangeError);

    const cmd = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now: NOW,
      },
      registry,
    );
    const short = { ...cmd, header: { ...cmd.header, reply_to: toBase64Url(new Uint8Array(8)) } };
    await expectCode(openCommand(short, trust, registry), "invalid_format");
  });

  test("a command without reply_to is still accepted (account key is the recipient)", async () => {
    const { agent, account, registry, trust } = setup();
    const cmd = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now: NOW,
      },
      registry,
    );
    expect(cmd.header.reply_to).toBeUndefined();
    const opened = await openCommand(cmd, trust, registry);
    expect(opened.replyTo).toBeUndefined();
  });
});

describe("event envelope", () => {
  test("openAgentEvent unwraps { in_reply_to, data } and only the recipient can open it", () => {
    const agent = generateSigningKeyPair();
    const session = generateSigningKeyPair();
    const account = generateSigningKeyPair();
    const message = sealAgentMessage({
      type: "server.list.result",
      body: wrapEventBody("abc", { servers: [] }),
      agentKeyPair: agent,
      recipientPublicKey: session.publicKey,
      sentAt: NOW,
      seq: 1,
    });

    const opened = openAgentEvent(message, agent.publicKey, session);
    expect(opened.inReplyTo).toBe("abc");
    expect(opened.data).toEqual({ servers: [] });

    // The account key is not the recipient and cannot decrypt it.
    expectThrowCode(() => openAgentEvent(message, agent.publicKey, account), "wrong_recipient");
    expect(message.header.recipient).toBe(fingerprint(session.publicKey));
  });

  test("in_reply_to is optional but data is required", () => {
    const agent = generateSigningKeyPair();
    const account = generateSigningKeyPair();
    const noReply = sealAgentMessage({
      type: "x",
      body: wrapEventBody(undefined, 1),
      agentKeyPair: agent,
      recipientPublicKey: account.publicKey,
      sentAt: NOW,
      seq: 1,
    });
    expect(openAgentEvent(noReply, agent.publicKey, account).inReplyTo).toBeNull();

    const legacy = sealAgentMessage({
      type: "x",
      body: { at: 1 },
      agentKeyPair: agent,
      recipientPublicKey: account.publicKey,
      sentAt: NOW,
      seq: 2,
    });
    expectThrowCode(() => openAgentEvent(legacy, agent.publicKey, account), "invalid_body");
  });
});

describe("hello / auth", () => {
  test("round-trips and the nonce is single-use", () => {
    const agent = generateSigningKeyPair();
    const agentId = fingerprint(agent.publicKey);
    const hello = createHelloFrame({ agent: agentId, serverTime: NOW });
    expect(transportFrameSchema.safeParse(hello).success).toBe(true);

    const auth = signAgentAuth({ agentKeyPair: agent, hello, ts: NOW });
    expect(transportFrameSchema.safeParse(auth).success).toBe(true);

    const used = new Set<string>();
    const verified = verifyAgentAuth(auth, {
      agentPublicKey: agent.publicKey,
      expectedNonce: hello.body.nonce,
      now: NOW,
      usedNonces: used,
    });
    expect(verified.body.nonce).toBe(hello.body.nonce);

    // Replaying the same auth frame (same nonce) is refused.
    expectThrowCode(
      () =>
        verifyAgentAuth(auth, {
          agentPublicKey: agent.publicKey,
          expectedNonce: hello.body.nonce,
          now: NOW,
          usedNonces: used,
        }),
      "replayed",
    );
  });

  test("rejects a nonce that is not the one challenged, stale timestamps and bad signatures", () => {
    const agent = generateSigningKeyPair();
    const agentId = fingerprint(agent.publicKey);
    const hello = createHelloFrame({ agent: agentId, serverTime: NOW });
    const auth = signAgentAuth({ agentKeyPair: agent, hello, ts: NOW });

    const base = { agentPublicKey: agent.publicKey, expectedNonce: hello.body.nonce, now: NOW };
    expectThrowCode(
      () => verifyAgentAuth(auth, { ...base, expectedNonce: generateAgentNonce() }),
      "auth_invalid",
    );
    expectThrowCode(() => verifyAgentAuth(auth, { ...base, now: NOW + 61_000 }), "auth_invalid");
    expectThrowCode(() => verifyAgentAuth(auth, { ...base, now: NOW - 61_000 }), "auth_invalid");
    expect(() => verifyAgentAuth(auth, { ...base, now: NOW + 59_000 })).not.toThrow();

    const tamperedTs = { ...auth, body: { ...auth.body, ts: NOW + 1 } };
    expectThrowCode(() => verifyAgentAuth(tamperedTs, base), "bad_signature");

    const other = generateSigningKeyPair();
    expectThrowCode(
      () => verifyAgentAuth(auth, { ...base, agentPublicKey: other.publicKey }),
      "wrong_agent",
    );
    expectThrowCode(() => verifyAgentAuth({ kind: "auth" }, base), "invalid_format");
  });

  test("the agent refuses to answer a hello meant for another agent", () => {
    const agent = generateSigningKeyPair();
    const other = generateSigningKeyPair();
    const hello = createHelloFrame({ agent: fingerprint(other.publicKey), serverTime: NOW });
    expectThrowCode(() => signAgentAuth({ agentKeyPair: agent, hello, ts: NOW }), "wrong_agent");
  });

  test("hello nonce must be 32 bytes of base64url", () => {
    const agentId = fingerprint(generateSigningKeyPair().publicKey);
    expect(() => createHelloFrame({ agent: agentId, serverTime: NOW, nonce: "short" })).toThrow();
  });
});

describe("signed agent HTTP requests", () => {
  const body = JSON.stringify({ server_id: "survival", size_bytes: 10 });
  const path = "/v1/agents/self/backup-upload-url";

  function headersOf(h: Record<string, string>) {
    return (name: string) =>
      h[Object.keys(h).find((k) => k.toLowerCase() === name.toLowerCase()) ?? ""];
  }

  test("verifies a correctly signed request", () => {
    const agent = generateSigningKeyPair();
    const headers = signAgentRequest({
      agentKeyPair: agent,
      method: "post",
      pathWithQuery: path,
      body,
      ts: NOW,
    });
    expect(headers["X-Tegra-Agent"]).toBe(fingerprint(agent.publicKey));
    expect(headers["X-Tegra-Ts"]).toBe(String(NOW));
    const result = verifyAgentRequest({
      getHeader: headersOf(headers),
      method: "POST",
      pathWithQuery: path,
      body,
      agentPublicKey: agent.publicKey,
      now: NOW + 5_000,
    });
    expect(result.agent).toBe(fingerprint(agent.publicKey));
  });

  test("refuses a changed method, path, query or body", () => {
    const agent = generateSigningKeyPair();
    const headers = signAgentRequest({
      agentKeyPair: agent,
      method: "POST",
      pathWithQuery: `${path}?a=1`,
      body,
      ts: NOW,
    });
    const base = {
      getHeader: headersOf(headers),
      method: "POST",
      pathWithQuery: `${path}?a=1`,
      body,
      agentPublicKey: agent.publicKey,
      now: NOW,
    };
    expect(() => verifyAgentRequest(base)).not.toThrow();
    expectThrowCode(() => verifyAgentRequest({ ...base, method: "PUT" }), "bad_signature");
    expectThrowCode(
      () => verifyAgentRequest({ ...base, pathWithQuery: `${path}?a=2` }),
      "bad_signature",
    );
    expectThrowCode(
      () => verifyAgentRequest({ ...base, pathWithQuery: "/v1/agents/pairing" }),
      "bad_signature",
    );
    expectThrowCode(
      () => verifyAgentRequest({ ...base, body: body.replace("10", "11") }),
      "bad_signature",
    );
    expectThrowCode(() => verifyAgentRequest({ ...base, body: undefined }), "bad_signature");
  });

  test("refuses a timestamp outside the window, a tampered ts, and a different agent", () => {
    const agent = generateSigningKeyPair();
    const headers = signAgentRequest({
      agentKeyPair: agent,
      method: "GET",
      pathWithQuery: "/v1/agents/pairing/abc/grant",
      ts: NOW,
    });
    const base = {
      getHeader: headersOf(headers),
      method: "GET",
      pathWithQuery: "/v1/agents/pairing/abc/grant",
      agentPublicKey: agent.publicKey,
      now: NOW,
    };
    expect(() => verifyAgentRequest(base)).not.toThrow();
    expectThrowCode(() => verifyAgentRequest({ ...base, now: NOW + 61_000 }), "expired");
    expectThrowCode(() => verifyAgentRequest({ ...base, now: NOW - 61_000 }), "not_yet_valid");

    const tampered = { ...headers, [AGENT_HTTP_HEADER_TS]: String(NOW + 1) };
    expectThrowCode(
      () => verifyAgentRequest({ ...base, getHeader: headersOf(tampered) }),
      "bad_signature",
    );
    const garbage = { ...headers, [AGENT_HTTP_HEADER_TS]: "12abc" };
    expectThrowCode(
      () => verifyAgentRequest({ ...base, getHeader: headersOf(garbage) }),
      "request_invalid",
    );

    const other = generateSigningKeyPair();
    expectThrowCode(
      () => verifyAgentRequest({ ...base, agentPublicKey: other.publicKey }),
      "wrong_agent",
    );
  });

  test("refuses missing or malformed signature headers", () => {
    const agent = generateSigningKeyPair();
    const headers = signAgentRequest({
      agentKeyPair: agent,
      method: "GET",
      pathWithQuery: "/x",
      ts: NOW,
    });
    const base = {
      method: "GET",
      pathWithQuery: "/x",
      agentPublicKey: agent.publicKey,
      now: NOW,
    };
    const { [AGENT_HTTP_HEADER_SIG]: _sig, ...withoutSig } = headers;
    expectThrowCode(
      () => verifyAgentRequest({ ...base, getHeader: headersOf(withoutSig) }),
      "request_invalid",
    );
    expectThrowCode(
      () =>
        verifyAgentRequest({
          ...base,
          getHeader: headersOf({ ...headers, [AGENT_HTTP_HEADER_SIG]: "!!!" }),
        }),
      "bad_signature",
    );
    expect(() =>
      signAgentRequest({ agentKeyPair: agent, method: "GET", pathWithQuery: "no-slash", ts: NOW }),
    ).toThrow(RangeError);
  });
});

describe("role grants", () => {
  const agentId = "a".repeat(32);

  test("sign and verify round-trip, including the account id", () => {
    const owner = generateSigningKeyPair();
    const member = generateSigningKeyPair();
    const grant = signRoleGrant({
      granter: owner,
      accountPublicKey: member.publicKey,
      agent: agentId,
      servers: ["survival"],
      role: "operator",
      issuedAt: NOW,
      expiresAt: NOW + 60_000,
    });
    const verified = verifyRoleGrant(grant, owner.publicKey, { agent: agentId, now: NOW });
    expect(verified.accountId).toBe(fingerprint(member.publicKey));
    expect(verified.grant.servers).toEqual(["survival"]);
  });

  test("refuses forged, tampered, expired and misaddressed grants", () => {
    const owner = generateSigningKeyPair();
    const forger = generateSigningKeyPair();
    const member = generateSigningKeyPair();
    const common = {
      accountPublicKey: member.publicKey,
      agent: agentId,
      servers: "*" as const,
      role: "viewer" as const,
      issuedAt: NOW,
    };
    const options = { agent: agentId, now: NOW };

    const forged = signRoleGrant({ ...common, granter: forger });
    expectThrowCode(() => verifyRoleGrant(forged, owner.publicKey, options), "role_grant_invalid");

    const real = signRoleGrant({ ...common, granter: owner });
    expectThrowCode(
      () => verifyRoleGrant({ ...real, role: "admin" }, owner.publicKey, options),
      "role_grant_invalid",
    );
    expectThrowCode(
      () => verifyRoleGrant({ ...real, servers: ["x"] }, owner.publicKey, options),
      "role_grant_invalid",
    );
    expectThrowCode(
      () => verifyRoleGrant({ ...real, role: "owner" }, owner.publicKey, options),
      "role_grant_invalid",
    );

    expectThrowCode(
      () =>
        verifyRoleGrant(real, owner.publicKey, {
          agent: fingerprint(generateSigningKeyPair().publicKey),
          now: NOW,
        }),
      "role_grant_invalid",
    );

    const expiring = signRoleGrant({ ...common, granter: owner, expiresAt: NOW + 1000 });
    expect(() => verifyRoleGrant(expiring, owner.publicKey, options)).not.toThrow();
    expectThrowCode(
      () => verifyRoleGrant(expiring, owner.publicKey, { agent: agentId, now: NOW + 1000 }),
      "role_grant_invalid",
    );

    const future = signRoleGrant({ ...common, granter: owner, issuedAt: NOW + 10 * 60_000 });
    expectThrowCode(() => verifyRoleGrant(future, owner.publicKey, options), "role_grant_invalid");

    expectThrowCode(
      () => verifyRoleGrant({ junk: true }, owner.publicKey, options),
      "role_grant_invalid",
    );
  });

  test("domain separation: a role grant signature is not a valid trust or session signature", () => {
    const owner = generateSigningKeyPair();
    const member = generateSigningKeyPair();
    const grant = signRoleGrant({
      granter: owner,
      accountPublicKey: member.publicKey,
      agent: agentId,
      servers: "*",
      role: "viewer",
      issuedAt: NOW,
    });
    // Reusing the same signature under another kind must fail the grant schema.
    expectThrowCode(
      () =>
        verifyRoleGrant({ ...grant, kind: "trust" }, owner.publicKey, { agent: agentId, now: NOW }),
      "role_grant_invalid",
    );
  });
});

describe("RoleTable", () => {
  const A = "b".repeat(32);

  function entry(over: Partial<MemberEntry>): MemberEntry {
    return {
      account_key: toBase64Url(generateSigningKeyPair().publicKey),
      account: A,
      granted_by: A,
      role: "operator",
      servers: ["a"],
      issued_at: NOW,
      ...over,
    };
  }

  test("per-server and all-server grants resolve to the highest matching role", () => {
    const table = new RoleTable([
      entry({ servers: ["a"], role: "operator" }),
      entry({ servers: ["a", "b"], role: "viewer" }),
    ]);
    expect(table.roleFor(A, "a", NOW)).toBe("operator");
    expect(table.roleFor(A, "b", NOW)).toBe("viewer");
    expect(table.roleFor(A, "c", NOW)).toBeNull();

    table.set(entry({ servers: "*", role: "editor" }));
    expect(table.roleFor(A, "c", NOW)).toBe("editor");
    expect(table.roleFor(A, "*", NOW)).toBe("editor");
  });

  test("agent scope: only per-server grants give the viewer floor, none gives null", () => {
    const table = new RoleTable([entry({ servers: ["a"], role: "admin" })]);
    expect(table.roleFor(A, "*", NOW)).toBe("viewer");
    expect(table.roleFor(fingerprint(generateSigningKeyPair().publicKey), "*", NOW)).toBeNull();
  });

  test("expired grants give nothing and the account key is no longer known", () => {
    const table = new RoleTable([entry({ servers: "*", expires_at: NOW + 1000 })]);
    expect(table.roleFor(A, "a", NOW)).toBe("operator");
    expect(table.keyFor(A, NOW)).not.toBeNull();
    expect(table.roleFor(A, "a", NOW + 1000)).toBeNull();
    expect(table.keyFor(A, NOW + 1000)).toBeNull();
  });

  test("revoke removes everything, or only the listed servers of per-server grants", () => {
    const table = new RoleTable([entry({ servers: ["a", "b"] }), entry({ servers: ["c"] })]);
    expect(table.revoke(A, ["b"])).toBe(1);
    expect(table.roleFor(A, "a", NOW)).toBe("operator");
    expect(table.roleFor(A, "b", NOW)).toBeNull();
    expect(table.revoke(A)).toBe(2);
    expect(table.roleFor(A, "a", NOW)).toBeNull();
    expect(table.accountCount()).toBe(0);

    const all = new RoleTable([entry({ servers: "*" })]);
    expect(all.revoke(A, ["a"])).toBe(0);
    expect(all.roleFor(A, "a", NOW)).toBe("operator");
  });
});

// Minimum role per command, straight from the contract table.
const MIN_ROLE: Record<string, Role> = {
  "agent.ping": "viewer",
  "agent.subscribe": "viewer",
  "agent.unsubscribe": "viewer",
  "server.status": "viewer",
  "server.list": "viewer",
  "server.console.subscribe": "viewer",
  "server.console.unsubscribe": "viewer",
  "files.list": "viewer",
  "files.stat": "viewer",
  "server.mods.list": "viewer",
  "server.backup.list": "viewer",
  "server.backup.config.get": "viewer",
  "server.world.import": "editor",
  "tunnel.playit.status": "viewer",
  "server.start": "operator",
  "server.stop": "operator",
  "server.restart": "operator",
  "server.console.send": "operator",
  "server.mods.install": "editor",
  "server.mods.remove": "editor",
  "server.origin.plan": "editor",
  "server.origin.apply": "editor",
  "server.origin.unlink": "editor",
  "server.update_settings": "editor",
  "server.backup.create": "editor",
  "server.backup.config.set": "editor",
  "server.deploy.serverpack": "editor",
  "server.create": "admin",
  "server.backup.delete": "admin",
  "server.backup.restore": "admin",
  "server.delete": "admin",
  "agent.members.set": "admin",
  "agent.members.revoke": "admin",
  "agent.revocations.set": "admin",
};

describe("minimum roles", () => {
  const registry = createCoreRegistry();

  test("every registered command has the contract's minimum role", () => {
    for (const type of registry.types()) {
      const definition = registry.get(type);
      const expected =
        MIN_ROLE[type] ??
        (type.startsWith("files.")
          ? "editor"
          : type.startsWith("tunnel.playit.")
            ? "admin"
            : undefined);
      expect(expected).toBeDefined();
      expect(definition?.minRole).toBe(expected as Role);
    }
    for (const type of Object.keys(MIN_ROLE)) {
      expect(registry.has(type)).toBe(true);
    }
  });

  test("destructive and sensitive commands need an admin and the direct account key", () => {
    for (const type of [
      "server.backup.restore",
      "server.delete",
      "agent.members.set",
      "agent.members.revoke",
    ]) {
      expect(registry.get(type)?.sensitive).toBe(true);
      expect(registry.get(type)?.minRole).toBe("admin");
    }
  });

  // A concrete, valid body for every command type that can be sent with just a server id.
  const SERVER = "survival";
  const BODIES: Record<string, unknown> = {
    "agent.ping": {},
    "server.start": { server_id: SERVER },
    "server.stop": { server_id: SERVER },
    "server.restart": { server_id: SERVER },
    "server.status": { server_id: SERVER },
    "server.list": {},
    "server.console.send": { server_id: SERVER, line: "list" },
    "server.console.subscribe": { server_id: SERVER },
    "server.console.unsubscribe": { server_id: SERVER },
    "server.update_settings": { server_id: SERVER, memory_mb: 2048 },
    "files.list": { server_id: SERVER },
    "files.stat": { server_id: SERVER, path: "a" },
    "files.read": { server_id: SERVER, path: "a" },
    "server.backup.list": { server_id: SERVER },
    "server.backup.create": { server_id: SERVER },
    "server.backup.config.set": { server_id: SERVER },
    "server.backup.delete": { server_id: SERVER, backup_id: "20260101T000000Z-abcdef" },
  };

  async function attempt(
    registryForSigning: CommandRegistry,
    role: GrantableRole | "owner",
    type: string,
    body: unknown,
  ): Promise<"ok" | "insufficient_role" | string> {
    const agent = generateSigningKeyPair();
    const account = generateSigningKeyPair();
    const owner = generateSigningKeyPair();
    const accountId = fingerprint(account.publicKey);
    const members: MemberEntry[] =
      role === "owner"
        ? []
        : [
            {
              account_key: toBase64Url(account.publicKey),
              account: accountId,
              granted_by: fingerprint(owner.publicKey),
              role,
              servers: [SERVER],
              issued_at: NOW,
            },
          ];
    const trust = createInMemoryTrustContext({
      agentKeyPair: agent,
      trustedAccountKeys: role === "owner" ? [account.publicKey] : [owner.publicKey],
      members,
      now: () => NOW,
    });
    const cmd = createSignedCommand(
      { type, body, agentPublicKey: agent.publicKey, signer: account, counter: 1, now: NOW },
      registryForSigning,
    );
    try {
      await openCommand(cmd, trust, registryForSigning);
      return "ok";
    } catch (err) {
      return err instanceof ProtocolError ? err.code : String(err);
    }
  }

  test("role x command matrix on a server the member is scoped to", async () => {
    const permissive = createCoreRegistry();
    const roles: (GrantableRole | "owner")[] = ["viewer", "operator", "editor", "admin", "owner"];
    for (const [type, body] of Object.entries(BODIES)) {
      const definition = registry.get(type);
      expect(definition).toBeDefined();
      for (const role of roles) {
        const result = await attempt(permissive, role, type, body);
        const allowed = ROLE_LEVEL[role] >= ROLE_LEVEL[definition?.minRole ?? "owner"];
        if (allowed) {
          expect(`${type} as ${role}: ${result}`).toBe(`${type} as ${role}: ok`);
        } else {
          expect(`${type} as ${role}: ${result}`).toBe(`${type} as ${role}: insufficient_role`);
        }
      }
    }
  });

  test("a grant on one server gives nothing on another server", async () => {
    const permissive = createCoreRegistry();
    const agent = generateSigningKeyPair();
    const account = generateSigningKeyPair();
    const owner = generateSigningKeyPair();
    const trust = createInMemoryTrustContext({
      agentKeyPair: agent,
      trustedAccountKeys: [owner.publicKey],
      members: [
        {
          account_key: toBase64Url(account.publicKey),
          account: fingerprint(account.publicKey),
          granted_by: fingerprint(owner.publicKey),
          role: "editor",
          servers: ["alpha"],
          issued_at: NOW,
        },
      ],
      now: () => NOW,
    });
    let counter = 0;
    async function run(type: string, body: unknown): Promise<string> {
      const cmd = createSignedCommand(
        {
          type,
          body,
          agentPublicKey: agent.publicKey,
          signer: account,
          counter: ++counter,
          now: NOW,
        },
        permissive,
      );
      try {
        const opened = await openCommand(cmd, trust, permissive);
        return `ok:${opened.role}`;
      } catch (err) {
        return err instanceof ProtocolError ? err.code : String(err);
      }
    }
    expect(await run("server.start", { server_id: "alpha" })).toBe("ok:editor");
    expect(await run("server.start", { server_id: "beta" })).toBe("insufficient_role");
    // Agent-level scope: a scoped member only has the viewer floor there.
    expect(await run("server.list", {})).toBe("ok:viewer");
    expect(await run("agent.ping", {})).toBe("ok:viewer");
    expect(await run("agent.members.revoke", { account: fingerprint(owner.publicKey) })).toBe(
      "insufficient_role",
    );
  });

  test("a stranger and an expired member are not trusted at all", async () => {
    const permissive = createCoreRegistry();
    const agent = generateSigningKeyPair();
    const account = generateSigningKeyPair();
    const owner = generateSigningKeyPair();
    const trust = createInMemoryTrustContext({
      agentKeyPair: agent,
      trustedAccountKeys: [owner.publicKey],
      members: [
        {
          account_key: toBase64Url(account.publicKey),
          account: fingerprint(account.publicKey),
          granted_by: fingerprint(owner.publicKey),
          role: "viewer",
          servers: "*",
          issued_at: NOW - 10_000,
          expires_at: NOW - 1,
        },
      ],
      now: () => NOW,
    });
    const cmd = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now: NOW,
      },
      permissive,
    );
    await expectCode(openCommand(cmd, trust, permissive), "untrusted_signer");
  });

  test("session-signed commands take the role of their account", async () => {
    const permissive = createCoreRegistry();
    const agent = generateSigningKeyPair();
    const account = generateSigningKeyPair();
    const session = generateSigningKeyPair();
    const owner = generateSigningKeyPair();
    const trust = createInMemoryTrustContext({
      agentKeyPair: agent,
      trustedAccountKeys: [owner.publicKey],
      members: [
        {
          account_key: toBase64Url(account.publicKey),
          account: fingerprint(account.publicKey),
          granted_by: fingerprint(owner.publicKey),
          role: "operator",
          servers: ["alpha"],
          issued_at: NOW,
        },
      ],
      now: () => NOW,
    });
    const certificate = signSessionCertificate({
      sessionPublicKey: session.publicKey,
      accountKeyPair: account,
      notBefore: NOW - 1000,
      notAfter: NOW + 1_000_000,
    });
    const start = createSignedCommand(
      {
        type: "server.start",
        body: { server_id: "alpha" },
        agentPublicKey: agent.publicKey,
        signer: session,
        session: certificate,
        counter: 1,
        now: NOW,
      },
      permissive,
    );
    expect((await openCommand(start, trust, permissive)).role).toBe("operator");

    const files = createSignedCommand(
      {
        type: "files.read",
        body: { server_id: "alpha", path: "a" },
        agentPublicKey: agent.publicKey,
        signer: session,
        session: certificate,
        counter: 2,
        now: NOW,
      },
      permissive,
    );
    await expectCode(openCommand(files, trust, permissive), "insufficient_role");
  });

  test("roleAtLeast", () => {
    expect(roleAtLeast("owner", "admin")).toBe(true);
    expect(roleAtLeast("viewer", "operator")).toBe(false);
    expect(roleAtLeast(null, "viewer")).toBe(false);
    expect(roleAtLeast("editor", "editor")).toBe(true);
  });
});
