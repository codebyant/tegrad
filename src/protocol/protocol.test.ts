// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { beforeAll, describe, expect, test } from "bun:test";
import {
  canonicalize,
  fingerprint,
  fromBase64Url,
  generateSigningKeyPair,
  ready,
  sealTo,
  sign,
  signingKeyPairFromSeed,
  toBase64Url,
} from "../crypto";
import {
  createCoreRegistry,
  createInMemoryTrustContext,
  createSignedCommand,
  DOMAIN_COMMAND,
  DOMAIN_SESSION,
  MAX_COMMAND_TTL_MS,
  openAgentMessage,
  openCommand,
  PROTOCOL_VERSION,
  ProtocolError,
  type ProtocolErrorCode,
  sealAgentMessage,
  signRevocationList,
  signSessionCertificate,
  transportFrameSchema,
  verifyRevocationList,
  verifySessionCertificate,
} from "./index";

const BASE_TIME = 1_700_000_000_000;

beforeAll(async () => {
  await ready();
});

async function expectProtocolError(
  promise: Promise<unknown>,
  expectedCode: ProtocolErrorCode,
): Promise<void> {
  try {
    await promise;
    throw new Error(`Expected ProtocolError(${expectedCode}), but succeeded`);
  } catch (err) {
    expect(err).toBeInstanceOf(ProtocolError);
    expect((err as ProtocolError).code).toBe(expectedCode);
  }
}

function makeFixture() {
  const account = generateSigningKeyPair();
  const session = generateSigningKeyPair();
  const agent = generateSigningKeyPair();
  const registry = createCoreRegistry();
  const now = BASE_TIME;

  const sessionCert = signSessionCertificate({
    sessionPublicKey: session.publicKey,
    accountKeyPair: account,
    notBefore: now - 60_000,
    notAfter: now + 3_600_000,
  });

  const trust = createInMemoryTrustContext({
    agentKeyPair: agent,
    trustedAccountKeys: [account.publicKey],
    now: () => now,
  });

  return { account, session, agent, registry, sessionCert, trust, now };
}

describe("fixed protocol vector", () => {
  test("canonical command header and Ed25519 signature match fixed vector", () => {
    const account = signingKeyPairFromSeed(new Uint8Array(32).fill(0x11));
    const agent = signingKeyPairFromSeed(new Uint8Array(32).fill(0x22));

    const header = {
      v: PROTOCOL_VERSION,
      id: "AAAAAAAAAAAAAAAAAAAAAA",
      type: "server.start",
      agent: fingerprint(agent.publicKey),
      signer: fingerprint(account.publicKey),
      issued_at: BASE_TIME,
      expires_at: BASE_TIME + 300_000,
      counter: 1,
    };

    const canonHeader = canonicalize(header);
    expect(new TextDecoder().decode(canonHeader)).toBe(
      '{"agent":"7sgisx6bisee5ge2gkt4x67uondk2ojg","counter":1,"expires_at":1700000300000,"id":"AAAAAAAAAAAAAAAAAAAAAA","issued_at":1700000000000,"signer":"2o6xl7gxm5sqizy645pzlypnplng2fun","type":"server.start","v":1}',
    );

    const fixedPayload = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const input = new Uint8Array(DOMAIN_COMMAND.length + canonHeader.length + fixedPayload.length);
    input.set(DOMAIN_COMMAND, 0);
    input.set(canonHeader, DOMAIN_COMMAND.length);
    input.set(fixedPayload, DOMAIN_COMMAND.length + canonHeader.length);

    const sig = sign(input, account.secretKey);
    expect(toBase64Url(sig)).toBe(
      "SI0IX7mt3GFTZirFUj5J_7fnMfgC9SW76UVlL77DnGkWxa9vq3o_hFeCF_JGKnSGld7mbeskTV7QyVso9s-NBg",
    );
  });
});

describe("happy paths", () => {
  test("command signed by session key opens cleanly", async () => {
    const { account, session, agent, registry, sessionCert, trust, now } = makeFixture();
    const cmd = createSignedCommand(
      {
        type: "server.start",
        body: { server_id: "srv-1" },
        agentPublicKey: agent.publicKey,
        signer: session,
        session: sessionCert,
        counter: 1,
        now,
      },
      registry,
    );

    const opened = await openCommand(cmd, trust, registry);
    expect(opened.header.type).toBe("server.start");
    expect(opened.body).toEqual({ server_id: "srv-1" });
    expect(opened.signerType).toBe("session");
    expect(opened.accountId).toBe(fingerprint(account.publicKey));
    expect(opened.sessionId).toBe(sessionCert.id);
  });

  test("sensitive command signed directly by account key opens cleanly", async () => {
    const { account, agent, registry, trust, now } = makeFixture();
    const cmd = createSignedCommand(
      {
        type: "server.delete",
        body: { server_id: "srv-1" },
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now,
      },
      registry,
    );

    const opened = await openCommand(cmd, trust, registry);
    expect(opened.header.type).toBe("server.delete");
    expect(opened.body).toEqual({ server_id: "srv-1" });
    expect(opened.signerType).toBe("account");
    expect(opened.accountId).toBe(fingerprint(account.publicKey));
    expect(opened.sessionId).toBeUndefined();
  });

  test("AgentMessage round-trip", () => {
    const { account, agent, now } = makeFixture();
    const msg = sealAgentMessage({
      type: "server.status",
      body: { server_id: "srv-1", status: "running" },
      agentKeyPair: agent,
      recipientPublicKey: account.publicKey,
      sentAt: now,
      seq: 1,
    });

    const opened = openAgentMessage(msg, agent.publicKey, account);
    expect(opened.header.type).toBe("server.status");
    expect(opened.header.seq).toBe(1);
    expect(opened.body).toEqual({ server_id: "srv-1", status: "running" });
  });

  test("RevocationList round-trip and SessionCertificate verification", () => {
    const { account, sessionCert, now } = makeFixture();
    const verified = verifySessionCertificate(sessionCert, account.publicKey, now);
    expect(verified.certificate.id).toBe(sessionCert.id);

    const revList = signRevocationList({
      accountKeyPair: account,
      issuedAt: now,
      revoked: [sessionCert.id],
    });
    const verifiedRev = verifyRevocationList(revList, account.publicKey);
    expect(verifiedRev.revoked).toEqual([sessionCert.id]);
  });

  test("TransportFrame validates command, event, ack, and ping frames", () => {
    const { account, agent, registry, now } = makeFixture();
    const agentId = fingerprint(agent.publicKey);
    const accountId = fingerprint(account.publicKey);

    const cmd = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now,
      },
      registry,
    );
    const event = sealAgentMessage({
      type: "agent.pong",
      body: {},
      agentKeyPair: agent,
      recipientPublicKey: account.publicKey,
      sentAt: now,
      seq: 1,
    });

    expect(
      transportFrameSchema.safeParse({
        v: PROTOCOL_VERSION,
        kind: "command",
        route: { agent: agentId },
        body: cmd,
      }).success,
    ).toBe(true);

    expect(
      transportFrameSchema.safeParse({
        v: PROTOCOL_VERSION,
        kind: "event",
        route: { agent: agentId, recipient: accountId },
        body: event,
      }).success,
    ).toBe(true);

    expect(
      transportFrameSchema.safeParse({
        v: PROTOCOL_VERSION,
        kind: "ack",
        route: { agent: agentId },
        body: { id: cmd.header.id, ok: true },
      }).success,
    ).toBe(true);

    expect(
      transportFrameSchema.safeParse({
        v: PROTOCOL_VERSION,
        kind: "ping",
        route: { agent: agentId },
        body: { ts: now },
      }).success,
    ).toBe(true);
  });
});

describe("rejections", () => {
  test("rejects tampered header", async () => {
    const { account, agent, registry, trust, now } = makeFixture();
    const cmd = createSignedCommand(
      {
        type: "server.start",
        body: { server_id: "srv-1" },
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now,
      },
      registry,
    );
    const tampered = { ...cmd, header: { ...cmd.header, counter: 2 } };
    await expectProtocolError(openCommand(tampered, trust, registry), "bad_signature");
  });

  test("rejects tampered payload", async () => {
    const { account, agent, registry, trust, now } = makeFixture();
    const cmd = createSignedCommand(
      {
        type: "server.start",
        body: { server_id: "srv-1" },
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now,
      },
      registry,
    );
    const bytes = fromBase64Url(cmd.payload);
    bytes[0] = (bytes[0] ?? 0) ^ 0xff;
    const tampered = { ...cmd, payload: toBase64Url(bytes) };
    await expectProtocolError(openCommand(tampered, trust, registry), "bad_signature");
  });

  test("rejects signature reused from another domain", async () => {
    const { account, agent, registry, trust, now } = makeFixture();
    const cmd = createSignedCommand(
      {
        type: "server.start",
        body: { server_id: "srv-1" },
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now,
      },
      registry,
    );
    const canonHeader = canonicalize(cmd.header);
    const payloadBytes = fromBase64Url(cmd.payload);
    const wrongDomainInput = new Uint8Array(
      DOMAIN_SESSION.length + canonHeader.length + payloadBytes.length,
    );
    wrongDomainInput.set(DOMAIN_SESSION, 0);
    wrongDomainInput.set(canonHeader, DOMAIN_SESSION.length);
    wrongDomainInput.set(payloadBytes, DOMAIN_SESSION.length + canonHeader.length);

    const wrongDomainSig = sign(wrongDomainInput, account.secretKey);
    const forged = { ...cmd, sig: toBase64Url(wrongDomainSig) };
    await expectProtocolError(openCommand(forged, trust, registry), "bad_signature");
  });

  test("rejects wrong agent", async () => {
    const { account, registry, trust, now } = makeFixture();
    const otherAgent = generateSigningKeyPair();
    const cmd = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: otherAgent.publicKey,
        signer: account,
        counter: 1,
        now,
      },
      registry,
    );
    await expectProtocolError(openCommand(cmd, trust, registry), "wrong_agent");
  });

  test("rejects expired command", async () => {
    const { account, agent, registry, trust, now } = makeFixture();
    const cmd = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now: now - 120_000,
        ttlMs: 60_000,
      },
      registry,
    );
    await expectProtocolError(openCommand(cmd, trust, registry), "expired");
  });

  test("rejects command issued in the future", async () => {
    const { account, agent, registry, trust, now } = makeFixture();
    const cmd = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now: now + 120_000,
      },
      registry,
    );
    await expectProtocolError(openCommand(cmd, trust, registry), "not_yet_valid");
  });

  test("rejects command with TTL exceeding maximum", async () => {
    const { account, agent, registry, trust, now } = makeFixture();
    const cmd = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now,
        ttlMs: MAX_COMMAND_TTL_MS + 1,
      },
      registry,
    );
    await expectProtocolError(openCommand(cmd, trust, registry), "ttl_too_long");
  });

  test("rejects untrusted direct signer", async () => {
    const { agent, registry, trust, now } = makeFixture();
    const stranger = generateSigningKeyPair();
    const cmd = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: stranger,
        counter: 1,
        now,
      },
      registry,
    );
    await expectProtocolError(openCommand(cmd, trust, registry), "untrusted_signer");
  });

  test("rejects expired session certificate", async () => {
    const { account, session, agent, registry, trust, now } = makeFixture();
    const expiredCert = signSessionCertificate({
      sessionPublicKey: session.publicKey,
      accountKeyPair: account,
      notBefore: now - 120_000,
      notAfter: now - 1_000,
    });
    const cmd = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: session,
        session: expiredCert,
        counter: 1,
        now,
      },
      registry,
    );
    await expectProtocolError(openCommand(cmd, trust, registry), "session_invalid");
  });

  test("rejects revoked session certificate", async () => {
    const { session, agent, registry, sessionCert, trust, now } = makeFixture();
    trust.revokeSession(sessionCert.id);
    const cmd = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: session,
        session: sessionCert,
        counter: 1,
        now,
      },
      registry,
    );
    await expectProtocolError(openCommand(cmd, trust, registry), "session_revoked");
  });

  test("rejects session certificate signed by untrusted account key", async () => {
    const { session, agent, registry, trust, now } = makeFixture();
    const untrustedAccount = generateSigningKeyPair();
    const cert = signSessionCertificate({
      sessionPublicKey: session.publicKey,
      accountKeyPair: untrustedAccount,
      notBefore: now - 60_000,
      notAfter: now + 60_000,
    });
    const cmd = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: session,
        session: cert,
        counter: 1,
        now,
      },
      registry,
    );
    await expectProtocolError(openCommand(cmd, trust, registry), "untrusted_signer");
  });

  test("rejects replay of the same command id", async () => {
    const { account, agent, registry, trust, now } = makeFixture();
    const cmd = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now,
      },
      registry,
    );
    await openCommand(cmd, trust, registry);
    await expectProtocolError(openCommand(cmd, trust, registry), "replayed");
  });

  test("rejects regressing counter and does not consume counter on invalid signature", async () => {
    const { account, agent, registry, trust, now } = makeFixture();

    const forgedHighCounter = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 100,
        now,
      },
      registry,
    );
    const badSigBytes = fromBase64Url(forgedHighCounter.sig);
    badSigBytes[0] = (badSigBytes[0] ?? 0) ^ 0xff;
    await expectProtocolError(
      openCommand({ ...forgedHighCounter, sig: toBase64Url(badSigBytes) }, trust, registry),
      "bad_signature",
    );

    const valid5 = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 5,
        now,
      },
      registry,
    );
    await openCommand(valid5, trust, registry);

    const regressed4 = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 4,
        now,
      },
      registry,
    );
    await expectProtocolError(openCommand(regressed4, trust, registry), "replayed");
  });

  test("rejects unsupported protocol version", async () => {
    const { account, agent, registry, trust, now } = makeFixture();
    const cmd = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now,
      },
      registry,
    );
    const v2 = { ...cmd, header: { ...cmd.header, v: 2 } };
    await expectProtocolError(openCommand(v2, trust, registry), "unsupported_version");
  });

  test("rejects unknown command type", async () => {
    const { account, agent, registry, trust, now } = makeFixture();
    const header = {
      v: PROTOCOL_VERSION,
      id: "AAAAAAAAAAAAAAAAAAAAAA",
      type: "server.unknown",
      agent: fingerprint(agent.publicKey),
      signer: fingerprint(account.publicKey),
      issued_at: now,
      expires_at: now + 60_000,
      counter: 1,
    };
    const payloadBytes = sealTo(canonicalize({}), agent.publicKey);
    const canonHeader = canonicalize(header);
    const input = new Uint8Array(DOMAIN_COMMAND.length + canonHeader.length + payloadBytes.length);
    input.set(DOMAIN_COMMAND, 0);
    input.set(canonHeader, DOMAIN_COMMAND.length);
    input.set(payloadBytes, DOMAIN_COMMAND.length + canonHeader.length);
    const cmd = {
      header,
      payload: toBase64Url(payloadBytes),
      sig: toBase64Url(sign(input, account.secretKey)),
    };
    await expectProtocolError(openCommand(cmd, trust, registry), "unknown_command");
  });

  test("rejects body not matching command schema", async () => {
    const { account, agent, registry, trust, now } = makeFixture();
    const header = {
      v: PROTOCOL_VERSION,
      id: "AAAAAAAAAAAAAAAAAAAAAA",
      type: "server.start",
      agent: fingerprint(agent.publicKey),
      signer: fingerprint(account.publicKey),
      issued_at: now,
      expires_at: now + 60_000,
      counter: 1,
    };
    const payloadBytes = sealTo(canonicalize({ wrong_field: 123 }), agent.publicKey);
    const canonHeader = canonicalize(header);
    const input = new Uint8Array(DOMAIN_COMMAND.length + canonHeader.length + payloadBytes.length);
    input.set(DOMAIN_COMMAND, 0);
    input.set(canonHeader, DOMAIN_COMMAND.length);
    input.set(payloadBytes, DOMAIN_COMMAND.length + canonHeader.length);
    const cmd = {
      header,
      payload: toBase64Url(payloadBytes),
      sig: toBase64Url(sign(input, account.secretKey)),
    };
    await expectProtocolError(openCommand(cmd, trust, registry), "invalid_body");
  });

  test("rejects sensitive command signed by session key", async () => {
    const { session, agent, registry, sessionCert, trust, now } = makeFixture();
    const cmd = createSignedCommand(
      {
        type: "server.delete",
        body: { server_id: "srv-1" },
        agentPublicKey: agent.publicKey,
        signer: session,
        session: sessionCert,
        counter: 1,
        now,
      },
      registry,
    );
    await expectProtocolError(openCommand(cmd, trust, registry), "elevation_required");
  });

  test("rejects decryption failure when payload is sealed for wrong key", async () => {
    const { account, agent, registry, trust, now } = makeFixture();
    const wrongRecipient = generateSigningKeyPair();
    const header = {
      v: PROTOCOL_VERSION,
      id: "AAAAAAAAAAAAAAAAAAAAAA",
      type: "agent.ping",
      agent: fingerprint(agent.publicKey),
      signer: fingerprint(account.publicKey),
      issued_at: now,
      expires_at: now + 60_000,
      counter: 1,
    };
    const payloadBytes = sealTo(canonicalize({}), wrongRecipient.publicKey);
    const canonHeader = canonicalize(header);
    const input = new Uint8Array(DOMAIN_COMMAND.length + canonHeader.length + payloadBytes.length);
    input.set(DOMAIN_COMMAND, 0);
    input.set(canonHeader, DOMAIN_COMMAND.length);
    input.set(payloadBytes, DOMAIN_COMMAND.length + canonHeader.length);
    const cmd = {
      header,
      payload: toBase64Url(payloadBytes),
      sig: toBase64Url(sign(input, account.secretKey)),
    };
    await expectProtocolError(openCommand(cmd, trust, registry), "decrypt_failed");
  });
});
