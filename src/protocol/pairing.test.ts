// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { beforeAll, describe, expect, test } from "bun:test";
import { fingerprint, generateSigningKeyPair, ready } from "../crypto";
import {
  buildPairingFragment,
  createCoreRegistry,
  createInMemoryTrustContext,
  createSignedCommand,
  generatePairingCode,
  generatePairingSecret,
  MAX_TRUST_GRANT_TTL_MS,
  openCommand,
  PAIRING_CODE_LENGTH,
  ProtocolError,
  type ProtocolErrorCode,
  parsePairingFragment,
  signRevocationList,
  signTrustGrant,
  type TrustGrant,
  verifyTrustGrant,
} from "./index";

const BASE_TIME = 1_700_000_000_000;

beforeAll(async () => {
  await ready();
});

function expectProtocolErrorSync(fn: () => unknown, expectedCode: ProtocolErrorCode): void {
  try {
    fn();
    throw new Error(`Expected ProtocolError(${expectedCode}), but succeeded`);
  } catch (err) {
    expect(err).toBeInstanceOf(ProtocolError);
    expect((err as ProtocolError).code).toBe(expectedCode);
  }
}

describe("pairing fragments", () => {
  test("generatePairingCode produces 10 uppercase Crockford base32 chars without I, L, O, U", () => {
    for (let i = 0; i < 50; i++) {
      const code = generatePairingCode();
      expect(code.length).toBe(PAIRING_CODE_LENGTH);
      expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{10}$/);
      expect(code).not.toMatch(/[ILOU]/);
    }
  });

  test("buildPairingFragment and parsePairingFragment round-trip with and without leading #", () => {
    const agent = generateSigningKeyPair();
    const agentFingerprint = fingerprint(agent.publicKey);
    const code = generatePairingCode();
    const secret = generatePairingSecret();

    const fragment = buildPairingFragment({ code, secret, agentFingerprint });
    expect(fragment).toBe(`${code}.${secret}.${agentFingerprint}`);

    expect(parsePairingFragment(fragment)).toEqual({
      code,
      secret,
      agentFingerprint,
    });
    expect(parsePairingFragment(`#${fragment}`)).toEqual({
      code,
      secret,
      agentFingerprint,
    });
  });

  test("parsePairingFragment accepts short code only (with or without #)", () => {
    const code = generatePairingCode();
    expect(parsePairingFragment(code)).toEqual({ code });
    expect(parsePairingFragment(`#${code}`)).toEqual({ code });
  });

  test("parsePairingFragment rejects invalid formats", () => {
    const agent = generateSigningKeyPair();
    const fp = fingerprint(agent.publicKey);
    const code = generatePairingCode();
    const secret = generatePairingSecret();

    const invalidInputs = [
      "",
      "#",
      "TOO-SHORT",
      "012345678I", // contains I
      "012345678L", // contains L
      "012345678O", // contains O
      "012345678U", // contains U
      "012345678a", // lowercase
      `${code}.${secret}`, // 2 parts
      `${code}.${secret}.${fp}.extra`, // 4 parts
      `${code}.short.${fp}`, // wrong secret length
      `${code}.${secret}.not-a-valid-fingerprint`,
    ];

    for (const input of invalidInputs) {
      expectProtocolErrorSync(() => parsePairingFragment(input), "invalid_format");
    }
  });
});

describe("TrustGrant signing and verification", () => {
  test("accepts valid grant with proof and returns accountPublicKey, accountId, proven: true", () => {
    const account = generateSigningKeyPair();
    const agent = generateSigningKeyPair();
    const secret = generatePairingSecret();

    const grant = signTrustGrant({
      accountKeyPair: account,
      agentPublicKey: agent.publicKey,
      secret,
      issuedAt: BASE_TIME,
    });

    const verified = verifyTrustGrant(grant, {
      agentPublicKey: agent.publicKey,
      secret,
      now: BASE_TIME + 5_000,
      requireProof: true,
    });

    expect(verified.proven).toBe(true);
    expect(verified.accountId).toBe(fingerprint(account.publicKey));
    expect(verified.accountPublicKey).toEqual(account.publicKey);
  });

  test("accepts valid grant without proof when requireProof is false", () => {
    const account = generateSigningKeyPair();
    const agent = generateSigningKeyPair();

    const grant = signTrustGrant({
      accountKeyPair: account,
      agentPublicKey: agent.publicKey,
      issuedAt: BASE_TIME,
    });

    expect(grant.proof).toBeUndefined();

    const verified = verifyTrustGrant(grant, {
      agentPublicKey: agent.publicKey,
      now: BASE_TIME + 1_000,
      requireProof: false,
    });

    expect(verified.proven).toBe(false);
    expect(verified.accountId).toBe(fingerprint(account.publicKey));
  });

  test("rejects wrong agent with grant_wrong_agent", () => {
    const account = generateSigningKeyPair();
    const agent1 = generateSigningKeyPair();
    const agent2 = generateSigningKeyPair();
    const secret = generatePairingSecret();

    const grant = signTrustGrant({
      accountKeyPair: account,
      agentPublicKey: agent1.publicKey,
      secret,
      issuedAt: BASE_TIME,
    });

    expectProtocolErrorSync(
      () =>
        verifyTrustGrant(grant, {
          agentPublicKey: agent2.publicKey,
          secret,
          now: BASE_TIME,
          requireProof: true,
        }),
      "grant_wrong_agent",
    );
  });

  test("rejects expired grant with grant_expired", () => {
    const account = generateSigningKeyPair();
    const agent = generateSigningKeyPair();
    const secret = generatePairingSecret();

    const grant = signTrustGrant({
      accountKeyPair: account,
      agentPublicKey: agent.publicKey,
      secret,
      issuedAt: BASE_TIME,
      ttlMs: 60_000,
    });

    expectProtocolErrorSync(
      () =>
        verifyTrustGrant(grant, {
          agentPublicKey: agent.publicKey,
          secret,
          now: BASE_TIME + 60_000,
          requireProof: true,
        }),
      "grant_expired",
    );
  });

  test("rejects not-yet-valid grant with not_yet_valid", () => {
    const account = generateSigningKeyPair();
    const agent = generateSigningKeyPair();
    const secret = generatePairingSecret();

    const grant = signTrustGrant({
      accountKeyPair: account,
      agentPublicKey: agent.publicKey,
      secret,
      issuedAt: BASE_TIME + 60_000,
    });

    expectProtocolErrorSync(
      () =>
        verifyTrustGrant(grant, {
          agentPublicKey: agent.publicKey,
          secret,
          now: BASE_TIME,
          requireProof: true,
        }),
      "not_yet_valid",
    );
  });

  test("rejects grant with TTL exceeding 15 minutes with grant_invalid", () => {
    const account = generateSigningKeyPair();
    const agent = generateSigningKeyPair();
    const grant = signTrustGrant({
      accountKeyPair: account,
      agentPublicKey: agent.publicKey,
      issuedAt: BASE_TIME,
    });

    const tooLong: TrustGrant = {
      ...grant,
      expires_at: BASE_TIME + MAX_TRUST_GRANT_TTL_MS + 1,
    };

    expectProtocolErrorSync(
      () =>
        verifyTrustGrant(tooLong, {
          agentPublicKey: agent.publicKey,
          now: BASE_TIME,
          requireProof: false,
        }),
      "grant_invalid",
    );
  });

  test("rejects tampered signature with grant_bad_signature", () => {
    const account = generateSigningKeyPair();
    const agent = generateSigningKeyPair();
    const secret = generatePairingSecret();

    const grant = signTrustGrant({
      accountKeyPair: account,
      agentPublicKey: agent.publicKey,
      secret,
      issuedAt: BASE_TIME,
    });

    const tampered: TrustGrant = {
      ...grant,
      expires_at: grant.expires_at - 1000,
    };

    expectProtocolErrorSync(
      () =>
        verifyTrustGrant(tampered, {
          agentPublicKey: agent.publicKey,
          secret,
          now: BASE_TIME,
          requireProof: true,
        }),
      "grant_bad_signature",
    );
  });

  test("rejects missing proof when requireProof is true with grant_proof_required", () => {
    const account = generateSigningKeyPair();
    const agent = generateSigningKeyPair();
    const secret = generatePairingSecret();

    const grant = signTrustGrant({
      accountKeyPair: account,
      agentPublicKey: agent.publicKey,
      issuedAt: BASE_TIME,
    });

    expectProtocolErrorSync(
      () =>
        verifyTrustGrant(grant, {
          agentPublicKey: agent.publicKey,
          secret,
          now: BASE_TIME,
          requireProof: true,
        }),
      "grant_proof_required",
    );
  });

  test("rejects wrong proof (different secret) with grant_bad_proof", () => {
    const account = generateSigningKeyPair();
    const agent = generateSigningKeyPair();
    const secret1 = generatePairingSecret();
    const secret2 = generatePairingSecret();

    const grant = signTrustGrant({
      accountKeyPair: account,
      agentPublicKey: agent.publicKey,
      secret: secret1,
      issuedAt: BASE_TIME,
    });

    expectProtocolErrorSync(
      () =>
        verifyTrustGrant(grant, {
          agentPublicKey: agent.publicKey,
          secret: secret2,
          now: BASE_TIME,
          requireProof: true,
        }),
      "grant_bad_proof",
    );
  });

  test("rejects grant with proof stripped as grant_bad_signature", () => {
    const account = generateSigningKeyPair();
    const agent = generateSigningKeyPair();
    const secret = generatePairingSecret();

    const grant = signTrustGrant({
      accountKeyPair: account,
      agentPublicKey: agent.publicKey,
      secret,
      issuedAt: BASE_TIME,
    });

    const { proof: _removed, ...stripped } = grant;

    expectProtocolErrorSync(
      () =>
        verifyTrustGrant(stripped, {
          agentPublicKey: agent.publicKey,
          secret,
          now: BASE_TIME,
          requireProof: false,
        }),
      "grant_bad_signature",
    );
  });

  test("rejects grant signed by attacker key with proof from another secret as grant_bad_proof", () => {
    const attacker = generateSigningKeyPair();
    const agent = generateSigningKeyPair();
    const agentSecret = generatePairingSecret();
    const attackerSecret = generatePairingSecret();

    const forgedGrant = signTrustGrant({
      accountKeyPair: attacker,
      agentPublicKey: agent.publicKey,
      secret: attackerSecret,
      issuedAt: BASE_TIME,
    });

    expectProtocolErrorSync(
      () =>
        verifyTrustGrant(forgedGrant, {
          agentPublicKey: agent.publicKey,
          secret: agentSecret,
          now: BASE_TIME,
          requireProof: true,
        }),
      "grant_bad_proof",
    );
  });
});

describe("agent.revocations.set command", () => {
  test("is registered in createCoreRegistry as non-sensitive and opens cleanly", async () => {
    const registry = createCoreRegistry();
    const def = registry.get("agent.revocations.set");
    expect(def).toBeDefined();
    expect(def?.sensitive).toBe(false);

    const account = generateSigningKeyPair();
    const agent = generateSigningKeyPair();
    const list = signRevocationList({
      accountKeyPair: account,
      issuedAt: BASE_TIME,
      revoked: ["sess_abc"],
    });

    const cmd = createSignedCommand(
      {
        type: "agent.revocations.set",
        body: { list },
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now: BASE_TIME,
      },
      registry,
    );

    const trust = createInMemoryTrustContext({
      agentKeyPair: agent,
      trustedAccountKeys: [account.publicKey],
      now: () => BASE_TIME,
    });

    const opened = await openCommand(cmd, trust, registry);
    expect(opened.header.type).toBe("agent.revocations.set");
    expect(opened.body).toEqual({ list });
  });
});
