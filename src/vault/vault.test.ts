// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { beforeAll, describe, expect, test } from "bun:test";
import {
  fingerprint,
  generateSigningKeyPair,
  KDF_FLOOR,
  KDF_MODERATE,
  ready,
  toBase64Url,
} from "../crypto";
import {
  createCoreRegistry,
  createInMemoryTrustContext,
  MAX_ELEVATED_SESSION_MS,
  openCommand,
  ProtocolError,
  signSessionCertificate,
  verifyRevocationList,
  verifySessionCertificate,
} from "../protocol";
import {
  changePassword,
  createCommandFromSession,
  createMemoryCounterStore,
  createSensitiveCommand,
  createVault,
  isElevatedSession,
  isSessionExpired,
  issueElevatedSession,
  issueSession,
  parseRecoveryCode,
  parseSession,
  resetPasswordWithRecovery,
  rotateRecoveryCode,
  SESSION_DURATION_MS,
  serializeSession,
  sessionExpiresAt,
  signRevocation,
  unlockVault,
  unlockVaultWithRecovery,
  type VaultBlob,
  VaultError,
  validatePassword,
  withUnlockedVault,
} from "./index";

const STRONG_PW_1 = "correct-horse-battery-staple-91!";
const STRONG_PW_2 = "cobalt-lantern-quartz-monolith-73#";
const STRONG_PW_3 = "velvet-compass-harbor-nebula-48$";
const BASE_TIME = 1_750_000_000_000;

function expectVaultError(fn: () => unknown, code: VaultError["code"]): VaultError {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(VaultError);
    const ve = err as VaultError;
    expect(ve.code).toBe(code);
    return ve;
  }
  throw new Error(`Expected VaultError(${code}), but function did not throw`);
}

async function expectProtocolError(
  promise: Promise<unknown>,
  code: ProtocolError["code"],
): Promise<void> {
  try {
    await promise;
  } catch (err) {
    expect(err).toBeInstanceOf(ProtocolError);
    expect((err as ProtocolError).code).toBe(code);
    return;
  }
  throw new Error(`Expected ProtocolError(${code}), but promise resolved`);
}

beforeAll(async () => {
  await ready();
});

describe("password policy", () => {
  test("rejects short, empty, whitespace-only, and weak passwords", () => {
    expect(validatePassword("")).toEqual({ ok: false, reason: "too_short" });
    expect(validatePassword("short!9X")).toEqual({ ok: false, reason: "too_short" });
    // 11 emoji = 22 UTF-16 code units, but only 11 Unicode code points
    expect(validatePassword("🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑")).toEqual({ ok: false, reason: "too_short" });
    expect(validatePassword("            ")).toEqual({ ok: false, reason: "too_weak" });
    expect(validatePassword("\t\n   \t\n     ")).toEqual({ ok: false, reason: "too_weak" });
    expect(validatePassword("passwordpassword")).toEqual({ ok: false, reason: "too_weak" });
    expect(validatePassword("123456789012")).toEqual({ ok: false, reason: "too_weak" });
  });

  test("accepts strong random passphrase and rejects passwords derived from userInputs", () => {
    expect(validatePassword(STRONG_PW_1)).toEqual({ ok: true });

    const email = "mariana.silva@example.com";
    const derived = "mariana.silva2026";
    expect(validatePassword(derived, { userInputs: [email, "mariana", "silva"] })).toEqual({
      ok: false,
      reason: "too_weak",
    });
  });

  test("vault mutations reject weak passwords with weak_password", () => {
    expectVaultError(
      () => createVault({ password: "passwordpassword", now: BASE_TIME, kdf: KDF_FLOOR }),
      "weak_password",
    );

    const { blob, recoveryCode, unlocked } = createVault({
      password: STRONG_PW_1,
      now: BASE_TIME,
      kdf: KDF_FLOOR,
    });
    unlocked.lock();

    expectVaultError(
      () => changePassword(blob, STRONG_PW_1, "123456789012", { now: BASE_TIME, kdf: KDF_FLOOR }),
      "weak_password",
    );
    expectVaultError(
      () =>
        resetPasswordWithRecovery(blob, recoveryCode, "short", {
          now: BASE_TIME,
          kdf: KDF_FLOOR,
        }),
      "weak_password",
    );
  });
});

describe("vault lifecycle and protocol integration", () => {
  test("full cycle: createVault -> JSON round-trip -> unlock -> session -> openCommand", async () => {
    const registry = createCoreRegistry();
    const agentKeyPair = generateSigningKeyPair();

    const created = createVault({ password: STRONG_PW_1, now: BASE_TIME, kdf: KDF_FLOOR });
    const serialized = JSON.stringify(created.blob);
    created.unlocked.lock();

    const parsedBlob: unknown = JSON.parse(serialized);
    const unlocked = unlockVault(parsedBlob, STRONG_PW_1);
    expect(unlocked.account).toBe(created.blob.account);
    expect(toBase64Url(unlocked.publicKey)).toBe(created.blob.public_key);

    const session = issueSession(unlocked, { duration: "24h", now: BASE_TIME });
    const counters = createMemoryCounterStore();
    const counter = await counters.next(fingerprint(session.keyPair.publicKey), BASE_TIME);

    const command = createCommandFromSession(session, {
      type: "server.start",
      body: { server_id: "srv-1" },
      agentPublicKey: agentKeyPair.publicKey,
      counter,
      now: BASE_TIME + 1000,
      registry,
    });

    const trust = createInMemoryTrustContext({
      agentKeyPair,
      trustedAccountKeys: [unlocked.publicKey],
      now: () => BASE_TIME + 2000,
    });

    const opened = await openCommand(command, trust, registry);
    expect(opened.signerType).toBe("session");
    expect(opened.accountId).toBe(unlocked.account);
    expect(opened.sessionId).toBe(session.certificate.id);
    expect(opened.body).toEqual({ server_id: "srv-1" });
    // Replies to a session command are sealed for the session key by default.
    expect(command.header.reply_to).toBe(toBase64Url(session.keyPair.publicKey));

    unlocked.lock();
  });

  test("sensitive command succeeds with account key and is rejected with session key", async () => {
    const registry = createCoreRegistry();
    const agentKeyPair = generateSigningKeyPair();
    const { unlocked } = createVault({ password: STRONG_PW_1, now: BASE_TIME, kdf: KDF_FLOOR });

    const trust = createInMemoryTrustContext({
      agentKeyPair,
      trustedAccountKeys: [unlocked.publicKey],
      now: () => BASE_TIME + 1000,
    });

    const session = issueSession(unlocked, { duration: "24h", now: BASE_TIME });
    const sessionCmd = createCommandFromSession(session, {
      type: "server.delete",
      body: { server_id: "srv-9" },
      agentPublicKey: agentKeyPair.publicKey,
      counter: 1,
      now: BASE_TIME + 500,
      registry,
    });

    await expectProtocolError(openCommand(sessionCmd, trust, registry), "elevation_required");

    const accountCmd = createSensitiveCommand(unlocked, {
      type: "server.delete",
      body: { server_id: "srv-9" },
      agentPublicKey: agentKeyPair.publicKey,
      counter: 1,
      now: BASE_TIME + 500,
      registry,
    });

    const opened = await openCommand(accountCmd, trust, registry);
    expect(opened.signerType).toBe("account");
    expect(opened.accountId).toBe(unlocked.account);
    expect(opened.body).toEqual({ server_id: "srv-9" });

    unlocked.lock();
  });

  test("wrong password and tampered blobs fail with unlock_failed or invalid_blob", () => {
    const { blob, recoveryCode, unlocked } = createVault({
      password: STRONG_PW_1,
      now: BASE_TIME,
      kdf: KDF_FLOOR,
    });
    unlocked.lock();

    // Wrong password
    const wrongErr = expectVaultError(() => unlockVault(blob, STRONG_PW_2), "unlock_failed");
    expect(wrongErr.message).not.toContain(STRONG_PW_2);
    expect(wrongErr.message).not.toContain(blob.password.wrapped_secret);

    // Tampered account
    const otherAccount = fingerprint(generateSigningKeyPair().publicKey);
    const tamperedAccount: VaultBlob = { ...blob, account: otherAccount };
    expectVaultError(() => unlockVault(tamperedAccount, STRONG_PW_1), "unlock_failed");

    // Tampered public_key
    const otherPub = toBase64Url(generateSigningKeyPair().publicKey);
    const tamperedPub: VaultBlob = { ...blob, public_key: otherPub };
    expectVaultError(() => unlockVault(tamperedPub, STRONG_PW_1), "unlock_failed");

    // Tampered KDF opslimit (still >= floor so it passes floor check and fails AAD/key derivation)
    const tamperedKdf: VaultBlob = {
      ...blob,
      password: {
        ...blob.password,
        kdf: { ...blob.password.kdf, opslimit: blob.password.kdf.opslimit + 1 },
      },
    };
    expectVaultError(() => unlockVault(tamperedKdf, STRONG_PW_1), "unlock_failed");

    // Swap password copy with recovery copy
    const swappedToPassword: VaultBlob = {
      ...blob,
      password: {
        ...blob.password,
        wrapped_secret: blob.recovery.wrapped_secret,
      },
    };
    expectVaultError(() => unlockVault(swappedToPassword, STRONG_PW_1), "unlock_failed");

    // Swap recovery copy with password copy
    const swappedToRecovery: VaultBlob = {
      ...blob,
      recovery: {
        wrapped_secret: blob.password.wrapped_secret,
      },
    };
    expectVaultError(
      () => unlockVaultWithRecovery(swappedToRecovery, recoveryCode),
      "unlock_failed",
    );
  });

  test("KDF below floor in blob is rejected immediately with invalid_blob", () => {
    const { blob, unlocked } = createVault({
      password: STRONG_PW_1,
      now: BASE_TIME,
      kdf: KDF_FLOOR,
    });
    unlocked.lock();

    const lowMem: VaultBlob = {
      ...blob,
      password: {
        ...blob.password,
        kdf: { ...blob.password.kdf, memlimit: 1024 * 1024 },
      },
    };

    const start = performance.now();
    expectVaultError(() => unlockVault(lowMem, STRONG_PW_1), "invalid_blob");
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(100);

    const lowOps: VaultBlob = {
      ...blob,
      password: {
        ...blob.password,
        kdf: { ...blob.password.kdf, opslimit: 1 },
      },
    };
    expectVaultError(() => unlockVault(lowOps, STRONG_PW_1), "invalid_blob");
  });

  test("default createVault uses KDF_MODERATE and records its parameters in the blob", () => {
    const { blob, unlocked } = createVault({ password: STRONG_PW_1, now: BASE_TIME });
    expect(blob.password.kdf.alg).toBe(KDF_MODERATE.alg);
    expect(blob.password.kdf.opslimit).toBe(KDF_MODERATE.opslimit);
    expect(blob.password.kdf.memlimit).toBe(KDF_MODERATE.memlimit);
    unlocked.lock();

    const reopened = unlockVault(blob, STRONG_PW_1);
    expect(reopened.account).toBe(blob.account);
    reopened.lock();
  });
});

describe("recovery codes and password changes", () => {
  test("recovery code unlocks vault, detects typos, and rejects another vault's code", () => {
    const v1 = createVault({ password: STRONG_PW_1, now: BASE_TIME, kdf: KDF_FLOOR });
    const v2 = createVault({ password: STRONG_PW_2, now: BASE_TIME, kdf: KDF_FLOOR });
    v1.unlocked.lock();
    v2.unlocked.lock();

    // Format check: 13 groups of 4 + 1 check char
    expect(v1.recoveryCode).toMatch(/^([0-9A-HJKMNP-TV-Z]{4}-){13}[0-9A-HJKMNP-TV-Z]$/);

    // Works with lowercase and spaces
    const messy = v1.recoveryCode.toLowerCase().replaceAll("-", " ");
    const u1 = unlockVaultWithRecovery(v1.blob, messy);
    expect(u1.account).toBe(v1.blob.account);
    u1.lock();

    // Single character substitution caught by check digit
    const firstChar = v1.recoveryCode[0] ?? "0";
    const replacement = firstChar === "A" ? "B" : "A";
    const typo = `${replacement}${v1.recoveryCode.slice(1)}`;
    const typoErr = expectVaultError(
      () => unlockVaultWithRecovery(v1.blob, typo),
      "invalid_recovery_code",
    );
    expect(typoErr.message).not.toContain(typo);

    // Adjacent transposition caught by check digit
    const raw = v1.recoveryCode.replaceAll("-", "");
    let swapped = raw;
    for (let i = 0; i < raw.length - 2; i++) {
      if (raw[i] !== raw[i + 1]) {
        swapped = raw.slice(0, i) + (raw[i + 1] ?? "") + (raw[i] ?? "") + raw.slice(i + 2);
        break;
      }
    }
    expectVaultError(() => parseRecoveryCode(swapped), "invalid_recovery_code");

    // Recovery code from another vault fails decryption with unlock_failed
    expectVaultError(() => unlockVaultWithRecovery(v1.blob, v2.recoveryCode), "unlock_failed");
  });

  test("rotateRecoveryCode invalidates old code and preserves password access", () => {
    const {
      blob,
      recoveryCode: oldCode,
      unlocked,
    } = createVault({
      password: STRONG_PW_1,
      now: BASE_TIME,
      kdf: KDF_FLOOR,
    });
    unlocked.lock();

    const rotated = rotateRecoveryCode(blob, STRONG_PW_1);
    expect(rotated.recoveryCode).not.toBe(oldCode);
    expect(rotated.blob.account).toBe(blob.account);

    expectVaultError(() => unlockVaultWithRecovery(rotated.blob, oldCode), "unlock_failed");

    const byNewCode = unlockVaultWithRecovery(rotated.blob, rotated.recoveryCode);
    expect(byNewCode.account).toBe(blob.account);
    byNewCode.lock();

    const byPassword = unlockVault(rotated.blob, STRONG_PW_1);
    expect(byPassword.account).toBe(blob.account);
    byPassword.lock();
  });

  test("resetPasswordWithRecovery sets a new password and invalidates the old one", () => {
    const { blob, recoveryCode, unlocked } = createVault({
      password: STRONG_PW_1,
      now: BASE_TIME,
      kdf: KDF_FLOOR,
    });
    unlocked.lock();

    const resetBlob = resetPasswordWithRecovery(blob, recoveryCode, STRONG_PW_3, {
      now: BASE_TIME + 5000,
      kdf: KDF_FLOOR,
    });
    expect(resetBlob.account).toBe(blob.account);
    expect(resetBlob.password.kdf.salt).not.toBe(blob.password.kdf.salt);

    expectVaultError(() => unlockVault(resetBlob, STRONG_PW_1), "unlock_failed");

    const u = unlockVault(resetBlob, STRONG_PW_3);
    expect(u.account).toBe(blob.account);
    u.lock();
  });

  test("changePassword rotates salt, invalidates old password, preserves account and recovery", () => {
    const { blob, recoveryCode, unlocked } = createVault({
      password: STRONG_PW_1,
      now: BASE_TIME,
      kdf: KDF_FLOOR,
    });
    unlocked.lock();

    const nextBlob = changePassword(blob, STRONG_PW_1, STRONG_PW_2, {
      now: BASE_TIME + 10_000,
      kdf: KDF_FLOOR,
    });

    expect(nextBlob.account).toBe(blob.account);
    expect(nextBlob.public_key).toBe(blob.public_key);
    expect(nextBlob.password.kdf.salt).not.toBe(blob.password.kdf.salt);
    expect(nextBlob.recovery.wrapped_secret).toBe(blob.recovery.wrapped_secret);

    expectVaultError(() => unlockVault(nextBlob, STRONG_PW_1), "unlock_failed");

    const byNewPw = unlockVault(nextBlob, STRONG_PW_2);
    expect(byNewPw.account).toBe(blob.account);
    byNewPw.lock();

    const byRecovery = unlockVaultWithRecovery(nextBlob, recoveryCode);
    expect(byRecovery.account).toBe(blob.account);
    byRecovery.lock();
  });
});

describe("sessions, revocation, counter, and locking", () => {
  test("session durations, certificate verification, serialization, expiry, and revocation", async () => {
    const registry = createCoreRegistry();
    const agentKeyPair = generateSigningKeyPair();
    const { unlocked } = createVault({ password: STRONG_PW_1, now: BASE_TIME, kdf: KDF_FLOOR });

    // Check all four durations
    for (const duration of ["24h", "7d", "30d", "remember"] as const) {
      const s = issueSession(unlocked, { duration, now: BASE_TIME });
      expect(s.certificate.not_before).toBe(BASE_TIME);
      expect(sessionExpiresAt(s)).toBe(BASE_TIME + SESSION_DURATION_MS[duration]);
      const verified = verifySessionCertificate(s.certificate, unlocked.publicKey, BASE_TIME);
      expect(verified.sessionPublicKey).toEqual(s.keyPair.publicKey);
    }

    const session = issueSession(unlocked, { duration: "24h", now: BASE_TIME });

    // Serialize / parse round-trip
    const text = serializeSession(session);
    const restored = parseSession(text);
    expect(restored.certificate).toEqual(session.certificate);
    expect(restored.keyPair.publicKey).toEqual(session.keyPair.publicKey);
    expect(restored.keyPair.secretKey).toEqual(session.keyPair.secretKey);

    // Reject tampered serialized sessions
    expectVaultError(() => parseSession("not json"), "invalid_session");
    const parsedObj = JSON.parse(text) as Record<string, unknown>;
    const otherKp = generateSigningKeyPair();
    expectVaultError(
      () =>
        parseSession(JSON.stringify({ ...parsedObj, public_key: toBase64Url(otherKp.publicKey) })),
      "invalid_session",
    );
    expectVaultError(
      () =>
        parseSession(JSON.stringify({ ...parsedObj, secret_key: toBase64Url(otherKp.secretKey) })),
      "invalid_session",
    );

    // Expiry checks
    expect(isSessionExpired(session, BASE_TIME)).toBe(false);
    expect(isSessionExpired(session, sessionExpiresAt(session) - 1)).toBe(false);
    expect(isSessionExpired(session, sessionExpiresAt(session))).toBe(true);

    const expiredAt = sessionExpiresAt(session) + 1000;
    const expiredCmd = createCommandFromSession(session, {
      type: "agent.ping",
      body: {},
      agentPublicKey: agentKeyPair.publicKey,
      counter: 1,
      now: expiredAt,
      registry,
    });
    const trustExpired = createInMemoryTrustContext({
      agentKeyPair,
      trustedAccountKeys: [unlocked.publicKey],
      now: () => expiredAt + 500,
    });
    await expectProtocolError(openCommand(expiredCmd, trustExpired, registry), "session_invalid");

    // Revocation list
    const revList = signRevocation(unlocked, {
      revoked: [session.certificate.id],
      now: BASE_TIME + 5000,
    });
    const verifiedRev = verifyRevocationList(revList, unlocked.publicKey);
    expect(verifiedRev.revoked).toEqual([session.certificate.id]);

    const trustRevoked = createInMemoryTrustContext({
      agentKeyPair,
      trustedAccountKeys: [unlocked.publicKey],
      revokedSessionIds: verifiedRev.revoked,
      now: () => BASE_TIME + 6000,
    });
    const validCmd = createCommandFromSession(session, {
      type: "agent.ping",
      body: {},
      agentPublicKey: agentKeyPair.publicKey,
      counter: 1,
      now: BASE_TIME + 5500,
      registry,
    });
    await expectProtocolError(openCommand(validCmd, trustRevoked, registry), "session_revoked");

    unlocked.lock();
  });

  test("memory counter store is strictly increasing per signer even when clock repeats or rewinds", async () => {
    const store = createMemoryCounterStore();
    const signerA = fingerprint(generateSigningKeyPair().publicKey);
    const signerB = fingerprint(generateSigningKeyPair().publicKey);

    expect(await store.next(signerA, 1000)).toBe(1000);
    expect(await store.next(signerA, 1000)).toBe(1001);
    expect(await store.next(signerA, 500)).toBe(1002);
    expect(await store.next(signerA, 2000)).toBe(2000);

    // Independent per signer
    expect(await store.next(signerB, 500)).toBe(500);
    expect(await store.next(signerB, 500)).toBe(501);
  });

  test("lock zeroes secret key and blocks all further use; withUnlockedVault always locks", async () => {
    const { blob, unlocked } = createVault({
      password: STRONG_PW_1,
      now: BASE_TIME,
      kdf: KDF_FLOOR,
    });

    const secretRef = unlocked.keyPair.secretKey;
    expect(secretRef.some((b) => b !== 0)).toBe(true);

    unlocked.lock();
    // Idempotent second lock
    unlocked.lock();

    // Secret key buffer is zeroed
    expect(secretRef.every((b) => b === 0)).toBe(true);

    // Every access throws locked
    expectVaultError(() => unlocked.account, "locked");
    expectVaultError(() => unlocked.publicKey, "locked");
    expectVaultError(() => unlocked.keyPair, "locked");
    expectVaultError(() => issueSession(unlocked, { duration: "24h", now: BASE_TIME }), "locked");
    expectVaultError(() => signRevocation(unlocked, { revoked: [], now: BASE_TIME }), "locked");

    // withUnlockedVault locks on normal return
    const captured: { handle: typeof unlocked | null; secret: Uint8Array | null } = {
      handle: null,
      secret: null,
    };
    const accountId = await withUnlockedVault(blob, STRONG_PW_1, (u) => {
      captured.handle = u;
      captured.secret = u.keyPair.secretKey;
      return u.account;
    });
    expect(accountId).toBe(blob.account);
    expect(captured.secret?.every((b) => b === 0)).toBe(true);
    expectVaultError(() => captured.handle?.account, "locked");

    // withUnlockedVault locks even when fn throws
    const errCaptured: { handle: typeof unlocked | null; secret: Uint8Array | null } = {
      handle: null,
      secret: null,
    };
    await expect(
      withUnlockedVault(blob, STRONG_PW_1, (u) => {
        errCaptured.handle = u;
        errCaptured.secret = u.keyPair.secretKey;
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    expect(errCaptured.secret?.every((b) => b === 0)).toBe(true);
    expectVaultError(() => errCaptured.handle?.keyPair, "locked");
  });
});

describe("signing levels: session, sudo window, account", () => {
  function setup() {
    const registry = createCoreRegistry();
    const agentKeyPair = generateSigningKeyPair();
    const { unlocked } = createVault({ password: STRONG_PW_1, now: BASE_TIME, kdf: KDF_FLOOR });
    const trust = createInMemoryTrustContext({
      agentKeyPair,
      trustedAccountKeys: [unlocked.publicKey],
      now: () => BASE_TIME + 1000,
    });
    let counter = 0;
    const send = (
      signer: Parameters<typeof createCommandFromSession>[0] | "account",
      type: string,
      body: unknown,
    ) => {
      const params = {
        type,
        body,
        agentPublicKey: agentKeyPair.publicKey,
        counter: ++counter,
        now: BASE_TIME + 500,
        registry,
      };
      const command =
        signer === "account"
          ? createSensitiveCommand(unlocked, params)
          : createCommandFromSession(signer, params);
      return openCommand(command, trust, registry);
    };
    return { unlocked, registry, send };
  }

  test("a plain session runs everything inside the server folder", async () => {
    const { unlocked, send } = setup();
    const session = issueSession(unlocked, { duration: "7d", now: BASE_TIME });
    for (const [type, body] of [
      ["files.delete", { server_id: "srv", path: "a.txt" }],
      [
        "server.install_modpack",
        { server_id: "srv", source: "tegra", modpack_id: "a", version_id: "b" },
      ],
      ["server.backup.create", { server_id: "srv" }],
    ] as const) {
      const opened = await send(session, type, body);
      expect(opened.elevated).toBe(false);
    }
    unlocked.lock();
  });

  test("sudo commands need the elevated session; account commands need the account key", async () => {
    const { unlocked, send } = setup();
    const session = issueSession(unlocked, { duration: "7d", now: BASE_TIME });
    const elevated = issueElevatedSession(unlocked, { now: BASE_TIME });
    expect(isElevatedSession(elevated)).toBe(true);
    expect(isElevatedSession(session)).toBe(false);

    await expectProtocolError(
      send(session, "server.delete", { server_id: "srv" }),
      "elevation_required",
    );
    const opened = await send(elevated, "server.delete", { server_id: "srv" });
    expect(opened.signerType).toBe("session");
    expect(opened.elevated).toBe(true);

    const del = { server_id: "srv", backup_id: "bkp-1" };
    await expectProtocolError(send(elevated, "server.backup.delete", del), "account_key_required");
    await expectProtocolError(send(session, "server.backup.delete", del), "account_key_required");
    expect((await send("account", "server.backup.delete", del)).signerType).toBe("account");
    expect((await send("account", "server.delete", { server_id: "srv" })).signerType).toBe(
      "account",
    );
    unlocked.lock();
  });

  test("the elevated certificate is capped at 1 hour, by the signer and by the agent", async () => {
    const { unlocked, send } = setup();
    expect(() =>
      issueElevatedSession(unlocked, { now: BASE_TIME, validityMs: MAX_ELEVATED_SESSION_MS + 1 }),
    ).toThrow(RangeError);

    // A hand-built certificate over the cap is refused by the agent.
    const long = issueElevatedSession(unlocked, { now: BASE_TIME });
    const forged = {
      ...long,
      certificate: { ...long.certificate, not_after: BASE_TIME + MAX_ELEVATED_SESSION_MS + 1 },
    };
    await expectProtocolError(
      send(forged, "server.delete", { server_id: "srv" }),
      "elevation_invalid",
    );

    // The window closes when the certificate expires.
    const short = issueElevatedSession(unlocked, { now: BASE_TIME - 2000, validityMs: 1000 });
    await expectProtocolError(
      send(short, "server.delete", { server_id: "srv" }),
      "session_invalid",
    );
    unlocked.lock();
  });

  test("stripping or adding the elevated scope breaks the certificate signature", async () => {
    const { unlocked, send } = setup();
    const elevated = issueElevatedSession(unlocked, { now: BASE_TIME });
    const { scope: _scope, ...stripped } = elevated.certificate;
    await expectProtocolError(
      send({ ...elevated, certificate: stripped }, "files.read", { server_id: "srv", path: "a" }),
      "session_invalid",
    );

    // A plain certificate short enough to pass the cap, promoted by hand.
    const plain = generateSigningKeyPair();
    const plainCert = signSessionCertificate({
      sessionPublicKey: plain.publicKey,
      accountKeyPair: unlocked.keyPair,
      notBefore: BASE_TIME,
      notAfter: BASE_TIME + 30 * 60 * 1000,
    });
    const promoted = {
      keyPair: plain,
      certificate: { ...plainCert, scope: "elevated" as const },
    };
    await expectProtocolError(
      send(promoted, "server.delete", { server_id: "srv" }),
      "session_invalid",
    );

    // A long session promoted by hand is over the cap before its signature is even checked.
    const session = issueSession(unlocked, { duration: "24h", now: BASE_TIME });
    const promotedLong = {
      ...session,
      certificate: { ...session.certificate, scope: "elevated" as const },
    };
    await expectProtocolError(
      send(promotedLong, "server.delete", { server_id: "srv" }),
      "elevation_invalid",
    );

    expect(() =>
      signSessionCertificate({
        sessionPublicKey: elevated.keyPair.publicKey,
        accountKeyPair: generateSigningKeyPair(),
        notBefore: BASE_TIME,
        notAfter: BASE_TIME + MAX_ELEVATED_SESSION_MS + 1,
        elevated: true,
      }),
    ).toThrow(RangeError);
    unlocked.lock();
  });
});
