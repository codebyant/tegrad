// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fingerprint, generateSigningKeyPair, ready, toBase64Url } from "../crypto";
import { ProtocolError, signRevocationList } from "../protocol";
import { DEFAULT_LINUX_STATE_DIR, getStatePaths, resolveStateDir } from "./paths";
import {
  addTrustedAccount,
  applyRevocationList,
  clearTrust,
  createFileTrustContext,
  loadConfig,
  loadOrCreateIdentity,
  loadRevocations,
  loadTrust,
  MAX_RECENT_REPLAY_IDS,
  resetTrustState,
  StateError,
  writeFileAtomic,
} from "./state";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "tegrad-state-test-"));
  tempDirs.push(dir);
  return dir;
}

beforeAll(async () => {
  await ready();
});

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe("paths", () => {
  test("resolveStateDir honors TEGRAD_STATE_DIR, linux default, and non-linux home fallback", () => {
    expect(resolveStateDir({ TEGRAD_STATE_DIR: "/custom/dir" }, "linux", "/home/u")).toContain(
      "custom",
    );
    expect(resolveStateDir({}, "linux", "/home/u")).toBe(DEFAULT_LINUX_STATE_DIR);
    expect(resolveStateDir({}, "win32", "C:\\Users\\dev")).toBe(join("C:\\Users\\dev", ".tegrad"));
  });
});

describe("state files", () => {
  test("loadOrCreateIdentity is idempotent and enforces 0600 on POSIX", async () => {
    const dir = makeTempDir();
    const first = await loadOrCreateIdentity(dir);
    const second = await loadOrCreateIdentity(dir);

    expect(toBase64Url(second.publicKey)).toBe(toBase64Url(first.publicKey));
    expect(toBase64Url(second.secretKey)).toBe(toBase64Url(first.secretKey));

    if (process.platform !== "win32") {
      const { identityPath } = getStatePaths(dir);
      expect(statSync(identityPath).mode & 0o777).toBe(0o600);

      chmodSync(identityPath, 0o644);
      await expect(loadOrCreateIdentity(dir)).rejects.toThrow(StateError);
    }
  });

  test("writeFileAtomic leaves existing file intact and removes temp file on simulated write failure", () => {
    const dir = makeTempDir();
    const target = join(dir, "sample.json");
    writeFileAtomic(target, '{"ok":true}\n');

    expect(() =>
      writeFileAtomic(target, '{"ok":false}\n', {
        writeContent() {
          throw new Error("simulated disk failure");
        },
      }),
    ).toThrow("simulated disk failure");

    expect(readFileSync(target, "utf8")).toBe('{"ok":true}\n');
    expect(readdirSync(dir)).toEqual(["sample.json"]);
  });

  test("loadConfig validates presence, JSON, and https requirement", () => {
    const dir = makeTempDir();
    const { configPath } = getStatePaths(dir);

    expect(() => loadConfig(dir)).toThrow(StateError);

    writeFileSync(configPath, "{not-json", "utf8");
    expect(() => loadConfig(dir)).toThrow(StateError);

    writeFileSync(configPath, JSON.stringify({ api_url: "http://api.example.com" }), "utf8");
    expect(() => loadConfig(dir, { env: {} })).toThrow(StateError);
    expect(() => loadConfig(dir, { env: { TEGRAD_ALLOW_INSECURE: "1" } })).toThrow(StateError);

    writeFileSync(configPath, JSON.stringify({ api_url: "http://127.0.0.1:8080" }), "utf8");
    expect(() => loadConfig(dir, { env: {} })).toThrow(StateError);
    expect(loadConfig(dir, { env: { TEGRAD_ALLOW_INSECURE: "1" } }).apiUrl).toBe(
      "http://127.0.0.1:8080/",
    );

    writeFileSync(configPath, JSON.stringify({ api_url: "https://api.tegra.example" }), "utf8");
    expect(loadConfig(dir, { env: {} }).apiUrl).toBe("https://api.tegra.example/");
  });

  test("loadTrust returns empty list when trust.json is missing and loads valid account keys", async () => {
    const dir = makeTempDir();
    expect(await loadTrust(dir)).toEqual([]);

    const account = generateSigningKeyPair();
    const { trustPath } = getStatePaths(dir);
    writeFileSync(
      trustPath,
      JSON.stringify({ v: 1, accounts: [{ public_key: toBase64Url(account.publicKey) }] }),
      "utf8",
    );

    const loaded = await loadTrust(dir);
    expect(loaded.length).toBe(1);
    expect(toBase64Url(loaded[0] ?? new Uint8Array())).toBe(toBase64Url(account.publicKey));
  });
});

describe("persistent replay state", () => {
  test("counter and recent ids survive reload across TrustContext instances", async () => {
    const dir = makeTempDir();
    const agent = await loadOrCreateIdentity(dir);
    const account = generateSigningKeyPair();
    const accountId = fingerprint(account.publicKey);

    const ctx1 = createFileTrustContext({
      stateDir: dir,
      agentKeyPair: agent,
      trustedAccountKeys: [account.publicKey],
    });

    expect(ctx1.isTrustedAccountKey(accountId)).not.toBeNull();
    expect(ctx1.isSessionRevoked("sess_1")).toBe(false);
    ctx1.setRevokedSessionIds(["sess_1"]);
    expect(ctx1.isSessionRevoked("sess_1")).toBe(true);

    expect(ctx1.claimCommand(accountId, "cmd_id_0001", 1)).toBe(true);
    expect(ctx1.claimCommand(accountId, "cmd_id_0002", 5)).toBe(true);

    const ctx2 = createFileTrustContext({
      stateDir: dir,
      agentKeyPair: agent,
      trustedAccountKeys: [account.publicKey],
    });

    // Duplicate ID rejected after reload
    expect(ctx2.claimCommand(accountId, "cmd_id_0001", 6)).toBe(false);
    // Equal or lower counter rejected after reload
    expect(ctx2.claimCommand(accountId, "cmd_id_0003", 5)).toBe(false);
    expect(ctx2.claimCommand(accountId, "cmd_id_0003", 4)).toBe(false);
    // Strictly higher counter with new ID accepted
    expect(ctx2.claimCommand(accountId, "cmd_id_0003", 6)).toBe(true);
  });

  test("caps recent_ids at 4096 and evicts oldest entries", async () => {
    const dir = makeTempDir();
    const agent = await loadOrCreateIdentity(dir);
    const account = generateSigningKeyPair();
    const accountId = fingerprint(account.publicKey);

    // Pre-seed 4096 IDs on disk so we verify the exact 4096 cap without 4096 fsyncs
    const { replayPath } = getStatePaths(dir);
    const initialIds: string[] = [];
    for (let i = 0; i < MAX_RECENT_REPLAY_IDS; i++) {
      initialIds.push(`id_${i}`);
    }
    writeFileAtomic(
      replayPath,
      JSON.stringify({
        v: 1,
        last_counter: { [accountId]: MAX_RECENT_REPLAY_IDS },
        recent_ids: initialIds,
      }),
    );

    const ctx = createFileTrustContext({
      stateDir: dir,
      agentKeyPair: agent,
      trustedAccountKeys: [account.publicKey],
    });

    expect(ctx.claimCommand(accountId, "id_4096", MAX_RECENT_REPLAY_IDS + 1)).toBe(true);
    expect(ctx.claimCommand(accountId, "id_4097", MAX_RECENT_REPLAY_IDS + 2)).toBe(true);

    const persisted = JSON.parse(readFileSync(replayPath, "utf8")) as {
      recent_ids: string[];
      last_counter: Record<string, number>;
    };
    expect(persisted.recent_ids.length).toBe(MAX_RECENT_REPLAY_IDS);
    expect(persisted.recent_ids[0]).toBe("id_2");
    expect(persisted.recent_ids[persisted.recent_ids.length - 1]).toBe("id_4097");
    expect(persisted.last_counter[accountId]).toBe(MAX_RECENT_REPLAY_IDS + 2);
  });
});

describe("trust and revocations persistence", () => {
  test("addTrustedAccount is atomic, idempotent by fingerprint, preserves 0600, and clearTrust removes trust.json", async () => {
    const dir = makeTempDir();
    const account1 = generateSigningKeyPair();
    const account2 = generateSigningKeyPair();
    const { trustPath } = getStatePaths(dir);

    const r1 = await addTrustedAccount(dir, account1.publicKey);
    expect(r1.added).toBe(true);
    expect(r1.accountId).toBe(fingerprint(account1.publicKey));

    // Idempotent duplicate add
    const r1Dup = await addTrustedAccount(dir, account1.publicKey);
    expect(r1Dup.added).toBe(false);
    expect((await loadTrust(dir)).length).toBe(1);

    const r2 = await addTrustedAccount(dir, account2.publicKey);
    expect(r2.added).toBe(true);
    expect((await loadTrust(dir)).length).toBe(2);

    if (process.platform !== "win32") {
      expect(statSync(trustPath).mode & 0o777).toBe(0o600);
    }

    clearTrust(dir);
    expect(existsSync(trustPath)).toBe(false);
    expect(await loadTrust(dir)).toEqual([]);
  });

  test("applyRevocationList validates trust, signature, monotonic issued_at, superset, and persists across reloads", async () => {
    const dir = makeTempDir();
    const agent = await loadOrCreateIdentity(dir);
    const trustedAccount = generateSigningKeyPair();
    const untrustedAccount = generateSigningKeyPair();

    await addTrustedAccount(dir, trustedAccount.publicKey);

    // Untrusted account rejected
    const untrustedList = signRevocationList({
      accountKeyPair: untrustedAccount,
      issuedAt: 1000,
      revoked: ["sess_1"],
    });
    await expect(applyRevocationList(dir, untrustedList)).rejects.toMatchObject({
      code: "untrusted_signer",
    });

    // Invalid signature rejected
    const validList1 = signRevocationList({
      accountKeyPair: trustedAccount,
      issuedAt: 1000,
      revoked: ["sess_1"],
    });
    await expect(
      applyRevocationList(dir, { ...validList1, revoked: ["sess_2"] }),
    ).rejects.toMatchObject({
      code: "bad_signature",
    });

    // Valid list accepted
    const applied1 = await applyRevocationList(dir, validList1);
    expect(applied1).toEqual({
      account: fingerprint(trustedAccount.publicKey),
      count: 1,
    });

    // Equal or older issued_at rejected
    const staleList = signRevocationList({
      accountKeyPair: trustedAccount,
      issuedAt: 1000,
      revoked: ["sess_1", "sess_2"],
    });
    await expect(applyRevocationList(dir, staleList)).rejects.toMatchObject({
      code: "revocation_stale",
    });

    // Non-superset rejected with revocation_not_superset
    const shrinkingList = signRevocationList({
      accountKeyPair: trustedAccount,
      issuedAt: 2000,
      revoked: ["sess_2"],
    });
    try {
      await applyRevocationList(dir, shrinkingList);
      throw new Error("Expected revocation_not_superset");
    } catch (err) {
      expect(err).toBeInstanceOf(ProtocolError);
      expect((err as ProtocolError).code).toBe("revocation_not_superset");
    }

    // Newer superset accepted
    const validList2 = signRevocationList({
      accountKeyPair: trustedAccount,
      issuedAt: 2000,
      revoked: ["sess_1", "sess_2"],
    });
    const applied2 = await applyRevocationList(dir, validList2);
    expect(applied2.count).toBe(2);

    // Reloaded FileTrustContext reflects persisted revocations
    const ctx = createFileTrustContext({
      stateDir: dir,
      agentKeyPair: agent,
      trustedAccountKeys: await loadTrust(dir),
    });
    expect(ctx.isSessionRevoked("sess_1")).toBe(true);
    expect(ctx.isSessionRevoked("sess_2")).toBe(true);
    expect(ctx.isSessionRevoked("sess_3")).toBe(false);

    // Corrupted revocations.json throws StateError
    const { revocationsPath } = getStatePaths(dir);
    writeFileSync(revocationsPath, '{"v":999}', "utf8");
    expect(() => loadRevocations(dir)).toThrow(StateError);
  });

  test("FileTrustContext picks up live trust.json changes and resetTrustState preserves identity", async () => {
    const dir = makeTempDir();
    const agent = await loadOrCreateIdentity(dir);
    const account1 = generateSigningKeyPair();
    const account2 = generateSigningKeyPair();

    await addTrustedAccount(dir, account1.publicKey);
    const ctx = createFileTrustContext({
      stateDir: dir,
      agentKeyPair: agent,
      trustedAccountKeys: [account1.publicKey],
    });
    expect(ctx.isTrustedAccountKey(fingerprint(account1.publicKey))).not.toBeNull();
    expect(ctx.isTrustedAccountKey(fingerprint(account2.publicKey))).toBeNull();

    // Live reset while context is active
    resetTrustState(dir);
    expect(ctx.isTrustedAccountKey(fingerprint(account1.publicKey))).toBeNull();

    // Identity still exists
    const reloadedAgent = await loadOrCreateIdentity(dir);
    expect(fingerprint(reloadedAgent.publicKey)).toBe(fingerprint(agent.publicKey));

    // Live re-pair with account2
    await addTrustedAccount(dir, account2.publicKey);
    expect(ctx.isTrustedAccountKey(fingerprint(account2.publicKey))).not.toBeNull();
  });
});
