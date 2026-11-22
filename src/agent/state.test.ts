// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import {
  chmodSync,
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
import { DEFAULT_LINUX_STATE_DIR, getStatePaths, resolveStateDir } from "./paths";
import {
  createFileTrustContext,
  loadConfig,
  loadOrCreateIdentity,
  loadTrust,
  MAX_RECENT_REPLAY_IDS,
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
