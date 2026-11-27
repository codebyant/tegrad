// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createLogger,
  getStatePaths,
  loadConfig,
  loadOrCreateIdentity,
  validateCdnHost,
} from "../agent";
import { openTestEvent } from "../agent/test-events";
import { createAgentRuntime } from "../cli/run";
import { fingerprint, generateSigningKeyPair, ready, toBase64Url } from "../crypto";
import { createZipBuffer } from "../files";
import {
  createCoreRegistry,
  createHelloFrame,
  createSignedCommand,
  PROTOCOL_VERSION,
  ProtocolError,
  STATE_COMMANDS,
  signSessionCertificate,
  type TransportFrame,
} from "../protocol";
import type { FetchLike } from "../server/download";
import { readServerMetadata, type ServerMetadata, writeServerMetadata } from "../server/registry";
import type { BackupHook } from "./backup-hook";
import {
  buildAllowedDownloadHosts,
  downloadVerifiedBuffer,
  downloadVerifiedToFile,
} from "./download";
import { isVersionLoaderLocked } from "./lock";
import { createStateManager } from "./manager";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function sha1Hex(data: Uint8Array): string {
  return createHash("sha1").update(data).digest("hex");
}

function sha256Hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

function sha512Hex(data: Uint8Array): string {
  return createHash("sha512").update(data).digest("hex");
}

function createTestServer(
  serversDir: string,
  serverId: string,
  overrides: Partial<ServerMetadata> = {},
): ServerMetadata {
  const serverDir = join(serversDir, serverId);
  mkdirSync(serverDir, { recursive: true });
  const meta: ServerMetadata = {
    v: 1,
    id: serverId,
    name: "Test Server",
    minecraft_version: "1.21.1",
    loader: "fabric",
    loader_version: "0.16.0",
    memory_mb: 2048,
    jvm_args: [],
    port: 25565,
    created_at: 1_700_000_000_000,
    ...overrides,
  };
  writeServerMetadata(serversDir, meta);
  return meta;
}

function makeMockFetch(routes: Readonly<Record<string, () => Response>>): FetchLike {
  return async (input) => {
    const url = typeof input === "string" ? input : input.toString();
    const handler = routes[url];
    if (!handler) {
      return new Response("Not Found", { status: 404 });
    }
    return handler();
  };
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

describe("metadata backwards compatibility and config cdn_host", () => {
  test("reads legacy v1 tegrad-server.json without mods/origin/origin_sync", () => {
    const serversDir = makeTempDir("tegrad-state-compat-");
    const serverDir = join(serversDir, "legacy-1");
    mkdirSync(serverDir, { recursive: true });
    writeFileSync(
      join(serverDir, "tegrad-server.json"),
      JSON.stringify({
        v: 1,
        id: "legacy-1",
        name: "Legacy",
        minecraft_version: "1.20.4",
        loader: "vanilla",
        loader_version: null,
        memory_mb: 2048,
        jvm_args: [],
        port: 25565,
        created_at: 1_700_000_000_000,
      }),
      "utf8",
    );

    const meta = readServerMetadata(serversDir, "legacy-1");
    expect(meta.mods).toBeUndefined();
    expect(meta.origin).toBeUndefined();
    expect(isVersionLoaderLocked(meta)).toBe(false);

    const mgr = createStateManager({ serversDir });
    const list = mgr.listMods("legacy-1");
    expect(list.mods).toEqual([]);
    expect(list.origin).toBeNull();
    expect(list.version_loader_locked).toBe(false);
  });

  test("loadConfig validates optional cdn_host and tegra_cdn_host", () => {
    const stateDir = makeTempDir("tegrad-state-cfg-");
    const { configPath } = getStatePaths(stateDir);
    writeFileSync(
      configPath,
      JSON.stringify({
        api_url: "https://api.tegra.example",
        cdn_host: "CDN.Tegra.GG",
        tegra_cdn_host: "packs.tegra.gg",
      }),
      "utf8",
    );

    const cfg = loadConfig(stateDir);
    expect(cfg.cdnHost).toBe("cdn.tegra.gg");
    expect(cfg.tegraCdnHost).toBe("packs.tegra.gg");

    expect(() => validateCdnHost("127.0.0.1")).toThrow();
    expect(() => validateCdnHost("localhost")).toThrow();
    expect(() => validateCdnHost("https://cdn.tegra.gg")).toThrow();
    expect(() => validateCdnHost("cdn.tegra.gg:8443")).toThrow();
    expect(() => validateCdnHost("cdn.tegra.gg/path")).toThrow();
  });
});

describe("safe downloads (host allowlist, redirects, size cap, hashes)", () => {
  test("allows default hosts and configured Tegra CDN host, rejects disallowed hosts and http", async () => {
    const payload = new TextEncoder().encode("mod-jar-bytes");
    const allowedHosts = buildAllowedDownloadHosts(["cdn.tegra.gg"]);
    const fetchImpl = makeMockFetch({
      "https://cdn.modrinth.com/data/a/a.jar": () => new Response(payload, { status: 200 }),
      "https://cdn.tegra.gg/packs/p.zip": () => new Response(payload, { status: 200 }),
    });

    const ok1 = await downloadVerifiedBuffer({
      url: "https://cdn.modrinth.com/data/a/a.jar",
      allowedHosts,
      expectedHashes: { sha1: sha1Hex(payload), sha256: sha256Hex(payload) },
      fetchImpl,
    });
    expect(ok1.bytes).toBe(payload.byteLength);

    const ok2 = await downloadVerifiedBuffer({
      url: "https://cdn.tegra.gg/packs/p.zip",
      allowedHosts,
      expectedHashes: { sha512: sha512Hex(payload) },
      fetchImpl,
    });
    expect(ok2.sha512).toBe(sha512Hex(payload));

    await expect(
      downloadVerifiedBuffer({
        url: "http://cdn.modrinth.com/data/a/a.jar",
        allowedHosts,
        fetchImpl,
      }),
    ).rejects.toMatchObject({ code: "download_failed" });

    await expect(
      downloadVerifiedBuffer({
        url: "https://evil.example/data/a/a.jar",
        allowedHosts,
        fetchImpl,
      }),
    ).rejects.toMatchObject({ code: "download_failed" });
  });

  test("follows redirects within allowlist and blocks redirects outside allowlist or to http", async () => {
    const payload = new TextEncoder().encode("redirected-ok");
    const allowedHosts = buildAllowedDownloadHosts();
    const fetchImpl = makeMockFetch({
      "https://cdn.modrinth.com/redir-ok": () =>
        new Response(null, {
          status: 302,
          headers: { location: "https://mediafilez.forgecdn.net/final.jar" },
        }),
      "https://mediafilez.forgecdn.net/final.jar": () => new Response(payload, { status: 200 }),
      "https://cdn.modrinth.com/redir-evil": () =>
        new Response(null, {
          status: 302,
          headers: { location: "https://evil.example/steal.jar" },
        }),
      "https://cdn.modrinth.com/redir-http": () =>
        new Response(null, {
          status: 302,
          headers: { location: "http://cdn.modrinth.com/insecure.jar" },
        }),
      "https://cdn.modrinth.com/loop": () =>
        new Response(null, {
          status: 302,
          headers: { location: "https://cdn.modrinth.com/loop" },
        }),
    });

    const res = await downloadVerifiedBuffer({
      url: "https://cdn.modrinth.com/redir-ok",
      allowedHosts,
      fetchImpl,
    });
    expect(res.bytes).toBe(payload.byteLength);

    await expect(
      downloadVerifiedBuffer({
        url: "https://cdn.modrinth.com/redir-evil",
        allowedHosts,
        fetchImpl,
      }),
    ).rejects.toMatchObject({ code: "download_failed" });

    await expect(
      downloadVerifiedBuffer({
        url: "https://cdn.modrinth.com/redir-http",
        allowedHosts,
        fetchImpl,
      }),
    ).rejects.toMatchObject({ code: "download_failed" });

    await expect(
      downloadVerifiedBuffer({
        url: "https://cdn.modrinth.com/loop",
        allowedHosts,
        maxRedirects: 2,
        fetchImpl,
      }),
    ).rejects.toMatchObject({ code: "download_failed" });
  });

  test("enforces max download size and fails closed on hash mismatch", async () => {
    const payload = new Uint8Array(1024).fill(0x41);
    const allowedHosts = buildAllowedDownloadHosts();
    const fetchImpl = makeMockFetch({
      "https://edge.forgecdn.net/mod.jar": () => new Response(payload, { status: 200 }),
    });

    await expect(
      downloadVerifiedBuffer({
        url: "https://edge.forgecdn.net/mod.jar",
        allowedHosts,
        maxBytes: 512,
        fetchImpl,
      }),
    ).rejects.toMatchObject({ code: "download_failed" });

    await expect(
      downloadVerifiedBuffer({
        url: "https://edge.forgecdn.net/mod.jar",
        allowedHosts,
        expectedHashes: { sha256: "0".repeat(64) },
        fetchImpl,
      }),
    ).rejects.toMatchObject({ code: "hash_mismatch" });
  });
});

describe("streamed downloads to disk", () => {
  test("writes the body to the file, returns its hashes and removes the file on a bad hash", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tegrad-dl-file-"));
    try {
      const body = new Uint8Array(Buffer.from("server-pack-bytes"));
      const sha1 = createHash("sha1").update(body).digest("hex");
      const fetchImpl: FetchLike = async () => new Response(new Uint8Array(body), { status: 200 });
      const allowedHosts = buildAllowedDownloadHosts();

      const ok = await downloadVerifiedToFile({
        url: "https://edge.forgecdn.net/files/1/2/pack.zip",
        destPath: join(dir, "ok.zip"),
        allowedHosts,
        expectedHashes: { sha1 },
        fetchImpl,
      });
      expect(ok.bytes).toBe(body.byteLength);
      expect(ok.sha1).toBe(sha1);
      expect(readFileSync(join(dir, "ok.zip"))).toEqual(Buffer.from(body));

      await expect(
        downloadVerifiedToFile({
          url: "https://edge.forgecdn.net/files/1/2/pack.zip",
          destPath: join(dir, "bad.zip"),
          allowedHosts,
          expectedHashes: { sha1: "0".repeat(40) },
          fetchImpl,
        }),
      ).rejects.toMatchObject({ code: "hash_mismatch" });
      expect(existsSync(join(dir, "bad.zip"))).toBe(false);

      await expect(
        downloadVerifiedToFile({
          url: "https://edge.forgecdn.net/files/1/2/pack.zip",
          destPath: join(dir, "big.zip"),
          allowedHosts,
          maxBytes: 4,
          fetchImpl,
        }),
      ).rejects.toMatchObject({ code: "download_failed" });
      expect(existsSync(join(dir, "big.zip"))).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("StateManager: mods, version/loader lock, origin sync, and server pack deploy", () => {
  test("installs and removes mods safely, rejects bad hashes and path traversal", async () => {
    const serversDir = makeTempDir("tegrad-state-mods-");
    createTestServer(serversDir, "srv-1");
    const modBytes = new TextEncoder().encode("fabric-api-jar");
    const fetchImpl = makeMockFetch({
      "https://cdn.modrinth.com/fabric-api.jar": () => new Response(modBytes, { status: 200 }),
    });

    const mgr = createStateManager({ serversDir, fetchImpl });

    // Wrong hash fails closed and writes nothing
    await expect(
      mgr.installMod({
        server_id: "srv-1",
        file: "fabric-api.jar",
        url: "https://cdn.modrinth.com/fabric-api.jar",
        source: "modrinth",
        sha256: "f".repeat(64),
      }),
    ).rejects.toMatchObject({ code: "hash_mismatch" });
    expect(existsSync(join(serversDir, "srv-1", "mods", "fabric-api.jar"))).toBe(false);

    // Path traversal filename rejected
    await expect(
      mgr.installMod({
        server_id: "srv-1",
        file: "../escape.jar",
        url: "https://cdn.modrinth.com/fabric-api.jar",
        source: "modrinth",
      }),
    ).rejects.toBeInstanceOf(ProtocolError);

    // Valid install succeeds and records user layer
    const installed = await mgr.installMod({
      server_id: "srv-1",
      file: "fabric-api.jar",
      url: "https://cdn.modrinth.com/fabric-api.jar",
      source: "modrinth",
      project_id: "P7dR8mSH",
      version_id: "v1",
      sha1: sha1Hex(modBytes),
      sha256: sha256Hex(modBytes),
    });
    expect(installed.mod.layer).toBe("user");
    expect(readFileSync(join(serversDir, "srv-1", "mods", "fabric-api.jar"))).toEqual(
      Buffer.from(modBytes),
    );

    const listed = mgr.listMods("srv-1");
    expect(listed.mods.length).toBe(1);
    expect(listed.mods[0]?.file).toBe("fabric-api.jar");

    const removed = mgr.removeMod({ server_id: "srv-1", file: "fabric-api.jar" });
    expect(removed.removed).toBe(true);
    expect(removed.tracked_origin_removal).toBe(false);
    expect(existsSync(join(serversDir, "srv-1", "mods", "fabric-api.jar"))).toBe(false);
  });

  test("version/loader lock enforced when linked to modpack and unlocked by server.origin.unlink", () => {
    const serversDir = makeTempDir("tegrad-state-lock-");
    createTestServer(serversDir, "srv-lock", {
      origin: {
        kind: "modpack",
        source: "modrinth",
        modpack_id: "pack-1",
        version_id: "1.0.0",
      },
      mods: [
        {
          file: "origin-mod.jar",
          source: "modrinth",
          project_id: "m1",
          layer: "origin",
        },
      ],
    });

    const mgr = createStateManager({ serversDir });
    expect(mgr.listMods("srv-lock").version_loader_locked).toBe(true);

    expect(() =>
      mgr.updateVersionLoader({
        server_id: "srv-lock",
        minecraft_version: "1.21.4",
      }),
    ).toThrow(ProtocolError);

    try {
      mgr.updateVersionLoader({ server_id: "srv-lock", loader: "neoforge" });
    } catch (err) {
      expect(err).toBeInstanceOf(ProtocolError);
      expect((err as ProtocolError).code).toBe("origin_locked");
    }

    const unlinked = mgr.unlinkOrigin("srv-lock");
    expect(unlinked.origin).toBeNull();
    expect(unlinked.version_loader_locked).toBe(false);

    const metaAfterUnlink = readServerMetadata(serversDir, "srv-lock");
    expect(metaAfterUnlink.origin).toBeNull();
    expect(metaAfterUnlink.mods?.[0]?.layer).toBe("user");

    const updated = mgr.updateVersionLoader({
      server_id: "srv-lock",
      minecraft_version: "1.21.4",
      loader: "neoforge",
      loader_version: "21.4.1",
    });
    expect(updated.minecraft_version).toBe("1.21.4");
    expect(updated.loader).toBe("neoforge");
  });

  test("origin plan & apply enforces plan_id validity, expiry, staleness, backup hook, and preserves user additions/removals", async () => {
    const serversDir = makeTempDir("tegrad-state-sync-");
    const modABytes = new TextEncoder().encode("mod-a-v1");
    const modBNewBytes = new TextEncoder().encode("mod-b-v2");
    const modCBytes = new TextEncoder().encode("mod-c-v1");
    const userModBytes = new TextEncoder().encode("user-extra-mod");
    const cfgBytes = new TextEncoder().encode("difficulty=hard\n");

    createTestServer(serversDir, "srv-sync", {
      origin: {
        kind: "modpack",
        source: "tegra",
        modpack_id: "pack-alpha",
        version_id: "1.0.0",
      },
      mods: [
        {
          file: "mod-a.jar",
          source: "tegra",
          project_id: "mod-a",
          sha1: sha1Hex(modABytes),
          layer: "origin",
        },
        {
          file: "mod-b-v1.jar",
          source: "tegra",
          project_id: "mod-b",
          sha1: sha1Hex(new TextEncoder().encode("mod-b-v1")),
          layer: "origin",
        },
        {
          file: "mod-gone.jar",
          source: "tegra",
          project_id: "mod-gone",
          sha1: sha1Hex(new TextEncoder().encode("gone")),
          layer: "origin",
        },
        {
          file: "user-extra.jar",
          source: "modrinth",
          project_id: "user-extra",
          sha1: sha1Hex(userModBytes),
          layer: "user",
        },
      ],
      origin_sync: {
        excluded_mod_keys: [],
        synced_mod_keys: ["id:mod-a", "id:mod-b", "id:mod-gone"],
        removed_origin_files: [],
        synced_files: [],
        last_synced_at: null,
        last_synced_version_id: "1.0.0",
      },
    });
    mkdirSync(join(serversDir, "srv-sync", "mods"), { recursive: true });
    writeFileSync(join(serversDir, "srv-sync", "mods", "mod-a.jar"), modABytes);
    writeFileSync(join(serversDir, "srv-sync", "mods", "mod-b-v1.jar"), "mod-b-v1");
    writeFileSync(join(serversDir, "srv-sync", "mods", "mod-gone.jar"), "gone");
    writeFileSync(join(serversDir, "srv-sync", "mods", "user-extra.jar"), userModBytes);

    let currentTime = 1_700_000_000_000;
    const backupCalls: string[] = [];
    const backupHook: BackupHook = {
      async beforeChange(serverId: string) {
        backupCalls.push(serverId);
      },
    };

    const fetchImpl = makeMockFetch({
      "https://cdn.modrinth.com/mod-b-v2.jar": () => new Response(modBNewBytes, { status: 200 }),
      "https://cdn.modrinth.com/mod-c.jar": () => new Response(modCBytes, { status: 200 }),
      "https://cdn.modrinth.com/mod-a.jar": () => new Response(modABytes, { status: 200 }),
    });

    const mgr = createStateManager({
      serversDir,
      backupHook,
      fetchImpl,
      planTtlMs: 60_000,
      now: () => currentTime,
    });

    // User removes an origin mod (mod-a.jar); should be tracked so sync won't re-add it by default
    const rmResult = mgr.removeMod({ server_id: "srv-sync", file: "mod-a.jar" });
    expect(rmResult.tracked_origin_removal).toBe(true);

    const planBody = {
      server_id: "srv-sync",
      to_version_id: "2.0.0",
      mods: [
        {
          key: "id:mod-a",
          file: "mod-a.jar",
          project_id: "mod-a",
          sha1: sha1Hex(modABytes),
          url: "https://cdn.modrinth.com/mod-a.jar",
        },
        {
          key: "id:mod-b",
          file: "mod-b-v2.jar",
          project_id: "mod-b",
          version_id: "2.0",
          sha1: sha1Hex(modBNewBytes),
          url: "https://cdn.modrinth.com/mod-b-v2.jar",
        },
        {
          key: "id:mod-c",
          file: "mod-c.jar",
          project_id: "mod-c",
          sha1: sha1Hex(modCBytes),
          url: "https://cdn.modrinth.com/mod-c.jar",
        },
      ],
      files: [
        {
          path: "config/pack.toml",
          sha1: sha1Hex(cfgBytes),
          size_bytes: cfgBytes.byteLength,
          content_base64: Buffer.from(cfgBytes).toString("base64"),
        },
      ],
    };

    const plan = mgr.planOriginSync(planBody);
    expect(plan.changes.mods.find((m) => m.key === "id:mod-a")?.selected_by_default).toBe(false);
    expect(plan.changes.mods.find((m) => m.key === "id:mod-b")?.kind).toBe("updated");
    expect(plan.changes.mods.find((m) => m.key === "id:mod-c")?.kind).toBe("added");
    expect(plan.changes.mods.find((m) => m.key === "id:mod-gone")?.kind).toBe("removed");

    // Unknown plan_id rejected
    await expect(
      mgr.applyOriginSync({ server_id: "srv-sync", plan_id: "nonexistent" }),
    ).rejects.toMatchObject({ code: "plan_not_found" });

    // Expired plan rejected
    const expiringPlan = mgr.planOriginSync(planBody);
    currentTime += 60_001;
    await expect(
      mgr.applyOriginSync({ server_id: "srv-sync", plan_id: expiringPlan.plan_id }),
    ).rejects.toMatchObject({ code: "plan_expired" });

    // Stale plan rejected when server state changes after planning
    const stalePlan = mgr.planOriginSync(planBody);
    writeFileSync(join(serversDir, "srv-sync", "mods", "manual-change.jar"), "changed");
    await expect(
      mgr.applyOriginSync({ server_id: "srv-sync", plan_id: stalePlan.plan_id }),
    ).rejects.toMatchObject({ code: "plan_stale" });
    rmSync(join(serversDir, "srv-sync", "mods", "manual-change.jar"));

    // Path traversal in plan files rejected
    expect(() =>
      mgr.planOriginSync({
        ...planBody,
        files: [{ path: "../outside.txt", sha1: sha1Hex(cfgBytes), size_bytes: 1 }],
      }),
    ).toThrow();

    // Fresh plan applies cleanly and invokes backupHook once
    const freshPlan = mgr.planOriginSync(planBody);
    const applied = await mgr.applyOriginSync({
      server_id: "srv-sync",
      plan_id: freshPlan.plan_id,
    });
    expect(backupCalls).toEqual(["srv-sync"]);
    expect(applied.mods_added).toBe(1);
    expect(applied.mods_updated).toBe(1);
    expect(applied.mods_removed).toBe(1);
    expect(applied.files_written).toBe(1);

    // User mod preserved, mod-a still removed, mod-b updated, mod-c added, mod-gone removed
    expect(existsSync(join(serversDir, "srv-sync", "mods", "user-extra.jar"))).toBe(true);
    expect(existsSync(join(serversDir, "srv-sync", "mods", "mod-a.jar"))).toBe(false);
    expect(existsSync(join(serversDir, "srv-sync", "mods", "mod-b-v1.jar"))).toBe(false);
    expect(existsSync(join(serversDir, "srv-sync", "mods", "mod-b-v2.jar"))).toBe(true);
    expect(existsSync(join(serversDir, "srv-sync", "mods", "mod-c.jar"))).toBe(true);
    expect(existsSync(join(serversDir, "srv-sync", "mods", "mod-gone.jar"))).toBe(false);
    expect(readFileSync(join(serversDir, "srv-sync", "config", "pack.toml"), "utf8")).toBe(
      "difficulty=hard\n",
    );

    // Re-applying consumed plan fails
    await expect(
      mgr.applyOriginSync({ server_id: "srv-sync", plan_id: freshPlan.plan_id }),
    ).rejects.toMatchObject({ code: "plan_not_found" });
  });

  test("deployServerPack verifies hash, invokes backupHook, extracts safely, and rejects zip-slip", async () => {
    const serversDir = makeTempDir("tegrad-state-pack-");
    createTestServer(serversDir, "srv-pack");

    const goodZip = createZipBuffer([
      { name: "mods/pack-mod.jar", data: new TextEncoder().encode("jar-content") },
      { name: "config/server.toml", data: new TextEncoder().encode("ok=true\n") },
    ]);
    const evilZip = createZipBuffer([
      { name: "../escaped.txt", data: new TextEncoder().encode("pwned") },
    ]);

    const backupCalls: string[] = [];
    const backupHook: BackupHook = {
      async beforeChange(serverId: string) {
        backupCalls.push(serverId);
      },
    };

    const fetchImpl = makeMockFetch({
      "https://cdn.tegra.gg/packs/good.zip": () => new Response(goodZip, { status: 200 }),
      "https://cdn.tegra.gg/packs/evil.zip": () => new Response(evilZip, { status: 200 }),
    });

    const mgr = createStateManager({
      serversDir,
      cdnHost: "cdn.tegra.gg",
      backupHook,
      fetchImpl,
    });

    // Wrong hash fails BEFORE backup hook or extraction
    await expect(
      mgr.deployServerPack({
        server_id: "srv-pack",
        url: "https://cdn.tegra.gg/packs/good.zip",
        sha256: "a".repeat(64),
      }),
    ).rejects.toMatchObject({ code: "hash_mismatch" });
    expect(backupCalls).toEqual([]);
    expect(existsSync(join(serversDir, "srv-pack", "mods", "pack-mod.jar"))).toBe(false);

    // Zip slip rejected
    await expect(
      mgr.deployServerPack({
        server_id: "srv-pack",
        url: "https://cdn.tegra.gg/packs/evil.zip",
        sha256: sha256Hex(evilZip),
      }),
    ).rejects.toThrow();
    expect(existsSync(join(serversDir, "escaped.txt"))).toBe(false);

    // Good pack deploys cleanly
    backupCalls.length = 0;
    const res = await mgr.deployServerPack({
      server_id: "srv-pack",
      url: "https://cdn.tegra.gg/packs/good.zip",
      sha256: sha256Hex(goodZip),
      origin: {
        kind: "modpack",
        source: "tegra",
        modpack_id: "official-pack",
        version_id: "1.0.0",
      },
    });
    expect(backupCalls).toEqual(["srv-pack"]);
    expect(res.extracted_files).toEqual(["mods/pack-mod.jar", "config/server.toml"]);
    expect(existsSync(join(serversDir, "srv-pack", "mods", "pack-mod.jar"))).toBe(true);

    const meta = readServerMetadata(serversDir, "srv-pack");
    expect(meta.origin).toEqual({
      kind: "modpack",
      source: "tegra",
      modpack_id: "official-pack",
      version_id: "1.0.0",
    });
    expect(meta.mods?.[0]?.layer).toBe("origin");
  });
});

describe("state commands protocol & runtime wiring", () => {
  test("all STATE_COMMANDS reach handlers through createAgentRuntime and enforce sensitive rules", async () => {
    const stateDir = makeTempDir("tegrad-state-rt-");
    const serversDir = makeTempDir("tegrad-state-rt-srv-");
    const backupsDir = makeTempDir("tegrad-state-rt-bkp-");
    createTestServer(serversDir, "srv-rt");

    const agent = await loadOrCreateIdentity(stateDir);
    const agentId = fingerprint(agent.publicKey);
    const account = generateSigningKeyPair();
    const sessionKey = generateSigningKeyPair();
    const now = Date.now();
    const sessionCert = signSessionCertificate({
      accountKeyPair: account,
      sessionPublicKey: sessionKey.publicKey,
      notBefore: now - 1000,
      notAfter: now + 3_600_000,
    });

    const { configPath, trustPath } = getStatePaths(stateDir);
    writeFileSync(
      configPath,
      JSON.stringify({ api_url: "https://api.tegra.example", tegra_cdn_host: "cdn.tegra.gg" }),
      "utf8",
    );
    writeFileSync(
      trustPath,
      JSON.stringify({ v: 1, accounts: [{ public_key: toBase64Url(account.publicKey) }] }),
      "utf8",
    );

    const modBytes = new TextEncoder().encode("runtime-mod");
    const packZip = createZipBuffer([
      { name: "config/hello.txt", data: new TextEncoder().encode("hi") },
    ]);
    const fetchImpl = makeMockFetch({
      "https://cdn.modrinth.com/m.jar": () => new Response(modBytes, { status: 200 }),
      "https://cdn.tegra.gg/pack.zip": () => new Response(packZip, { status: 200 }),
    });

    const sent: TransportFrame[] = [];
    const runtime = await createAgentRuntime({
      stateDir,
      serversDir,
      backupsDir,
      fetch: fetchImpl,
      logger: createLogger({ level: "error", stdout: () => {}, stderr: () => {} }),
      now: () => now,
      webSocketFactory: () => {
        const socket = {
          readyState: 1,
          onopen: null as (() => void) | null,
          onmessage: null as ((ev: { readonly data: unknown }) => void) | null,
          onclose: null as
            | ((ev: { readonly code?: number; readonly reason?: string }) => void)
            | null,
          onerror: null as ((ev: unknown) => void) | null,
          send(data: string) {
            sent.push(JSON.parse(data) as TransportFrame);
          },
          close() {
            socket.readyState = 3;
          },
        };
        queueMicrotask(() => {
          socket.onopen?.();
          socket.onmessage?.({
            data: JSON.stringify(createHelloFrame({ agent: agentId, serverTime: Date.now() })),
          });
        });
        return socket;
      },
    });
    runtime.start();
    await new Promise((resolve) => setTimeout(resolve, 10));

    const registry = createCoreRegistry();
    let accCounter = 1;
    let sessCounter = 1;

    async function send(type: string, body: unknown, useSession: boolean) {
      const start = sent.length;
      const signed = createSignedCommand(
        {
          type,
          body,
          agentPublicKey: agent.publicKey,
          signer: useSession ? sessionKey : account,
          ...(useSession ? { session: sessionCert } : {}),
          counter: useSession ? sessCounter++ : accCounter++,
          now,
        },
        registry,
      );
      await runtime.queue.enqueue({
        v: PROTOCOL_VERSION,
        kind: "command",
        route: { agent: agentId },
        body: signed,
      });
      const slice = sent.slice(start);
      const ack = slice.find(
        (f): f is Extract<TransportFrame, { kind: "ack" }> => f.kind === "ack",
      );
      const events = slice
        .filter((f): f is Extract<TransportFrame, { kind: "event" }> => f.kind === "event")
        .map((f) => {
          const opened = openTestEvent(f.body, agent.publicKey, account);
          return { type: opened.header.type, body: opened.body };
        });
      return { ack, events };
    }

    const exercised = new Set<string>();
    try {
      // Non-sensitive commands work with session key
      const listRes = await send("server.mods.list", { server_id: "srv-rt" }, true);
      exercised.add("server.mods.list");
      expect(listRes.ack?.body.ok).toBe(true);

      const installRes = await send(
        "server.mods.install",
        {
          server_id: "srv-rt",
          file: "m.jar",
          url: "https://cdn.modrinth.com/m.jar",
          source: "modrinth",
          sha256: sha256Hex(modBytes),
        },
        true,
      );
      exercised.add("server.mods.install");
      expect(installRes.ack?.body.ok).toBe(true);

      const removeRes = await send(
        "server.mods.remove",
        { server_id: "srv-rt", file: "m.jar" },
        true,
      );
      exercised.add("server.mods.remove");
      expect(removeRes.ack?.body.ok).toBe(true);

      const planRes = await send(
        "server.origin.plan",
        {
          server_id: "srv-rt",
          to_version_id: "1.0.0",
          modpack_id: "pack-rt",
          source: "tegra",
          mods: [],
        },
        true,
      );
      exercised.add("server.origin.plan");
      expect(planRes.ack?.body.ok).toBe(true);
      const planId = (planRes.events[0]?.body as { plan_id?: string } | undefined)?.plan_id;
      expect(planId).toBeDefined();
      if (!planId) throw new Error("Missing plan_id");

      // Sensitive: server.origin.apply rejects session key, accepts account key
      const applySession = await send(
        "server.origin.apply",
        { server_id: "srv-rt", plan_id: planId },
        true,
      );
      expect(applySession.ack?.body.ok).toBe(false);
      if (applySession.ack && !applySession.ack.body.ok) {
        expect(applySession.ack.body.code).toBe("sensitive_requires_account_key");
      }

      const applyAccount = await send(
        "server.origin.apply",
        { server_id: "srv-rt", plan_id: planId },
        false,
      );
      exercised.add("server.origin.apply");
      expect(applyAccount.ack?.body.ok).toBe(true);

      // Non-sensitive: server.origin.unlink works with session key
      const unlinkRes = await send("server.origin.unlink", { server_id: "srv-rt" }, true);
      exercised.add("server.origin.unlink");
      expect(unlinkRes.ack?.body.ok).toBe(true);

      // Sensitive: server.deploy.serverpack rejects session key, accepts account key
      const deploySession = await send(
        "server.deploy.serverpack",
        {
          server_id: "srv-rt",
          url: "https://cdn.tegra.gg/pack.zip",
          sha256: sha256Hex(packZip),
        },
        true,
      );
      expect(deploySession.ack?.body.ok).toBe(false);
      if (deploySession.ack && !deploySession.ack.body.ok) {
        expect(deploySession.ack.body.code).toBe("sensitive_requires_account_key");
      }

      const deployAccount = await send(
        "server.deploy.serverpack",
        {
          server_id: "srv-rt",
          url: "https://cdn.tegra.gg/pack.zip",
          sha256: sha256Hex(packZip),
        },
        false,
      );
      exercised.add("server.deploy.serverpack");
      expect(deployAccount.ack?.body.ok).toBe(true);

      // server.world.import reaches its handler; without a stopped server it is refused, never no_handler
      const worldRes = await send(
        "server.world.import",
        {
          server_id: "srv-rt",
          world_name: "world",
          url: "https://cdn.modrinth.com/w.bin",
          sha256: "a".repeat(64),
          key: toBase64Url(new Uint8Array(32)),
        },
        true,
      );
      exercised.add("server.world.import");
      expect(worldRes.ack?.body.ok).toBe(false);
      expect(worldRes.ack?.body.code).not.toBe("no_handler");

      // Verify 100% coverage of STATE_COMMANDS
      expect([...exercised].sort()).toEqual(STATE_COMMANDS.map((c) => c.type).sort());

      // Verify BackupHook wired through createAgentRuntime created before_change backups
      // for both server.origin.apply and server.deploy.serverpack
      const backups = await runtime.backupManager.listBackups({ server_id: "srv-rt" });
      expect(
        backups.backups.filter((b) => b.trigger === "before_change").length,
      ).toBeGreaterThanOrEqual(2);
    } finally {
      await runtime.shutdown(1000);
    }
  });
});

describe("adversarial security checks for state downloads, mods, and server packs", () => {
  test("enforces streaming size cap even when Content-Length is missing or understated", async () => {
    const allowedHosts = buildAllowedDownloadHosts();
    const streamingFetch: FetchLike = async () => {
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new Uint8Array(64).fill(0x41));
          controller.enqueue(new Uint8Array(64).fill(0x42));
          controller.close();
        },
      });
      return new Response(stream, {
        status: 200,
        headers: { "Content-Length": "10" },
      });
    };

    await expect(
      downloadVerifiedBuffer({
        url: "https://cdn.modrinth.com/streamed.jar",
        allowedHosts,
        maxBytes: 100,
        fetchImpl: streamingFetch,
      }),
    ).rejects.toMatchObject({ code: "download_failed" });
  });

  test("rejects redirects with non-standard port, credentials, or URL fragment", async () => {
    const allowedHosts = buildAllowedDownloadHosts();
    const fetchImpl = makeMockFetch({
      "https://cdn.modrinth.com/port": () =>
        new Response(null, {
          status: 302,
          headers: { location: "https://cdn.modrinth.com:8443/mod.jar" },
        }),
      "https://cdn.modrinth.com/creds": () =>
        new Response(null, {
          status: 302,
          headers: { location: "https://user:pass@cdn.modrinth.com/mod.jar" },
        }),
      "https://cdn.modrinth.com/frag": () =>
        new Response(null, {
          status: 302,
          headers: { location: "https://cdn.modrinth.com/mod.jar#section" },
        }),
    });

    for (const url of [
      "https://cdn.modrinth.com/port",
      "https://cdn.modrinth.com/creds",
      "https://cdn.modrinth.com/frag",
    ]) {
      await expect(downloadVerifiedBuffer({ url, allowedHosts, fetchImpl })).rejects.toMatchObject({
        code: "download_failed",
      });
    }
  });

  test("rejects traversal, encoded separators, reserved names, and bidi chars in mod filenames", async () => {
    const serversDir = makeTempDir("tegrad-state-adv-mod-");
    createTestServer(serversDir, "srv-adv");
    const fetchImpl = makeMockFetch({
      "https://cdn.modrinth.com/ok.jar": () => new Response(new Uint8Array([1, 2, 3])),
    });
    const mgr = createStateManager({ serversDir, fetchImpl });

    const maliciousNames = [
      "../escape.jar",
      "sub/mod.jar",
      "sub\\mod.jar",
      "mod\0.jar",
      "CON.jar",
      "mod.jar.",
      "mod.jar ",
      "a:b.jar",
      "..%2fescape.jar",
      ".tmp-upload-x.jar",
      ".runtime",
      "mod\u202Eraj.exe",
    ];

    for (const file of maliciousNames) {
      await expect(
        mgr.installMod({
          server_id: "srv-adv",
          file,
          url: "https://cdn.modrinth.com/ok.jar",
          source: "modrinth",
        }),
      ).rejects.toMatchObject({ code: "invalid_body" });
    }
  });

  test("server.deploy.serverpack refuses archives attempting to overwrite start.sh or tegrad-server.json", async () => {
    const serversDir = makeTempDir("tegrad-state-adv-pack-");
    createTestServer(serversDir, "srv-prot");
    const startShPath = join(serversDir, "srv-prot", "start.sh");
    writeFileSync(startShPath, "#!/bin/sh\nexec java -jar server.jar nogui\n", "utf8");
    const originalMetaJson = readFileSync(
      join(serversDir, "srv-prot", "tegrad-server.json"),
      "utf8",
    );

    const zipWithStartSh = createZipBuffer([
      { name: "start.sh", data: new TextEncoder().encode("#!/bin/sh\nid > /tmp/pwned\n") },
      { name: "config/a.txt", data: new TextEncoder().encode("x") },
    ]);
    const zipWithMetadata = createZipBuffer([
      { name: "tegrad-server.json", data: new TextEncoder().encode('{"tampered":true}') },
    ]);

    const fetchImpl = makeMockFetch({
      "https://cdn.tegra.gg/start.zip": () => new Response(zipWithStartSh, { status: 200 }),
      "https://cdn.tegra.gg/meta.zip": () => new Response(zipWithMetadata, { status: 200 }),
    });

    const mgr = createStateManager({
      serversDir,
      cdnHost: "cdn.tegra.gg",
      fetchImpl,
      backupBeforeChange: false,
    });

    await expect(
      mgr.deployServerPack({
        server_id: "srv-prot",
        url: "https://cdn.tegra.gg/start.zip",
        sha256: sha256Hex(zipWithStartSh),
      }),
    ).rejects.toThrow(/protected path/i);
    expect(readFileSync(startShPath, "utf8")).toBe("#!/bin/sh\nexec java -jar server.jar nogui\n");
    expect(existsSync(join(serversDir, "srv-prot", "config", "a.txt"))).toBe(false);

    await expect(
      mgr.deployServerPack({
        server_id: "srv-prot",
        url: "https://cdn.tegra.gg/meta.zip",
        sha256: sha256Hex(zipWithMetadata),
      }),
    ).rejects.toThrow(/protected path/i);
    expect(readFileSync(join(serversDir, "srv-prot", "tegrad-server.json"), "utf8")).toBe(
      originalMetaJson,
    );
  });

  test("origin apply verifies sha256 on inline content_base64 files and fails closed before backupHook", async () => {
    const serversDir = makeTempDir("tegrad-state-adv-b64-");
    createTestServer(serversDir, "srv-b64");
    const content = new TextEncoder().encode("safe-config=1\n");
    const backupCalls: string[] = [];

    const mgr = createStateManager({
      serversDir,
      backupHook: {
        async beforeChange(id) {
          backupCalls.push(id);
        },
      },
    });

    const plan = mgr.planOriginSync({
      server_id: "srv-b64",
      to_version_id: "2.0.0",
      mods: [],
      files: [
        {
          path: "config/test.cfg",
          sha1: sha1Hex(content),
          sha256: "0".repeat(64),
          size_bytes: content.byteLength,
          content_base64: Buffer.from(content).toString("base64"),
        },
      ],
    });

    await expect(
      mgr.applyOriginSync({ server_id: "srv-b64", plan_id: plan.plan_id }),
    ).rejects.toMatchObject({ code: "hash_mismatch" });
    expect(backupCalls).toEqual([]);
    expect(existsSync(join(serversDir, "srv-b64", "config", "test.cfg"))).toBe(false);
  });
});
