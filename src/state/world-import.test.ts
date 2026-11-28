// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  collectChunks,
  encryptBlobChunks,
  generateSymmetricKey,
  ready,
  toBase64Url,
} from "../crypto";
import { createZipBuffer } from "../files";
import { serverWorldImportBodySchema } from "../protocol";
import type { FetchLike } from "../server/download";
import { type ServerMetadata, writeServerMetadata } from "../server/registry";
import type { BackupHook } from "./backup-hook";
import { createStateManager } from "./manager";

const tempDirs: string[] = [];
const text = (value: string) => new TextEncoder().encode(value);

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

function sha256Hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

function makeServer(): { serversDir: string; serverDir: string } {
  const serversDir = mkdtempSync(join(tmpdir(), "tegrad-world-"));
  tempDirs.push(serversDir);
  const serverDir = join(serversDir, "srv");
  mkdirSync(serverDir, { recursive: true });
  const meta: ServerMetadata = {
    v: 1,
    id: "srv",
    name: "Test",
    minecraft_version: "1.21.1",
    loader: "fabric",
    loader_version: "0.16.0",
    memory_mb: 2048,
    jvm_args: [],
    port: 25565,
    created_at: 1_700_000_000_000,
  };
  writeServerMetadata(serversDir, meta);
  return { serversDir, serverDir };
}

async function sealBlob(plain: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  return collectChunks(encryptBlobChunks(plain, key));
}

function fetchOf(blobs: Record<string, Uint8Array>): FetchLike {
  return async (input) => {
    const blob = blobs[String(input)];
    return blob ? new Response(blob, { status: 200 }) : new Response("nope", { status: 404 });
  };
}

const URL_WORLD = "https://cdn.tegra.gg/blobs/world";

describe("server.world.import", () => {
  const worldZip = createZipBuffer([
    { name: "level.dat", data: text("new-level") },
    { name: "region/r.0.0.mca", data: text("new-region") },
  ]);

  async function setup(options: { active?: boolean } = {}) {
    const { serversDir, serverDir } = makeServer();
    const key = generateSymmetricKey();
    const blob = await sealBlob(worldZip, key);
    const backups: string[] = [];
    const hook: BackupHook = {
      async beforeChange(id) {
        backups.push(id);
      },
    };
    const manager = createStateManager({
      serversDir,
      cdnHost: "cdn.tegra.gg",
      backupHook: hook,
      fetchImpl: fetchOf({ [URL_WORLD]: blob }),
      isServerActive: async () => options.active ?? false,
      serverGroupId: null,
    });
    const body = {
      server_id: "srv",
      world_name: "world",
      url: URL_WORLD,
      sha256: sha256Hex(blob),
      key: toBase64Url(key),
    };
    return { serversDir, serverDir, manager, backups, body, key, blob };
  }

  test("replaces the world after backing up the current one", async () => {
    const { serverDir, manager, backups, body } = await setup();
    mkdirSync(join(serverDir, "world"), { recursive: true });
    writeFileSync(join(serverDir, "world", "level.dat"), "old-level");
    writeFileSync(join(serverDir, "world", "stale.txt"), "stale");

    const result = await manager.importWorld(body);
    expect(result).toEqual({ server_id: "srv", world_name: "world" });
    expect(backups).toEqual(["srv"]);
    expect(readFileSync(join(serverDir, "world", "level.dat"), "utf8")).toBe("new-level");
    expect(readFileSync(join(serverDir, "world", "region", "r.0.0.mca"), "utf8")).toBe(
      "new-region",
    );
    expect(existsSync(join(serverDir, "world", "stale.txt"))).toBe(false);
    // No staging or previous folders are left behind.
    expect(readdirSync(serverDir).filter((n) => n.startsWith(".tegrad-"))).toEqual([]);
  });

  test("creates the world when there was none and unwraps a single top-level folder", async () => {
    const { serversDir, serverDir } = makeServer();
    const key = generateSymmetricKey();
    const zip = createZipBuffer([
      { name: "MyWorld/level.dat", data: text("inner") },
      { name: "MyWorld/data/x.dat", data: text("x") },
    ]);
    const blob = await sealBlob(zip, key);
    const manager = createStateManager({
      serversDir,
      cdnHost: "cdn.tegra.gg",
      fetchImpl: fetchOf({ [URL_WORLD]: blob }),
      isServerActive: async () => false,
      serverGroupId: null,
    });
    await manager.importWorld({
      server_id: "srv",
      world_name: "imported",
      url: URL_WORLD,
      sha256: sha256Hex(blob),
      key: toBase64Url(key),
    });
    expect(readFileSync(join(serverDir, "imported", "level.dat"), "utf8")).toBe("inner");
    expect(readFileSync(join(serverDir, "imported", "data", "x.dat"), "utf8")).toBe("x");
  });

  test("refuses while the server is running or when no liveness check is configured", async () => {
    const running = await setup({ active: true });
    await expect(running.manager.importWorld(running.body)).rejects.toMatchObject({
      code: "server_running",
    });
    expect(running.backups).toEqual([]);

    const { serversDir } = makeServer();
    const unchecked = createStateManager({ serversDir, cdnHost: "cdn.tegra.gg" });
    await expect(unchecked.importWorld(running.body)).rejects.toMatchObject({
      code: "server_running",
    });
  });

  test("a wrong sha256 or key changes nothing and takes no backup", async () => {
    const { serverDir, manager, backups, body } = await setup();
    mkdirSync(join(serverDir, "world"), { recursive: true });
    writeFileSync(join(serverDir, "world", "level.dat"), "old-level");

    await expect(manager.importWorld({ ...body, sha256: "a".repeat(64) })).rejects.toMatchObject({
      code: "hash_mismatch",
    });
    await expect(
      manager.importWorld({ ...body, key: toBase64Url(generateSymmetricKey()) }),
    ).rejects.toMatchObject({ code: "decrypt_failed" });
    expect(backups).toEqual([]);
    expect(readFileSync(join(serverDir, "world", "level.dat"), "utf8")).toBe("old-level");
  });

  test("a tampered blob (hash still matches the tampered bytes) fails authentication", async () => {
    const { serversDir, serverDir } = makeServer();
    const key = generateSymmetricKey();
    const blob = (await sealBlob(worldZip, key)).slice();
    blob[blob.length - 3] = (blob[blob.length - 3] ?? 0) ^ 1;
    const manager = createStateManager({
      serversDir,
      cdnHost: "cdn.tegra.gg",
      fetchImpl: fetchOf({ [URL_WORLD]: blob }),
      isServerActive: async () => false,
      serverGroupId: null,
    });
    await expect(
      manager.importWorld({
        server_id: "srv",
        world_name: "world",
        url: URL_WORLD,
        sha256: sha256Hex(blob),
        key: toBase64Url(key),
      }),
    ).rejects.toMatchObject({ code: "decrypt_failed" });
    expect(existsSync(join(serverDir, "world"))).toBe(false);
  });

  test("a zip-slip archive is rejected and leaves the existing world alone", async () => {
    const { serversDir, serverDir } = makeServer();
    mkdirSync(join(serverDir, "world"), { recursive: true });
    writeFileSync(join(serverDir, "world", "level.dat"), "old-level");
    const key = generateSymmetricKey();
    const blob = await sealBlob(
      createZipBuffer([{ name: "../escaped.txt", data: text("pwned") }]),
      key,
    );
    const manager = createStateManager({
      serversDir,
      cdnHost: "cdn.tegra.gg",
      fetchImpl: fetchOf({ [URL_WORLD]: blob }),
      isServerActive: async () => false,
      serverGroupId: null,
    });
    await expect(
      manager.importWorld({
        server_id: "srv",
        world_name: "world",
        url: URL_WORLD,
        sha256: sha256Hex(blob),
        key: toBase64Url(key),
      }),
    ).rejects.toThrow();
    expect(existsSync(join(serversDir, "escaped.txt"))).toBe(false);
    expect(readFileSync(join(serverDir, "world", "level.dat"), "utf8")).toBe("old-level");
    expect(readdirSync(serverDir).filter((n) => n.startsWith(".tegrad-"))).toEqual([]);
  });

  test("a download host outside the allow list is refused", async () => {
    const { manager, body } = await setup();
    await expect(
      manager.importWorld({ ...body, url: "https://evil.example/blobs/world" }),
    ).rejects.toMatchObject({ code: "download_failed" });
  });

  test("world_name cannot escape the server or hit reserved folders", () => {
    const base = {
      server_id: "srv",
      url: URL_WORLD,
      sha256: "a".repeat(64),
      key: toBase64Url(generateSymmetricKey()),
    };
    for (const bad of [
      "../x",
      "a/b",
      "..",
      ".hidden",
      "mods",
      "Config",
      "logs",
      "",
      "a b",
      "x".repeat(65),
    ]) {
      expect(serverWorldImportBodySchema.safeParse({ ...base, world_name: bad }).success).toBe(
        false,
      );
    }
    for (const good of ["world", "My_World-2", "world_nether", "a.b"]) {
      expect(serverWorldImportBodySchema.safeParse({ ...base, world_name: good }).success).toBe(
        true,
      );
    }
    expect(
      serverWorldImportBodySchema.safeParse({ ...base, world_name: "w", key: "short" }).success,
    ).toBe(false);
  });
});

describe("server.deploy.serverpack with an encrypted blob", () => {
  test("decrypts with key and extracts; a wrong key fails before the backup hook", async () => {
    const { serversDir, serverDir } = makeServer();
    const key = generateSymmetricKey();
    const zip = createZipBuffer([{ name: "config/a.toml", data: text("a=1\n") }]);
    const blob = await sealBlob(zip, key);
    const url = "https://cdn.tegra.gg/packs/enc.zip";
    const calls: string[] = [];
    const manager = createStateManager({
      serversDir,
      cdnHost: "cdn.tegra.gg",
      backupHook: {
        async beforeChange(id) {
          calls.push(id);
        },
      },
      fetchImpl: fetchOf({ [url]: blob }),
      serverGroupId: null,
    });

    await expect(
      manager.deployServerPack({
        server_id: "srv",
        url,
        sha256: sha256Hex(blob),
        key: toBase64Url(generateSymmetricKey()),
      }),
    ).rejects.toMatchObject({ code: "decrypt_failed" });
    expect(calls).toEqual([]);

    const result = await manager.deployServerPack({
      server_id: "srv",
      url,
      sha256: sha256Hex(blob),
      key: toBase64Url(key),
    });
    expect(result.extracted_files).toEqual(["config/a.toml"]);
    expect(readFileSync(join(serverDir, "config", "a.toml"), "utf8")).toBe("a=1\n");
    expect(calls).toEqual(["srv"]);
  });

  test("without key the blob is treated as a plain zip, as before", async () => {
    const { serversDir, serverDir } = makeServer();
    const zip = createZipBuffer([{ name: "config/b.toml", data: text("b=1\n") }]);
    const url = "https://cdn.tegra.gg/packs/plain.zip";
    const manager = createStateManager({
      serversDir,
      cdnHost: "cdn.tegra.gg",
      fetchImpl: fetchOf({ [url]: zip }),
      serverGroupId: null,
    });
    await manager.deployServerPack({ server_id: "srv", url, sha256: sha256Hex(zip) });
    expect(readFileSync(join(serverDir, "config", "b.toml"), "utf8")).toBe("b=1\n");
  });
});
