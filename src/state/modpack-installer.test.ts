// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createAgentApiClient,
  createCommandQueue,
  createLogger,
  type TransportCommandFrame,
} from "../agent";
import { openTestEvent } from "../agent/test-events";
import { fingerprint, generateSigningKeyPair, ready } from "../crypto";
import { createZipBuffer, findServerPackRoot } from "../files";
import {
  createCoreRegistry,
  createInMemoryTrustContext,
  createSignedCommand,
  PROTOCOL_VERSION,
  ProtocolError,
  type ServerInstallModpackAcceptedEvent,
  type ServerInstallModpackProgressEvent,
  type ServerInstallModpackResultEvent,
  type ServerInstallModpackStatusResult,
  serverInstallModpackProgressEventSchema,
  serverInstallModpackResultEventSchema,
  signRoleGrant,
  signSessionCertificate,
  type TransportFrame,
} from "../protocol";
import type { FetchLike } from "../server/download";
import { readServerMetadata, type ServerMetadata, writeServerMetadata } from "../server/registry";
import {
  assertRuntimeMatches,
  createModpackInstaller,
  registerModpackHandlers,
} from "./modpack-installer";

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
  writeFileSync(join(serverDir, "start.sh"), "#!/bin/sh\necho original\n", "utf8");
  const meta: ServerMetadata = {
    v: 1,
    id: serverId,
    name: "Modpack Server",
    minecraft_version: "1.21.1",
    loader: "fabric",
    loader_version: "0.16.5",
    memory_mb: 4096,
    jvm_args: [],
    port: 25565,
    created_at: 1_700_000_000_000,
    ...overrides,
  };
  writeServerMetadata(serversDir, meta);
  return meta;
}

function makeMockFetch(
  routes: Readonly<Record<string, () => Response | Promise<Response>>>,
): FetchLike {
  return async (input) => {
    const url = typeof input === "string" ? input : input.toString();
    const handler = routes[url];
    if (!handler) {
      return new Response("Not Found", { status: 404 });
    }
    return await handler();
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

beforeAll(async () => {
  await ready();
});

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir !== undefined) {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe("Background server.install_modpack", () => {
  test("happy path with official server pack: downloads, verifies hash, preserves protected files, records origin", async () => {
    const root = makeTempDir("tegrad-mpi-sp-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    createTestServer(serversDir, "smp");

    const modJar = new Uint8Array(Buffer.from("official-server-mod"));
    const packZip = createZipBuffer([
      { name: "mods/lithium.jar", data: modJar },
      { name: "config/lithium.properties", data: new Uint8Array(Buffer.from("enabled=true\n")) },
    ]);
    const packSha256 = sha256Hex(packZip);

    const progressEvents: ServerInstallModpackProgressEvent[] = [];
    const resultEvents: ServerInstallModpackResultEvent[] = [];

    const installer = createModpackInstaller({
      stateDir,
      serversDir,
      isServerActive: async () => false,
      fetchImpl: makeMockFetch({
        "https://edge.forgecdn.net/files/1/2/serverpack.zip": () =>
          new Response(new Uint8Array(packZip), { status: 200 }),
      }),
      resolveModpack: async () => ({
        server_pack: {
          url: "https://edge.forgecdn.net/files/1/2/serverpack.zip",
          sha256: packSha256,
          name: "serverpack.zip",
          size: packZip.byteLength,
        },
        files: [],
        minecraft_version: "1.21.1",
        loader: "fabric",
        loader_version: "0.16.5",
      }),
      onProgress: (ev) => progressEvents.push(serverInstallModpackProgressEventSchema.parse(ev)),
      onResult: (ev) => resultEvents.push(serverInstallModpackResultEventSchema.parse(ev)),
    });

    const accepted = await installer.startInstall({
      server_id: "smp",
      source: "curseforge",
      modpack_id: "555",
      version_id: "999",
      modpack_name: "Better MC",
      version_label: "v42",
    });
    expect(accepted.server_id).toBe("smp");
    expect(accepted.job_id.startsWith("mpi-")).toBe(true);

    await installer.waitForActiveJobs();

    expect(resultEvents).toHaveLength(1);
    expect(resultEvents[0]).toEqual({
      job_id: accepted.job_id,
      server_id: "smp",
      ok: true,
      installed: 1,
      skipped: [],
    });
    expect(progressEvents.map((e) => e.phase)).toContain("resolving");
    expect(progressEvents.map((e) => e.phase)).toContain("downloading");
    expect(progressEvents.map((e) => e.phase)).toContain("extracting");
    expect(progressEvents.map((e) => e.phase)).toContain("finalizing");

    expect(readFileSync(join(serversDir, "smp", "mods", "lithium.jar"))).toEqual(
      Buffer.from(modJar),
    );
    expect(readFileSync(join(serversDir, "smp", "config", "lithium.properties"), "utf8")).toBe(
      "enabled=true\n",
    );
    expect(readFileSync(join(serversDir, "smp", "start.sh"), "utf8")).toBe(
      "#!/bin/sh\necho original\n",
    );

    const meta = readServerMetadata(serversDir, "smp");
    expect(meta.origin).toEqual({
      kind: "modpack",
      source: "curseforge",
      modpack_id: "555",
      version_id: "999",
      modpack_name: "Better MC",
    });
    expect(meta.mods).toHaveLength(1);
    expect(meta.mods?.[0]?.file).toBe("lithium.jar");
    expect(meta.mods?.[0]?.layer).toBe("origin");

    const status = installer.getStatus("smp");
    expect(status.job?.status).toBe("completed");
    expect(status.job?.installed).toBe(1);
  });

  test("happy path with mod list: filters client-only mods, keeps unknown env, applies server overrides only", async () => {
    const root = makeTempDir("tegrad-mpi-mods-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    createTestServer(serversDir, "smp");

    const serverMod = new Uint8Array(Buffer.from("server-mod-bytes"));
    const unknownEnvMod = new Uint8Array(Buffer.from("unknown-env-mod-bytes"));
    const overridesZip = createZipBuffer([
      { name: "overrides/config/common.toml", data: new Uint8Array(Buffer.from("base=1\n")) },
      { name: "overrides/config/shared.toml", data: new Uint8Array(Buffer.from("from=base\n")) },
      {
        name: "server-overrides/config/shared.toml",
        data: new Uint8Array(Buffer.from("from=server\n")),
      },
      { name: "client-overrides/options.txt", data: new Uint8Array(Buffer.from("fov:100\n")) },
      { name: "overrides/start.sh", data: new Uint8Array(Buffer.from("rm -rf /\n")) },
      { name: "overrides/tegrad-server.json", data: new Uint8Array(Buffer.from("{}\n")) },
    ]);

    const fetchedUrls: string[] = [];
    const resultEvents: ServerInstallModpackResultEvent[] = [];

    const installer = createModpackInstaller({
      stateDir,
      serversDir,
      isServerActive: async () => false,
      fetchImpl: makeMockFetch({
        "https://edge.forgecdn.net/files/10/1/server-mod.jar": () => {
          fetchedUrls.push("server-mod");
          return new Response(new Uint8Array(serverMod), { status: 200 });
        },
        "https://edge.forgecdn.net/files/10/2/unknown-mod.jar": () => {
          fetchedUrls.push("unknown-mod");
          return new Response(new Uint8Array(unknownEnvMod), { status: 200 });
        },
        "https://edge.forgecdn.net/files/10/3/client-only.jar": () => {
          fetchedUrls.push("client-only");
          return new Response(new Uint8Array(Buffer.from("nope")), { status: 200 });
        },
        "https://edge.forgecdn.net/files/10/99/pack.zip": () =>
          new Response(new Uint8Array(overridesZip), { status: 200 }),
      }),
      resolveModpack: async () => ({
        files: [
          {
            name: "server-mod.jar",
            url: "https://edge.forgecdn.net/files/10/1/server-mod.jar",
            sha1: sha1Hex(serverMod),
            environment: { client: "required", server: "required" },
            project_id: "101",
            version_id: "201",
          },
          {
            name: "unknown-mod.jar",
            url: "https://edge.forgecdn.net/files/10/2/unknown-mod.jar",
            sha1: sha1Hex(unknownEnvMod),
            environment: { client: "unknown", server: "unknown" },
            project_id: "102",
            version_id: "202",
          },
          {
            name: "client-only.jar",
            url: "https://edge.forgecdn.net/files/10/3/client-only.jar",
            environment: { client: "required", server: "unsupported" },
            project_id: "103",
            version_id: "203",
          },
        ],
        overrides: {
          url: "https://edge.forgecdn.net/files/10/99/pack.zip",
          sha1: sha1Hex(overridesZip),
          prefix: "overrides",
          format: "zip",
        },
        minecraft_version: "1.21.1",
        loader: "fabric",
      }),
      onResult: (ev) => resultEvents.push(ev),
    });

    await installer.startInstall({
      server_id: "smp",
      source: "curseforge",
      modpack_id: "444",
      version_id: "888",
      modpack_name: "Pack With Mods",
    });
    await installer.waitForActiveJobs();

    expect(resultEvents[0]).toMatchObject({ ok: true, installed: 2, skipped: [] });
    expect(fetchedUrls.sort()).toEqual(["server-mod", "unknown-mod"]);
    expect(existsSync(join(serversDir, "smp", "mods", "client-only.jar"))).toBe(false);
    expect(existsSync(join(serversDir, "smp", "options.txt"))).toBe(false);
    expect(readFileSync(join(serversDir, "smp", "config", "common.toml"), "utf8")).toBe("base=1\n");
    expect(readFileSync(join(serversDir, "smp", "config", "shared.toml"), "utf8")).toBe(
      "from=server\n",
    );
    expect(readFileSync(join(serversDir, "smp", "start.sh"), "utf8")).toBe(
      "#!/bin/sh\necho original\n",
    );
  });

  test("happy path with Modrinth .mrpack: reads modrinth.index.json and installs mods + overrides", async () => {
    const root = makeTempDir("tegrad-mpi-mrpack-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    createTestServer(serversDir, "smp");

    const modBytes = new Uint8Array(Buffer.from("fabric-api-jar"));
    const indexJson = JSON.stringify({
      formatVersion: 1,
      game: "minecraft",
      files: [
        {
          path: "mods/fabric-api.jar",
          hashes: { sha1: sha1Hex(modBytes), sha512: sha512Hex(modBytes) },
          env: { client: "required", server: "required" },
          downloads: ["https://cdn.modrinth.com/data/P7dR8mSH/versions/1/fabric-api.jar"],
          fileSize: modBytes.byteLength,
        },
        {
          path: "mods/iris.jar",
          hashes: { sha1: sha1Hex(new Uint8Array(Buffer.from("iris"))) },
          env: { client: "required", server: "unsupported" },
          downloads: ["https://cdn.modrinth.com/data/YL57xq9U/versions/1/iris.jar"],
        },
      ],
      dependencies: { minecraft: "1.21.1", "fabric-loader": "0.16.5" },
    });
    const mrpackZip = createZipBuffer([
      { name: "modrinth.index.json", data: new Uint8Array(Buffer.from(indexJson)) },
      { name: "overrides/config/fabric.json", data: new Uint8Array(Buffer.from('{"ok":true}')) },
    ]);

    const resultEvents: ServerInstallModpackResultEvent[] = [];
    const installer = createModpackInstaller({
      stateDir,
      serversDir,
      isServerActive: async () => false,
      fetchImpl: makeMockFetch({
        "https://cdn.modrinth.com/data/pack/versions/1/pack.mrpack": () =>
          new Response(new Uint8Array(mrpackZip), { status: 200 }),
        "https://cdn.modrinth.com/data/P7dR8mSH/versions/1/fabric-api.jar": () =>
          new Response(new Uint8Array(modBytes), { status: 200 }),
      }),
      resolveModpack: async () => ({
        files: [],
        overrides: {
          url: "https://cdn.modrinth.com/data/pack/versions/1/pack.mrpack",
          sha1: sha1Hex(mrpackZip),
          format: "mrpack",
        },
        minecraft_version: "1.21.1",
        loader: "fabric",
      }),
      onResult: (ev) => resultEvents.push(ev),
    });

    await installer.startInstall({
      server_id: "smp",
      source: "modrinth",
      modpack_id: "sop",
      version_id: "v1",
    });
    await installer.waitForActiveJobs();

    expect(resultEvents[0]).toMatchObject({ ok: true, installed: 1, skipped: [] });
    expect(existsSync(join(serversDir, "smp", "mods", "fabric-api.jar"))).toBe(true);
    expect(existsSync(join(serversDir, "smp", "mods", "iris.jar"))).toBe(false);
    expect(readFileSync(join(serversDir, "smp", "config", "fabric.json"), "utf8")).toBe(
      '{"ok":true}',
    );
  });

  test("disallowed host and blocked files become skipped with reasons while valid mods install", async () => {
    const root = makeTempDir("tegrad-mpi-skip-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    createTestServer(serversDir, "smp");

    const okMod = new Uint8Array(Buffer.from("valid-mod"));
    const resultEvents: ServerInstallModpackResultEvent[] = [];

    const installer = createModpackInstaller({
      stateDir,
      serversDir,
      isServerActive: async () => false,
      fetchImpl: makeMockFetch({
        "https://cdn.modrinth.com/ok.jar": () =>
          new Response(new Uint8Array(okMod), { status: 200 }),
      }),
      resolveModpack: async () => ({
        files: [
          {
            name: "ok.jar",
            url: "https://cdn.modrinth.com/ok.jar",
            sha256: sha256Hex(okMod),
          },
          {
            name: "evil-host.jar",
            url: "https://evil.example.org/evil-host.jar",
          },
          {
            name: "restricted.jar",
            blocked: true,
            blocked_reason: "distribution_disabled",
          },
        ],
        minecraft_version: "1.21.1",
        loader: "fabric",
      }),
      onResult: (ev) => resultEvents.push(ev),
    });

    await installer.startInstall({
      server_id: "smp",
      source: "curseforge",
      modpack_id: "123",
      version_id: "456",
    });
    await installer.waitForActiveJobs();

    expect(resultEvents[0]?.ok).toBe(true);
    expect(resultEvents[0]?.installed).toBe(1);
    expect(resultEvents[0]?.skipped).toEqual([
      { name: "evil-host.jar", reason: "host_not_allowed" },
      { name: "restricted.jar", reason: "distribution_disabled" },
    ]);
  });

  test("a file with the wrong hash is skipped and the rest of the pack still installs", async () => {
    const root = makeTempDir("tegrad-mpi-hash-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    createTestServer(serversDir, "smp");

    const firstMod = new Uint8Array(Buffer.from("first-mod"));
    const corruptMod = new Uint8Array(Buffer.from("corrupted-bytes"));
    const resultEvents: ServerInstallModpackResultEvent[] = [];

    const installer = createModpackInstaller({
      stateDir,
      serversDir,
      concurrency: 1,
      isServerActive: async () => false,
      fetchImpl: makeMockFetch({
        "https://cdn.modrinth.com/a.jar": () =>
          new Response(new Uint8Array(firstMod), { status: 200 }),
        "https://cdn.modrinth.com/b.jar": () =>
          new Response(new Uint8Array(corruptMod), { status: 200 }),
      }),
      resolveModpack: async () => ({
        files: [
          { name: "a.jar", url: "https://cdn.modrinth.com/a.jar", sha256: sha256Hex(firstMod) },
          { name: "b.jar", url: "https://cdn.modrinth.com/b.jar", sha256: "0".repeat(64) },
        ],
        minecraft_version: "1.21.1",
        loader: "fabric",
      }),
      onResult: (ev) => resultEvents.push(ev),
    });

    await installer.startInstall({
      server_id: "smp",
      source: "modrinth",
      modpack_id: "p1",
      version_id: "v1",
    });
    await installer.waitForActiveJobs();

    expect(resultEvents[0]).toMatchObject({ ok: true, installed: 1 });
    expect(resultEvents[0]?.skipped).toEqual([{ name: "b.jar", reason: "hash_mismatch" }]);
    expect(existsSync(join(serversDir, "smp", "mods", "a.jar"))).toBe(true);
    expect(existsSync(join(serversDir, "smp", "mods", "b.jar"))).toBe(false);
    const meta = readServerMetadata(serversDir, "smp");
    expect(meta.origin?.kind).toBe("modpack");
    expect(meta.mods?.map((m) => m.file)).toEqual(["a.jar"]);
  });

  test("files listed without a link are taken from the pack archive instead of being reported", async () => {
    const root = makeTempDir("tegrad-mpi-archive-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    createTestServer(serversDir, "smp");

    const mod = new Uint8Array(Buffer.from("mod-ok"));
    const archive = createZipBuffer([
      { name: "config/example-common.toml", data: new Uint8Array(Buffer.from("a=1")) },
      { name: "shaderpacks/pretty.zip", data: new Uint8Array(Buffer.from("x")) },
    ]);
    const resultEvents: ServerInstallModpackResultEvent[] = [];
    const installer = createModpackInstaller({
      stateDir,
      serversDir,
      isServerActive: async () => false,
      fetchImpl: makeMockFetch({
        "https://cdn.modrinth.com/mod.jar": () =>
          new Response(new Uint8Array(mod), { status: 200 }),
        "https://cdn2.seijin.com.br/pack.zip": () =>
          new Response(new Uint8Array(archive), { status: 200 }),
      }),
      resolveModpack: async () => ({
        files: [
          { name: "mod.jar", url: "https://cdn.modrinth.com/mod.jar", sha256: sha256Hex(mod) },
          { name: "example-common.toml", path: "config/example-common.toml" },
        ],
        overrides: { url: "https://cdn2.seijin.com.br/pack.zip", prefix: ".", format: "zip" },
        minecraft_version: "1.21.1",
        loader: "fabric",
      }),
      onResult: (ev) => resultEvents.push(ev),
    });

    await installer.startInstall({
      server_id: "smp",
      source: "tegra",
      modpack_id: "p",
      version_id: "v",
    });
    await installer.waitForActiveJobs();

    expect(resultEvents[0]).toMatchObject({ ok: true, installed: 1, skipped: [] });
    expect(readFileSync(join(serversDir, "smp", "config", "example-common.toml"), "utf8")).toBe(
      "a=1",
    );
  });

  test("server pack zipped inside a folder with its own start script installs and keeps the agent's script", async () => {
    const root = makeTempDir("tegrad-mpi-nested-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    createTestServer(serversDir, "smp");

    const packZip = createZipBuffer([
      { name: "Pack-Server/mods/create.jar", data: new Uint8Array(Buffer.from("create")) },
      { name: "Pack-Server/config/create.toml", data: new Uint8Array(Buffer.from("a=1")) },
      {
        name: "Pack-Server/start.sh",
        data: new Uint8Array(Buffer.from("#!/bin/sh" + String.fromCharCode(10) + "echo pack")),
      },
    ]);
    const resultEvents: ServerInstallModpackResultEvent[] = [];
    const installer = createModpackInstaller({
      stateDir,
      serversDir,
      isServerActive: async () => false,
      fetchImpl: makeMockFetch({
        "https://edge.forgecdn.net/files/3/4/pack.zip": () =>
          new Response(new Uint8Array(packZip), { status: 200 }),
      }),
      resolveModpack: async () => ({
        server_pack: {
          url: "https://edge.forgecdn.net/files/3/4/pack.zip",
          sha256: sha256Hex(packZip),
          name: "pack.zip",
        },
        files: [],
        minecraft_version: "1.21.1",
        loader: "fabric",
      }),
      onResult: (ev) => resultEvents.push(ev),
    });

    await installer.startInstall({
      server_id: "smp",
      source: "curseforge",
      modpack_id: "1",
      version_id: "2",
    });
    await installer.waitForActiveJobs();

    expect(resultEvents[0]).toMatchObject({ ok: true, installed: 1 });
    expect(existsSync(join(serversDir, "smp", "mods", "create.jar"))).toBe(true);
    expect(readFileSync(join(serversDir, "smp", "config", "create.toml"), "utf8")).toBe("a=1");
    expect(readFileSync(join(serversDir, "smp", "start.sh"), "utf8")).toContain("echo original");
    expect(existsSync(join(serversDir, "smp", "Pack-Server"))).toBe(false);
    expect(existsSync(join(stateDir, "modpack-installs", "smp.serverpack.zip"))).toBe(false);
  });

  test("server pack root is the archive root unless every entry sits in one folder", () => {
    expect(findServerPackRoot(["mods/a.jar", "start.sh"])).toBe("");
    expect(findServerPackRoot(["Pack/mods/a.jar", "Pack/config/b.toml"])).toBe("Pack");
    expect(findServerPackRoot(["A/x", "B/y"])).toBe("");
    expect(findServerPackRoot(["config/a.toml"])).toBe("");
  });

  test("refuses a pack built for another Minecraft version or loader before downloading anything", async () => {
    const root = makeTempDir("tegrad-mpi-runtime-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    createTestServer(serversDir, "smp");

    let downloads = 0;
    const resultEvents: ServerInstallModpackResultEvent[] = [];
    const installer = createModpackInstaller({
      stateDir,
      serversDir,
      isServerActive: async () => false,
      fetchImpl: async () => {
        downloads += 1;
        return new Response(new Uint8Array(Buffer.from("mod")), { status: 200 });
      },
      resolveModpack: async () => ({
        files: [{ name: "a.jar", url: "https://cdn.modrinth.com/a.jar" }],
        minecraft_version: "1.20.1",
        loader: "forge",
      }),
      onResult: (ev) => resultEvents.push(ev),
    });

    await installer.startInstall({
      server_id: "smp",
      source: "curseforge",
      modpack_id: "p1",
      version_id: "v1",
    });
    await installer.waitForActiveJobs();

    expect(resultEvents[0]).toMatchObject({
      ok: false,
      installed: 0,
      error_code: "runtime_mismatch",
    });
    expect(downloads).toBe(0);
    expect(existsSync(join(serversDir, "smp", "mods", "a.jar"))).toBe(false);
    expect(readServerMetadata(serversDir, "smp").origin).toBeUndefined();
  });

  test("runtime check accepts a pack that names no version or a vanilla loader", () => {
    const meta = { minecraft_version: "1.21.1", loader: "fabric" } as const;
    expect(() =>
      assertRuntimeMatches(meta, { minecraft_version: "1.21.1", loader: "Fabric" }),
    ).not.toThrow();
    expect(() =>
      assertRuntimeMatches(meta, { minecraft_version: "", loader: "vanilla" }),
    ).not.toThrow();
    expect(() =>
      assertRuntimeMatches(meta, { minecraft_version: "1.21.1", loader: "neoforge" }),
    ).toThrow(ProtocolError);
    expect(() =>
      assertRuntimeMatches(meta, { minecraft_version: "1.20.1", loader: "fabric" }),
    ).toThrow(ProtocolError);
  });

  test("resumes after restart, only downloading remaining files without re-resolving API", async () => {
    const root = makeTempDir("tegrad-mpi-resume-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    createTestServer(serversDir, "smp");

    const mod1 = new Uint8Array(Buffer.from("mod-one"));
    const mod2 = new Uint8Array(Buffer.from("mod-two"));
    const mod2Started = deferred<void>();
    const mod2Hold = deferred<Response>();

    let resolveCalls = 0;
    const mod1Downloads: number[] = [];

    const installer1 = createModpackInstaller({
      stateDir,
      serversDir,
      concurrency: 1,
      isServerActive: async () => false,
      fetchImpl: makeMockFetch({
        "https://cdn.modrinth.com/mod1.jar": () => {
          mod1Downloads.push(1);
          return new Response(new Uint8Array(mod1), { status: 200 });
        },
        "https://cdn.modrinth.com/mod2.jar": async () => {
          mod2Started.resolve();
          return await mod2Hold.promise;
        },
      }),
      resolveModpack: async () => {
        resolveCalls++;
        return {
          files: [
            { name: "mod1.jar", url: "https://cdn.modrinth.com/mod1.jar", sha256: sha256Hex(mod1) },
            { name: "mod2.jar", url: "https://cdn.modrinth.com/mod2.jar", sha256: sha256Hex(mod2) },
          ],
          minecraft_version: "1.21.1",
          loader: "fabric",
        };
      },
    });

    await installer1.startInstall({
      server_id: "smp",
      source: "modrinth",
      modpack_id: "pack",
      version_id: "v1",
    });
    await mod2Started.promise;

    // Simulate abrupt shutdown while mod2 is in flight.
    mod2Hold.reject(new Error("aborted"));
    await installer1.close();

    expect(existsSync(join(serversDir, "smp", "mods", "mod1.jar"))).toBe(true);
    expect(mod1Downloads).toHaveLength(1);
    expect(resolveCalls).toBe(1);

    const results2: ServerInstallModpackResultEvent[] = [];
    const installer2 = createModpackInstaller({
      stateDir,
      serversDir,
      concurrency: 1,
      isServerActive: async () => false,
      fetchImpl: makeMockFetch({
        "https://cdn.modrinth.com/mod1.jar": () => {
          mod1Downloads.push(2);
          return new Response(new Uint8Array(mod1), { status: 200 });
        },
        "https://cdn.modrinth.com/mod2.jar": () =>
          new Response(new Uint8Array(mod2), { status: 200 }),
      }),
      resolveModpack: async () => {
        resolveCalls++;
        throw new Error("Should not re-resolve API after resume");
      },
      onResult: (ev) => results2.push(ev),
    });

    installer2.start();
    await installer2.waitForActiveJobs();

    expect(resolveCalls).toBe(1);
    expect(mod1Downloads).toHaveLength(1);
    expect(results2[0]).toMatchObject({ ok: true, installed: 2, skipped: [] });
    expect(existsSync(join(serversDir, "smp", "mods", "mod2.jar"))).toBe(true);
  });

  test("rejects second concurrent request with install_in_progress and rejects running server with server_running", async () => {
    const root = makeTempDir("tegrad-mpi-guards-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    createTestServer(serversDir, "smp");
    createTestServer(serversDir, "active-srv");

    const gate = deferred<void>();
    const installer = createModpackInstaller({
      stateDir,
      serversDir,
      isServerActive: async (id) => id === "active-srv",
      resolveModpack: async () => {
        await gate.promise;
        return { files: [], minecraft_version: "1.21.1", loader: "fabric" };
      },
    });

    // Running server refused
    await expect(
      installer.startInstall({
        server_id: "active-srv",
        source: "tegra",
        modpack_id: "p",
        version_id: "v",
      }),
    ).rejects.toMatchObject({ code: "server_running" });

    // Start first job and hold resolving
    await installer.startInstall({
      server_id: "smp",
      source: "tegra",
      modpack_id: "p",
      version_id: "v",
    });

    // Second request for same server refused
    await expect(
      installer.startInstall({
        server_id: "smp",
        source: "tegra",
        modpack_id: "p",
        version_id: "v",
      }),
    ).rejects.toMatchObject({ code: "install_in_progress" });

    gate.resolve();
    await installer.waitForActiveJobs();
  });

  test("refuses path traversal in overrides, reports it and keeps the installed mods", async () => {
    const root = makeTempDir("tegrad-mpi-zipslip-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    createTestServer(serversDir, "smp");

    const mod = new Uint8Array(Buffer.from("mod-ok"));
    const evilZip = createZipBuffer([
      { name: "overrides/../../etc/passwd", data: new Uint8Array(Buffer.from("pwned")) },
    ]);

    const resultEvents: ServerInstallModpackResultEvent[] = [];
    const installer = createModpackInstaller({
      stateDir,
      serversDir,
      isServerActive: async () => false,
      fetchImpl: makeMockFetch({
        "https://cdn.modrinth.com/mod.jar": () =>
          new Response(new Uint8Array(mod), { status: 200 }),
        "https://cdn.modrinth.com/evil.zip": () =>
          new Response(new Uint8Array(evilZip), { status: 200 }),
      }),
      resolveModpack: async () => ({
        files: [
          { name: "mod.jar", url: "https://cdn.modrinth.com/mod.jar", sha256: sha256Hex(mod) },
        ],
        overrides: {
          url: "https://cdn.modrinth.com/evil.zip",
          sha256: sha256Hex(evilZip),
          format: "zip",
        },
        minecraft_version: "1.21.1",
        loader: "fabric",
      }),
      onResult: (ev) => resultEvents.push(ev),
    });

    await installer.startInstall({
      server_id: "smp",
      source: "curseforge",
      modpack_id: "1",
      version_id: "2",
    });
    await installer.waitForActiveJobs();

    expect(resultEvents[0]).toMatchObject({ ok: true, installed: 1 });
    expect(resultEvents[0]?.skipped).toEqual([{ name: "overrides", reason: "pack_unavailable" }]);
    expect(existsSync(join(serversDir, "smp", "mods", "mod.jar"))).toBe(true);
    expect(existsSync(join(root, "etc", "passwd"))).toBe(false);
  });

  test("enforces editor role and account key sensitivity on CommandQueue and supports status + cancel", async () => {
    const root = makeTempDir("tegrad-mpi-queue-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    createTestServer(serversDir, "smp");

    const agent = generateSigningKeyPair();
    const owner = generateSigningKeyPair();
    const viewer = generateSigningKeyPair();
    const session = generateSigningKeyPair();
    const nowMs = 1_700_000_000_000;

    const ownerCert = signSessionCertificate({
      sessionPublicKey: session.publicKey,
      accountKeyPair: owner,
      notBefore: nowMs - 1000,
      notAfter: nowMs + 3_600_000,
    });

    const viewerGrant = signRoleGrant({
      granter: owner,
      accountPublicKey: viewer.publicKey,
      agent: fingerprint(agent.publicKey),
      role: "viewer",
      servers: "*",
      issuedAt: nowMs - 1000,
      expiresAt: nowMs + 3_600_000,
    });

    const registry = createCoreRegistry();
    const trust = createInMemoryTrustContext({
      agentKeyPair: agent,
      trustedAccountKeys: [owner.publicKey],
      now: () => nowMs,
    });

    const frames: TransportFrame[] = [];
    const queue = createCommandQueue({
      trust,
      registry,
      sendFrame: (f) => frames.push(f),
      logger: createLogger({ level: "error", stdout: () => {}, stderr: () => {} }),
    });

    const holdResolve = deferred<void>();
    const installer = createModpackInstaller({
      stateDir,
      serversDir,
      now: () => nowMs,
      isServerActive: async () => false,
      resolveModpack: async (_req, signal) => {
        await new Promise<void>((resolve, reject) => {
          if (signal?.aborted) {
            reject(new ProtocolError("cancelled", "aborted"));
            return;
          }
          signal?.addEventListener(
            "abort",
            () => reject(new ProtocolError("cancelled", "aborted")),
            {
              once: true,
            },
          );
          void holdResolve.promise.then(resolve);
        });
        return { files: [], minecraft_version: "1.21.1", loader: "fabric" };
      },
      onProgress: (ev) => {
        queue.publish("server.modpack", "server.install_modpack.progress", ev, {
          serverId: ev.server_id,
        });
      },
      onResult: (ev) => {
        queue.publish("server.modpack", "server.install_modpack.result", ev, {
          serverId: ev.server_id,
        });
      },
    });
    registerModpackHandlers(queue, installer);

    let counter = 1;
    const sendCmd = async (
      type: string,
      body: unknown,
      opts: { signer: typeof owner; session?: typeof ownerCert; replyTo?: typeof owner.publicKey },
    ) => {
      const signed = createSignedCommand(
        {
          type,
          body,
          agentPublicKey: agent.publicKey,
          signer: opts.signer,
          ...(opts.session !== undefined ? { session: opts.session } : {}),
          ...(opts.replyTo !== undefined ? { replyTo: opts.replyTo } : {}),
          counter: counter++,
          now: nowMs,
        },
        registry,
      );
      const frame: TransportCommandFrame = {
        v: PROTOCOL_VERSION,
        kind: "command",
        route: { agent: fingerprint(agent.publicKey) },
        body: signed,
      };
      await queue.enqueue(frame);
      return frames.filter((f) => f.kind === "ack").at(-1);
    };

    // Grant viewer role via signed role grant
    const grantAck = await sendCmd(
      "agent.members.set",
      { grant: viewerGrant },
      { signer: owner, replyTo: session.publicKey },
    );
    expect(grantAck?.kind === "ack" && grantAck.body.ok).toBe(true);

    // 1. Viewer denied
    const viewerAck = await sendCmd(
      "server.install_modpack",
      { server_id: "smp", source: "tegra", modpack_id: "a", version_id: "b" },
      { signer: viewer },
    );
    expect(viewerAck?.kind === "ack" && viewerAck.body.ok === false && viewerAck.body.code).toBe(
      "insufficient_role",
    );

    // 2. Session key (without account key) denied for sensitive command
    const sessionAck = await sendCmd(
      "server.install_modpack",
      { server_id: "smp", source: "tegra", modpack_id: "a", version_id: "b" },
      { signer: session, session: ownerCert, replyTo: session.publicKey },
    );
    expect(sessionAck?.kind === "ack" && sessionAck.body.ok === false && sessionAck.body.code).toBe(
      "sensitive_requires_account_key",
    );

    // Subscribe via session to receive pubsub events
    await sendCmd(
      "agent.subscribe",
      { topics: ["server.modpack"] },
      { signer: session, session: ownerCert, replyTo: session.publicKey },
    );

    // 3. Owner account key accepted immediately
    const ownerAck = await sendCmd(
      "server.install_modpack",
      { server_id: "smp", source: "tegra", modpack_id: "a", version_id: "b" },
      { signer: owner, replyTo: session.publicKey },
    );
    expect(ownerAck?.kind === "ack" && ownerAck.body.ok).toBe(true);

    const acceptedEvent = frames
      .filter((f): f is Extract<TransportFrame, { kind: "event" }> => f.kind === "event")
      .map((f) => openTestEvent(f.body, agent.publicKey, session))
      .find((e) => e.header.type === "server.install_modpack.accepted");
    expect(acceptedEvent).toBeDefined();
    const acceptedBody = acceptedEvent?.body as ServerInstallModpackAcceptedEvent;
    expect(acceptedBody.server_id).toBe("smp");

    // 4. Status query while running
    await sendCmd(
      "server.install_modpack.status",
      { server_id: "smp" },
      { signer: session, session: ownerCert, replyTo: session.publicKey },
    );
    const statusEvent = frames
      .filter((f): f is Extract<TransportFrame, { kind: "event" }> => f.kind === "event")
      .map((f) => openTestEvent(f.body, agent.publicKey, session))
      .filter((e) => e.header.type === "server.install_modpack.status.result")
      .at(-1)?.body as ServerInstallModpackStatusResult;
    expect(statusEvent.job?.status).toBe("running");

    // 5. Cancel command aborts running job and emits cancelled result
    await sendCmd(
      "server.install_modpack.cancel",
      { server_id: "smp", job_id: acceptedBody.job_id },
      { signer: session, session: ownerCert, replyTo: session.publicKey },
    );
    await installer.waitForActiveJobs();

    const resultEvent = frames
      .filter((f): f is Extract<TransportFrame, { kind: "event" }> => f.kind === "event")
      .map((f) => openTestEvent(f.body, agent.publicKey, session))
      .find((e) => e.header.type === "server.install_modpack.result")?.body as
      | ServerInstallModpackResultEvent
      | undefined;
    expect(resultEvent).toEqual({
      job_id: acceptedBody.job_id,
      server_id: "smp",
      ok: false,
      installed: 0,
      skipped: [],
      error_code: "cancelled",
    });

    // Also verify createAgentApiClient.resolveModpack integration against local Bun server
    const server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: async (req) => {
        const url = new URL(req.url);
        if (req.method === "POST" && url.pathname === "/v1/agents/self/modpacks/resolve") {
          return new Response(
            JSON.stringify({
              files: [{ name: "a.jar", url: "https://cdn.modrinth.com/a.jar" }],
              minecraft_version: "1.21.1",
              loader: "fabric",
            }),
            { status: 200 },
          );
        }
        return new Response("not found", { status: 404 });
      },
    });
    try {
      const apiClient = createAgentApiClient({
        apiUrl: `http://127.0.0.1:${server.port}`,
        agentKeyPair: agent,
        allowInsecure: true,
        now: () => nowMs,
      });
      const resolved = await apiClient.resolveModpack({
        source: "modrinth",
        modpack_id: "p1",
        version_id: "v1",
      });
      expect(resolved.minecraft_version).toBe("1.21.1");
      expect(resolved.files).toHaveLength(1);
    } finally {
      void server.stop(true);
    }
  });
});
