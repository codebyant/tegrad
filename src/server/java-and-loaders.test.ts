// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ProtocolError, type ProtocolErrorCode } from "../protocol";
import {
  ensureJavaRuntime,
  type FetchLike,
  installServerLoader,
  type RunFixedLike,
  selectJavaMajor,
} from "./index";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

function sha256Hex(data: Uint8Array | string): string {
  return createHash("sha256").update(data).digest("hex");
}

function sha1Hex(data: Uint8Array | string): string {
  return createHash("sha1").update(data).digest("hex");
}

async function expectProtocolError(
  promise: Promise<unknown>,
  code: ProtocolErrorCode,
): Promise<void> {
  try {
    await promise;
    throw new Error(`Expected ProtocolError(${code}), but succeeded`);
  } catch (err) {
    expect(err).toBeInstanceOf(ProtocolError);
    expect((err as ProtocolError).code).toBe(code);
  }
}

describe("selectJavaMajor", () => {
  test("maps Minecraft versions to the required Java major version", () => {
    expect(selectJavaMajor("1.7.10")).toBe(8);
    expect(selectJavaMajor("1.8.9")).toBe(8);
    expect(selectJavaMajor("1.12.2")).toBe(8);
    expect(selectJavaMajor("1.16.5")).toBe(8);
    expect(selectJavaMajor("1.17")).toBe(16);
    expect(selectJavaMajor("1.17.1")).toBe(16);
    expect(selectJavaMajor("1.18.2")).toBe(17);
    expect(selectJavaMajor("1.19.4")).toBe(17);
    expect(selectJavaMajor("1.20.4")).toBe(17);
    expect(selectJavaMajor("1.20.5")).toBe(21);
    expect(selectJavaMajor("1.20.6")).toBe(21);
    expect(selectJavaMajor("1.21.4")).toBe(21);
    expect(selectJavaMajor("26.1")).toBe(21);

    // Snapshots
    expect(selectJavaMajor("20w45a")).toBe(8);
    expect(selectJavaMajor("21w19a")).toBe(16);
    expect(selectJavaMajor("21w37a")).toBe(17);
    expect(selectJavaMajor("24w14a")).toBe(21);
  });

  test("rejects invalid Minecraft version formats", () => {
    expect(() => selectJavaMajor("not-a-version")).toThrow(ProtocolError);
  });
});

describe("ensureJavaRuntime", () => {
  test("verifies SHA-256 across allowed redirect hops, extracts via tar, and reuses cached runtime", async () => {
    const serversDir = makeTempDir("tegrad-java-test-");
    const archiveBytes = new TextEncoder().encode("fake-tar-gz-bytes");
    const goodHash = sha256Hex(archiveBytes);

    let fetchCount = 0;
    const fetchImpl: FetchLike = async (input) => {
      fetchCount++;
      const url = String(input);
      if (url.startsWith("https://api.adoptium.net/v3/assets/latest/21/hotspot")) {
        return new Response(
          JSON.stringify([
            {
              binary: {
                package: {
                  link: "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21/jre.tar.gz",
                  checksum: goodHash,
                  size: archiveBytes.byteLength,
                },
              },
            },
          ]),
          { status: 200 },
        );
      }
      if (url.startsWith("https://github.com/")) {
        return new Response(null, {
          status: 302,
          headers: {
            location: "https://objects.githubusercontent.com/temurin/jre21.tar.gz",
          },
        });
      }
      if (url === "https://objects.githubusercontent.com/temurin/jre21.tar.gz") {
        return new Response(archiveBytes, { status: 200 });
      }
      return new Response("not found", { status: 404 });
    };

    const tarCalls: { cmd: string; args: readonly string[] }[] = [];
    const runFixedImpl: RunFixedLike = async (cmd, args) => {
      tarCalls.push({ cmd, args });
      const extractDir = args[3];
      if (!extractDir) {
        return { code: 1, stdout: "", stderr: "missing dir", timedOut: false, truncated: false };
      }
      const binDir = join(extractDir, "jdk-21.0.5-jre", "bin");
      mkdirSync(binDir, { recursive: true });
      writeFileSync(join(binDir, "java"), "#!/bin/sh\n");
      return { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
    };

    const result = await ensureJavaRuntime({
      serversDir,
      minecraftVersion: "1.21.4",
      platform: "linux",
      fetchImpl,
      runFixedImpl,
    });

    expect(result.major).toBe(21);
    expect(existsSync(result.javaBin)).toBe(true);
    expect(tarCalls).toHaveLength(1);
    expect(tarCalls[0]?.cmd).toBe("tar");
    expect(tarCalls[0]?.args[0]).toBe("-xzf");

    // Second call uses cached runtime without fetching again
    const prevFetchCount = fetchCount;
    const cached = await ensureJavaRuntime({
      serversDir,
      minecraftVersion: "1.21.4",
      platform: "linux",
      fetchImpl,
      runFixedImpl,
    });
    expect(cached.javaBin).toBe(result.javaBin);
    expect(fetchCount).toBe(prevFetchCount);
  });

  test("deletes temp file and refuses extraction on SHA-256 mismatch", async () => {
    const serversDir = makeTempDir("tegrad-java-badhash-");
    let tarCalled = false;

    const fetchImpl: FetchLike = async (input) => {
      const url = String(input);
      if (url.startsWith("https://api.adoptium.net/")) {
        return new Response(
          JSON.stringify([
            {
              binary: {
                package: {
                  link: "https://objects.githubusercontent.com/temurin/jre21.tar.gz",
                  checksum: "a".repeat(64),
                },
              },
            },
          ]),
          { status: 200 },
        );
      }
      return new Response(new TextEncoder().encode("tampered-bytes"), { status: 200 });
    };

    const runFixedImpl: RunFixedLike = async () => {
      tarCalled = true;
      return { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
    };

    await expectProtocolError(
      ensureJavaRuntime({
        serversDir,
        minecraftVersion: "1.21.4",
        platform: "linux",
        fetchImpl,
        runFixedImpl,
      }),
      "hash_mismatch",
    );

    expect(tarCalled).toBe(false);
    const runtimeRoot = join(serversDir, ".runtime", "java");
    if (existsSync(runtimeRoot)) {
      expect(readdirSync(runtimeRoot)).toEqual([]);
    }
  });

  test("rejects http:// URLs and redirects to disallowed hosts", async () => {
    const serversDir = makeTempDir("tegrad-java-host-");

    const httpFetch: FetchLike = async () =>
      new Response(
        JSON.stringify([
          {
            binary: {
              package: {
                link: "http://api.adoptium.net/insecure.tar.gz",
                checksum: "a".repeat(64),
              },
            },
          },
        ]),
        { status: 200 },
      );

    await expectProtocolError(
      ensureJavaRuntime({
        serversDir,
        minecraftVersion: "1.21.4",
        platform: "linux",
        fetchImpl: httpFetch,
      }),
      "download_failed",
    );

    const evilRedirectFetch: FetchLike = async (input) => {
      const url = String(input);
      if (url.startsWith("https://api.adoptium.net/")) {
        return new Response(
          JSON.stringify([
            {
              binary: {
                package: {
                  link: "https://github.com/adoptium/jre.tar.gz",
                  checksum: "a".repeat(64),
                },
              },
            },
          ]),
          { status: 200 },
        );
      }
      return new Response(null, {
        status: 302,
        headers: { location: "https://evil.example.com/jre.tar.gz" },
      });
    };

    await expectProtocolError(
      ensureJavaRuntime({
        serversDir,
        minecraftVersion: "1.21.4",
        platform: "linux",
        fetchImpl: evilRedirectFetch,
      }),
      "download_failed",
    );
  });
});

describe("installServerLoader", () => {
  test("Vanilla verifies SHA-1 and rejects mismatched hash or disallowed host", async () => {
    const serverDir = makeTempDir("tegrad-vanilla-");
    const jarBytes = new TextEncoder().encode("PK-vanilla-server-jar");
    const goodSha1 = sha1Hex(jarBytes);

    const fetchImpl: FetchLike = async (input) => {
      const url = String(input);
      if (url === "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json") {
        return new Response(
          JSON.stringify({
            versions: [
              {
                id: "1.21.4",
                url: "https://piston-meta.mojang.com/v1/packages/abc/1.21.4.json",
              },
            ],
          }),
          { status: 200 },
        );
      }
      if (url === "https://piston-meta.mojang.com/v1/packages/abc/1.21.4.json") {
        return new Response(
          JSON.stringify({
            downloads: {
              server: {
                sha1: goodSha1,
                size: jarBytes.byteLength,
                url: "https://piston-data.mojang.com/v1/objects/server.jar",
              },
            },
          }),
          { status: 200 },
        );
      }
      if (url === "https://piston-data.mojang.com/v1/objects/server.jar") {
        return new Response(jarBytes, { status: 200 });
      }
      return new Response("not found", { status: 404 });
    };

    const result = await installServerLoader({
      serverDir,
      minecraftVersion: "1.21.4",
      loader: "vanilla",
      javaBin: "/usr/bin/java",
      fetchImpl,
    });

    expect(result.loader).toBe("vanilla");
    expect(result.launchTarget).toEqual({ kind: "jar", jar_relative_path: "server.jar" });
    expect(existsSync(join(serverDir, "server.jar"))).toBe(true);

    // Unknown MC version rejected without building arbitrary URL
    await expectProtocolError(
      installServerLoader({
        serverDir: makeTempDir("tegrad-vanilla-unknown-"),
        minecraftVersion: "../evil",
        loader: "vanilla",
        javaBin: "/usr/bin/java",
        fetchImpl,
      }),
      "download_failed",
    );

    // Tampered JAR fails with hash_mismatch and leaves no server.jar
    const badDir = makeTempDir("tegrad-vanilla-tampered-");
    const badFetch: FetchLike = async (input) => {
      const url = String(input);
      if (url === "https://piston-data.mojang.com/v1/objects/server.jar") {
        return new Response(new TextEncoder().encode("corrupted-jar"), { status: 200 });
      }
      return fetchImpl(input);
    };
    await expectProtocolError(
      installServerLoader({
        serverDir: badDir,
        minecraftVersion: "1.21.4",
        loader: "vanilla",
        javaBin: "/usr/bin/java",
        fetchImpl: badFetch,
      }),
      "hash_mismatch",
    );
    expect(existsSync(join(badDir, "server.jar"))).toBe(false);
    expect(readdirSync(badDir)).toEqual([]);
  });

  test("Fabric validates metadata, checks Maven SHA-256, runs installer, and cleans temp jar", async () => {
    const serverDir = makeTempDir("tegrad-fabric-");
    const installerBytes = new TextEncoder().encode("fabric-installer-jar");
    const installerSha256 = sha256Hex(installerBytes);
    const installerUrl =
      "https://maven.fabricmc.net/net/fabricmc/fabric-installer/1.0.1/fabric-installer-1.0.1.jar";

    const fetchImpl: FetchLike = async (input) => {
      const url = String(input);
      if (url === "https://meta.fabricmc.net/v2/versions/game") {
        return new Response(JSON.stringify([{ version: "1.21.4", stable: true }]), { status: 200 });
      }
      if (url === "https://meta.fabricmc.net/v2/versions/loader") {
        return new Response(JSON.stringify([{ version: "0.16.9", stable: true }]), { status: 200 });
      }
      if (url === "https://meta.fabricmc.net/v2/versions/installer") {
        return new Response(
          JSON.stringify([{ version: "1.0.1", url: installerUrl, stable: true }]),
          { status: 200 },
        );
      }
      if (url === `${installerUrl}.sha256`) {
        return new Response(`${installerSha256}\n`, { status: 200 });
      }
      if (url === installerUrl) {
        return new Response(installerBytes, { status: 200 });
      }
      return new Response("not found", { status: 404 });
    };

    const execCalls: { cmd: string; args: readonly string[] }[] = [];
    const runFixedImpl: RunFixedLike = async (cmd, args) => {
      execCalls.push({ cmd, args });
      writeFileSync(join(serverDir, "fabric-server-launch.jar"), "launch");
      return { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
    };

    const result = await installServerLoader({
      serverDir,
      minecraftVersion: "1.21.4",
      loader: "fabric",
      javaBin: "/opt/java/bin/java",
      fetchImpl,
      runFixedImpl,
    });

    expect(result.loaderVersion).toBe("0.16.9");
    expect(result.launchTarget).toEqual({
      kind: "jar",
      jar_relative_path: "fabric-server-launch.jar",
    });
    expect(execCalls).toHaveLength(1);
    expect(execCalls[0]?.cmd).toBe("/opt/java/bin/java");
    expect(execCalls[0]?.args).toContain("0.16.9");
    // Temp installer jar was deleted
    expect(readdirSync(serverDir)).toEqual(["fabric-server-launch.jar"]);
  });

  test("Forge and NeoForge verify Maven checksums, run installer, and produce unix_args.txt target", async () => {
    const forgeDir = makeTempDir("tegrad-forge-");
    const forgeInstallerBytes = new TextEncoder().encode("forge-installer");
    const forgeSha256 = sha256Hex(forgeInstallerBytes);
    const forgeUrl =
      "https://maven.minecraftforge.net/net/minecraftforge/forge/1.20.1-47.2.0/forge-1.20.1-47.2.0-installer.jar";

    const forgeFetch: FetchLike = async (input) => {
      const url = String(input);
      if (
        url === "https://files.minecraftforge.net/net/minecraftforge/forge/promotions_slim.json"
      ) {
        return new Response(JSON.stringify({ promos: { "1.20.1-recommended": "47.2.0" } }), {
          status: 200,
        });
      }
      if (url === `${forgeUrl}.sha256`) {
        return new Response(forgeSha256, { status: 200 });
      }
      if (url === forgeUrl) {
        return new Response(forgeInstallerBytes, { status: 200 });
      }
      return new Response("not found", { status: 404 });
    };

    const forgeRun: RunFixedLike = async (_cmd, _args) => {
      const unixArgsDir = join(
        forgeDir,
        "libraries",
        "net",
        "minecraftforge",
        "forge",
        "1.20.1-47.2.0",
      );
      mkdirSync(unixArgsDir, { recursive: true });
      writeFileSync(join(unixArgsDir, "unix_args.txt"), "-cp server.jar\n");
      return { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
    };

    const forgeResult = await installServerLoader({
      serverDir: forgeDir,
      minecraftVersion: "1.20.1",
      loader: "forge",
      javaBin: "/opt/java/bin/java",
      fetchImpl: forgeFetch,
      runFixedImpl: forgeRun,
    });

    expect(forgeResult.loaderVersion).toBe("47.2.0");
    expect(forgeResult.launchTarget).toEqual({
      kind: "args_file",
      args_file_relative_path: "libraries/net/minecraftforge/forge/1.20.1-47.2.0/unix_args.txt",
    });

    const neoDir = makeTempDir("tegrad-neoforge-");
    const neoInstallerBytes = new TextEncoder().encode("neoforge-installer");
    const neoSha1 = sha1Hex(neoInstallerBytes);
    const neoUrl =
      "https://maven.neoforged.net/releases/net/neoforged/neoforge/21.1.72/neoforge-21.1.72-installer.jar";

    const neoFetch: FetchLike = async (input) => {
      const url = String(input);
      if (
        url === "https://maven.neoforged.net/api/maven/versions/releases/net/neoforged/neoforge"
      ) {
        return new Response(JSON.stringify({ versions: ["21.1.70", "21.1.72"] }), { status: 200 });
      }
      if (url === `${neoUrl}.sha256`) {
        return new Response("not found", { status: 404 });
      }
      if (url === `${neoUrl}.sha1`) {
        return new Response(neoSha1, { status: 200 });
      }
      if (url === neoUrl) {
        return new Response(neoInstallerBytes, { status: 200 });
      }
      return new Response("not found", { status: 404 });
    };

    const neoRun: RunFixedLike = async () => ({
      code: 0,
      stdout: "",
      stderr: "",
      timedOut: false,
      truncated: false,
    });

    const neoResult = await installServerLoader({
      serverDir: neoDir,
      minecraftVersion: "1.21.1",
      loader: "neoforge",
      javaBin: "/opt/java/bin/java",
      fetchImpl: neoFetch,
      runFixedImpl: neoRun,
    });

    expect(neoResult.loaderVersion).toBe("21.1.72");
    expect(neoResult.launchTarget).toEqual({
      kind: "args_file",
      args_file_relative_path: "libraries/net/neoforged/neoforge/21.1.72/unix_args.txt",
    });
  });

  test("Quilt validates metadata, checks Maven SHA-1, and runs installer", async () => {
    const quiltDir = makeTempDir("tegrad-quilt-");
    const installerBytes = new TextEncoder().encode("quilt-installer");
    const installerSha1 = sha1Hex(installerBytes);
    const installerUrl =
      "https://maven.quiltmc.org/repository/release/org/quiltmc/quilt-installer/0.9.2/quilt-installer-0.9.2.jar";

    const quiltFetch: FetchLike = async (input) => {
      const url = String(input);
      if (url === "https://meta.quiltmc.org/v3/versions/game") {
        return new Response(JSON.stringify([{ version: "1.20.4", stable: true }]), { status: 200 });
      }
      if (url === "https://meta.quiltmc.org/v3/versions/loader") {
        return new Response(JSON.stringify([{ version: "0.26.4" }]), { status: 200 });
      }
      if (url === "https://meta.quiltmc.org/v3/versions/installer") {
        return new Response(JSON.stringify([{ version: "0.9.2", url: installerUrl }]), {
          status: 200,
        });
      }
      if (url === `${installerUrl}.sha256`) {
        return new Response("not found", { status: 404 });
      }
      if (url === `${installerUrl}.sha1`) {
        return new Response(installerSha1, { status: 200 });
      }
      if (url === installerUrl) {
        return new Response(installerBytes, { status: 200 });
      }
      return new Response("not found", { status: 404 });
    };

    const quiltRun: RunFixedLike = async () => {
      writeFileSync(join(quiltDir, "quilt-server-launch.jar"), "quilt-launch");
      return { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
    };

    const result = await installServerLoader({
      serverDir: quiltDir,
      minecraftVersion: "1.20.4",
      loader: "quilt",
      javaBin: "/opt/java/bin/java",
      fetchImpl: quiltFetch,
      runFixedImpl: quiltRun,
    });

    expect(result.loaderVersion).toBe("0.26.4");
    expect(result.launchTarget).toEqual({
      kind: "jar",
      jar_relative_path: "quilt-server-launch.jar",
    });
  });
});
