// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Glob } from "bun";
import { createLogger, getStatePaths, loadOrCreateIdentity } from "../agent";
import { createAgentRuntime } from "../cli/run";
import { MAX_JVM_ARGS, ProtocolError, type ProtocolErrorCode } from "../protocol";
import {
  type ConsoleLinesEvent,
  type ConsoleTimerHandle,
  type ConsoleTimerProvider,
  createConsoleSubscriptionManager,
  createServerManager,
  downloadVerifiedFile,
  type FetchLike,
  fetchWithAllowlist,
  getJavaBinPath,
  installServerLoader,
  LOADER_ALLOWED_HOSTS,
  readServerMetadata,
  resolveServerSubpath,
  selectJavaMajor,
  validateDownloadUrl,
  validateJvmArgs,
  validateLaunchTarget,
  writeServerProperties,
  writeStartScript,
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

function expectProtocolErrorSync(fn: () => unknown, expectedCode: ProtocolErrorCode): void {
  try {
    fn();
    throw new Error(`Expected ProtocolError(${expectedCode}), but succeeded`);
  } catch (err) {
    expect(err).toBeInstanceOf(ProtocolError);
    expect((err as ProtocolError).code).toBe(expectedCode);
  }
}

async function expectProtocolErrorAsync(
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

describe("adversarial static security invariants on src/server", () => {
  test("src/server never opens an inbound port and never invokes a shell", async () => {
    const forbiddenPatterns: readonly { name: string; regex: RegExp }[] = [
      { name: "Bun.serve", regex: /\bBun\.serve\b/ },
      {
        name: "net/http createServer",
        regex: /\b(?:net|https?|http2|tls|dgram)\.createServer\b/,
      },
      {
        name: "network server module import",
        regex: /from\s+["'](?:node:)?(?:net|https?|http2|tls|dgram)["']/,
      },
      { name: ".listen(", regex: /\.listen\s*\(/ },
      { name: "new Bun.TCPSocket", regex: /\bnew\s+Bun\.TCPSocket\b/ },
      { name: "Bun.listen", regex: /\bBun\.listen\b/ },
      { name: "child_process", regex: /\bchild_process\b/ },
      { name: "Bun.$", regex: /\bBun\.\$/ },
      { name: "shell: true", regex: /\bshell\s*:\s*true\b/ },
    ];

    const violations: string[] = [];
    let checkedCount = 0;

    for await (const path of new Glob("src/server/**/*.ts").scan(".")) {
      if (path.endsWith(".test.ts")) continue;
      checkedCount++;
      const content = await Bun.file(path).text();
      for (const rule of forbiddenPatterns) {
        if (rule.regex.test(content)) {
          violations.push(`${path}: matched ${rule.name}`);
        }
      }
    }

    expect(checkedCount).toBeGreaterThan(0);
    expect(violations).toEqual([]);
  });
});

describe("adversarial JVM args and launch target validation", () => {
  test("rejects case-variant flags, control chars, log4j/logback/jdk/proxy properties, and oversized args", () => {
    const attacks = [
      "-JAVAAGENT:/tmp/evil.jar",
      "-AgentLib:jdwp=transport=dt_socket,server=y",
      "-AgentPath:/tmp/lib.so",
      "-XMS512M",
      "-XMX512M",
      "-XBootClasspath/p:/tmp/evil.jar",
      "-XLOG:all=warning:file=/etc/passwd",
      "-XX:onoutofmemoryerror=sh",
      "-XX:onerror=sh",
      "-XX:+UseG1GC\t-jar",
      "-XX:+UseG1GC\v",
      "-XX:+UseG1GC\f",
      "-XX:+UseG1GC\\id",
      "-XX:+UseG1GC>out",
      "-XX:+UseG1GC<in",
      "-XX:+UseG1GC(1)",
      "-Xss10000000M",
      "-Xss0M",
      `-Dvalid.key=${"a".repeat(250)}`,
      "-Dlog4j.configurationFile=https://evil.example/log4j.xml",
      "-Dlog4j2.configurationFile=https://evil.example/log4j2.xml",
      "-Dlog4j2.enableJndiLookup=true",
      "-Dlog4j2.formatMsgNoLookups=TRUE",
      "-Dlog4j2.formatMsgNoLookups=0",
      "-Dlogback.configurationFile=https://evil.example/logback.xml",
      "-Djava.util.logging.config.file=/etc/passwd",
      "-Djava.protocol.handler.pkgs=evil.pkg",
      "-Djava.net.useSystemProxies=true",
      "-Djdk.jndi.object.factoriesFilter=*",
      "-Djdk.xml.enableTemplatesImplDeserialization=true",
      "-Dsun.boot.library.path=/tmp",
      "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true",
      "-Djavax.management.builder.initial=evil.Builder",
      "-Dhttp.proxyHost=evil.example",
      "-Dhttps.proxyHost=evil.example",
      "-DsocksProxyHost=evil.example",
      "-Duser.dir=/var/lib/tegrad",
      "-Djava.class.path=/tmp/evil.jar",
      "-Djava.ext.dirs=/tmp",
      "-Djava.endorsed.dirs=/tmp",
    ];

    for (const arg of attacks) {
      expectProtocolErrorSync(() => validateJvmArgs([arg]), "invalid_jvm_args");
    }

    const tooMany = Array.from({ length: MAX_JVM_ARGS + 1 }, () => "-XX:+UseG1GC");
    expectProtocolErrorSync(() => validateJvmArgs(tooMany), "invalid_jvm_args");
  });

  test("rejects traversal, leading slashes, and arbitrary paths in launchTarget", () => {
    const badTargets = [
      { kind: "jar" as const, jar_relative_path: "/etc/evil.jar" },
      { kind: "jar" as const, jar_relative_path: "//evil.jar" },
      { kind: "jar" as const, jar_relative_path: "../evil.jar" },
      { kind: "jar" as const, jar_relative_path: "sub/../evil.jar" },
      { kind: "jar" as const, jar_relative_path: ".hidden.jar" },
      { kind: "jar" as const, jar_relative_path: "server.jar;id" },
      { kind: "args_file" as const, args_file_relative_path: "/etc/passwd" },
      {
        kind: "args_file" as const,
        args_file_relative_path: "libraries/../../etc/unix_args.txt",
      },
      {
        kind: "args_file" as const,
        args_file_relative_path: "libraries/evil/custom/unix_args.txt",
      },
      {
        kind: "args_file" as const,
        args_file_relative_path: "libraries/net/minecraftforge/forge/1.20.1/../../unix_args.txt",
      },
    ];

    for (const target of badTargets) {
      expectProtocolErrorSync(() => validateLaunchTarget(target), "invalid_body");
    }
  });

  test("rejects symlinks and intermediate directory symlinks escaping serverDir", () => {
    const rootDir = makeTempDir("tegrad-adv-root-");
    const outsideDir = makeTempDir("tegrad-adv-outside-");
    const serverDir = join(rootDir, "srv-1");
    mkdirSync(serverDir, { recursive: true });

    const outsideSecret = join(outsideDir, "secret.txt");
    writeFileSync(outsideSecret, "TOP_SECRET_KEY");

    let symlinksSupported = true;
    try {
      symlinkSync(outsideSecret, join(serverDir, "eula.txt"));
    } catch {
      symlinksSupported = false;
    }

    if (symlinksSupported) {
      expectProtocolErrorSync(() => resolveServerSubpath(serverDir, "eula.txt"), "invalid_body");

      // Intermediate directory symlink where target file does not exist yet
      symlinkSync(outsideDir, join(serverDir, "linked-dir"));
      expectProtocolErrorSync(
        () => resolveServerSubpath(serverDir, "linked-dir/new-file.txt"),
        "invalid_body",
      );

      // Dangling symlink pointing to non-existent file outside
      symlinkSync(join(outsideDir, "nonexistent.jar"), join(serverDir, "server.jar"));
      expectProtocolErrorSync(() => resolveServerSubpath(serverDir, "server.jar"), "invalid_body");
      expectProtocolErrorSync(
        () =>
          writeStartScript(serverDir, {
            javaBin: "/usr/bin/java",
            memoryMb: 2048,
            jvmArgs: [],
            launchTarget: { kind: "jar", jar_relative_path: "server.jar" },
          }),
        "invalid_body",
      );
    }
  });
});

describe("adversarial download streaming, redirects, and version validation", () => {
  test("rejects URLs with credentials, non-https protocols, non-standard ports, and excessive redirects", async () => {
    expectProtocolErrorSync(
      () => validateDownloadUrl("http://piston-meta.mojang.com/a.json", LOADER_ALLOWED_HOSTS),
      "download_failed",
    );
    expectProtocolErrorSync(
      () =>
        validateDownloadUrl(
          "https://user:pass@piston-meta.mojang.com/a.json",
          LOADER_ALLOWED_HOSTS,
        ),
      "download_failed",
    );
    expectProtocolErrorSync(
      () => validateDownloadUrl("https://piston-meta.mojang.com:8443/a.json", LOADER_ALLOWED_HOSTS),
      "download_failed",
    );
    expectProtocolErrorSync(
      () => validateDownloadUrl("https://evil.mojang.com/a.json", LOADER_ALLOWED_HOSTS),
      "download_failed",
    );

    // Redirect loop exceeding maxRedirects
    const loopFetch: FetchLike = async () =>
      new Response(null, {
        status: 302,
        headers: { location: "https://piston-meta.mojang.com/loop" },
      });
    await expectProtocolErrorAsync(
      fetchWithAllowlist("https://piston-meta.mojang.com/start", {
        allowedHosts: LOADER_ALLOWED_HOSTS,
        fetchImpl: loopFetch,
        maxRedirects: 3,
      }),
      "download_failed",
    );

    // Redirect downgrading to http:// on allowed host
    const downgradeFetch: FetchLike = async () =>
      new Response(null, {
        status: 302,
        headers: { location: "http://piston-meta.mojang.com/insecure.jar" },
      });
    await expectProtocolErrorAsync(
      fetchWithAllowlist("https://piston-meta.mojang.com/start", {
        allowedHosts: LOADER_ALLOWED_HOSTS,
        fetchImpl: downgradeFetch,
      }),
      "download_failed",
    );
  });

  test("aborts download and deletes temp file when stream exceeds maxBytes despite lying or missing Content-Length", async () => {
    const dir = makeTempDir("tegrad-adv-dl-");
    const destPath = join(dir, "server.jar");
    const chunk = new Uint8Array(64).fill(0x41);
    const fakeHash = createHash("sha256").update(chunk).digest("hex");

    const lyingStreamFetch: FetchLike = async () => {
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(chunk);
          controller.enqueue(chunk);
          controller.enqueue(chunk);
          controller.close();
        },
      });
      return new Response(stream, {
        status: 200,
        headers: { "content-length": "10" }, // lies about size (actual is 192 bytes)
      });
    };

    await expectProtocolErrorAsync(
      downloadVerifiedFile({
        url: "https://piston-data.mojang.com/server.jar",
        destPath,
        allowedHosts: LOADER_ALLOWED_HOSTS,
        expectedHash: { algorithm: "sha256", hex: fakeHash },
        maxBytes: 100,
        fetchImpl: lyingStreamFetch,
      }),
      "download_failed",
    );

    expect(existsSync(destPath)).toBe(false);
    expect(readdirSync(dir)).toEqual([]);
  });

  test("rejects path traversal in minecraft_version and loader_version across Java and all loaders", async () => {
    expectProtocolErrorSync(() => selectJavaMajor("1.20.1-../../etc/passwd"), "invalid_body");
    expectProtocolErrorSync(() => selectJavaMajor("1.21.4;id"), "invalid_body");

    const dir = makeTempDir("tegrad-adv-loader-");
    const loaders = ["vanilla", "fabric", "quilt", "forge", "neoforge"] as const;
    const badVersions = ["../evil", "1.20.1/../../evil", "1.20.1\\..\\evil", "1.20.1;id", "-flag"];

    let networkTouched = false;
    const forbidNetworkFetch: FetchLike = async () => {
      networkTouched = true;
      return new Response("unexpected network call", { status: 500 });
    };

    for (const loader of loaders) {
      for (const badVersion of badVersions) {
        await expectProtocolErrorAsync(
          installServerLoader({
            serverDir: dir,
            minecraftVersion: badVersion,
            loader,
            javaBin: "/usr/bin/java",
            fetchImpl: forbidNetworkFetch,
          }),
          "download_failed",
        );
        await expectProtocolErrorAsync(
          installServerLoader({
            serverDir: dir,
            minecraftVersion: "1.20.1",
            loader,
            loaderVersion: badVersion,
            javaBin: "/usr/bin/java",
            fetchImpl: forbidNetworkFetch,
          }),
          "download_failed",
        );
      }
    }
    expect(networkTouched).toBe(false);

    // Compromised remote Forge promotions returning traversal version string
    const evilPromoFetch: FetchLike = async () =>
      new Response(JSON.stringify({ promos: { "1.20.1-recommended": "../../evil" } }), {
        status: 200,
      });
    await expectProtocolErrorAsync(
      installServerLoader({
        serverDir: dir,
        minecraftVersion: "1.20.1",
        loader: "forge",
        javaBin: "/usr/bin/java",
        fetchImpl: evilPromoFetch,
      }),
      "download_failed",
    );
  });
});

describe("adversarial server.properties, metadata, and console streaming", () => {
  test("writeServerProperties neutralizes colon/space RCON bypasses, duplicate keys, and invalid ports", () => {
    const serverDir = makeTempDir("tegrad-adv-props-");
    const propsPath = join(serverDir, "server.properties");

    writeFileSync(
      propsPath,
      [
        "# Minecraft properties",
        "! Alternative comment",
        "enable-rcon: true",
        "enable-rcon true",
        "enable-rcon=true",
        "online-mode: false",
        "online-mode false",
        "server-port: 11111",
        "server-port=22222",
        "motd=Safe Server",
      ].join("\n"),
    );

    writeServerProperties(serverDir, { port: 25575 });
    const content = readFileSync(propsPath, "utf8");
    const lines = content.trim().split("\n");

    expect(lines.filter((l) => l.includes("enable-rcon"))).toEqual(["enable-rcon=false"]);
    expect(lines.filter((l) => l.includes("online-mode"))).toEqual(["online-mode=true"]);
    expect(lines.filter((l) => l.includes("server-port"))).toEqual(["server-port=25575"]);
    expect(lines).toContain("motd=Safe Server");

    expectProtocolErrorSync(() => writeServerProperties(serverDir, { port: 80 }), "invalid_body");
    expectProtocolErrorSync(
      () => writeServerProperties(serverDir, { port: 70000 }),
      "invalid_body",
    );
    expectProtocolErrorSync(
      () =>
        writeServerProperties(serverDir, {
          port: "25565\nenable-rcon=true" as unknown as number,
        }),
      "invalid_body",
    );
  });

  test("readServerMetadata rejects tampered launch_target or mismatched server id on disk", () => {
    const serversDir = makeTempDir("tegrad-adv-meta-");
    const srvDir = join(serversDir, "srv-1");
    mkdirSync(srvDir, { recursive: true });

    writeFileSync(
      join(srvDir, "tegrad-server.json"),
      JSON.stringify({
        v: 1,
        id: "srv-1",
        name: "Tampered",
        minecraft_version: "1.21.4",
        loader: "vanilla",
        loader_version: null,
        memory_mb: 2048,
        jvm_args: [],
        port: 25565,
        created_at: 1000,
        launch_target: {
          kind: "jar",
          jar_relative_path: "../../evil.jar",
        },
      }),
    );
    expectProtocolErrorSync(() => readServerMetadata(serversDir, "srv-1"), "invalid_format");
  });

  test("restartServer refuses when EULA is not accepted without calling systemctl", async () => {
    const serversDir = makeTempDir("tegrad-adv-restart-");
    preinstallJava(serversDir);

    const jarBytes = new TextEncoder().encode("jar");
    const sha1 = createHash("sha1").update(jarBytes).digest("hex");
    let systemctlCalled = false;

    const manager = createServerManager({
      serversDir,
      platform: "linux",
      fetchImpl: async (input) => {
        const url = String(input);
        if (url.endsWith("version_manifest_v2.json")) {
          return new Response(
            JSON.stringify({
              versions: [{ id: "1.21.4", url: "https://piston-meta.mojang.com/v1/1.21.4.json" }],
            }),
          );
        }
        if (url.endsWith("1.21.4.json")) {
          return new Response(
            JSON.stringify({
              downloads: {
                server: { sha1, url: "https://piston-data.mojang.com/server.jar" },
              },
            }),
          );
        }
        return new Response(jarBytes);
      },
      runFixedImpl: async () => {
        systemctlCalled = true;
        return { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
      },
    });

    await manager.createServer({
      server_id: "srv-eula",
      name: "No EULA",
      minecraft_version: "1.21.4",
      loader: "vanilla",
      memory_mb: 2048,
      eula_accepted: false,
    });

    await expectProtocolErrorAsync(manager.restartServer("srv-eula"), "eula_not_accepted");
    expect(systemctlCalled).toBe(false);
    manager.close();
  });

  test("console subscription preserves reset=true across rate-limit window and refuses symlinked console.log", () => {
    const serversDir = makeTempDir("tegrad-adv-console-");
    const logsDir = join(serversDir, "srv-1", "logs");
    mkdirSync(logsDir, { recursive: true });
    const logPath = join(logsDir, "console.log");
    writeFileSync(logPath, "l1\nl2\nl3\n");

    const callbacks = new Map<number, () => void>();
    let nextId = 1;
    const timers: ConsoleTimerProvider = {
      setInterval(fn) {
        const id = nextId++;
        callbacks.set(id, fn);
        return { id };
      },
      clearInterval(handle: ConsoleTimerHandle) {
        callbacks.delete(handle.id as number);
      },
    };
    const tick = () => {
      for (const fn of [...callbacks.values()]) fn();
    };

    let nowMs = 10_000;
    const manager = createConsoleSubscriptionManager({
      serversDir,
      timers,
      maxLinesPerEvent: 5,
      maxBytesPerEvent: 16,
      maxLinesPerSecond: 3,
      now: () => nowMs,
    });

    const events: ConsoleLinesEvent[] = [];
    manager.subscribe({
      serverId: "srv-1",
      sendEvent: (_type, body) => events.push(body),
    });

    // Initial poll consumed all 3 lines allowed in this 1-second window
    expect(events).toHaveLength(1);
    expect(events[0]?.lines).toEqual(["l1", "l2", "l3"]);

    // Truncate/rotate file while rate-limited in the same 1-second window
    writeFileSync(logPath, "new\n");
    tick();
    // Rate-limited, so no event emitted yet
    expect(events).toHaveLength(1);

    // Advance clock to next 1-second window: reset=true MUST still be delivered!
    nowMs += 1000;
    tick();
    expect(events).toHaveLength(2);
    expect(events[1]?.reset).toBe(true);
    expect(events[1]?.lines).toEqual(["new"]);

    // Single line exceeding maxBytesPerEvent (16 bytes) without newline is flushed with truncated=true
    nowMs += 1000;
    appendFileSync(logPath, "0123456789abcdefXYZ");
    tick();
    expect(events).toHaveLength(3);
    expect(events[2]?.lines).toEqual(["0123456789abcdef"]);
    expect(events[2]?.truncated).toBe(true);

    // Replacing console.log with a symlink to a secret file outside serverDir is ignored
    const outsideSecret = join(makeTempDir("tegrad-adv-secret-"), "identity.json");
    writeFileSync(outsideSecret, '{"secret_key":"DO_NOT_LEAK"}\n');
    rmSync(logPath, { force: true });
    let symlinkCreated = true;
    try {
      symlinkSync(outsideSecret, logPath);
    } catch {
      symlinkCreated = false;
    }
    if (symlinkCreated) {
      nowMs += 1000;
      tick();
      expect(events).toHaveLength(3);
    }

    manager.closeAll();
  });

  test("createAgentRuntime registers serverManager by default even when TEGRAD_SERVERS_DIR is unset", async () => {
    const stateDir = makeTempDir("tegrad-adv-runtime-");
    await loadOrCreateIdentity(stateDir);
    const { configPath } = getStatePaths(stateDir);
    writeFileSync(configPath, JSON.stringify({ api_url: "https://api.tegra.example" }), "utf8");

    const runtime = await createAgentRuntime({
      stateDir,
      env: {},
      logger: createLogger({ level: "error", stdout: () => {}, stderr: () => {} }),
    });
    expect(runtime.serverManager).toBeDefined();
    await runtime.shutdown(100);
  });
});

function preinstallJava(serversDir: string): void {
  const binPath = getJavaBinPath(serversDir, 21, "linux");
  mkdirSync(join(binPath, ".."), { recursive: true });
  writeFileSync(binPath, "#!/bin/sh\n");
}
