// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { describe, expect, test } from "bun:test";
import { resolve } from "node:path";
import { ProtocolError, type ProtocolErrorCode } from "../protocol";
import {
  assertValidServerId,
  formatServiceUnit,
  formatSocketUnit,
  renderStartScript,
  resolveFifoPath,
  resolveServerDir,
  resolveServerSubpath,
  SERVER_ID_REGEX,
  validateJvmArgs,
} from "./index";

function expectProtocolErrorSync(fn: () => unknown, expectedCode: ProtocolErrorCode): void {
  try {
    fn();
    throw new Error(`Expected ProtocolError(${expectedCode}), but succeeded`);
  } catch (err) {
    expect(err).toBeInstanceOf(ProtocolError);
    expect((err as ProtocolError).code).toBe(expectedCode);
  }
}

describe("server_id validation and path confinement", () => {
  test("accepts valid server IDs matching ^[a-z0-9][a-z0-9-]{0,62}$", () => {
    const valid = ["a", "0", "srv1", "survival-2026", "my-mc-server-01", `a${"b".repeat(62)}`];
    for (const id of valid) {
      expect(SERVER_ID_REGEX.test(id)).toBe(true);
      expect(assertValidServerId(id)).toBe(id);
      expect(formatServiceUnit(id)).toBe(`tegrad-server@${id}.service`);
      expect(formatSocketUnit(id)).toBe(`tegrad-server@${id}.socket`);
    }
  });

  test("rejects invalid server IDs including traversal, uppercase, underscore, and oversize", () => {
    const invalid = [
      "",
      "-leading-dash",
      "UpperCase",
      "has_underscore",
      "has space",
      "..",
      "../escape",
      "a/b",
      "a\\b",
      "srv.1",
      "srv;id",
      "srv\0null",
      `a${"b".repeat(63)}`,
    ];
    for (const id of invalid) {
      expect(SERVER_ID_REGEX.test(id)).toBe(false);
      expectProtocolErrorSync(() => assertValidServerId(id), "invalid_body");
      expectProtocolErrorSync(
        () => resolveServerDir("/var/lib/tegrad-servers", id),
        "invalid_body",
      );
      expectProtocolErrorSync(() => resolveFifoPath("/run/tegrad-server", id), "invalid_body");
      expectProtocolErrorSync(() => formatServiceUnit(id), "invalid_body");
    }
  });

  test("resolveServerDir and resolveServerSubpath stay strictly inside root", () => {
    const root = resolve("/var/lib/tegrad-servers");
    const srvDir = resolveServerDir(root, "srv-1");
    expect(srvDir).toBe(resolve(root, "srv-1"));

    const logPath = resolveServerSubpath(srvDir, "logs/console.log");
    expect(logPath).toBe(resolve(srvDir, "logs/console.log"));

    expectProtocolErrorSync(
      () => resolveServerSubpath(srvDir, "../other/server.jar"),
      "invalid_body",
    );
    expectProtocolErrorSync(() => resolveServerSubpath(srvDir, "/etc/passwd"), "invalid_body");
    expectProtocolErrorSync(() => resolveServerSubpath(srvDir, "logs/\0bad"), "invalid_body");
  });
});

describe("JVM argument allowlist", () => {
  test("accepts curated safe GC flags, stack size, and safe system properties", () => {
    const safeArgs = [
      "-Xss2M",
      "-XX:+UseG1GC",
      "-XX:+ParallelRefProcEnabled",
      "-XX:MaxGCPauseMillis=200",
      "-XX:+UnlockExperimentalVMOptions",
      "-XX:+DisableExplicitGC",
      "-XX:+AlwaysPreTouch",
      "-XX:G1NewSizePercent=30",
      "-XX:G1MaxNewSizePercent=40",
      "-XX:G1HeapRegionSize=8M",
      "-XX:G1ReservePercent=20",
      "-XX:G1HeapWastePercent=5",
      "-XX:G1MixedGCCountTarget=4",
      "-XX:InitiatingHeapOccupancyPercent=15",
      "-XX:G1MixedGCLiveThresholdPercent=90",
      "-XX:G1RSetUpdatingPauseTimePercent=5",
      "-XX:SurvivorRatio=32",
      "-XX:+PerfDisableSharedMem",
      "-XX:MaxTenuringThreshold=1",
      "-Dlog4j2.formatMsgNoLookups=true",
      "-Dusing.aikars.flags=https://mcflags.emc.gs",
      "-Daikars.new.flags=true",
    ];
    expect(validateJvmArgs(safeArgs)).toEqual(safeArgs);
  });

  test("rejects every injection attempt, unsafe JVM flag, and blocked system property", () => {
    const maliciousArgs = [
      "-javaagent:/tmp/evil.jar",
      "-javaagent",
      "-agentlib:jdwp=transport=dt_socket",
      "-agentpath:/tmp/evil.so",
      "-cp",
      "-classpath",
      "--class-path",
      "-jar",
      "-p",
      "--module-path=/tmp",
      "--upgrade-module-path=/tmp",
      "--patch-module=java.base=/tmp",
      "--add-opens=java.base/java.lang=ALL-UNNAMED",
      "--add-exports=java.base/sun.misc=ALL-UNNAMED",
      "--add-reads=java.base=ALL-UNNAMED",
      "--add-modules=ALL-SYSTEM",
      "-XX:OnOutOfMemoryError=id",
      "-XX:OnError=sh",
      "-XX:ErrorFile=/tmp/err",
      "-XX:HeapDumpPath=/tmp/dump",
      "-XX:LogFile=/tmp/log",
      "-XX:CompileCommandFile=/tmp/cmd",
      "-XX:SharedArchiveFile=/tmp/jsa",
      "-Xbootclasspath/a:/tmp/evil.jar",
      "-Xlog:gc*:file=/tmp/gc.log",
      "-Xms4096M",
      "-Xmx4096M",
      "@/etc/passwd",
      "@libraries/net/minecraftforge/forge/unix_args.txt",
      "-XX:+UseG1GC;id",
      "-XX:+UseG1GC|sh",
      "-XX:+UseG1GC&id",
      "-XX:+UseG1GC$(id)",
      "-XX:+UseG1GC`id`",
      "-XX:+UseG1GC\nid",
      "-XX:+UseG1GC\rid",
      "-XX:+UseG1GC\0id",
      "-XX:+UseG1GC 'x'",
      '-XX:+UseG1GC "x"',
      "-XX:+UnknownFlag",
      "-XX:MaxGCPauseMillis=200;rm",
      "-Djava.security.policy=/tmp/all.policy",
      "-Dcom.sun.management.jmxremote.port=9999",
      "-Djavax.net.ssl.trustStore=/tmp/ts",
      "-Dsun.rmi.transport.tcp.responseTimeout=1",
      "-Djava.library.path=/tmp",
      "-Duser.home=/root",
      "-Djava.io.tmpdir=/tmp",
      "-Dlog4j2.formatMsgNoLookups=false",
      "-Dfoo.bar=../../etc/passwd",
      "",
    ];

    for (const arg of maliciousArgs) {
      expectProtocolErrorSync(() => validateJvmArgs([arg]), "invalid_jvm_args");
    }
  });
});

describe("start.sh golden tests", () => {
  test("Vanilla server start.sh matches exact golden output", () => {
    const script = renderStartScript({
      javaBin: "/var/lib/tegrad-servers/.runtime/java/21/bin/java",
      memoryMb: 2048,
      jvmArgs: ["-XX:+UseG1GC", "-XX:MaxGCPauseMillis=200"],
      serverDir: "/var/lib/tegrad-servers/srv1",
      launchTarget: {
        kind: "jar",
        jar_relative_path: "server.jar",
      },
    });

    expect(script).toBe(
      [
        "#!/bin/sh",
        "set -eu",
        "exec '/var/lib/tegrad-servers/.runtime/java/21/bin/java' -Xms2048M -Xmx2048M '-XX:+UseG1GC' '-XX:MaxGCPauseMillis=200' -jar '/var/lib/tegrad-servers/srv1/server.jar' nogui",
        "",
      ].join("\n"),
    );
  });

  test("Fabric server start.sh matches exact golden output", () => {
    const script = renderStartScript({
      javaBin: "/var/lib/tegrad-servers/.runtime/java/21/bin/java",
      memoryMb: 4096,
      jvmArgs: [],
      serverDir: "/var/lib/tegrad-servers/fabric-smp",
      launchTarget: {
        kind: "jar",
        jar_relative_path: "fabric-server-launch.jar",
      },
    });

    expect(script).toBe(
      [
        "#!/bin/sh",
        "set -eu",
        "exec '/var/lib/tegrad-servers/.runtime/java/21/bin/java' -Xms4096M -Xmx4096M -jar '/var/lib/tegrad-servers/fabric-smp/fabric-server-launch.jar' nogui",
        "",
      ].join("\n"),
    );
  });

  test("Forge/NeoForge unix_args.txt start.sh matches exact golden output", () => {
    const forgeScript = renderStartScript({
      javaBin: "/var/lib/tegrad-servers/.runtime/java/17/bin/java",
      memoryMb: 6144,
      jvmArgs: ["-XX:+UseG1GC"],
      serverDir: "/var/lib/tegrad-servers/modded-1",
      launchTarget: {
        kind: "args_file",
        args_file_relative_path: "libraries/net/minecraftforge/forge/1.20.1-47.2.0/unix_args.txt",
      },
    });

    expect(forgeScript).toBe(
      [
        "#!/bin/sh",
        "set -eu",
        "exec '/var/lib/tegrad-servers/.runtime/java/17/bin/java' -Xms6144M -Xmx6144M '-XX:+UseG1GC' '@libraries/net/minecraftforge/forge/1.20.1-47.2.0/unix_args.txt' nogui",
        "",
      ].join("\n"),
    );

    const neoForgeScript = renderStartScript({
      javaBin: "/var/lib/tegrad-servers/.runtime/java/21/bin/java",
      memoryMb: 8192,
      jvmArgs: ["-XX:+UseZGC", "-XX:+ZGenerational"],
      serverDir: "/var/lib/tegrad-servers/neo-1",
      launchTarget: {
        kind: "args_file",
        args_file_relative_path: "libraries/net/neoforged/neoforge/21.1.72/unix_args.txt",
      },
    });

    expect(neoForgeScript).toBe(
      [
        "#!/bin/sh",
        "set -eu",
        "exec '/var/lib/tegrad-servers/.runtime/java/21/bin/java' -Xms8192M -Xmx8192M '-XX:+UseZGC' '-XX:+ZGenerational' '@libraries/net/neoforged/neoforge/21.1.72/unix_args.txt' nogui",
        "",
      ].join("\n"),
    );
  });
});
