// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import {
  chmodSync,
  chownSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fingerprint, generateSigningKeyPair, ready } from "../crypto";
import {
  createCoreRegistry,
  createInMemoryTrustContext,
  createSignedCommand,
  PROTOCOL_VERSION,
  type TransportFrame,
} from "../protocol";
import {
  assertServerPathsUsable,
  createServerPermissionContext,
  finalizeServerPath,
  inspectServersRoot,
  inspectTree,
  type PermissionDirentLike,
  type PermissionFailure,
  type PermissionFsOps,
  type PermissionStatLike,
  resolveGroupId,
  SERVER_DIR_MODE,
  SERVER_TREE_PLAN,
  SHARED_TREE_PLAN,
  secureDirectory,
  secureTree,
} from "../server/permissions";
import { createAgentConnection, type TimerProvider, type WebSocketLike } from "./connection";
import { resolveCommandPath } from "./exec";
import { createCommandQueue, sanitizeErrorMessage } from "./jobs";
import { createLogger } from "./logger";

const NOW = 1_700_000_000_000;
const tempDirs: string[] = [];
const posix = process.platform !== "win32";

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

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "tegrad-hard-"));
  tempDirs.push(dir);
  return dir;
}

describe("resolveGroupId", () => {
  test("reads the gid of a named group and returns null when absent", () => {
    const dir = tempDir();
    const file = join(dir, "group");
    writeFileSync(file, "root:x:0:\ntegrad:x:991:\ntegrad-srv:x:992:tegrad\n");
    expect(resolveGroupId("tegrad-srv", file)).toBe(992);
    expect(resolveGroupId("tegrad", file)).toBe(991);
    expect(resolveGroupId("missing", file)).toBeNull();
    expect(resolveGroupId("tegrad-srv", join(dir, "nope"))).toBeNull();
  });
});

describe("server file permissions (injected fs, cross-platform)", () => {
  interface FakeNode {
    kind: "dir" | "file" | "symlink";
    mode: number;
    uid?: number;
    gid: number;
    children?: string[];
  }

  function makeFakeFs(nodes: Map<string, FakeNode>, options?: { failOnPath?: string }) {
    const chmodCalls: { path: string; mode: number }[] = [];
    const chownCalls: { path: string; uid: number; gid: number }[] = [];

    const normalize = (p: string) => p.replace(/\\/g, "/");
    const getNode = (p: string): FakeNode => {
      const node = nodes.get(normalize(p));
      if (!node) {
        const err = new Error(`ENOENT: ${p}`) as Error & { code: string; errno: number };
        err.code = "ENOENT";
        err.errno = -2;
        throw err;
      }
      return node;
    };

    const fs: PermissionFsOps = {
      existsSync: (p) => nodes.has(normalize(p)),
      lstatSync: (p): PermissionStatLike => {
        const node = getNode(p);
        return {
          mode: node.mode,
          uid: node.uid ?? 991,
          gid: node.gid,
          isSymbolicLink: () => node.kind === "symlink",
          isDirectory: () => node.kind === "dir",
          isFile: () => node.kind === "file",
        };
      },
      chownSync: (p, uid, gid) => {
        const np = normalize(p);
        chownCalls.push({ path: np, uid, gid });
        // Simulate Bun 1.3.12: passing uid -1 (or any negative uid) throws EINVAL.
        if (uid < 0) {
          const err = new Error("EINVAL: invalid argument, chown") as Error & {
            code: string;
            errno: number;
          };
          err.code = "EINVAL";
          err.errno = -22;
          throw err;
        }
        if (options?.failOnPath === np) {
          const err = new Error("Operation not permitted") as Error & {
            code: string;
            errno: number;
          };
          err.code = "EPERM";
          err.errno = -1;
          throw err;
        }
        getNode(p).gid = gid;
      },
      chmodSync: (p, mode) => {
        const np = normalize(p);
        chmodCalls.push({ path: np, mode });
        // Simulate systemd RestrictSUIDSGID=yes: reject any SUID/SGID bit with EPERM.
        if ((mode & 0o6000) !== 0) {
          const err = new Error("Operation not permitted (RestrictSUIDSGID)") as Error & {
            code: string;
          };
          err.code = "EPERM";
          throw err;
        }
        if (options?.failOnPath === np) {
          const err = new Error("Operation not permitted") as Error & { code: string };
          err.code = "EPERM";
          throw err;
        }
        const node = getNode(p);
        // Simulate Linux chmod without setgid clearing any existing setgid bit.
        node.mode = mode & 0o777;
      },
      readdirSync: (p): readonly PermissionDirentLike[] => {
        const np = normalize(p);
        const node = getNode(p);
        return (node.children ?? []).map((name) => {
          const child = getNode(`${np}/${name}`);
          return {
            name,
            isSymbolicLink: () => child.kind === "symlink",
            isDirectory: () => child.kind === "dir",
            isFile: () => child.kind === "file",
          };
        });
      },
    };

    return { fs, chmodCalls, chownCalls };
  }

  test("never calls chmod with setgid/setuid bits and preserves existing setgid when 9-bit mode matches", () => {
    const nodes = new Map<string, FakeNode>([
      ["/var/lib/tegrad-servers", { kind: "dir", mode: 0o2770, gid: 992, children: ["srv1"] }],
      [
        "/var/lib/tegrad-servers/srv1",
        { kind: "dir", mode: 0o2770, gid: 992, children: ["start.sh", "server.jar", "logs"] },
      ],
      ["/var/lib/tegrad-servers/srv1/logs", { kind: "dir", mode: 0o2700, gid: 991, children: [] }],
      ["/var/lib/tegrad-servers/srv1/start.sh", { kind: "file", mode: 0o700, gid: 991 }],
      ["/var/lib/tegrad-servers/srv1/server.jar", { kind: "file", mode: 0o600, gid: 991 }],
    ]);
    const { fs, chmodCalls, chownCalls } = makeFakeFs(nodes);

    const failures = secureTree("/var/lib/tegrad-servers/srv1", SERVER_TREE_PLAN, {
      gid: 992,
      platform: "linux",
      serversRoot: "/var/lib/tegrad-servers",
      fs,
    });

    expect(failures).toEqual([]);
    // Never passed any setgid/setuid bit to chmod
    expect(chmodCalls.every((c) => (c.mode & 0o6000) === 0)).toBe(true);
    // srv1 already had lower 9 bits 0o770 -> chmod was NOT called on it, preserving setgid 0o2770
    expect(chmodCalls.some((c) => c.path === "/var/lib/tegrad-servers/srv1")).toBe(false);
    expect(nodes.get("/var/lib/tegrad-servers/srv1")?.mode).toBe(0o2770);
    // logs, start.sh, server.jar got chowned to 992 and chmodded to 0o770 / 0o770 / 0o660
    expect(nodes.get("/var/lib/tegrad-servers/srv1/logs")).toMatchObject({ mode: 0o770, gid: 992 });
    expect(nodes.get("/var/lib/tegrad-servers/srv1/start.sh")).toMatchObject({
      mode: 0o770,
      gid: 992,
    });
    expect(nodes.get("/var/lib/tegrad-servers/srv1/server.jar")).toMatchObject({
      mode: 0o660,
      gid: 992,
    });
    expect(chownCalls.map((c) => c.path).sort()).toEqual([
      "/var/lib/tegrad-servers/srv1/logs",
      "/var/lib/tegrad-servers/srv1/server.jar",
      "/var/lib/tegrad-servers/srv1/start.sh",
    ]);
    // Never passes uid -1 (Bun 1.3.12 throws EINVAL); always passes the file's real uid.
    expect(chownCalls.every((c) => c.uid === 991 && c.gid === 992)).toBe(true);
  });

  test("chown always passes the real file uid (never -1) and logs code, errno and sanitized message on failure", () => {
    const nodes = new Map<string, FakeNode>([
      ["/var/lib/tegrad-servers/srv1/ok.jar", { kind: "file", mode: 0o660, uid: 1005, gid: 991 }],
      ["/var/lib/tegrad-servers/srv1/fail.jar", { kind: "file", mode: 0o660, uid: 1006, gid: 991 }],
    ]);
    const { fs, chownCalls } = makeFakeFs(nodes, {
      failOnPath: "/var/lib/tegrad-servers/srv1/fail.jar",
    });
    const logs: string[] = [];
    const logger = createLogger({
      level: "debug",
      stdout: (l) => logs.push(l),
      stderr: (l) => logs.push(l),
    });
    const ctx = createServerPermissionContext({
      serversRoot: "/var/lib/tegrad-servers",
      serverGroupId: 992,
      platform: "linux",
      logger,
      fs,
    });

    expect(finalizeServerPath("/var/lib/tegrad-servers/srv1/ok.jar", 0o660, ctx)).toEqual([]);
    const failures = finalizeServerPath("/var/lib/tegrad-servers/srv1/fail.jar", 0o660, ctx);

    expect(chownCalls).toEqual([
      { path: "/var/lib/tegrad-servers/srv1/ok.jar", uid: 1005, gid: 992 },
      { path: "/var/lib/tegrad-servers/srv1/fail.jar", uid: 1006, gid: 992 },
    ]);
    expect(chownCalls.some((c) => c.uid === -1)).toBe(false);
    expect(failures).toHaveLength(1);
    expect(failures[0]).toMatchObject({
      op: "chown",
      code: "EPERM",
      errno: -1,
    });
    const warnLine = logs.find((l) => l.includes("Could not adjust server path permissions"));
    expect(warnLine).toBeDefined();
    expect(warnLine).toContain('"code":"EPERM"');
    expect(warnLine).toContain('"errno":-1');
    expect(warnLine).toContain("Operation not permitted");
  });

  test("a chown/chmod failure on one file does not stop other files from being adjusted", () => {
    const nodes = new Map<string, FakeNode>([
      [
        "/var/lib/tegrad-servers/srv1",
        { kind: "dir", mode: 0o700, gid: 991, children: ["bad.txt", "start.sh", "server.jar"] },
      ],
      ["/var/lib/tegrad-servers/srv1/bad.txt", { kind: "file", mode: 0o600, gid: 991 }],
      ["/var/lib/tegrad-servers/srv1/start.sh", { kind: "file", mode: 0o700, gid: 991 }],
      ["/var/lib/tegrad-servers/srv1/server.jar", { kind: "file", mode: 0o600, gid: 991 }],
    ]);
    const { fs } = makeFakeFs(nodes, { failOnPath: "/var/lib/tegrad-servers/srv1/bad.txt" });
    const reported: PermissionFailure[] = [];

    const failures = secureTree("/var/lib/tegrad-servers/srv1", SERVER_TREE_PLAN, {
      gid: 992,
      platform: "linux",
      serversRoot: "/var/lib/tegrad-servers",
      fs,
      onError: (f) => reported.push(f),
    });

    expect(failures.length).toBe(2); // chown + chmod on bad.txt
    expect(reported.every((f) => f.path.endsWith("bad.txt") && f.code === "EPERM")).toBe(true);
    // Other files WERE adjusted despite the failure on bad.txt
    expect(nodes.get("/var/lib/tegrad-servers/srv1/start.sh")).toMatchObject({
      mode: 0o770,
      gid: 992,
    });
    expect(nodes.get("/var/lib/tegrad-servers/srv1/server.jar")).toMatchObject({
      mode: 0o660,
      gid: 992,
    });
  });

  test("never chmods or chowns the servers root directory itself", () => {
    const nodes = new Map<string, FakeNode>([
      ["/var/lib/tegrad-servers", { kind: "dir", mode: 0o2770, gid: 992, children: [] }],
    ]);
    const { fs, chmodCalls, chownCalls } = makeFakeFs(nodes);

    finalizeServerPath("/var/lib/tegrad-servers", SERVER_DIR_MODE, {
      gid: 992,
      platform: "linux",
      serversRoot: "/var/lib/tegrad-servers",
      fs,
    });
    secureTree("/var/lib/tegrad-servers", SERVER_TREE_PLAN, {
      gid: 992,
      platform: "linux",
      serversRoot: "/var/lib/tegrad-servers",
      fs,
    });

    expect(chmodCalls).toEqual([]);
    expect(chownCalls).toEqual([]);
  });

  test("assertServerPathsUsable throws a clear error when essential files lack group or permissions", () => {
    const nodes = new Map<string, FakeNode>([
      ["/srv/start.sh", { kind: "file", mode: 0o770, gid: 991 }],
      ["/srv/server.jar", { kind: "file", mode: 0o660, gid: 992 }],
    ]);
    const { fs } = makeFakeFs(nodes);

    expect(() =>
      assertServerPathsUsable(
        [
          { path: "/srv/start.sh", executable: true },
          { path: "/srv/server.jar", executable: false },
        ],
        { gid: 992, platform: "linux", fs },
      ),
    ).toThrow(/tegrad-srv.*start\.sh/i);

    // Fix group -> passes
    const startNode = nodes.get("/srv/start.sh");
    if (startNode) startNode.gid = 992;
    expect(() =>
      assertServerPathsUsable(
        [
          { path: "/srv/start.sh", executable: true },
          { path: "/srv/server.jar", executable: false },
        ],
        { gid: 992, platform: "linux", fs },
      ),
    ).not.toThrow();
  });

  test("inspectServersRoot requires setgid on root, while inspectTree does not require setgid on server subdirs", () => {
    const nodes = new Map<string, FakeNode>([
      ["/var/lib/tegrad-servers", { kind: "dir", mode: 0o2770, gid: 992, children: ["srv1"] }],
      [
        "/var/lib/tegrad-servers/srv1",
        { kind: "dir", mode: 0o770, gid: 992, children: ["start.sh", "server.jar"] },
      ],
      ["/var/lib/tegrad-servers/srv1/start.sh", { kind: "file", mode: 0o770, gid: 992 }],
      ["/var/lib/tegrad-servers/srv1/server.jar", { kind: "file", mode: 0o660, gid: 992 }],
    ]);
    const { fs } = makeFakeFs(nodes);

    expect(inspectServersRoot("/var/lib/tegrad-servers", 992, fs)).toEqual([]);
    expect(inspectTree("/var/lib/tegrad-servers/srv1", SERVER_TREE_PLAN, 992, 20, fs)).toEqual([]);

    // Drop setgid on root -> reported
    const rootNode = nodes.get("/var/lib/tegrad-servers");
    if (rootNode) rootNode.mode = 0o770;
    expect(inspectServersRoot("/var/lib/tegrad-servers", 992, fs)[0]?.problem).toContain("setgid");

    // Drop group exec on start.sh -> reported
    const startNode = nodes.get("/var/lib/tegrad-servers/srv1/start.sh");
    if (startNode) startNode.mode = 0o660;
    const problems = inspectTree("/var/lib/tegrad-servers/srv1", SERVER_TREE_PLAN, 992, 20, fs);
    expect(problems.some((p) => p.path.endsWith("start.sh") && p.problem.includes("execute"))).toBe(
      true,
    );
  });
});

describe.skipIf(!posix)("server file permissions", () => {
  // Use the current gid so chown always succeeds without privileges.
  const gid = posix ? (process.getgid?.() ?? 0) : 0;

  test("secureTree gives dirs 0770 (no setgid), files 0660 and keeps executables executable for the group", () => {
    const root = tempDir();
    const server = join(root, "srv");
    mkdirSync(join(server, "logs"), { recursive: true });
    writeFileSync(join(server, "server.jar"), "jar");
    writeFileSync(join(server, "eula.txt"), "eula=true");
    writeFileSync(join(server, "start.sh"), "#!/bin/sh\n");
    chmodSync(join(server, "start.sh"), 0o755);
    writeFileSync(join(server, "logs", "console.log"), "");
    chmodSync(join(server, "eula.txt"), 0o644);

    secureTree(server, SERVER_TREE_PLAN, { gid, serversRoot: root });

    expect(statSync(server).mode & 0o777).toBe(0o770);
    expect(statSync(join(server, "logs")).mode & 0o777).toBe(0o770);
    expect(statSync(join(server, "server.jar")).mode & 0o7777).toBe(0o660);
    expect(statSync(join(server, "eula.txt")).mode & 0o7777).toBe(0o660);
    expect(statSync(join(server, "start.sh")).mode & 0o7777).toBe(0o770);
    expect(statSync(server).gid).toBe(gid);
    expect(statSync(join(server, "start.sh")).gid).toBe(gid);
    // Nothing is accessible to others.
    for (const name of ["server.jar", "eula.txt", "start.sh"]) {
      expect(statSync(join(server, name)).mode & 0o007).toBe(0);
    }
  });

  test("secureDirectory preserves an existing setgid bit when the 9-bit mode already matches", () => {
    const dir = join(tempDir(), "srv");
    mkdirSync(dir);
    chmodSync(dir, 0o2770);
    expect(statSync(dir).mode & 0o2000).toBe(0o2000);
    secureDirectory(dir, SERVER_DIR_MODE, { gid });
    expect(statSync(dir).mode & 0o2000).toBe(0o2000);
  });

  test("the shared runtime plan is read/execute only for the group", () => {
    const root = tempDir();
    const java = join(root, ".runtime", "java", "21");
    mkdirSync(join(java, "bin"), { recursive: true });
    writeFileSync(join(java, "bin", "java"), "elf");
    chmodSync(join(java, "bin", "java"), 0o750);
    writeFileSync(join(java, "release"), "x");
    chmodSync(join(java, "release"), 0o664);

    secureTree(join(root, ".runtime"), SHARED_TREE_PLAN, { gid, serversRoot: root });

    expect(statSync(join(root, ".runtime")).mode & 0o777).toBe(0o750);
    expect(statSync(join(java, "bin")).mode & 0o777).toBe(0o750);
    expect(statSync(join(java, "bin", "java")).mode & 0o7777).toBe(0o750);
    expect(statSync(join(java, "release")).mode & 0o7777).toBe(0o640);
  });

  test("symbolic links are not followed or changed", () => {
    const root = tempDir();
    const outside = join(root, "outside.txt");
    writeFileSync(outside, "secret");
    chmodSync(outside, 0o600);
    const server = join(root, "srv");
    mkdirSync(server);
    require("node:fs").symlinkSync(outside, join(server, "link"));
    secureTree(server, SERVER_TREE_PLAN, { gid, serversRoot: root });
    expect(statSync(outside).mode & 0o777).toBe(0o600);
  });

  test("inspectTree reports wrong group, lost group access and world access without requiring setgid on subdirs", () => {
    const root = tempDir();
    const server = join(root, "srv");
    mkdirSync(server);
    writeFileSync(join(server, "good.txt"), "x");
    writeFileSync(join(server, "world-readable.txt"), "x");
    writeFileSync(join(server, "no-group.txt"), "x");
    secureTree(server, SERVER_TREE_PLAN, { gid, serversRoot: root });
    chmodSync(server, 0o770);
    expect(inspectTree(server, SERVER_TREE_PLAN, gid)).toEqual([]);

    chmodSync(join(server, "world-readable.txt"), 0o664 | 0o004);
    chmodSync(join(server, "no-group.txt"), 0o600);

    const problems = inspectTree(server, SERVER_TREE_PLAN, gid).map(
      (p) => `${p.path.slice(server.length)}: ${p.problem}`,
    );
    expect(
      problems.some((p) => p.includes("no-group.txt") && p.includes("group access missing")),
    ).toBe(true);
    expect(problems.some((p) => p.includes("world-readable.txt") && p.includes("others"))).toBe(
      true,
    );

    // A different expected group is reported for every entry (capped by the limit).
    const wrong = inspectTree(server, SERVER_TREE_PLAN, gid + 12345, 3);
    expect(wrong).toHaveLength(3);
    expect(wrong[0]?.problem).toContain("group is");
  });

  test("a chown that is not permitted is reported, not thrown", () => {
    const root = tempDir();
    const errors: string[] = [];
    if (process.getuid?.() === 0) {
      return; // root can always chown
    }
    secureTree(root, SERVER_TREE_PLAN, {
      gid: 0,
      onChownError: (path) => errors.push(path),
    });
    expect(errors.length).toBeGreaterThan(0);
    void chownSync;
  });
});

describe("resolveCommandPath", () => {
  test("resolves bare names against the given search path and keeps explicit paths", () => {
    if (!posix) {
      expect(resolveCommandPath("systemctl", "win32")).toBe("systemctl");
      return;
    }
    const dir = tempDir();
    const tool = join(dir, "mytool");
    writeFileSync(tool, "#!/bin/sh\n");
    chmodSync(tool, 0o755);
    const plain = join(dir, "plain");
    writeFileSync(plain, "x");
    chmodSync(plain, 0o644);

    expect(resolveCommandPath("mytool", "linux", `/nonexistent:${dir}`)).toBe(tool);
    expect(resolveCommandPath("plain", "linux", dir)).toBe("plain");
    expect(resolveCommandPath("absent", "linux", dir)).toBe("absent");
    expect(resolveCommandPath("/usr/bin/systemctl", "linux", dir)).toBe("/usr/bin/systemctl");
  });
});

describe("handler_error logging", () => {
  test("sanitizeErrorMessage strips URL queries and control characters and caps length", () => {
    const message = sanitizeErrorMessage(
      new Error("PUT https://storage.example/a/b?sig=SECRET#frag failed\nwith\u0000nul"),
    );
    expect(message).not.toContain("SECRET");
    expect(message).not.toContain("\n");
    expect(message).not.toContain("\u0000");
    expect(message).toContain("https://storage.example/a/b?<redacted>");
    expect(sanitizeErrorMessage(new Error("x".repeat(1000))).length).toBeLessThan(310);
    expect(sanitizeErrorMessage(42)).toBe("non-error value");
  });

  test("a handler that throws is logged with the error name and sanitized message", async () => {
    const agent = generateSigningKeyPair();
    const owner = generateSigningKeyPair();
    const lines: string[] = [];
    const logger = createLogger({
      level: "debug",
      stdout: (l) => lines.push(l),
      stderr: (l) => lines.push(l),
    });
    const trust = createInMemoryTrustContext({
      agentKeyPair: agent,
      trustedAccountKeys: [owner.publicKey],
      now: () => NOW,
    });
    const registry = createCoreRegistry();
    const sent: TransportFrame[] = [];
    const queue = createCommandQueue({ trust, registry, sendFrame: (f) => sent.push(f), logger });
    queue.registerHandler("server.backup.create", () => {
      throw new RangeError("archive failed at https://x.example/up?token=SECRET");
    });
    const command = createSignedCommand(
      {
        type: "server.backup.create",
        body: { server_id: "srv" },
        agentPublicKey: agent.publicKey,
        signer: owner,
        counter: 1,
        now: NOW,
      },
      registry,
    );
    await queue.enqueue({
      v: PROTOCOL_VERSION,
      kind: "command",
      route: { agent: fingerprint(agent.publicKey) },
      body: command,
    });

    const ack = sent.find((f) => f.kind === "ack");
    expect(ack?.kind === "ack" && ack.body.code).toBe("handler_error");
    const logged = lines.find((l) => l.includes("handler_error"));
    expect(logged).toBeDefined();
    expect(logged).toContain("RangeError");
    expect(logged).toContain("archive failed");
    expect(logged).not.toContain("SECRET");
  });
});

describe("WebSocket error log level", () => {
  test("warns for the first 3 failed attempts, drops to debug, logs info summary every 10 attempts, and resets on connect", async () => {
    const lines: string[] = [];
    const logger = createLogger({
      level: "debug",
      stdout: (l) => lines.push(l),
      stderr: (l) => lines.push(l),
    });
    const pending: (() => void)[] = [];
    const timers: TimerProvider = {
      setTimeout: (fn) => {
        pending.push(fn);
        return pending.length;
      },
      clearTimeout: () => {},
      setInterval: () => 0,
      clearInterval: () => {},
      now: () => NOW,
    };
    const sockets: WebSocketLike[] = [];
    const connection = createAgentConnection({
      apiUrl: "https://api.tegra.example",
      agentId: "a".repeat(32),
      logger,
      timers,
      webSocketFactory: () => {
        const socket: WebSocketLike = {
          readyState: 1,
          onopen: null,
          onmessage: null,
          onclose: null,
          onerror: null,
          send() {},
          close() {},
        };
        sockets.push(socket);
        return socket;
      },
      onFrame: () => {},
    });
    connection.start();

    for (let attempt = 0; attempt < 21; attempt++) {
      const socket = sockets[attempt];
      socket?.onerror?.(new Error("down"));
      socket?.onclose?.({ code: 1006 });
      const next = pending.shift();
      next?.();
    }

    const errors = lines.filter((l) => l.includes("WebSocket error occurred"));
    expect(errors).toHaveLength(21);
    expect(errors.slice(0, 3).every((l) => l.includes('"level":"warn"'))).toBe(true);
    expect(errors.slice(3).every((l) => l.includes('"level":"debug"'))).toBe(true);

    const summaries = lines.filter((l) => l.includes("Still reconnecting"));
    expect(summaries).toHaveLength(2);
    expect(summaries[0]).toContain('"level":"info"');
    expect(summaries[0]).toContain('"attempt":10');
    expect(summaries[1]).toContain('"level":"info"');
    expect(summaries[1]).toContain('"attempt":20');

    // Connect successfully -> consecutive failure counter resets so next error warns again
    const activeSocket = sockets[sockets.length - 1];
    activeSocket?.onopen?.();
    await Promise.resolve();
    await Promise.resolve();
    const beforeNextErr = lines.length;
    activeSocket?.onerror?.(new Error("new outage"));
    const afterReconnectErr = lines
      .slice(beforeNextErr)
      .find((l) => l.includes("WebSocket error occurred"));
    expect(afterReconnectErr).toContain('"level":"warn"');

    connection.stop();
  });
});

describe("server.backup.config.get", () => {
  test("returns the current configuration without secrets and needs only viewer", async () => {
    const { createBackupManager, registerBackupHandlers } = await import("../backup");
    const { openTestEvent } = await import("./test-events");
    const root = tempDir();
    const manager = createBackupManager({
      stateDir: join(root, "state"),
      serversBaseDir: join(root, "servers"),
      localBackupsDir: join(root, "backups"),
    });
    manager.setConfig({
      server_id: "srv",
      auto_before_change: false,
      s3: {
        enabled: true,
        bucket: "b",
        region: "us-east-1",
        endpoint: "https://s3.example.com",
        access_key_id: "AKIDEXAMPLE",
        secret_access_key: "SECRETKEYEXAMPLE",
      },
    });

    const agent = generateSigningKeyPair();
    const owner = generateSigningKeyPair();
    const viewer = generateSigningKeyPair();
    const trust = createInMemoryTrustContext({
      agentKeyPair: agent,
      trustedAccountKeys: [owner.publicKey],
      members: [
        {
          account_key: Buffer.from(viewer.publicKey).toString("base64url"),
          account: fingerprint(viewer.publicKey),
          granted_by: fingerprint(owner.publicKey),
          role: "viewer",
          servers: ["srv"],
          issued_at: NOW,
        },
      ],
      now: () => NOW,
    });
    const registry = createCoreRegistry();
    const sent: TransportFrame[] = [];
    const queue = createCommandQueue({
      trust,
      registry,
      sendFrame: (f) => sent.push(f),
      logger: createLogger({ level: "error", stdout: () => {}, stderr: () => {} }),
    });
    registerBackupHandlers(queue, manager);

    const command = createSignedCommand(
      {
        type: "server.backup.config.get",
        body: { server_id: "srv" },
        agentPublicKey: agent.publicKey,
        signer: viewer,
        counter: 1,
        now: NOW,
      },
      registry,
    );
    await queue.enqueue({
      v: PROTOCOL_VERSION,
      kind: "command",
      route: { agent: fingerprint(agent.publicKey) },
      body: command,
    });

    const event = sent.find((f) => f.kind === "event");
    expect(event?.kind).toBe("event");
    if (event?.kind !== "event") return;
    const opened = openTestEvent(event.body, agent.publicKey, viewer);
    expect(opened.header.type).toBe("server.backup.config.result");
    const config = (
      opened.body as { config: { auto_before_change: boolean; s3: Record<string, unknown> } }
    ).config;
    expect(config.auto_before_change).toBe(false);
    expect(config.s3.credentials_configured).toBe(true);
    expect(JSON.stringify(opened.body)).not.toContain("SECRETKEYEXAMPLE");
    expect(JSON.stringify(opened.body)).not.toContain("AKIDEXAMPLE");
  });
});
