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
  inspectTree,
  resolveGroupId,
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

describe.skipIf(!posix)("server file permissions", () => {
  // Use the current gid so chown always succeeds without privileges.
  const gid = posix ? (process.getgid?.() ?? 0) : 0;

  test("secureTree gives dirs setgid 2770, files 0660 and keeps executables executable for the group", () => {
    const root = tempDir();
    const server = join(root, "srv");
    mkdirSync(join(server, "logs"), { recursive: true });
    writeFileSync(join(server, "server.jar"), "jar");
    writeFileSync(join(server, "eula.txt"), "eula=true");
    writeFileSync(join(server, "start.sh"), "#!/bin/sh\n");
    chmodSync(join(server, "start.sh"), 0o755);
    writeFileSync(join(server, "logs", "console.log"), "");
    chmodSync(join(server, "eula.txt"), 0o644);

    secureTree(server, SERVER_TREE_PLAN, { gid });

    expect(statSync(server).mode & 0o7777).toBe(0o2770);
    expect(statSync(join(server, "logs")).mode & 0o7777).toBe(0o2770);
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

  test("an explicit chmod to 770 would drop setgid; secureDirectory keeps it", () => {
    const dir = join(tempDir(), "srv");
    mkdirSync(dir);
    secureDirectory(dir, 0o2770, { gid });
    expect(statSync(dir).mode & 0o2000).toBe(0o2000);
    chmodSync(dir, 0o770);
    expect(statSync(dir).mode & 0o2000).toBe(0);
    secureDirectory(dir, 0o2770, { gid });
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

    secureTree(join(root, ".runtime"), SHARED_TREE_PLAN, { gid });

    expect(statSync(join(root, ".runtime")).mode & 0o7777).toBe(0o2750);
    expect(statSync(join(java, "bin")).mode & 0o7777).toBe(0o2750);
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
    secureTree(server, SERVER_TREE_PLAN, { gid });
    expect(statSync(outside).mode & 0o777).toBe(0o600);
  });

  test("inspectTree reports wrong group, missing setgid, lost group access and world access", () => {
    const root = tempDir();
    const server = join(root, "srv");
    mkdirSync(server);
    writeFileSync(join(server, "good.txt"), "x");
    writeFileSync(join(server, "world-readable.txt"), "x");
    writeFileSync(join(server, "no-group.txt"), "x");
    secureTree(server, SERVER_TREE_PLAN, { gid });
    expect(inspectTree(server, SERVER_TREE_PLAN, gid)).toEqual([]);

    chmodSync(join(server, "world-readable.txt"), 0o664 | 0o004);
    chmodSync(join(server, "no-group.txt"), 0o600);
    chmodSync(server, 0o770);

    const problems = inspectTree(server, SERVER_TREE_PLAN, gid).map(
      (p) => `${p.path.slice(server.length)}: ${p.problem}`,
    );
    expect(problems.some((p) => p.includes("missing the setgid bit"))).toBe(true);
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
  test("warns for the first failed attempts, then drops to debug", () => {
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
          readyState: 0,
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

    for (let attempt = 0; attempt < 6; attempt++) {
      const socket = sockets[attempt];
      socket?.onerror?.(new Error("down"));
      socket?.onclose?.({ code: 1006 });
      const next = pending.shift();
      next?.();
    }
    connection.stop();

    const errors = lines.filter((l) => l.includes("WebSocket error occurred"));
    expect(errors).toHaveLength(6);
    expect(
      errors.slice(0, 3).every((l) => l.includes('"level":"warn"') || l.includes("warn")),
    ).toBe(true);
    expect(errors.slice(3).every((l) => l.includes("debug"))).toBe(true);
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
