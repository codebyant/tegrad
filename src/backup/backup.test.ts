// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, describe, expect, test } from "bun:test";
import {
  appendFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCommandQueue } from "../agent/jobs";
import { createLogger } from "../agent/logger";
import { openTestEvent } from "../agent/test-events";
import { generateSigningKeyPair, ready, toBase64Url } from "../crypto";
import { createZipBuffer } from "../files";
import {
  createCoreRegistry,
  createInMemoryTrustContext,
  createSignedCommand,
  openCommand,
  PROTOCOL_VERSION,
  ProtocolError,
  signSessionCertificate,
  type TransportFrame,
} from "../protocol";
import {
  type BackupDestination,
  type BackupMetadata,
  type BackupTimerHandle,
  type BackupTimerProvider,
  createBackupHook,
  createBackupManager,
  registerBackupHandlers,
  type ServerRuntimeProvider,
} from "./index";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function createSampleServer(
  serversDir: string,
  serverId: string,
  files: Readonly<Record<string, string>>,
): string {
  const serverDir = join(serversDir, serverId);
  mkdirSync(join(serverDir, "logs"), { recursive: true });
  for (const [relPath, content] of Object.entries(files)) {
    const fullPath = join(serverDir, relPath);
    mkdirSync(join(fullPath, ".."), { recursive: true });
    writeFileSync(fullPath, content, "utf8");
  }
  return serverDir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir !== undefined) {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe("Local backups, rotation, and independent destinations", () => {
  test("creates local backups, rotates oldest beyond retention_count, and enforces 0700/0600 on POSIX", async () => {
    const root = makeTempDir("tegrad-bkp-local-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    const backupsDir = join(root, "backups");
    createSampleServer(serversDir, "survival", {
      "world/level.dat": "level-v1",
      "server.properties": "motd=Hello\n",
    });

    let clock = 1_700_000_000_000;
    const manager = createBackupManager({
      stateDir,
      serversBaseDir: serversDir,
      localBackupsDir: backupsDir,
      now: () => {
        clock += 1000;
        return clock;
      },
    });

    manager.setConfig({
      server_id: "survival",
      local: { enabled: true, retention_count: 2 },
    });

    const b1 = await manager.createBackup({ server_id: "survival", note: "first" });
    const b2 = await manager.createBackup({ server_id: "survival", note: "second" });
    const b3 = await manager.createBackup({ server_id: "survival", note: "third" });

    expect(b1.destinations).toHaveLength(1);
    expect(b1.destinations[0]?.ok).toBe(true);
    expect(b3.destinations[0]?.ok).toBe(true);

    const listed = await manager.listBackups({ server_id: "survival" });
    expect(listed.errors).toEqual([]);
    expect(listed.backups.map((b) => b.id)).toEqual([b3.backup_id, b2.backup_id]);
    expect(existsSync(join(backupsDir, "survival", `${b1.backup_id}.zip`))).toBe(false);

    if (process.platform !== "win32") {
      expect(statSync(backupsDir).mode & 0o777).toBe(0o700);
      expect(statSync(join(backupsDir, "survival")).mode & 0o777).toBe(0o700);
      expect(statSync(join(backupsDir, "survival", `${b3.backup_id}.zip`)).mode & 0o777).toBe(
        0o600,
      );
    }
  });

  test("all destinations disabled is valid and succeeds cleanly", async () => {
    const root = makeTempDir("tegrad-bkp-none-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    const backupsDir = join(root, "backups");
    createSampleServer(serversDir, "creative", { "server.properties": "motd=Creative\n" });

    const manager = createBackupManager({
      stateDir,
      serversBaseDir: serversDir,
      localBackupsDir: backupsDir,
    });

    const cfg = manager.setConfig({
      server_id: "creative",
      local: { enabled: false },
      s3: { enabled: false },
      tegra_cloud: { enabled: false },
    });
    expect(cfg.local.enabled).toBe(false);
    expect(cfg.s3.enabled).toBe(false);
    expect(cfg.tegra_cloud.enabled).toBe(false);

    const created = await manager.createBackup({ server_id: "creative" });
    expect(created.destinations).toEqual([]);
    expect(created.size_bytes).toBe(0);

    const listed = await manager.listBackups({ server_id: "creative" });
    expect(listed.backups).toEqual([]);
    expect(listed.errors).toEqual([]);
  });

  test("failure of one destination does not abort or crash other destinations", async () => {
    const root = makeTempDir("tegrad-bkp-iso-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    createSampleServer(serversDir, "smp", { "world/region.mca": "chunk-data" });

    const uploadedToGood: string[] = [];
    const failingDest: BackupDestination = {
      kind: "s3",
      isEnabled: () => true,
      async upload() {
        throw new Error("Simulated S3 outage");
      },
      async list() {
        throw new Error("Simulated S3 list outage");
      },
      async download() {
        throw new Error("Simulated S3 download outage");
      },
      async delete() {
        throw new Error("Simulated S3 delete outage");
      },
    };

    const goodDest: BackupDestination = {
      kind: "local",
      isEnabled: () => true,
      async upload(archive, ctx): Promise<BackupMetadata> {
        uploadedToGood.push(ctx.backupId);
        return {
          id: ctx.backupId,
          server_id: ctx.serverId,
          created_at: ctx.createdAt,
          size_bytes: archive.byteLength,
          sha256: ctx.sha256,
          trigger: ctx.trigger,
          destination: "local",
        };
      },
      async list(): Promise<readonly BackupMetadata[]> {
        return [];
      },
      async download() {
        return new Uint8Array(0);
      },
      async delete() {},
    };

    const progressEvents: { destination: string; state: string; error?: string | undefined }[] = [];
    const manager = createBackupManager({
      stateDir,
      serversBaseDir: serversDir,
      destinations: [failingDest, goodDest],
      onUploadProgress: (event) => progressEvents.push(event),
    });

    const result = await manager.createBackup({ server_id: "smp" });
    expect(result.destinations).toHaveLength(1);
    expect(result.destinations[0]).toMatchObject({
      destination: "local",
      ok: true,
    });
    expect(result.pending_uploads).toHaveLength(1);
    expect(result.pending_uploads?.[0]).toMatchObject({
      destination: "s3",
      state: "queued",
    });
    expect(uploadedToGood).toEqual([result.backup_id]);

    await manager.waitForPendingUploads();
    expect(progressEvents.some((e) => e.destination === "s3" && e.state === "failed")).toBe(true);

    const listed = await manager.listBackups({ server_id: "smp" });
    expect(listed.errors).toEqual([{ destination: "s3", error: "Simulated S3 list outage" }]);
  });
});

describe("World consistency (save-off / save-all flush / save-on)", () => {
  test("calls makeServerReadable after save-all flush confirmation and before archiving", async () => {
    const root = makeTempDir("tegrad-bkp-readable-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    const backupsDir = join(root, "backups");
    const serverDir = createSampleServer(serversDir, "live-perms", {
      "world/level.dat": "world-bytes",
      "logs/console.log": "[12:00:00] [Server thread/INFO]: Done!\n",
    });

    const timeline: string[] = [];
    const runtime: ServerRuntimeProvider = {
      isRunning: async () => true,
      sendConsole(_serverId, line) {
        timeline.push(`console:${line}`);
        if (line === "save-all flush") {
          appendFileSync(
            join(serverDir, "logs", "console.log"),
            "[12:00:01] [Server thread/INFO]: Saved the game\n",
          );
        }
      },
    };

    const manager = createBackupManager({
      stateDir,
      serversBaseDir: serversDir,
      localBackupsDir: backupsDir,
      runtime,
      makeServerReadableImpl: async (id) => {
        timeline.push(`readable:${id}`);
        return true;
      },
      archiveImpl: (opts) => {
        timeline.push(`archive:${opts.serverId}`);
        return {
          buffer: createZipBuffer([{ name: "world/level.dat", data: new Uint8Array([1, 2, 3]) }]),
          sha256: "a".repeat(64),
          entryCount: 1,
          uncompressedBytes: 3,
        };
      },
    });
    manager.setConfig({ server_id: "live-perms", local: { enabled: true } });

    const res = await manager.createBackup({ server_id: "live-perms" });
    expect(res.destinations[0]?.ok).toBe(true);
    expect(timeline).toEqual([
      "console:save-off",
      "console:save-all flush",
      "readable:live-perms",
      "archive:live-perms",
      "console:save-on",
    ]);
  });

  test("sends save-off, save-all flush, waits for confirmation, archives, and sends save-on when running", async () => {
    const root = makeTempDir("tegrad-bkp-running-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    const backupsDir = join(root, "backups");
    const serverDir = createSampleServer(serversDir, "live", {
      "world/level.dat": "world-bytes",
      "logs/console.log": "[12:00:00] [Server thread/INFO]: Done!\n",
    });

    const sentLines: string[] = [];
    const runtime: ServerRuntimeProvider = {
      isRunning: async () => true,
      sendConsole(_serverId, line) {
        sentLines.push(line);
        if (line === "save-all flush") {
          appendFileSync(
            join(serverDir, "logs", "console.log"),
            "[12:00:01] [Server thread/INFO]: Saved the game\n",
          );
        }
      },
    };

    const manager = createBackupManager({
      stateDir,
      serversBaseDir: serversDir,
      localBackupsDir: backupsDir,
      runtime,
      saveTimeoutMs: 500,
      savePollIntervalMs: 5,
    });

    const res = await manager.createBackup({ server_id: "live" });
    expect(res.destinations[0]?.ok).toBe(true);
    expect(sentLines).toEqual(["save-off", "save-all flush", "save-on"]);
  });

  test("ALWAYS sends save-on in finally even when waiting for save confirmation times out", async () => {
    const root = makeTempDir("tegrad-bkp-timeout-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    const backupsDir = join(root, "backups");
    createSampleServer(serversDir, "stuck", {
      "world/level.dat": "world-bytes",
      "logs/console.log": "[12:00:00] [Server thread/INFO]: Running...\n",
    });

    const sentLines: string[] = [];
    let clock = 1000;
    const runtime: ServerRuntimeProvider = {
      isRunning: async () => true,
      sendConsole(_serverId, line) {
        sentLines.push(line);
      },
    };

    const manager = createBackupManager({
      stateDir,
      serversBaseDir: serversDir,
      localBackupsDir: backupsDir,
      runtime,
      saveTimeoutMs: 50,
      savePollIntervalMs: 10,
      now: () => clock,
      sleep: async (ms) => {
        clock += ms;
      },
    });

    await expect(manager.createBackup({ server_id: "stuck" })).rejects.toThrow(
      /Timed out waiting for Minecraft server save confirmation/,
    );
    expect(sentLines).toEqual(["save-off", "save-all flush", "save-on"]);
  });

  test("ALWAYS sends save-on in finally even when archiving throws", async () => {
    const root = makeTempDir("tegrad-bkp-archfail-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    const backupsDir = join(root, "backups");
    const serverDir = createSampleServer(serversDir, "errsrv", {
      "logs/console.log": "",
    });

    const sentLines: string[] = [];
    const runtime: ServerRuntimeProvider = {
      isRunning: async () => true,
      sendConsole(_serverId, line) {
        sentLines.push(line);
        if (line === "save-all flush") {
          appendFileSync(
            join(serverDir, "logs", "console.log"),
            "[12:00:01] [Server thread/INFO]: Saved the world\n",
          );
        }
      },
    };

    const manager = createBackupManager({
      stateDir,
      serversBaseDir: serversDir,
      localBackupsDir: backupsDir,
      runtime,
      saveTimeoutMs: 500,
      savePollIntervalMs: 5,
      archiveImpl: () => {
        throw new Error("Simulated archive I/O failure");
      },
    });

    await expect(manager.createBackup({ server_id: "errsrv" })).rejects.toThrow(
      "Simulated archive I/O failure",
    );
    expect(sentLines).toEqual(["save-off", "save-all flush", "save-on"]);
  });

  test("archives directly without console commands when server is stopped", async () => {
    const root = makeTempDir("tegrad-bkp-stopped-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    const backupsDir = join(root, "backups");
    createSampleServer(serversDir, "offline", { "world/level.dat": "stopped-world" });

    const sentLines: string[] = [];
    const runtime: ServerRuntimeProvider = {
      isRunning: async () => false,
      sendConsole(_serverId, line) {
        sentLines.push(line);
      },
    };

    const manager = createBackupManager({
      stateDir,
      serversBaseDir: serversDir,
      localBackupsDir: backupsDir,
      runtime,
    });

    const res = await manager.createBackup({ server_id: "offline" });
    expect(res.destinations[0]?.ok).toBe(true);
    expect(sentLines).toEqual([]);
  });
});

describe("BackupHook and scheduled backups", () => {
  test("BackupHook runs backup by default (auto_before_change: true) and skips when toggled off", async () => {
    const root = makeTempDir("tegrad-bkp-hook-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    const backupsDir = join(root, "backups");
    createSampleServer(serversDir, "modded", { "mods/example.jar": "jar-bytes" });

    const manager = createBackupManager({
      stateDir,
      serversBaseDir: serversDir,
      localBackupsDir: backupsDir,
    });
    const hook = createBackupHook(manager);

    // Default auto_before_change is true
    expect(manager.getConfig("modded").auto_before_change).toBe(true);
    await hook.beforeChange("modded");
    let listed = await manager.listBackups({ server_id: "modded" });
    expect(listed.backups).toHaveLength(1);
    expect(listed.backups[0]?.trigger).toBe("before_change");

    // Disable auto_before_change
    manager.setConfig({ server_id: "modded", auto_before_change: false });
    await hook.beforeChange("modded");
    listed = await manager.listBackups({ server_id: "modded" });
    expect(listed.backups).toHaveLength(1);
  });

  test("scheduler runs per-server interval backups and honors schedule retention_count", async () => {
    const root = makeTempDir("tegrad-bkp-sched-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    const backupsDir = join(root, "backups");
    createSampleServer(serversDir, "hourly", { "world/level.dat": "v1" });

    const scheduledCallbacks: { fn: () => void; ms: number; cleared: boolean }[] = [];
    const fakeTimers: BackupTimerProvider = {
      setInterval(fn, ms): BackupTimerHandle {
        const entry = { fn, ms, cleared: false };
        scheduledCallbacks.push(entry);
        return { id: entry };
      },
      clearInterval(handle) {
        const entry = handle.id as { cleared: boolean };
        entry.cleared = true;
      },
    };

    let clock = 1_700_000_000_000;
    const manager = createBackupManager({
      stateDir,
      serversBaseDir: serversDir,
      localBackupsDir: backupsDir,
      timers: fakeTimers,
      now: () => {
        clock += 1000;
        return clock;
      },
    });

    manager.setConfig({
      server_id: "hourly",
      schedule: { enabled: true, interval_minutes: 60, retention_count: 1 },
    });

    expect(scheduledCallbacks).toHaveLength(1);
    expect(scheduledCallbacks[0]?.ms).toBe(60 * 60_000);

    scheduledCallbacks[0]?.fn();
    await new Promise((r) => setTimeout(r, 20));
    scheduledCallbacks[0]?.fn();
    await new Promise((r) => setTimeout(r, 20));

    const listed = await manager.listBackups({ server_id: "hourly" });
    expect(listed.backups).toHaveLength(1);
    expect(listed.backups[0]?.trigger).toBe("scheduled");

    manager.close();
    expect(scheduledCallbacks[0]?.cleared).toBe(true);
  });
});

describe("Restore with safety backup and confinement", () => {
  test("takes a pre_restore safety backup before restoring files and rejects zip-slip archives", async () => {
    const root = makeTempDir("tegrad-bkp-restore-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    const backupsDir = join(root, "backups");
    const serverDir = createSampleServer(serversDir, "restorable", {
      "world/level.dat": "original-v1",
    });

    let clock = 1_700_000_000_000;
    const manager = createBackupManager({
      stateDir,
      serversBaseDir: serversDir,
      localBackupsDir: backupsDir,
      now: () => {
        clock += 1000;
        return clock;
      },
    });

    const originalBackup = await manager.createBackup({ server_id: "restorable" });
    // Mutate current server state
    writeFileSync(join(serverDir, "world", "level.dat"), "corrupted-v2", "utf8");

    const restoreRes = await manager.restoreBackup({
      server_id: "restorable",
      backup_id: originalBackup.backup_id,
    });

    expect(restoreRes.destination).toBe("local");
    expect(restoreRes.safety_backup?.trigger).toBe("pre_restore");
    expect(readFileSync(join(serverDir, "world", "level.dat"), "utf8")).toBe("original-v1");

    const listed = await manager.listBackups({ server_id: "restorable" });
    expect(listed.backups.some((b) => b.trigger === "pre_restore")).toBe(true);

    // Tamper local zip with zip-slip entry -> restore must fail closed
    const evilZip = createZipBuffer([
      { name: "../escaped.txt", data: new TextEncoder().encode("pwned") },
    ]);
    writeFileSync(join(backupsDir, "restorable", `${originalBackup.backup_id}.zip`), evilZip);
    await expect(
      manager.restoreBackup({
        server_id: "restorable",
        backup_id: originalBackup.backup_id,
      }),
    ).rejects.toThrow();
    expect(existsSync(join(serversDir, "escaped.txt"))).toBe(false);
  });
});

describe("S3 and Tegra Cloud destinations with fake HTTP servers", () => {
  test("S3 destination uploads, lists, downloads, rotates, deletes, and never leaks secrets", async () => {
    const root = makeTempDir("tegrad-bkp-s3-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    createSampleServer(serversDir, "s3srv", { "world/level.dat": "s3-world-v1" });

    const objects = new Map<string, Uint8Array>();
    const server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      async fetch(req) {
        const url = new URL(req.url);
        const key = url.pathname.replace(/^\/+/, "");
        if (req.method === "PUT") {
          const bytes = new Uint8Array(await req.arrayBuffer());
          objects.set(key, bytes);
          return new Response(null, { status: 200, headers: { ETag: '"abc"' } });
        }
        if (req.method === "HEAD") {
          const obj = objects.get(key);
          if (obj === undefined) {
            return new Response(null, { status: 404 });
          }
          return new Response(null, {
            status: 200,
            headers: { "Content-Length": String(obj.byteLength) },
          });
        }
        if (req.method === "GET") {
          const obj = objects.get(key);
          if (obj === undefined) {
            return new Response("Not Found", { status: 404 });
          }
          return new Response(obj, { status: 200 });
        }
        if (req.method === "DELETE") {
          objects.delete(key);
          return new Response(null, { status: 204 });
        }
        return new Response("Method Not Allowed", { status: 405 });
      },
    });

    const logLines: string[] = [];
    const logger = createLogger({
      level: "debug",
      stdout: (line) => logLines.push(line),
      stderr: (line) => logLines.push(line),
    });

    try {
      const secretKey = "SUPER_SECRET_S3_KEY_DO_NOT_LOG";
      const accessKey = "AKIA_TEST_ACCESS_KEY";
      let clock = 1_700_000_000_000;
      const manager = createBackupManager({
        stateDir,
        serversBaseDir: serversDir,
        localBackupsDir: join(root, "backups"),
        allowInsecure: true,
        logger,
        now: () => {
          clock += 1000;
          return clock;
        },
      });

      const cfg = manager.setConfig({
        server_id: "s3srv",
        local: { enabled: false },
        s3: {
          enabled: true,
          bucket: "tegra-backups",
          region: "us-east-1",
          endpoint: `http://127.0.0.1:${server.port}`,
          prefix: "prod",
          retention_count: 1,
          access_key_id: accessKey,
          secret_access_key: secretKey,
        },
      });

      expect(cfg.s3.credentials_configured).toBe(true);
      expect(JSON.stringify(cfg)).not.toContain(secretKey);
      expect(JSON.stringify(cfg)).not.toContain(accessKey);

      if (process.platform !== "win32") {
        const credsPath = manager.configStore.s3CredentialsPath;
        expect(statSync(credsPath).mode & 0o777).toBe(0o600);
      }

      const b1 = await manager.createBackup({ server_id: "s3srv" });
      expect(b1.destinations).toHaveLength(1);
      expect(b1.destinations[0]?.ok).toBe(true);

      const b2 = await manager.createBackup({ server_id: "s3srv" });
      expect(b2.destinations[0]?.ok).toBe(true);

      // Rotation kept only b2
      const listed = await manager.listBackups({ server_id: "s3srv", destination: "s3" });
      expect(listed.backups.map((b) => b.id)).toEqual([b2.backup_id]);
      expect(objects.has(`tegra-backups/prod/s3srv/${b1.backup_id}.zip`)).toBe(false);
      expect(objects.has(`tegra-backups/prod/s3srv/${b2.backup_id}.zip`)).toBe(true);

      // Restore from S3
      writeFileSync(join(serversDir, "s3srv", "world", "level.dat"), "changed", "utf8");
      const restored = await manager.restoreBackup({
        server_id: "s3srv",
        backup_id: b2.backup_id,
        destination: "s3",
      });
      expect(restored.destination).toBe("s3");
      expect(readFileSync(join(serversDir, "s3srv", "world", "level.dat"), "utf8")).toBe(
        "s3-world-v1",
      );

      // Delete from S3
      await manager.deleteBackup({
        server_id: "s3srv",
        backup_id: b2.backup_id,
        destination: "s3",
      });
      expect(objects.has(`tegra-backups/prod/s3srv/${b2.backup_id}.zip`)).toBe(false);

      // Verify secrets never appeared in logs
      const allLogs = logLines.join("\n");
      expect(allLogs).not.toContain(secretKey);
      expect(allLogs).not.toContain(accessKey);

      // On POSIX, permissive credentials file must be rejected by assertStrictPermissions
      if (process.platform !== "win32") {
        chmodSync(manager.configStore.s3CredentialsPath, 0o644);
        expect(() => manager.configStore.getS3Credentials("s3srv")).toThrow(/0600/);
      }
    } finally {
      server.stop(true);
    }
  });

  test("Tegra Cloud destination uploads and downloads via presigned URLs, enforces HTTPS and size limits", async () => {
    const root = makeTempDir("tegrad-bkp-cloud-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    createSampleServer(serversDir, "cloudsrv", { "world/level.dat": "cloud-world-v1" });

    let receivedBody: Uint8Array | undefined;
    let receivedShaHeader: string | null = null;
    const server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      async fetch(req) {
        if (req.method === "PUT") {
          receivedShaHeader = req.headers.get("x-tegra-backup-sha256");
          receivedBody = new Uint8Array(await req.arrayBuffer());
          return new Response(null, { status: 200 });
        }
        if (req.method === "GET") {
          if (receivedBody === undefined) {
            return new Response("Not Found", { status: 404 });
          }
          return new Response(receivedBody, { status: 200 });
        }
        return new Response("Method Not Allowed", { status: 405 });
      },
    });

    try {
      const uploadUrl = `http://127.0.0.1:${server.port}/upload?sig=secret-presigned-token`;
      const downloadUrl = `http://127.0.0.1:${server.port}/download?sig=secret-download-token`;

      // Strict mode (allowInsecure: false) rejects http:// loopback URLs
      const strictManager = createBackupManager({
        stateDir: join(root, "state-strict"),
        serversBaseDir: serversDir,
        localBackupsDir: join(root, "backups-strict"),
        allowInsecure: false,
      });
      strictManager.setConfig({
        server_id: "cloudsrv",
        local: { enabled: false },
        tegra_cloud: { enabled: true },
      });
      const strictRes = await strictManager.createBackup({
        server_id: "cloudsrv",
        tegra_cloud_upload_url: uploadUrl,
      });
      expect(strictRes.destinations[0]?.ok).toBe(false);
      expect(strictRes.destinations[0]?.error).toMatch(/https:\/\//);

      // Insecure test mode allows loopback HTTP
      const manager = createBackupManager({
        stateDir,
        serversBaseDir: serversDir,
        localBackupsDir: join(root, "backups"),
        allowInsecure: true,
      });
      manager.setConfig({
        server_id: "cloudsrv",
        local: { enabled: false },
        tegra_cloud: { enabled: true },
      });

      const created = await manager.createBackup({
        server_id: "cloudsrv",
        tegra_cloud_upload_url: uploadUrl,
      });
      expect(created.destinations[0]?.ok).toBe(true);
      expect(receivedBody?.byteLength).toBe(created.size_bytes);
      expect(receivedShaHeader as string | null).toBe(created.sha256);

      // Presigned URL must never be persisted on disk
      const indexContent = readFileSync(join(stateDir, "backup-cloud-index.json"), "utf8");
      expect(indexContent).not.toContain("secret-presigned-token");

      // Restore from Tegra Cloud presigned download URL
      writeFileSync(join(serversDir, "cloudsrv", "world", "level.dat"), "mutated", "utf8");
      const restored = await manager.restoreBackup({
        server_id: "cloudsrv",
        backup_id: created.backup_id,
        destination: "tegra_cloud",
        tegra_cloud_download_url: downloadUrl,
      });
      expect(restored.destination).toBe("tegra_cloud");
      expect(readFileSync(join(serversDir, "cloudsrv", "world", "level.dat"), "utf8")).toBe(
        "cloud-world-v1",
      );
    } finally {
      server.stop(true);
    }
  });
});

describe("Protocol commands, sensitivity, and server_id validation", () => {
  test("server.backup.restore and server.backup.delete reject session keys and accept direct account keys", async () => {
    await ready();
    const agentKeyPair = generateSigningKeyPair();
    const accountKeyPair = generateSigningKeyPair();
    const sessionKeyPair = generateSigningKeyPair();
    const registry = createCoreRegistry();
    const nowMs = 1_700_000_000_000;

    const sessionCert = signSessionCertificate({
      accountKeyPair,
      sessionPublicKey: sessionKeyPair.publicKey,
      notBefore: nowMs - 1000,
      notAfter: nowMs + 60_000,
      id: toBase64Url(new Uint8Array(16).fill(1)),
    });

    const trust = createInMemoryTrustContext({
      agentKeyPair,
      trustedAccountKeys: [accountKeyPair.publicKey],
      now: () => nowMs,
    });

    // Session key rejected for server.backup.restore
    const restoreWithSession = createSignedCommand(
      {
        type: "server.backup.restore",
        body: { server_id: "smp", backup_id: "bkp-1" },
        agentPublicKey: agentKeyPair.publicKey,
        signer: sessionKeyPair,
        session: sessionCert,
        counter: 1,
        now: nowMs,
      },
      registry,
    );
    try {
      await openCommand(restoreWithSession, trust, registry);
      expect.unreachable("Expected sensitive_requires_account_key");
    } catch (err) {
      expect(err instanceof ProtocolError && err.code).toBe("sensitive_requires_account_key");
    }

    // Session key rejected for server.backup.delete
    const deleteWithSession = createSignedCommand(
      {
        type: "server.backup.delete",
        body: { server_id: "smp", backup_id: "bkp-1" },
        agentPublicKey: agentKeyPair.publicKey,
        signer: sessionKeyPair,
        session: sessionCert,
        counter: 2,
        now: nowMs,
      },
      registry,
    );
    try {
      await openCommand(deleteWithSession, trust, registry);
      expect.unreachable("Expected sensitive_requires_account_key");
    } catch (err) {
      expect(err instanceof ProtocolError && err.code).toBe("sensitive_requires_account_key");
    }

    // Direct account key accepted for server.backup.restore
    const restoreWithAccount = createSignedCommand(
      {
        type: "server.backup.restore",
        body: { server_id: "smp", backup_id: "bkp-1" },
        agentPublicKey: agentKeyPair.publicKey,
        signer: accountKeyPair,
        counter: 1,
        now: nowMs,
      },
      registry,
    );
    const openedRestore = await openCommand(restoreWithAccount, trust, registry);
    expect(openedRestore.header.type).toBe("server.backup.restore");

    // Invalid server_id rejected at protocol boundary
    expect(() =>
      createSignedCommand(
        {
          type: "server.backup.create",
          body: { server_id: "../etc" },
          agentPublicKey: agentKeyPair.publicKey,
          signer: accountKeyPair,
          counter: 2,
          now: nowMs,
        },
        registry,
      ),
    ).toThrow(ProtocolError);
  });

  test("registerBackupHandlers executes config, create, list, restore, and delete through CommandQueue", async () => {
    await ready();
    const root = makeTempDir("tegrad-bkp-queue-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    const backupsDir = join(root, "backups");
    createSampleServer(serversDir, "qserver", { "world/level.dat": "queue-v1" });

    const agentKeyPair = generateSigningKeyPair();
    const accountKeyPair = generateSigningKeyPair();
    const nowMs = 1_700_000_000_000;
    const registry = createCoreRegistry();
    const trust = createInMemoryTrustContext({
      agentKeyPair,
      trustedAccountKeys: [accountKeyPair.publicKey],
      now: () => nowMs,
    });

    const frames: TransportFrame[] = [];
    const logger = createLogger({ level: "error", stdout: () => {}, stderr: () => {} });
    const queue = createCommandQueue({
      trust,
      registry,
      sendFrame: (frame) => frames.push(frame),
      logger,
    });

    const manager = createBackupManager({
      stateDir,
      serversBaseDir: serversDir,
      localBackupsDir: backupsDir,
      now: () => nowMs,
    });
    registerBackupHandlers(queue, manager);

    let counter = 1;
    const sendCmd = async (type: string, body: unknown) => {
      const signed = createSignedCommand(
        {
          type,
          body,
          agentPublicKey: agentKeyPair.publicKey,
          signer: accountKeyPair,
          counter: counter++,
          now: nowMs,
        },
        registry,
      );
      await queue.enqueue({
        v: PROTOCOL_VERSION,
        kind: "command",
        route: { agent: "agent-1" },
        body: signed,
      });
    };

    await sendCmd("server.backup.config.set", {
      server_id: "qserver",
      local: { enabled: true, retention_count: 5 },
    });
    await sendCmd("server.backup.create", { server_id: "qserver", note: "from-queue" });
    await sendCmd("server.backup.list", { server_id: "qserver" });

    const events = frames
      .filter((f): f is Extract<TransportFrame, { kind: "event" }> => f.kind === "event")
      .map((f) => openTestEvent(f.body, agentKeyPair.publicKey, accountKeyPair));

    expect(events.map((e) => e.header.type)).toEqual([
      "server.backup.config.updated",
      "server.backup.created",
      "server.backup.list.result",
    ]);

    const createdBody = events[1]?.body as { readonly backup_id: string };
    await sendCmd("server.backup.restore", {
      server_id: "qserver",
      backup_id: createdBody.backup_id,
    });
    await sendCmd("server.backup.delete", {
      server_id: "qserver",
      backup_id: createdBody.backup_id,
    });

    const acks = frames.filter(
      (f): f is Extract<TransportFrame, { kind: "ack" }> => f.kind === "ack",
    );
    expect(acks).toHaveLength(5);
    expect(acks.every((a) => a.body.ok)).toBe(true);
  });
});

describe("Adversarial backup security checks", () => {
  test("never leaks presigned URL query tokens in validation errors, fetch errors, or logs", async () => {
    const root = makeTempDir("tegrad-bkp-adv-redact-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    const backupsDir = join(root, "backups");
    createSampleServer(serversDir, "cloudredact", { "world/level.dat": "v1" });

    const secretToken = "X-Amz-Signature=TOP_SECRET_PRESIGNED_TOKEN_987654321";
    const logLines: string[] = [];
    const logger = createLogger({
      level: "debug",
      stdout: (line) => logLines.push(line),
      stderr: (line) => logLines.push(line),
    });

    const manager = createBackupManager({
      stateDir,
      serversBaseDir: serversDir,
      localBackupsDir: backupsDir,
      allowInsecure: false,
      logger,
      cloudFetchImpl: async (url) => {
        throw new Error(`Simulated network failure for ${String(url)}`);
      },
    });
    manager.setConfig({
      server_id: "cloudredact",
      local: { enabled: false },
      tegra_cloud: { enabled: true },
    });

    // 1. Malformed URL with secret query token
    const badRes = await manager.createBackup({
      server_id: "cloudredact",
      tegra_cloud_upload_url: `not a valid url?${secretToken}`,
    });
    expect(badRes.destinations[0]?.ok).toBe(false);
    expect(badRes.destinations[0]?.error).not.toContain(secretToken);

    // 2. HTTP URL rejected in strict mode
    const httpRes = await manager.createBackup({
      server_id: "cloudredact",
      tegra_cloud_upload_url: `http://127.0.0.1:9000/upload?${secretToken}`,
    });
    expect(httpRes.destinations[0]?.ok).toBe(false);
    expect(httpRes.destinations[0]?.error).not.toContain(secretToken);

    // 3. Valid HTTPS URL whose fetch throws raw error containing the URL
    const fetchErrRes = await manager.createBackup({
      server_id: "cloudredact",
      tegra_cloud_upload_url: `https://backups.tegra.example/upload?${secretToken}`,
    });
    expect(fetchErrRes.destinations[0]?.ok).toBe(false);
    expect(fetchErrRes.destinations[0]?.error).not.toContain(secretToken);

    // 4. Download error must also never leak presigned token
    try {
      await manager.restoreBackup({
        server_id: "cloudredact",
        backup_id: "bkp-nonexistent",
        destination: "tegra_cloud",
        tegra_cloud_download_url: `https://backups.tegra.example/download?${secretToken}`,
      });
      expect.unreachable("Expected restore to fail");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      expect(msg).not.toContain(secretToken);
    }

    expect(logLines.join("\n")).not.toContain(secretToken);
  });

  test("blocks SSRF private/loopback HTTPS targets, redirects, host allowlist violations, and streaming overflow on Tegra Cloud", async () => {
    const root = makeTempDir("tegrad-bkp-adv-ssrf-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    const backupsDir = join(root, "backups");
    createSampleServer(serversDir, "ssrf", { "world/level.dat": "data" });

    const manager = createBackupManager({
      stateDir,
      serversBaseDir: serversDir,
      localBackupsDir: backupsDir,
      allowInsecure: false,
      cloudAllowedHosts: new Set(["backups.tegra.example"]),
      cloudMaxBytes: 1024,
      cloudFetchImpl: async (input) => {
        const url = String(input);
        if (url.includes("/redirect")) {
          return new Response(null, {
            status: 302,
            headers: { location: "https://evil.example/steal" },
          });
        }
        const stream = new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new Uint8Array(600).fill(0x41));
            controller.enqueue(new Uint8Array(600).fill(0x42));
            controller.close();
          },
        });
        return new Response(stream, { status: 200 });
      },
    });
    manager.setConfig({
      server_id: "ssrf",
      local: { enabled: false },
      tegra_cloud: { enabled: true },
    });

    const ssrfUrls = [
      "https://127.0.0.1/upload?sig=1",
      "https://169.254.169.254/latest/meta-data/",
      "https://10.0.0.1/internal",
      "https://192.168.1.1/router",
      "https://[::1]/local",
      "https://[::ffff:127.0.0.1]/mapped",
      "https://localhost/admin",
      "https://evil.example/upload",
      "https://backups.tegra.example:8443/upload",
    ];
    for (const url of ssrfUrls) {
      const res = await manager.createBackup({
        server_id: "ssrf",
        tegra_cloud_upload_url: url,
      });
      expect(res.destinations[0]?.ok).toBe(false);
      expect(res.destinations[0]?.error).toMatch(
        /not allowed|private or loopback|non-standard port/i,
      );
    }

    // Redirect on upload rejected
    const redirUpload = await manager.createBackup({
      server_id: "ssrf",
      tegra_cloud_upload_url: "https://backups.tegra.example/redirect",
    });
    expect(redirUpload.destinations[0]?.ok).toBe(false);
    expect(redirUpload.destinations[0]?.error).toMatch(/redirect/i);

    // Redirect on download rejected
    await expect(
      manager.restoreBackup({
        server_id: "ssrf",
        backup_id: "bkp-1",
        destination: "tegra_cloud",
        tegra_cloud_download_url: "https://backups.tegra.example/redirect",
      }),
    ).rejects.toMatchObject({ code: "backup_failed" });

    // Streaming overflow without Content-Length rejected
    await expect(
      manager.restoreBackup({
        server_id: "ssrf",
        backup_id: "bkp-1",
        destination: "tegra_cloud",
        tegra_cloud_download_url: "https://backups.tegra.example/overflow",
      }),
    ).rejects.toMatchObject({ code: "backup_failed" });
  });

  test("rejects traversal in backup_id and S3 bucket/prefix and prevents start.sh overwrite during restore", async () => {
    const root = makeTempDir("tegrad-bkp-adv-paths-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    const backupsDir = join(root, "backups");
    const serverDir = createSampleServer(serversDir, "safe-srv", {
      "world/level.dat": "good-world",
      "start.sh": "#!/bin/sh\nexec java -jar server.jar nogui\n",
    });

    const evilStartZip = createZipBuffer([
      { name: "start.sh", data: new TextEncoder().encode("#!/bin/sh\necho pwned\n") },
      { name: "world/level.dat", data: new TextEncoder().encode("replaced") },
    ]);

    const manager = createBackupManager({
      stateDir,
      serversBaseDir: serversDir,
      localBackupsDir: backupsDir,
      allowInsecure: false,
      cloudFetchImpl: async () => new Response(evilStartZip, { status: 200 }),
    });

    // Traversal backup_id rejected
    for (const badId of ["../escape", "a/b", "..", ".hidden", "id\\win"]) {
      await expect(
        manager.deleteBackup({ server_id: "safe-srv", backup_id: badId }),
      ).rejects.toThrow();
    }

    // Invalid S3 bucket / prefix rejected
    expect(() =>
      manager.setConfig({
        server_id: "safe-srv",
        s3: {
          enabled: false,
          bucket: "../other-bucket",
        },
      }),
    ).toThrow(ProtocolError);

    expect(() =>
      manager.setConfig({
        server_id: "safe-srv",
        s3: {
          enabled: false,
          prefix: "../../other-server",
        },
      }),
    ).toThrow(ProtocolError);

    // Local backup omits start.sh so restoring an agent-created backup succeeds cleanly
    const created = await manager.createBackup({ server_id: "safe-srv" });
    writeFileSync(join(serverDir, "world", "level.dat"), "mutated", "utf8");
    const restored = await manager.restoreBackup({
      server_id: "safe-srv",
      backup_id: created.backup_id,
    });
    expect(restored.safety_backup?.destinations.some((d) => d.ok)).toBe(true);
    expect(readFileSync(join(serverDir, "world", "level.dat"), "utf8")).toBe("good-world");

    // Remote archive attempting to overwrite start.sh MUST fail closed
    await expect(
      manager.restoreBackup({
        server_id: "safe-srv",
        backup_id: "bkp-remote-evil",
        destination: "tegra_cloud",
        tegra_cloud_download_url: "https://backups.tegra.example/evil.zip",
      }),
    ).rejects.toThrow(/protected path/i);
    expect(readFileSync(join(serverDir, "start.sh"), "utf8")).toBe(
      "#!/bin/sh\nexec java -jar server.jar nogui\n",
    );
  });

  test("fails closed with hash_mismatch when local backup archive is tampered", async () => {
    const root = makeTempDir("tegrad-bkp-adv-hash-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    const backupsDir = join(root, "backups");
    createSampleServer(serversDir, "hashsrv", { "world/level.dat": "original" });

    const manager = createBackupManager({
      stateDir,
      serversBaseDir: serversDir,
      localBackupsDir: backupsDir,
    });
    const created = await manager.createBackup({ server_id: "hashsrv" });

    // Replace archive bytes with a different valid zip while keeping original metadata hash
    const tamperedZip = createZipBuffer([
      { name: "world/level.dat", data: new TextEncoder().encode("tampered") },
    ]);
    writeFileSync(join(backupsDir, "hashsrv", `${created.backup_id}.zip`), tamperedZip);

    await expect(
      manager.restoreBackup({
        server_id: "hashsrv",
        backup_id: created.backup_id,
      }),
    ).rejects.toMatchObject({ code: "hash_mismatch" });
    expect(readFileSync(join(serversDir, "hashsrv", "world", "level.dat"), "utf8")).toBe(
      "original",
    );
  });
});
