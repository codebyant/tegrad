// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AgentApiError,
  createAgentApiClient,
  createCommandQueue,
  createLogger,
  type TransportCommandFrame,
} from "../agent";
import { openTestEvent } from "../agent/test-events";
import { fingerprint, generateSigningKeyPair, ready } from "../crypto";
import {
  createCoreRegistry,
  createInMemoryTrustContext,
  createSignedCommand,
  PROTOCOL_VERSION,
  type ServerBackupUploadEvent,
  serverBackupUploadEventSchema,
  signSessionCertificate,
  type TransportFrame,
} from "../protocol";
import { createBackupManager, registerBackupHandlers } from "./index";
import type { BackupCreateResult, BackupListResult } from "./types";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function createSampleServer(
  serversDir: string,
  serverId: string,
  files: Readonly<Record<string, string | Uint8Array>>,
): void {
  const serverDir = join(serversDir, serverId);
  mkdirSync(join(serverDir, "logs"), { recursive: true });
  for (const [relPath, content] of Object.entries(files)) {
    const fullPath = join(serverDir, relPath);
    mkdirSync(join(fullPath, ".."), { recursive: true });
    writeFileSync(fullPath, content);
  }
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

describe("Background multi-destination backups and progress events", () => {
  test("server.backup.create responds after local finishes while Tegra Cloud uploads and confirms in background", async () => {
    const root = makeTempDir("tegrad-bkp-bg-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    const backupsDir = join(root, "backups");
    createSampleServer(serversDir, "smp", { "world/level.dat": "cloud-bg-world-v1" });

    const putStarted = deferred<void>();
    const allowPutFinish = deferred<void>();
    let uploadedBytes: Uint8Array | undefined;
    const confirmCalls: string[] = [];

    let storagePort = 0;
    const storageServer = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      async fetch(req): Promise<Response> {
        const url = new URL(req.url);
        if (req.method === "PUT" && url.pathname === "/upload/object") {
          uploadedBytes = new Uint8Array(await req.arrayBuffer());
          putStarted.resolve();
          await allowPutFinish.promise;
          return new Response(null, { status: 200 });
        }
        if (req.method === "POST" && url.pathname === "/v1/agents/self/backup-upload-url") {
          return new Response(
            JSON.stringify({
              id: "cloud-bkp-99",
              put_url: `http://127.0.0.1:${storagePort}/upload/object?sig=secret-put-token`,
              headers: { "content-type": "application/octet-stream" },
              expires_at: Date.now() + 60_000,
              max_bytes: 10 * 1024 * 1024,
            }),
            { status: 200 },
          );
        }
        if (
          req.method === "POST" &&
          url.pathname === "/v1/agents/self/backups/cloud-bkp-99/confirm"
        ) {
          confirmCalls.push(url.pathname);
          return new Response(
            JSON.stringify({
              id: "cloud-bkp-99",
              size_bytes: uploadedBytes?.byteLength ?? 0,
              status: "stored",
            }),
            { status: 200 },
          );
        }
        return new Response("not found", { status: 404 });
      },
    });
    storagePort = storageServer.port ?? 0;

    try {
      const agent = generateSigningKeyPair();
      const owner = generateSigningKeyPair();
      const session = generateSigningKeyPair();
      const nowMs = 1_700_000_000_000;
      const cert = signSessionCertificate({
        sessionPublicKey: session.publicKey,
        accountKeyPair: owner,
        notBefore: nowMs - 1000,
        notAfter: nowMs + 3_600_000,
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
        sendFrame: (frame) => frames.push(frame),
        logger: createLogger({ level: "error", stdout: () => {}, stderr: () => {} }),
      });

      const apiClient = createAgentApiClient({
        apiUrl: `http://127.0.0.1:${storageServer.port}`,
        agentKeyPair: agent,
        allowInsecure: true,
        now: () => nowMs,
      });

      const manager = createBackupManager({
        stateDir,
        serversBaseDir: serversDir,
        localBackupsDir: backupsDir,
        allowInsecure: true,
        now: () => nowMs,
        cloudUploadUrlProvider: (req) => apiClient.requestBackupUploadUrl(req),
        cloudUploadConfirmer: async (id) => {
          await apiClient.confirmBackupUpload(id);
        },
        onUploadProgress: (event) => {
          queue.publish("server.backup", "server.backup.upload", event, {
            serverId: event.server_id,
          });
        },
      });
      manager.setConfig({
        server_id: "smp",
        local: { enabled: true },
        tegra_cloud: { enabled: true },
      });
      registerBackupHandlers(queue, manager);

      let counter = 1;
      const sendSessionCmd = async (type: string, body: unknown) => {
        const signed = createSignedCommand(
          {
            type,
            body,
            agentPublicKey: agent.publicKey,
            signer: session,
            session: cert,
            replyTo: session.publicKey,
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
      };

      await sendSessionCmd("agent.subscribe", { topics: ["server.backup"] });
      await sendSessionCmd("server.backup.create", { server_id: "smp", note: "bg-test" });

      // Command already acked and server.backup.created already sent before cloud PUT finishes
      const createdAck = frames.filter((f) => f.kind === "ack")[1];
      expect(createdAck?.kind === "ack" && createdAck.body.ok).toBe(true);
      expect(confirmCalls).toHaveLength(0);

      const openedEvents = () =>
        frames
          .filter((f): f is Extract<TransportFrame, { kind: "event" }> => f.kind === "event")
          .map((f) => openTestEvent(f.body, agent.publicKey, session));

      const createdEvent = openedEvents().find((e) => e.header.type === "server.backup.created");
      if (!createdEvent) throw new Error("Expected server.backup.created event");
      const createdResult = createdEvent.body as BackupCreateResult;
      expect(createdResult.destinations).toHaveLength(1);
      expect(createdResult.destinations[0]).toMatchObject({ destination: "local", ok: true });
      expect(createdResult.pending_uploads).toEqual([
        {
          destination: "tegra_cloud",
          state: "queued",
          sent_bytes: 0,
          total_bytes: createdResult.size_bytes,
        },
      ]);

      // Wait until cloud PUT has actually started and inspect server.backup.list while in flight
      await putStarted.promise;
      await sendSessionCmd("server.backup.list", { server_id: "smp" });
      const listInFlight = openedEvents()
        .filter((e) => e.header.type === "server.backup.list.result")
        .at(-1)?.body as BackupListResult;
      expect(listInFlight.backups).toHaveLength(1);
      expect(listInFlight.backups[0]?.destination).toBe("local");
      expect(listInFlight.backups[0]?.pending_uploads).toHaveLength(1);
      expect(listInFlight.backups[0]?.pending_uploads?.[0]).toMatchObject({
        destination: "tegra_cloud",
        state: "uploading",
        total_bytes: createdResult.size_bytes,
      });

      // Let cloud upload + confirmation finish in the background
      allowPutFinish.resolve();
      await manager.waitForPendingUploads();

      expect(confirmCalls).toEqual(["/v1/agents/self/backups/cloud-bkp-99/confirm"]);
      expect(uploadedBytes?.byteLength).toBe(createdResult.size_bytes);

      const uploadEvents = openedEvents()
        .filter((e) => e.header.type === "server.backup.upload")
        .map((e) => serverBackupUploadEventSchema.parse(e.body));
      expect(uploadEvents[0]?.state).toBe("queued");
      expect(uploadEvents.some((e) => e.state === "uploading")).toBe(true);
      expect(uploadEvents.at(-1)).toEqual({
        server_id: "smp",
        backup_id: createdResult.backup_id,
        destination: "tegra_cloud",
        state: "done",
        sent_bytes: createdResult.size_bytes,
        total_bytes: createdResult.size_bytes,
      });

      // After completion, pending_uploads is gone and both local + tegra_cloud appear in list
      const listedDone = await manager.listBackups({ server_id: "smp" });
      expect(listedDone.backups.map((b) => b.destination).sort()).toEqual(["local", "tegra_cloud"]);
      for (const b of listedDone.backups) {
        expect(b.pending_uploads).toBeUndefined();
      }

      // Local restore continues working normally
      writeFileSync(join(serversDir, "smp", "world", "level.dat"), "mutated", "utf8");
      await manager.restoreBackup({
        server_id: "smp",
        backup_id: createdResult.backup_id,
        destination: "local",
      });
      expect(readFileSync(join(serversDir, "smp", "world", "level.dat"), "utf8")).toBe(
        "cloud-bg-world-v1",
      );
    } finally {
      void storageServer.stop(true);
    }
  });

  test("throttles uploading progress events to at most ~2/sec and always emits final state", async () => {
    const root = makeTempDir("tegrad-bkp-throttle-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    const backupsDir = join(root, "backups");
    // 320 KiB incompressible bytes -> >5 chunks of 64 KiB
    const bigData = randomBytes(320 * 1024);
    createSampleServer(serversDir, "big", { "world/region.bin": bigData });

    let fakeNow = 1_700_000_000_000;
    const events: ServerBackupUploadEvent[] = [];
    const storageServer = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      async fetch(req) {
        await req.arrayBuffer();
        return new Response(null, { status: 200 });
      },
    });

    try {
      const manager = createBackupManager({
        stateDir,
        serversBaseDir: serversDir,
        localBackupsDir: backupsDir,
        allowInsecure: true,
        now: () => fakeNow,
        uploadProgressThrottleMs: 500,
        cloudFetchImpl: async (input, init) => {
          // Advance fakeNow by 150 ms per 64 KiB chunk read so >500ms passes across 6 chunks
          const body = init?.body;
          if (body instanceof ReadableStream) {
            const reader = body.getReader();
            while (true) {
              const { done } = await reader.read();
              if (done) break;
              fakeNow += 150;
            }
          }
          return await fetch(input, { method: "PUT", body: new Uint8Array(0) });
        },
        cloudUploadUrlProvider: async () => ({
          put_url: `http://127.0.0.1:${storageServer.port}/obj`,
          headers: {},
          expires_at: fakeNow + 60_000,
          max_bytes: 50 * 1024 * 1024,
        }),
        onUploadProgress: (ev) => events.push(ev),
      });
      manager.setConfig({
        server_id: "big",
        local: { enabled: true },
        tegra_cloud: { enabled: true },
      });

      await manager.createBackup({ server_id: "big" });
      await manager.waitForPendingUploads();

      const uploadingEvents = events.filter((e) => e.state === "uploading");
      // Initial uploading (0 bytes) + throttled updates (~500ms apart over ~600ms) -> far fewer than chunk count
      expect(uploadingEvents.length).toBeGreaterThanOrEqual(2);
      expect(uploadingEvents.length).toBeLessThanOrEqual(3);
      expect(events[0]?.state).toBe("queued");
      expect(events.at(-1)?.state).toBe("done");
      expect(events.at(-1)?.sent_bytes).toBe(events.at(-1)?.total_bytes);
    } finally {
      void storageServer.stop(true);
    }
  });

  test("failed confirm or PUT leaves local backup intact, omits failed upload from cloud index, and exposes stable code", async () => {
    const root = makeTempDir("tegrad-bkp-confirm-fail-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    const backupsDir = join(root, "backups");
    createSampleServer(serversDir, "srv", { "world/level.dat": "keep-local" });

    const storageServer = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      async fetch(req) {
        await req.arrayBuffer();
        return new Response(null, { status: 200 });
      },
    });

    try {
      const events: ServerBackupUploadEvent[] = [];
      const manager = createBackupManager({
        stateDir,
        serversBaseDir: serversDir,
        localBackupsDir: backupsDir,
        allowInsecure: true,
        cloudUploadUrlProvider: async () => ({
          id: "cloud-bkp-fail",
          put_url: `http://127.0.0.1:${storageServer.port}/obj?sig=SECRET_DO_NOT_LEAK`,
          headers: {},
          expires_at: Date.now() + 60_000,
          max_bytes: 10 * 1024 * 1024,
        }),
        cloudUploadConfirmer: async () => {
          throw new AgentApiError("quota_exceeded", "Backup storage quota exceeded", 413);
        },
        onUploadProgress: (ev) => events.push(ev),
      });
      manager.setConfig({
        server_id: "srv",
        local: { enabled: true },
        tegra_cloud: { enabled: true },
      });

      const created = await manager.createBackup({ server_id: "srv" });
      expect(created.destinations[0]).toMatchObject({ destination: "local", ok: true });
      await manager.waitForPendingUploads();

      expect(events.at(-1)).toMatchObject({
        server_id: "srv",
        backup_id: created.backup_id,
        destination: "tegra_cloud",
        state: "failed",
        error: "quota_exceeded",
      });
      expect(JSON.stringify(events)).not.toContain("SECRET_DO_NOT_LEAK");

      // Backup was NOT recorded in tegra_cloud index because confirm failed
      const cloudList = await manager.listBackups({ server_id: "srv", destination: "tegra_cloud" });
      expect(cloudList.backups).toHaveLength(0);

      // Local backup remains valid and list shows pending_uploads failed entry
      const allList = await manager.listBackups({ server_id: "srv" });
      expect(allList.backups).toHaveLength(1);
      expect(allList.backups[0]?.destination).toBe("local");
      expect(allList.backups[0]?.pending_uploads).toEqual([
        {
          destination: "tegra_cloud",
          state: "failed",
          sent_bytes: created.size_bytes,
          total_bytes: created.size_bytes,
          error: "quota_exceeded",
        },
      ]);
    } finally {
      void storageServer.stop(true);
    }
  });

  test("single destination (tegra_cloud only) preserves synchronous result and still runs confirm", async () => {
    const root = makeTempDir("tegrad-bkp-single-");
    const stateDir = join(root, "state");
    const serversDir = join(root, "servers");
    const backupsDir = join(root, "backups");
    createSampleServer(serversDir, "onlycloud", { "world/level.dat": "single" });

    const confirmedIds: string[] = [];
    const storageServer = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      async fetch(req) {
        await req.arrayBuffer();
        return new Response(null, { status: 200 });
      },
    });

    try {
      const events: ServerBackupUploadEvent[] = [];
      const manager = createBackupManager({
        stateDir,
        serversBaseDir: serversDir,
        localBackupsDir: backupsDir,
        allowInsecure: true,
        cloudUploadUrlProvider: async () => ({
          id: "single-cloud-id",
          put_url: `http://127.0.0.1:${storageServer.port}/obj`,
          headers: {},
          expires_at: Date.now() + 60_000,
          max_bytes: 10 * 1024 * 1024,
        }),
        cloudUploadConfirmer: async (id) => {
          confirmedIds.push(id);
        },
        onUploadProgress: (ev) => events.push(ev),
      });
      manager.setConfig({
        server_id: "onlycloud",
        local: { enabled: false },
        tegra_cloud: { enabled: true },
      });

      const created = await manager.createBackup({ server_id: "onlycloud" });
      expect(created.destinations).toHaveLength(1);
      expect(created.destinations[0]).toMatchObject({ destination: "tegra_cloud", ok: true });
      expect(created.pending_uploads).toBeUndefined();
      expect(confirmedIds).toEqual(["single-cloud-id"]);
      expect(events).toHaveLength(0);
    } finally {
      void storageServer.stop(true);
    }
  });
});
