// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { createLogger, getStatePaths, loadOrCreateIdentity } from "../agent";
import { openTestEvent } from "../agent/test-events";
import {
  fingerprint,
  generateSigningKeyPair,
  ready,
  type SigningKeyPair,
  toBase64Url,
} from "../crypto";
import {
  CommandRegistry,
  createCoreRegistry,
  createHelloFrame,
  createSignedCommand,
  defineCommand,
  FILES_COMMANDS,
  PROTOCOL_VERSION,
  signSessionCertificate,
  type TransportFrame,
} from "../protocol";
import { createAgentRuntime } from "./run";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function sha256Hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

interface Harness {
  readonly stateDir: string;
  readonly serversDir: string;
  readonly agentPublicKey: Uint8Array;
  readonly agentId: string;
  readonly account: SigningKeyPair;
  readonly session: {
    readonly keyPair: SigningKeyPair;
    readonly certificate: ReturnType<typeof signSessionCertificate>;
  };
  readonly now: number;
  readonly runtime: Awaited<ReturnType<typeof createAgentRuntime>>;
  readonly frames: TransportFrame[];
  sendCommand(
    type: string,
    body: unknown,
    options?: { readonly useSession?: boolean },
  ): Promise<{
    readonly ack: Extract<TransportFrame, { kind: "ack" }>;
    readonly events: readonly { readonly type: string; readonly body: unknown }[];
  }>;
  dispose(): Promise<void>;
}

async function createHarness(serverId = "srv-1"): Promise<Harness> {
  const stateDir = makeTempDir("tegrad-files-state-");
  const serversDir = makeTempDir("tegrad-files-servers-");
  const backupsDir = makeTempDir("tegrad-files-backups-");
  mkdirSync(join(serversDir, serverId), { recursive: true });

  const agent = await loadOrCreateIdentity(stateDir);
  const agentId = fingerprint(agent.publicKey);
  const account = generateSigningKeyPair();
  const sessionKeyPair = generateSigningKeyPair();
  const now = Date.now();
  const sessionCert = signSessionCertificate({
    accountKeyPair: account,
    sessionPublicKey: sessionKeyPair.publicKey,
    notBefore: now - 1000,
    notAfter: now + 3_600_000,
  });

  const { configPath, trustPath } = getStatePaths(stateDir);
  writeFileSync(configPath, JSON.stringify({ api_url: "https://api.tegra.example" }), "utf8");
  writeFileSync(
    trustPath,
    JSON.stringify({ v: 1, accounts: [{ public_key: toBase64Url(account.publicKey) }] }),
    "utf8",
  );

  const sentPayloads: TransportFrame[] = [];
  const wsRuntime = await createAgentRuntime({
    stateDir,
    serversDir,
    backupsDir,
    logger: createLogger({ level: "error", stdout: () => {}, stderr: () => {} }),
    now: () => now,
    webSocketFactory: () => {
      const socket = {
        readyState: 1,
        onopen: null as (() => void) | null,
        onmessage: null as ((event: { readonly data: unknown }) => void) | null,
        onclose: null as
          | ((event: { readonly code?: number; readonly reason?: string }) => void)
          | null,
        onerror: null as ((event: unknown) => void) | null,
        send(data: string) {
          sentPayloads.push(JSON.parse(data) as TransportFrame);
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
  wsRuntime.start();
  await new Promise((resolve) => setTimeout(resolve, 10));

  const registry = createCoreRegistry();
  let accountCounter = 1;
  let sessionCounter = 1;

  return {
    stateDir,
    serversDir,
    agentPublicKey: agent.publicKey,
    agentId,
    account,
    session: { keyPair: sessionKeyPair, certificate: sessionCert },
    now,
    runtime: wsRuntime,
    frames: sentPayloads,
    async sendCommand(type, body, options = {}) {
      const startIdx = sentPayloads.length;
      const useSession = options.useSession ?? false;
      const signed = createSignedCommand(
        {
          type,
          body,
          agentPublicKey: agent.publicKey,
          signer: useSession ? sessionKeyPair : account,
          ...(useSession ? { session: sessionCert } : {}),
          counter: useSession ? sessionCounter++ : accountCounter++,
          now,
        },
        registry,
      );
      await wsRuntime.queue.enqueue({
        v: PROTOCOL_VERSION,
        kind: "command",
        route: { agent: agentId },
        body: signed,
      });

      const newFrames = sentPayloads.slice(startIdx);
      const ack = newFrames.find(
        (f): f is Extract<TransportFrame, { kind: "ack" }> => f.kind === "ack",
      );
      if (!ack) {
        throw new Error(`Expected ack frame for ${type}`);
      }
      const events = newFrames
        .filter((f): f is Extract<TransportFrame, { kind: "event" }> => f.kind === "event")
        .map((f) => {
          const opened = openTestEvent(f.body, agent.publicKey, account);
          return { type: opened.header.type, body: opened.body };
        });

      return { ack, events };
    },
    async dispose() {
      await wsRuntime.shutdown(1000);
    },
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

describe("files.* runtime wiring", () => {
  test("every files.* command in FILES_COMMANDS reaches its handler through createAgentRuntime (never no_handler)", async () => {
    const serverId = "srv-1";
    const h = await createHarness(serverId);
    const exercised = new Set<string>();

    try {
      expect(h.runtime.fileManager).toBeDefined();

      // 1. files.mkdir
      const mkdirRes = await h.sendCommand("files.mkdir", {
        server_id: serverId,
        path: "configs",
      });
      exercised.add("files.mkdir");
      expect(mkdirRes.ack.body.ok).toBe(true);
      expect(mkdirRes.events[0]?.type).toBe("files.mkdir.result");

      // 2. files.write
      const writeRes = await h.sendCommand("files.write", {
        server_id: serverId,
        path: "configs/app.txt",
        content: "hello tegrad",
      });
      exercised.add("files.write");
      expect(writeRes.ack.body.ok).toBe(true);
      expect(writeRes.events[0]?.type).toBe("files.write.result");

      // 3. files.list
      const listRes = await h.sendCommand("files.list", {
        server_id: serverId,
        path: "configs",
      });
      exercised.add("files.list");
      expect(listRes.ack.body.ok).toBe(true);
      expect(listRes.events[0]?.type).toBe("files.list.result");

      // 4. files.stat
      const statRes = await h.sendCommand("files.stat", {
        server_id: serverId,
        path: "configs/app.txt",
      });
      exercised.add("files.stat");
      expect(statRes.ack.body.ok).toBe(true);
      expect(statRes.events[0]?.type).toBe("files.stat.result");

      // 5. files.read
      const readRes = await h.sendCommand("files.read", {
        server_id: serverId,
        path: "configs/app.txt",
      });
      exercised.add("files.read");
      expect(readRes.ack.body.ok).toBe(true);
      expect(readRes.events[0]?.type).toBe("files.read.result");

      // 6. files.copy
      const copyRes = await h.sendCommand("files.copy", {
        server_id: serverId,
        from_path: "configs/app.txt",
        to_path: "configs/copy.txt",
      });
      exercised.add("files.copy");
      expect(copyRes.ack.body.ok).toBe(true);
      expect(copyRes.events[0]?.type).toBe("files.copy.result");

      // 7. files.rename
      const renameRes = await h.sendCommand("files.rename", {
        server_id: serverId,
        path: "configs/copy.txt",
        new_name: "renamed.txt",
      });
      exercised.add("files.rename");
      expect(renameRes.ack.body.ok).toBe(true);
      expect(renameRes.events[0]?.type).toBe("files.rename.result");

      // 8. files.move
      const moveRes = await h.sendCommand("files.move", {
        server_id: serverId,
        from_path: "configs/renamed.txt",
        to_path: "moved.txt",
      });
      exercised.add("files.move");
      expect(moveRes.ack.body.ok).toBe(true);
      expect(moveRes.events[0]?.type).toBe("files.move.result");

      // 9. files.zip
      const zipRes = await h.sendCommand("files.zip", {
        server_id: serverId,
        paths: ["configs/app.txt"],
        dest_path: "archive.zip",
      });
      exercised.add("files.zip");
      expect(zipRes.ack.body.ok).toBe(true);
      expect(zipRes.events[0]?.type).toBe("files.zip.result");

      // 10. files.unzip
      const unzipRes = await h.sendCommand("files.unzip", {
        server_id: serverId,
        zip_path: "archive.zip",
        dest_path: "extracted",
      });
      exercised.add("files.unzip");
      expect(unzipRes.ack.body.ok).toBe(true);
      expect(unzipRes.events[0]?.type).toBe("files.unzip.result");

      // 11-13. files.upload.begin -> files.upload.part -> files.upload.commit
      const uploadBytes = new TextEncoder().encode("chunked upload data");
      const uploadBeginRes = await h.sendCommand("files.upload.begin", {
        server_id: serverId,
        path: "uploaded.txt",
        total_size: uploadBytes.byteLength,
        sha256: sha256Hex(uploadBytes),
      });
      exercised.add("files.upload.begin");
      expect(uploadBeginRes.ack.body.ok).toBe(true);
      const uploadId = (uploadBeginRes.events[0]?.body as { upload_id?: string } | undefined)
        ?.upload_id;
      expect(uploadId).toBeDefined();
      if (!uploadId) throw new Error("Missing upload_id");

      const uploadPartRes = await h.sendCommand("files.upload.part", {
        server_id: serverId,
        upload_id: uploadId,
        part_index: 0,
        data_base64: Buffer.from(uploadBytes).toString("base64"),
      });
      exercised.add("files.upload.part");
      expect(uploadPartRes.ack.body.ok).toBe(true);

      const uploadCommitRes = await h.sendCommand("files.upload.commit", {
        server_id: serverId,
        upload_id: uploadId,
      });
      exercised.add("files.upload.commit");
      expect(uploadCommitRes.ack.body.ok).toBe(true);

      // 14. files.upload.abort
      const abortBegin = await h.sendCommand("files.upload.begin", {
        server_id: serverId,
        path: "aborted.txt",
        total_size: uploadBytes.byteLength,
        sha256: sha256Hex(uploadBytes),
      });
      const abortId = (abortBegin.events[0]?.body as { upload_id?: string } | undefined)?.upload_id;
      expect(abortId).toBeDefined();
      if (!abortId) throw new Error("Missing abort upload_id");
      const uploadAbortRes = await h.sendCommand("files.upload.abort", {
        server_id: serverId,
        upload_id: abortId,
      });
      exercised.add("files.upload.abort");
      expect(uploadAbortRes.ack.body.ok).toBe(true);

      // 15-17. files.download.begin -> files.download.part -> files.download.close
      const dlBeginRes = await h.sendCommand("files.download.begin", {
        server_id: serverId,
        path: "uploaded.txt",
      });
      exercised.add("files.download.begin");
      expect(dlBeginRes.ack.body.ok).toBe(true);
      const downloadId = (dlBeginRes.events[0]?.body as { download_id?: string } | undefined)
        ?.download_id;
      expect(downloadId).toBeDefined();
      if (!downloadId) throw new Error("Missing download_id");

      const dlPartRes = await h.sendCommand("files.download.part", {
        server_id: serverId,
        download_id: downloadId,
        part_index: 0,
      });
      exercised.add("files.download.part");
      expect(dlPartRes.ack.body.ok).toBe(true);

      const dlCloseRes = await h.sendCommand("files.download.close", {
        server_id: serverId,
        download_id: downloadId,
      });
      exercised.add("files.download.close");
      expect(dlCloseRes.ack.body.ok).toBe(true);

      // 18. files.download (range)
      const dlRangeRes = await h.sendCommand("files.download", {
        server_id: serverId,
        path: "uploaded.txt",
        offset: 0,
        length: 7,
      });
      exercised.add("files.download");
      expect(dlRangeRes.ack.body.ok).toBe(true);

      // 19. files.delete (account key)
      const delRes = await h.sendCommand("files.delete", {
        server_id: serverId,
        path: "moved.txt",
      });
      exercised.add("files.delete");
      expect(delRes.ack.body.ok).toBe(true);
      expect(delRes.events[0]?.type).toBe("files.delete.result");

      // Assert 100% coverage of FILES_COMMANDS
      const allFileCommandTypes = FILES_COMMANDS.map((c) => c.type).sort();
      expect([...exercised].sort()).toEqual(allFileCommandTypes);
    } finally {
      await h.dispose();
    }
  });

  test("files.delete accepts session-key signatures and direct account signatures", async () => {
    const serverId = "srv-1";
    const h = await createHarness(serverId);

    try {
      // Non-destructive commands succeed with session key
      const writeRes = await h.sendCommand(
        "files.write",
        { server_id: serverId, path: "keep.txt", content: "data" },
        { useSession: true },
      );
      expect(writeRes.ack.body.ok).toBe(true);

      // files.delete stays inside the server folder, so a session key is enough
      const delWithSession = await h.sendCommand(
        "files.delete",
        { server_id: serverId, path: "keep.txt" },
        { useSession: true },
      );
      expect(delWithSession.ack.body.ok).toBe(true);
      const rewrite = await h.sendCommand(
        "files.write",
        { server_id: serverId, path: "keep.txt", content: "data" },
        { useSession: true },
      );
      expect(rewrite.ack.body.ok).toBe(true);

      // files.delete with direct account key succeeds
      const delWithAccount = await h.sendCommand(
        "files.delete",
        { server_id: serverId, path: "keep.txt" },
        { useSession: false },
      );
      expect(delWithAccount.ack.body.ok).toBe(true);
    } finally {
      await h.dispose();
    }
  });

  test("rejects invalid server_id and malformed bodies at protocol boundary", async () => {
    const h = await createHarness("srv-1");
    const registry = createCoreRegistry();

    try {
      // Bypass client-side schema check by signing with a permissive registry, then enqueueing
      // against the real runtime's strict registry.
      const permissive = new CommandRegistry();
      for (const cmd of FILES_COMMANDS) {
        permissive.register(
          defineCommand({
            type: cmd.type,
            level: cmd.level,
            minRole: cmd.minRole,
            body: z.unknown(),
          }),
        );
      }
      const badCases: readonly { readonly type: string; readonly body: unknown }[] = [
        { type: "files.list", body: { server_id: "../escape" } },
        { type: "files.read", body: { server_id: "BAD_ID", path: "a.txt" } },
        {
          type: "files.write",
          body: { server_id: "srv-1", path: "a.txt", content: "x", extra: 1 },
        },
        { type: "files.delete", body: { server_id: "", path: "a.txt" } },
      ];

      let counter = 100;
      for (const bad of badCases) {
        const startIdx = h.frames.length;
        const signed = createSignedCommand(
          {
            type: bad.type,
            body: bad.body,
            agentPublicKey: h.agentPublicKey,
            signer: h.account,
            counter: counter++,
            now: h.now,
          },
          permissive,
        );
        expect(registry.get(bad.type)).toBeDefined();

        await h.runtime.queue.enqueue({
          v: PROTOCOL_VERSION,
          kind: "command",
          route: { agent: h.agentId },
          body: signed,
        });

        const ack = h.frames
          .slice(startIdx)
          .find((f): f is Extract<TransportFrame, { kind: "ack" }> => f.kind === "ack");
        expect(ack).toBeDefined();
        expect(ack?.body.ok).toBe(false);
        if (ack && !ack.body.ok) {
          expect(ack.body.code).toBe("invalid_body");
        }
      }
    } finally {
      await h.dispose();
    }
  });

  test("shutdown disposes FileManager active transfers", async () => {
    const serverId = "srv-1";
    const h = await createHarness(serverId);

    await h.sendCommand("files.write", {
      server_id: serverId,
      path: "sample.txt",
      content: "hello",
    });
    const dlBegin = await h.sendCommand("files.download.begin", {
      server_id: serverId,
      path: "sample.txt",
    });
    expect(dlBegin.ack.body.ok).toBe(true);
    const downloadId = (dlBegin.events[0]?.body as { download_id?: string } | undefined)
      ?.download_id;
    expect(downloadId).toBeDefined();
    if (!downloadId) throw new Error("Missing download_id");

    await h.dispose();

    expect(() =>
      h.runtime.fileManager.downloadPart({
        server_id: serverId,
        download_id: downloadId,
        part_index: 0,
      }),
    ).toThrow();
  });
});
