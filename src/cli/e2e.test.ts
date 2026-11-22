// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createLogger, getStatePaths, loadOrCreateIdentity } from "../agent";
import { fingerprint, generateSigningKeyPair, ready, toBase64Url } from "../crypto";
import {
  createCoreRegistry,
  createSignedCommand,
  openAgentMessage,
  PROTOCOL_VERSION,
  type TransportFrame,
  transportFrameSchema,
} from "../protocol";
import { createAgentRuntime } from "./run";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "tegrad-e2e-test-"));
  tempDirs.push(dir);
  return dir;
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

describe("E2E local WebSocket ping/pong", () => {
  test("agent connects to local WS server, receives signed agent.ping, and replies with agent.pong + ack", async () => {
    const stateDir = makeTempDir();
    const agent = await loadOrCreateIdentity(stateDir);
    const agentId = fingerprint(agent.publicKey);
    const account = generateSigningKeyPair();
    const registry = createCoreRegistry();
    const now = Date.now();

    const receivedFrames: TransportFrame[] = [];
    let resolveBoth!: () => void;
    const bothReceived = new Promise<void>((resolve) => {
      resolveBoth = resolve;
    });

    const signedPing = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now,
      },
      registry,
    );

    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(req, srv) {
        const url = new URL(req.url);
        if (url.pathname === "/agents/connect" && url.searchParams.get("agent") === agentId) {
          if (srv.upgrade(req)) {
            return;
          }
        }
        return new Response("Not found", { status: 404 });
      },
      websocket: {
        open(ws) {
          const commandFrame: TransportFrame = {
            v: PROTOCOL_VERSION,
            kind: "command",
            route: { agent: agentId },
            body: signedPing,
          };
          ws.send(JSON.stringify(commandFrame));
        },
        message(_ws, message) {
          const text = typeof message === "string" ? message : new TextDecoder().decode(message);
          const frame = transportFrameSchema.parse(JSON.parse(text));
          receivedFrames.push(frame);
          const hasEvent = receivedFrames.some((f) => f.kind === "event");
          const hasAck = receivedFrames.some((f) => f.kind === "ack");
          if (hasEvent && hasAck) {
            resolveBoth();
          }
        },
      },
    });

    const { configPath, trustPath } = getStatePaths(stateDir);
    writeFileSync(
      configPath,
      JSON.stringify({ api_url: `http://127.0.0.1:${server.port}` }),
      "utf8",
    );
    writeFileSync(
      trustPath,
      JSON.stringify({ v: 1, accounts: [{ public_key: toBase64Url(account.publicKey) }] }),
      "utf8",
    );

    const runtime = await createAgentRuntime({
      stateDir,
      env: { TEGRAD_ALLOW_INSECURE: "1" },
      logger: createLogger({ level: "error", stdout: () => {}, stderr: () => {} }),
      now: () => now,
    });

    try {
      runtime.start();
      await Promise.race([
        bothReceived,
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error("Timed out waiting for agent.pong and ack")), 5000),
        ),
      ]);

      const eventFrame = receivedFrames.find((f) => f.kind === "event");
      const ackFrame = receivedFrames.find((f) => f.kind === "ack");

      expect(eventFrame).toBeDefined();
      if (eventFrame?.kind === "event") {
        const opened = openAgentMessage(eventFrame.body, agent.publicKey, account);
        expect(opened.header.type).toBe("agent.pong");
        expect(opened.body).toEqual({ at: now });
      }

      expect(ackFrame).toEqual({
        v: PROTOCOL_VERSION,
        kind: "ack",
        route: { agent: agentId },
        body: { id: signedPing.header.id, ok: true },
      });
    } finally {
      await runtime.shutdown(2000);
      server.stop(true);
    }
  });
});
