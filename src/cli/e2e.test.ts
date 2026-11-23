// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createLogger,
  getStatePaths,
  loadOrCreateIdentity,
  loadTrust,
  runPairingFlow,
} from "../agent";
import { openTestEvent } from "../agent/test-events";
import {
  fingerprint,
  fromBase64Url,
  generateSigningKeyPair,
  KDF_FLOOR,
  ready,
  toBase64Url,
} from "../crypto";
import {
  createCoreRegistry,
  createHelloFrame,
  createSignedCommand,
  PROTOCOL_VERSION,
  parsePairingFragment,
  signTrustGrant,
  type TransportFrame,
  transportFrameSchema,
  verifyAgentAuth,
  verifyAgentRequest,
} from "../protocol";
import { createCommandFromSession, createVault, issueSession } from "../vault";
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

    let helloNonce = "";
    let authVerified = false;
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(req, srv) {
        const url = new URL(req.url);
        if (url.pathname === "/v1/agents/connect" && url.searchParams.get("agent") === agentId) {
          if (srv.upgrade(req)) {
            return;
          }
        }
        return new Response("Not found", { status: 404 });
      },
      websocket: {
        open(ws) {
          const hello = createHelloFrame({ agent: agentId, serverTime: Date.now() });
          helloNonce = hello.body.nonce;
          ws.send(JSON.stringify(hello));
        },
        message(ws, message) {
          const text = typeof message === "string" ? message : new TextDecoder().decode(message);
          const frame = transportFrameSchema.parse(JSON.parse(text));
          if (frame.kind === "auth") {
            verifyAgentAuth(frame, {
              agentPublicKey: agent.publicKey,
              expectedNonce: helloNonce,
              now: Date.now(),
            });
            authVerified = true;
            const commandFrame: TransportFrame = {
              v: PROTOCOL_VERSION,
              kind: "command",
              route: { agent: agentId },
              body: signedPing,
            };
            ws.send(JSON.stringify(commandFrame));
            return;
          }
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

      expect(authVerified).toBe(true);
      const eventFrame = receivedFrames.find((f) => f.kind === "event");
      const ackFrame = receivedFrames.find((f) => f.kind === "ack");

      expect(eventFrame).toBeDefined();
      if (eventFrame?.kind === "event") {
        const opened = openTestEvent(eventFrame.body, agent.publicKey, account);
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

  test("full pairing E2E over local HTTP + WS server: vault signs TrustGrant, agent trusts account and accepts session agent.ping", async () => {
    const stateDir = makeTempDir();
    const agent = await loadOrCreateIdentity(stateDir);
    const agentId = fingerprint(agent.publicKey);
    const registry = createCoreRegistry();
    const now = Date.now();

    const pairings = new Map<string, { agentPublicKeyB64: string; grant?: unknown }>();
    const receivedFrames: TransportFrame[] = [];
    let resolveBoth!: () => void;
    const bothReceived = new Promise<void>((resolve) => {
      resolveBoth = resolve;
    });
    let commandToSend: ReturnType<typeof createSignedCommand> | null = null;
    let helloNonce = "";
    let authVerified = false;
    function agentPublicKeyFromPairing(): Uint8Array | null {
      for (const entry of pairings.values()) {
        return fromBase64Url(entry.agentPublicKeyB64);
      }
      return null;
    }

    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      async fetch(req, srv) {
        const url = new URL(req.url);
        if (url.pathname === "/v1/agents/connect" && url.searchParams.get("agent") === agentId) {
          if (srv.upgrade(req)) {
            return;
          }
        }
        if (req.method === "POST" && url.pathname === "/v1/agents/pairing") {
          const raw = await req.text();
          const body = JSON.parse(raw) as { code: string; agent_public_key: string };
          verifyAgentRequest({
            getHeader: (name) => req.headers.get(name),
            method: req.method,
            pathWithQuery: `${url.pathname}${url.search}`,
            body: raw,
            agentPublicKey: fromBase64Url(body.agent_public_key),
            now: Date.now(),
          });
          if (pairings.has(body.code)) {
            return new Response(null, { status: 409 });
          }
          pairings.set(body.code, { agentPublicKeyB64: body.agent_public_key });
          return new Response(null, { status: 201 });
        }
        const grantMatch = url.pathname.match(/^\/v1\/agents\/pairing\/([^/]+)\/grant$/);
        if (grantMatch) {
          const code = decodeURIComponent(grantMatch[1] ?? "");
          const entry = pairings.get(code);
          if (!entry) {
            return new Response(null, { status: 404 });
          }
          if (req.method === "POST") {
            const body = (await req.json()) as { grant: unknown };
            entry.grant = body.grant;
            return new Response(null, { status: 200 });
          }
          if (req.method === "GET") {
            verifyAgentRequest({
              getHeader: (name) => req.headers.get(name),
              method: req.method,
              pathWithQuery: `${url.pathname}${url.search}`,
              agentPublicKey: fromBase64Url(entry.agentPublicKeyB64),
              now: Date.now(),
            });
            if (entry.grant === undefined) {
              return new Response(null, { status: 202 });
            }
            return new Response(JSON.stringify({ grant: entry.grant }), {
              status: 200,
              headers: { "content-type": "application/json" },
            });
          }
        }
        const pairingMatch = url.pathname.match(/^\/v1\/agents\/pairing\/([^/]+)$/);
        if (pairingMatch) {
          const code = decodeURIComponent(pairingMatch[1] ?? "");
          const entry = pairings.get(code);
          if (req.method === "GET") {
            if (!entry) return new Response(null, { status: 404 });
            return new Response(JSON.stringify({ agent_public_key: entry.agentPublicKeyB64 }), {
              status: 200,
              headers: { "content-type": "application/json" },
            });
          }
          if (req.method === "DELETE") {
            pairings.delete(code);
            return new Response(null, { status: 204 });
          }
        }
        return new Response("Not found", { status: 404 });
      },
      websocket: {
        open(ws) {
          const hello = createHelloFrame({ agent: agentId, serverTime: Date.now() });
          helloNonce = hello.body.nonce;
          ws.send(JSON.stringify(hello));
        },
        message(ws, message) {
          const text = typeof message === "string" ? message : new TextDecoder().decode(message);
          const frame = transportFrameSchema.parse(JSON.parse(text));
          if (frame.kind === "auth") {
            const agentPublicKey = pairings.size > 0 ? agentPublicKeyFromPairing() : null;
            if (agentPublicKey !== null) {
              verifyAgentAuth(frame, {
                agentPublicKey,
                expectedNonce: helloNonce,
                now: Date.now(),
              });
            }
            authVerified = true;
            if (commandToSend !== null) {
              const out: TransportFrame = {
                v: PROTOCOL_VERSION,
                kind: "command",
                route: { agent: agentId },
                body: commandToSend,
              };
              ws.send(JSON.stringify(out));
            }
            return;
          }
          receivedFrames.push(frame);
          const hasEvent = receivedFrames.some((f) => f.kind === "event");
          const hasAck = receivedFrames.some((f) => f.kind === "ack");
          if (hasEvent && hasAck) {
            resolveBoth();
          }
        },
      },
    });

    const apiBase = `http://127.0.0.1:${server.port}`;
    const { configPath } = getStatePaths(stateDir);
    writeFileSync(configPath, JSON.stringify({ api_url: apiBase }), "utf8");

    const vault = createVault({
      password: "correct-horse-battery-staple-99!",
      kdf: KDF_FLOOR,
      now,
    });

    try {
      let stdout = "";
      let clientCompleted = false;

      const linkCode = await runPairingFlow({
        stateDir,
        env: { TEGRAD_ALLOW_INSECURE: "1" },
        now: () => now,
        pollIntervalMs: 25,
        stdout: (text) => {
          stdout += text;
          if (!clientCompleted && stdout.includes("Pairing URL: ")) {
            const match = stdout.match(/Pairing URL: (https:\/\/\S+)/);
            if (match?.[1]) {
              clientCompleted = true;
              const fragment = parsePairingFragment(new URL(match[1]).hash);
              void (async () => {
                const res = await fetch(`${apiBase}/v1/agents/pairing/${fragment.code}`);
                const data = (await res.json()) as { agent_public_key: string };
                const fetchedAgentPub = fromBase64Url(data.agent_public_key);
                expect(fragment.agentFingerprint).toBeDefined();
                expect(fingerprint(fetchedAgentPub)).toBe(fragment.agentFingerprint ?? "");

                const grant = signTrustGrant({
                  accountKeyPair: vault.unlocked.keyPair,
                  agentPublicKey: fetchedAgentPub,
                  ...(fragment.secret !== undefined ? { secret: fragment.secret } : {}),
                  issuedAt: now,
                });
                await fetch(`${apiBase}/v1/agents/pairing/${fragment.code}/grant`, {
                  method: "POST",
                  headers: { "content-type": "application/json" },
                  body: JSON.stringify({ grant }),
                });
              })();
            }
          }
        },
        stderr: () => {},
      });

      expect(linkCode).toBe(0);
      const trusted = await loadTrust(stateDir);
      expect(trusted.length).toBe(1);
      expect(fingerprint(trusted[0] ?? new Uint8Array())).toBe(vault.unlocked.account);

      // Issue a session from the vault and send a signed agent.ping to the running agent
      const session = issueSession(vault.unlocked, { duration: "24h", now });
      commandToSend = createCommandFromSession(session, {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        counter: 1,
        now,
        registry,
      });

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
            setTimeout(() => reject(new Error("Timed out waiting for paired agent.pong")), 5000),
          ),
        ]);

        expect(authVerified).toBe(true);
        const eventFrame = receivedFrames.find((f) => f.kind === "event");
        const ackFrame = receivedFrames.find((f) => f.kind === "ack");
        expect(eventFrame?.kind).toBe("event");
        if (eventFrame?.kind === "event") {
          const opened = openTestEvent(eventFrame.body, agent.publicKey, vault.unlocked.keyPair);
          expect(opened.header.type).toBe("agent.pong");
          expect(opened.body).toEqual({ at: now });
        }
        expect(ackFrame).toEqual({
          v: PROTOCOL_VERSION,
          kind: "ack",
          route: { agent: agentId },
          body: { id: commandToSend.header.id, ok: true },
        });
      } finally {
        await runtime.shutdown(2000);
      }
    } finally {
      vault.unlocked.lock();
      server.stop(true);
    }
  });
});
