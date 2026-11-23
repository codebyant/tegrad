// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import { EventEmitter } from "node:events";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fingerprint, generateSigningKeyPair, ready } from "../crypto";
import {
  createCoreRegistry,
  createSignedCommand,
  generatePairingSecret,
  PROTOCOL_VERSION,
  parsePairingFragment,
  signRevocationList,
  signSessionCertificate,
  signTrustGrant,
  type TransportFrame,
} from "../protocol";
import { createCommandQueue, type TransportCommandFrame } from "./jobs";
import { createLogger } from "./logger";
import { formatFingerprintGroups, runPairingFlow } from "./pairing";
import { createPairingApiClient, type FetchLike, PairingApiError } from "./pairing-api";
import { getStatePaths } from "./paths";
import {
  addTrustedAccount,
  applyRevocationList,
  createFileTrustContext,
  loadOrCreateIdentity,
  loadRevocations,
  loadTrust,
  StateError,
} from "./state";
import { openTestEvent } from "./test-events";

const BASE_TIME = 1_700_000_000_000;
const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "tegrad-pairing-test-"));
  tempDirs.push(dir);
  return dir;
}

function writeConfig(dir: string, apiUrl = "https://api.tegra.example", linkUrl?: string): void {
  const { configPath } = getStatePaths(dir);
  writeFileSync(
    configPath,
    JSON.stringify({ api_url: apiUrl, ...(linkUrl !== undefined ? { link_url: linkUrl } : {}) }),
    "utf8",
  );
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

describe("pairing API client", () => {
  test("rejects non-https URLs unless allowInsecure is enabled for localhost", () => {
    expect(() =>
      createPairingApiClient({
        agentKeyPair: generateSigningKeyPair(),
        apiUrl: "http://api.tegra.example",
      }),
    ).toThrow(StateError);
    expect(() =>
      createPairingApiClient({
        agentKeyPair: generateSigningKeyPair(),
        apiUrl: "http://127.0.0.1:8080",
        allowInsecure: false,
      }),
    ).toThrow(StateError);
    expect(() =>
      createPairingApiClient({
        agentKeyPair: generateSigningKeyPair(),
        apiUrl: "http://127.0.0.1:8080",
        allowInsecure: true,
      }),
    ).not.toThrow();
  });

  test("rejects oversized grant responses (> 64 KiB)", async () => {
    const hugeBody = JSON.stringify({ grant: "x".repeat(70 * 1024) });
    const fakeFetch: FetchLike = async () =>
      new Response(hugeBody, {
        status: 200,
        headers: { "content-type": "application/json" },
      });

    const api = createPairingApiClient({
      agentKeyPair: generateSigningKeyPair(),
      apiUrl: "https://api.tegra.example",
      fetch: fakeFetch,
    });

    await expect(api.pollGrant("0123456789")).rejects.toThrow(PairingApiError);
    await expect(api.pollGrant("0123456789")).rejects.toMatchObject({
      code: "response_too_large",
    });
  });
});

describe("tegrad link pairing flow", () => {
  test("happy path with proof writes trusted account, prints URL/QR/fingerprint, deletes pairing, and exits 0", async () => {
    const dir = makeTempDir();
    writeConfig(dir);
    const agent = await loadOrCreateIdentity(dir);
    const account = generateSigningKeyPair();
    const secret = generatePairingSecret();
    let now = BASE_TIME;
    let pollCount = 0;
    const deletedCodes: string[] = [];

    const fakeFetch: FetchLike = async (input, init) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (method === "POST" && url.endsWith("/agents/pairing")) {
        return new Response(null, { status: 201 });
      }
      if (method === "GET" && url.includes("/grant")) {
        pollCount++;
        if (pollCount === 1) {
          return new Response(null, { status: 202 });
        }
        const grant = signTrustGrant({
          accountKeyPair: account,
          agentPublicKey: agent.publicKey,
          secret,
          issuedAt: now,
        });
        return new Response(JSON.stringify({ grant }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (method === "DELETE") {
        deletedCodes.push(url);
        return new Response(null, { status: 204 });
      }
      return new Response("Not found", { status: 404 });
    };

    let stdout = "";
    let stderr = "";
    const logs: string[] = [];
    const logger = createLogger({
      level: "debug",
      stdout: (line) => logs.push(line),
      stderr: (line) => logs.push(line),
    });

    const exitCode = await runPairingFlow({
      stateDir: dir,
      fetch: fakeFetch,
      logger,
      now: () => now,
      sleep: async (ms) => {
        now += ms;
      },
      stdout: (text) => {
        stdout += text;
      },
      stderr: (text) => {
        stderr += text;
      },
      generateSecret: () => secret,
    });

    expect(exitCode).toBe(0);
    expect(stderr).toBe("");
    expect(stdout).toContain(formatFingerprintGroups(fingerprint(agent.publicKey)));
    expect(stdout).toContain("https://tegramc.com/link#");
    expect(stdout).toContain(fingerprint(account.publicKey));
    expect(deletedCodes.length).toBe(1);

    const trusted = await loadTrust(dir);
    expect(trusted.length).toBe(1);
    expect(fingerprint(trusted[0] ?? new Uint8Array())).toBe(fingerprint(account.publicKey));

    // Secret and grant signature must never appear in structured logs
    const joinedLogs = logs.join("\n");
    expect(joinedLogs).not.toContain(secret);
    expect(joinedLogs).not.toContain("agent-pairing");
  });

  test("rejects malicious API grant for another account without secret (exits 1, writes nothing, leaks no secret/grant)", async () => {
    const dir = makeTempDir();
    writeConfig(dir);
    const agent = await loadOrCreateIdentity(dir);
    const attacker = generateSigningKeyPair();
    const secret = generatePairingSecret();
    const attackerSecret = generatePairingSecret();
    const forgedGrant = signTrustGrant({
      accountKeyPair: attacker,
      agentPublicKey: agent.publicKey,
      secret: attackerSecret,
      issuedAt: BASE_TIME,
    });

    const fakeFetch: FetchLike = async (_input, init) => {
      if (init?.method === "POST") return new Response(null, { status: 201 });
      if (init?.method === "DELETE") return new Response(null, { status: 204 });
      return new Response(JSON.stringify({ grant: forgedGrant }), { status: 200 });
    };

    let stderr = "";
    const logs: string[] = [];
    const logger = createLogger({
      level: "debug",
      stdout: (line) => logs.push(line),
      stderr: (line) => logs.push(line),
    });

    const exitCode = await runPairingFlow({
      stateDir: dir,
      fetch: fakeFetch,
      logger,
      now: () => BASE_TIME,
      stdout: () => {},
      stderr: (text) => {
        stderr += text;
      },
      generateSecret: () => secret,
    });

    expect(exitCode).toBe(1);
    expect(stderr).toContain("grant_bad_proof");
    expect(stderr).not.toContain(secret);
    expect(stderr).not.toContain(forgedGrant.sig);
    expect(logs.join("\n")).not.toContain(secret);
    expect(logs.join("\n")).not.toContain(forgedGrant.sig);
    expect(await loadTrust(dir)).toEqual([]);
  });

  test("grant without proof is rejected by default and accepted with --allow-unverified with warning", async () => {
    const dir = makeTempDir();
    writeConfig(dir);
    const agent = await loadOrCreateIdentity(dir);
    const account = generateSigningKeyPair();
    const unverifiedGrant = signTrustGrant({
      accountKeyPair: account,
      agentPublicKey: agent.publicKey,
      issuedAt: BASE_TIME,
    });

    const fakeFetch: FetchLike = async (_input, init) => {
      if (init?.method === "POST") return new Response(null, { status: 201 });
      if (init?.method === "DELETE") return new Response(null, { status: 204 });
      return new Response(JSON.stringify({ grant: unverifiedGrant }), { status: 200 });
    };

    let stderrDefault = "";
    const codeDefault = await runPairingFlow({
      stateDir: dir,
      fetch: fakeFetch,
      now: () => BASE_TIME,
      stdout: () => {},
      stderr: (t) => {
        stderrDefault += t;
      },
    });
    expect(codeDefault).toBe(1);
    expect(stderrDefault).toContain("grant_proof_required");
    expect(await loadTrust(dir)).toEqual([]);

    let stderrUnverified = "";
    const codeUnverified = await runPairingFlow({
      stateDir: dir,
      fetch: fakeFetch,
      allowUnverified: true,
      now: () => BASE_TIME,
      stdout: () => {},
      stderr: (t) => {
        stderrUnverified += t;
      },
    });
    expect(codeUnverified).toBe(0);
    expect(stderrUnverified).toContain("WARNING");
    expect(stderrUnverified).toContain("--allow-unverified");
    expect((await loadTrust(dir)).length).toBe(1);
  });

  test("retries up to 3 times on 409 code conflict", async () => {
    const dir = makeTempDir();
    writeConfig(dir);
    const agent = await loadOrCreateIdentity(dir);
    const account = generateSigningKeyPair();
    const secret = generatePairingSecret();
    const codes = ["0000000001", "0000000002", "0000000003", "0000000004"];
    let codeIdx = 0;
    let postAttempts = 0;

    const fakeFetch: FetchLike = async (_input, init) => {
      if (init?.method === "POST") {
        postAttempts++;
        if (postAttempts <= 3) {
          return new Response(null, { status: 409 });
        }
        return new Response(null, { status: 201 });
      }
      if (init?.method === "DELETE") return new Response(null, { status: 204 });
      const grant = signTrustGrant({
        accountKeyPair: account,
        agentPublicKey: agent.publicKey,
        secret,
        issuedAt: BASE_TIME,
      });
      return new Response(JSON.stringify({ grant }), { status: 200 });
    };

    const exitCode = await runPairingFlow({
      stateDir: dir,
      fetch: fakeFetch,
      now: () => BASE_TIME,
      stdout: () => {},
      stderr: () => {},
      generateCode: () => codes[codeIdx++] ?? "0000000009",
      generateSecret: () => secret,
    });

    expect(exitCode).toBe(0);
    expect(postAttempts).toBe(4);
  });

  test("exits 1 on 404/410 expiration or 10 min timeout", async () => {
    const dir = makeTempDir();
    writeConfig(dir);

    const expiredFetch: FetchLike = async (_input, init) => {
      if (init?.method === "POST") return new Response(null, { status: 201 });
      return new Response(null, { status: 410 });
    };

    const expiredCode = await runPairingFlow({
      stateDir: dir,
      fetch: expiredFetch,
      now: () => BASE_TIME,
      stdout: () => {},
      stderr: () => {},
    });
    expect(expiredCode).toBe(1);

    let now = BASE_TIME;
    let deleted = false;
    const pendingFetch: FetchLike = async (_input, init) => {
      if (init?.method === "POST") return new Response(null, { status: 201 });
      if (init?.method === "DELETE") {
        deleted = true;
        return new Response(null, { status: 204 });
      }
      return new Response(null, { status: 202 });
    };

    const timeoutCode = await runPairingFlow({
      stateDir: dir,
      fetch: pendingFetch,
      now: () => now,
      sleep: async (ms) => {
        now += ms;
      },
      stdout: () => {},
      stderr: () => {},
    });
    expect(timeoutCode).toBe(1);
    expect(deleted).toBe(true);
    expect(now - BASE_TIME).toBe(10 * 60 * 1000);
  });

  test("SIGINT cancels pairing and deletes the pairing request", async () => {
    const dir = makeTempDir();
    writeConfig(dir);
    const signalTarget = new EventEmitter();
    let deleted = false;

    const fakeFetch: FetchLike = async (_input, init) => {
      if (init?.method === "POST") return new Response(null, { status: 201 });
      if (init?.method === "DELETE") {
        deleted = true;
        return new Response(null, { status: 204 });
      }
      return new Response(null, { status: 202 });
    };

    const exitCode = await runPairingFlow({
      stateDir: dir,
      fetch: fakeFetch,
      now: () => BASE_TIME,
      signalTarget: signalTarget as unknown as Pick<NodeJS.Process, "on" | "off">,
      sleep: async () => {
        signalTarget.emit("SIGINT");
      },
      stdout: () => {},
      stderr: () => {},
    });

    expect(exitCode).toBe(1);
    expect(deleted).toBe(true);
  });

  test("refuses when already linked without --add/--reset; --add appends; --reset confirms, clears trust/revocations/replay, keeps identity & server data", async () => {
    const dir = makeTempDir();
    writeConfig(dir);
    const agent = await loadOrCreateIdentity(dir);
    const account1 = generateSigningKeyPair();
    const account2 = generateSigningKeyPair();
    const account3 = generateSigningKeyPair();
    const secret = generatePairingSecret();

    await addTrustedAccount(dir, account1.publicKey);
    await applyRevocationList(
      dir,
      signRevocationList({
        accountKeyPair: account1,
        issuedAt: BASE_TIME,
        revoked: ["sess_old"],
      }),
    );
    const { replayPath } = getStatePaths(dir);
    writeFileSync(replayPath, JSON.stringify({ v: 1, last_counter: {}, recent_ids: [] }), "utf8");
    const serversDir = join(dir, "servers");
    mkdirSync(serversDir, { recursive: true });
    writeFileSync(join(serversDir, "world.txt"), "keep-me", "utf8");

    // Refused without --add / --reset
    let refusedErr = "";
    const refusedCode = await runPairingFlow({
      stateDir: dir,
      stdout: () => {},
      stderr: (t) => {
        refusedErr += t;
      },
    });
    expect(refusedCode).toBe(1);
    expect(refusedErr).toContain("--add");
    expect(refusedErr).toContain("--reset");

    // --add adds account2 alongside account1
    const makeGrantFetch = (acct: ReturnType<typeof generateSigningKeyPair>): FetchLike => {
      return async (_input, init) => {
        if (init?.method === "POST") return new Response(null, { status: 201 });
        if (init?.method === "DELETE") return new Response(null, { status: 204 });
        const grant = signTrustGrant({
          accountKeyPair: acct,
          agentPublicKey: agent.publicKey,
          secret,
          issuedAt: BASE_TIME,
        });
        return new Response(JSON.stringify({ grant }), { status: 200 });
      };
    };

    const addCode = await runPairingFlow({
      stateDir: dir,
      add: true,
      fetch: makeGrantFetch(account2),
      now: () => BASE_TIME,
      stdout: () => {},
      stderr: () => {},
      generateSecret: () => secret,
    });
    expect(addCode).toBe(0);
    expect((await loadTrust(dir)).length).toBe(2);

    // --reset rejected when confirmation is not 'yes'
    const cancelResetCode = await runPairingFlow({
      stateDir: dir,
      reset: true,
      confirm: async () => "no",
      stdout: () => {},
      stderr: () => {},
    });
    expect(cancelResetCode).toBe(1);
    expect((await loadTrust(dir)).length).toBe(2);

    // --reset accepted when confirmed with 'yes'
    const resetCode = await runPairingFlow({
      stateDir: dir,
      reset: true,
      confirm: async () => "yes",
      fetch: makeGrantFetch(account3),
      now: () => BASE_TIME,
      stdout: () => {},
      stderr: () => {},
      generateSecret: () => secret,
    });
    expect(resetCode).toBe(0);

    // Only account3 trusted, revocations & replay cleared, identity & server data intact
    const finalTrusted = await loadTrust(dir);
    expect(finalTrusted.length).toBe(1);
    expect(fingerprint(finalTrusted[0] ?? new Uint8Array())).toBe(fingerprint(account3.publicKey));
    expect(loadRevocations(dir)).toEqual({ v: 1, accounts: {} });
    expect(existsSync(replayPath)).toBe(false);
    expect(fingerprint((await loadOrCreateIdentity(dir)).publicKey)).toBe(
      fingerprint(agent.publicKey),
    );
    expect(readFileSync(join(serversDir, "world.txt"), "utf8")).toBe("keep-me");
  });

  test("parses printed pairing URL fragment cleanly", async () => {
    const dir = makeTempDir();
    writeConfig(dir, "https://api.tegra.example", "https://custom.tegra.example/pair");
    const agent = await loadOrCreateIdentity(dir);
    const account = generateSigningKeyPair();

    let stdout = "";
    let capturedGrant: unknown = null;

    const fakeFetch: FetchLike = async (_input, init) => {
      if (init?.method === "POST") return new Response(null, { status: 201 });
      if (init?.method === "DELETE") return new Response(null, { status: 204 });
      if (capturedGrant === null) {
        const match = stdout.match(/Pairing URL: (https:\/\/\S+)/);
        const url = new URL(match?.[1] ?? "");
        const parsed = parsePairingFragment(url.hash);
        capturedGrant = signTrustGrant({
          accountKeyPair: account,
          agentPublicKey: agent.publicKey,
          ...(parsed.secret !== undefined ? { secret: parsed.secret } : {}),
          issuedAt: BASE_TIME,
        });
      }
      return new Response(JSON.stringify({ grant: capturedGrant }), { status: 200 });
    };

    const code = await runPairingFlow({
      stateDir: dir,
      fetch: fakeFetch,
      now: () => BASE_TIME,
      stdout: (t) => {
        stdout += t;
      },
      stderr: () => {},
    });

    expect(code).toBe(0);
    expect(stdout).toContain("https://custom.tegra.example/pair#");
  });
});

describe("end-to-end revocation via command queue", () => {
  test("agent.revocations.set applies revocations, emits agent.revocations.applied, and blocks revoked session", async () => {
    const dir = makeTempDir();
    const agent = await loadOrCreateIdentity(dir);
    const agentId = fingerprint(agent.publicKey);
    const account = generateSigningKeyPair();
    const session = generateSigningKeyPair();
    const now = BASE_TIME;

    await addTrustedAccount(dir, account.publicKey);
    const trust = createFileTrustContext({
      stateDir: dir,
      agentKeyPair: agent,
      trustedAccountKeys: [account.publicKey],
      now: () => now,
    });
    const registry = createCoreRegistry();
    const sent: TransportFrame[] = [];
    const queue = createCommandQueue({
      trust,
      registry,
      sendFrame: (frame) => sent.push(frame),
      logger: createLogger({ level: "error", stdout: () => {}, stderr: () => {} }),
    });

    const sessionCert = signSessionCertificate({
      sessionPublicKey: session.publicKey,
      accountKeyPair: account,
      notBefore: now - 60_000,
      notAfter: now + 3_600_000,
    });

    const wrap = (body: ReturnType<typeof createSignedCommand>): TransportCommandFrame => ({
      v: PROTOCOL_VERSION,
      kind: "command",
      route: { agent: agentId },
      body,
    });

    // Session works before revocation
    const pingBefore = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: session,
        session: sessionCert,
        counter: 1,
        now,
      },
      registry,
    );
    await queue.enqueue(wrap(pingBefore));
    expect(sent.pop()).toMatchObject({ kind: "ack", body: { id: pingBefore.header.id, ok: true } });
    sent.length = 0;

    // Apply revocation list via agent.revocations.set
    const list1 = signRevocationList({
      accountKeyPair: account,
      issuedAt: now,
      revoked: [sessionCert.id],
    });
    const revokeCmd = createSignedCommand(
      {
        type: "agent.revocations.set",
        body: { list: list1 },
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now,
      },
      registry,
    );
    await queue.enqueue(wrap(revokeCmd));

    const eventFrame = sent.find((f) => f.kind === "event");
    const ackFrame = sent.find((f) => f.kind === "ack");
    expect(eventFrame).toBeDefined();
    if (eventFrame?.kind === "event") {
      const openedEvent = openTestEvent(eventFrame.body, agent.publicKey, account);
      expect(openedEvent.header.type).toBe("agent.revocations.applied");
      expect(openedEvent.body).toEqual({
        account: fingerprint(account.publicKey),
        count: 1,
      });
    }
    expect(ackFrame).toMatchObject({ kind: "ack", body: { id: revokeCmd.header.id, ok: true } });
    sent.length = 0;

    // Session is now rejected with session_revoked
    const pingAfter = createSignedCommand(
      {
        type: "agent.ping",
        body: {},
        agentPublicKey: agent.publicKey,
        signer: session,
        session: sessionCert,
        counter: 2,
        now,
      },
      registry,
    );
    await queue.enqueue(wrap(pingAfter));
    expect(sent.pop()).toEqual({
      v: PROTOCOL_VERSION,
      kind: "ack",
      route: { agent: agentId },
      body: { id: pingAfter.header.id, ok: false, code: "session_revoked" },
    });

    // Non-superset revocation list returns ack with code revocation_not_superset
    const shrinkingList = signRevocationList({
      accountKeyPair: account,
      issuedAt: now + 1000,
      revoked: [],
    });
    const badRevokeCmd = createSignedCommand(
      {
        type: "agent.revocations.set",
        body: { list: shrinkingList },
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 2,
        now,
      },
      registry,
    );
    await queue.enqueue(wrap(badRevokeCmd));
    expect(sent.pop()).toEqual({
      v: PROTOCOL_VERSION,
      kind: "ack",
      route: { agent: agentId },
      body: { id: badRevokeCmd.header.id, ok: false, code: "revocation_not_superset" },
    });
  });
});
