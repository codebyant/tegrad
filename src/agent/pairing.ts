// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { createInterface } from "node:readline";
import { renderUnicodeCompact } from "uqr";
import { fingerprint, ready, toBase64Url } from "../crypto";
import {
  buildPairingFragment,
  generatePairingCode,
  generatePairingSecret,
  ProtocolError,
  verifyTrustGrant,
} from "../protocol";
import type { Logger } from "./logger";
import {
  createPairingApiClient,
  type FetchLike,
  type PairingApiClient,
  PairingApiError,
} from "./pairing-api";
import {
  type AgentConfig,
  addTrustedAccount,
  isInsecureAllowed,
  loadConfig,
  loadOrCreateIdentity,
  loadTrust,
  resetTrustState,
  validateLinkUrl,
} from "./state";

export const DEFAULT_LINK_URL = "https://tegramc.com/link";
export const DEFAULT_POLL_INTERVAL_MS = 2_000;
export const DEFAULT_PAIRING_TIMEOUT_MS = 10 * 60 * 1000;
export const MAX_CODE_CONFLICT_RETRIES = 3;

export function formatFingerprintGroups(fp: string): string {
  const groups: string[] = [];
  for (let i = 0; i < fp.length; i += 4) {
    groups.push(fp.slice(i, i + 4));
  }
  return groups.join(" ");
}

export function resolveLinkUrl(
  config: AgentConfig,
  env: Readonly<Record<string, string | undefined>> = process.env,
): string {
  const envUrl = env.TEGRAD_LINK_URL?.trim();
  if (envUrl && envUrl.length > 0) {
    return validateLinkUrl(envUrl);
  }
  if (config.linkUrl !== undefined) {
    return config.linkUrl;
  }
  return DEFAULT_LINK_URL;
}

function defaultSleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) {
    return Promise.resolve();
  }
  return new Promise<void>((resolve) => {
    const onAbort = (): void => {
      clearTimeout(timer);
      resolve();
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function defaultConfirm(prompt: string, stdout: (text: string) => void): Promise<string> {
  return new Promise<string>((resolve) => {
    stdout(prompt);
    const rl = createInterface({
      input: process.stdin,
      terminal: false,
    });
    let resolved = false;
    rl.once("line", (line) => {
      resolved = true;
      rl.close();
      resolve(line);
    });
    rl.once("close", () => {
      if (!resolved) {
        resolve("");
      }
    });
  });
}

export interface RunPairingFlowOptions {
  readonly stateDir: string;
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly add?: boolean;
  readonly reset?: boolean;
  readonly yes?: boolean;
  readonly allowUnverified?: boolean;
  readonly stdout?: (text: string) => void;
  readonly stderr?: (text: string) => void;
  readonly logger?: Logger;
  readonly fetch?: FetchLike;
  readonly apiClient?: PairingApiClient;
  readonly now?: () => number;
  readonly sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  readonly pollIntervalMs?: number;
  readonly timeoutMs?: number;
  readonly signalTarget?: Pick<NodeJS.Process, "on" | "off">;
  readonly confirm?: (prompt: string) => Promise<string>;
  readonly generateCode?: () => string;
  readonly generateSecret?: () => string;
}

export async function runPairingFlow(options: RunPairingFlowOptions): Promise<number> {
  await ready();

  const env = options.env ?? process.env;
  const stdout = options.stdout ?? ((text: string) => process.stdout.write(text));
  const stderr = options.stderr ?? ((text: string) => process.stderr.write(text));
  const now = options.now ?? (() => Date.now());
  const sleep = options.sleep ?? defaultSleep;
  const pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const timeoutMs = options.timeoutMs ?? DEFAULT_PAIRING_TIMEOUT_MS;
  const signalTarget = options.signalTarget ?? process;
  const confirm = options.confirm ?? ((prompt: string) => defaultConfirm(prompt, stdout));
  const generateCode = options.generateCode ?? generatePairingCode;
  const generateSecret = options.generateSecret ?? generatePairingSecret;
  const allowUnverified = options.allowUnverified ?? false;

  const config = loadConfig(options.stateDir, { env });
  const linkBaseUrl = resolveLinkUrl(config, env);
  const agentKeyPair = await loadOrCreateIdentity(options.stateDir);
  const agentId = fingerprint(agentKeyPair.publicKey);
  const existingTrusted = await loadTrust(options.stateDir);

  if (options.reset) {
    if (!options.yes) {
      const answer = await confirm(
        "This will remove all trusted accounts, revocations, and replay state (keeping the agent identity and server data). Type 'yes' to continue: ",
      );
      if (answer.trim() !== "yes") {
        stderr("Pairing reset cancelled.\n");
        return 1;
      }
    }
    resetTrustState(options.stateDir);
    options.logger?.info("Cleared trust, revocations, and replay state for reset");
  } else if (existingTrusted.length > 0 && !options.add) {
    stderr(
      `This agent is already linked to ${existingTrusted.length} account(s). Use --add to trust another account, or --reset to clear existing trust and link again.\n`,
    );
    return 1;
  }

  if (allowUnverified) {
    stderr(
      "WARNING: --allow-unverified is enabled. Accepting a trust grant without pairing proof trusts the API on first contact.\n",
    );
  }

  const api =
    options.apiClient ??
    createPairingApiClient({
      apiUrl: config.apiUrl,
      agentKeyPair,
      allowInsecure: isInsecureAllowed(env),
      ...(options.fetch !== undefined ? { fetch: options.fetch } : {}),
    });

  const abortController = new AbortController();
  let cancelled = false;
  let activeCode: string | null = null;

  const onSigInt = (): void => {
    cancelled = true;
    abortController.abort();
  };
  signalTarget.on("SIGINT", onSigInt);

  try {
    const secret = generateSecret();
    const agentPublicKeyB64 = toBase64Url(agentKeyPair.publicKey);

    let registeredCode: string | null = null;
    for (let attempt = 0; attempt <= MAX_CODE_CONFLICT_RETRIES; attempt++) {
      const candidate = generateCode();
      const status = await api.registerPairing(
        candidate,
        agentPublicKeyB64,
        abortController.signal,
      );
      if (status === "created") {
        registeredCode = candidate;
        break;
      }
      options.logger?.warn("Pairing code conflict, retrying with a new code", {
        attempt: attempt + 1,
      });
    }

    if (registeredCode === null) {
      stderr("Failed to register pairing code after multiple conflicts.\n");
      return 1;
    }

    activeCode = registeredCode;
    const fragment = buildPairingFragment({
      code: registeredCode,
      secret,
      agentFingerprint: agentId,
    });
    const pairingUrl = `${linkBaseUrl}#${fragment}`;
    const qr = renderUnicodeCompact(pairingUrl);

    options.logger?.info("Pairing request registered", { agentId });

    stdout(`Agent fingerprint: ${formatFingerprintGroups(agentId)}\n`);
    stdout(`Pairing URL: ${pairingUrl}\n\n`);
    stdout(`${qr}\n\n`);
    stdout("Waiting for pairing confirmation...\n");

    const deadline = now() + timeoutMs;

    while (!cancelled && now() < deadline) {
      const result = await api.pollGrant(registeredCode, abortController.signal);

      if (result.status === "expired") {
        options.logger?.warn("Pairing request expired");
        stderr("Pairing request expired.\n");
        return 1;
      }

      if (result.status === "ready") {
        try {
          const verified = verifyTrustGrant(result.grant, {
            agentPublicKey: agentKeyPair.publicKey,
            secret,
            now: now(),
            requireProof: !allowUnverified,
          });
          await addTrustedAccount(options.stateDir, verified.accountPublicKey);
          await api.deletePairing(registeredCode);
          activeCode = null;
          options.logger?.info("Agent linked to account", {
            accountId: verified.accountId,
            proven: verified.proven,
          });
          stdout(
            `Linked account: ${verified.accountId} (${formatFingerprintGroups(verified.accountId)})\n`,
          );
          return 0;
        } catch (err) {
          await api.deletePairing(registeredCode);
          activeCode = null;
          if (err instanceof ProtocolError) {
            options.logger?.warn("Trust grant rejected", { code: err.code });
            stderr(`Pairing rejected: ${err.code}\n`);
            return 1;
          }
          options.logger?.error("Unexpected error verifying trust grant", {
            errName: err instanceof Error ? err.name : "Error",
          });
          stderr("Pairing rejected: grant_invalid\n");
          return 1;
        }
      }

      const remaining = deadline - now();
      if (remaining <= 0 || cancelled) {
        break;
      }
      await sleep(Math.min(pollIntervalMs, remaining), abortController.signal);
    }

    if (cancelled) {
      await api.deletePairing(registeredCode);
      activeCode = null;
      options.logger?.info("Pairing cancelled by user");
      stderr("Pairing cancelled.\n");
      return 1;
    }

    await api.deletePairing(registeredCode);
    activeCode = null;
    options.logger?.warn("Pairing timed out");
    stderr("Pairing timed out.\n");
    return 1;
  } catch (err) {
    if (activeCode !== null) {
      await api.deletePairing(activeCode);
      activeCode = null;
    }
    if (cancelled || (err instanceof PairingApiError && err.code === "aborted")) {
      options.logger?.info("Pairing cancelled by user");
      stderr("Pairing cancelled.\n");
      return 1;
    }
    if (err instanceof PairingApiError) {
      options.logger?.error("Pairing API error", { code: err.code });
      stderr(`Pairing failed: ${err.code}\n`);
      return 1;
    }
    options.logger?.error("Unexpected pairing failure", {
      errName: err instanceof Error ? err.name : "Error",
    });
    stderr("Pairing failed.\n");
    return 1;
  } finally {
    signalTarget.off("SIGINT", onSigInt);
  }
}
