// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { randomBytes as nodeRandomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import { z } from "zod";
import {
  fingerprint,
  fromBase64Url,
  generateSigningKeyPair,
  type PublicKey,
  ready,
  SIGNING_PUBLIC_KEY_BYTES,
  SIGNING_SECRET_KEY_BYTES,
  type SigningKeyPair,
  toBase64Url,
} from "../crypto";
import {
  base64UrlSchema,
  type KeyId,
  keyIdSchema,
  PROTOCOL_VERSION,
  ProtocolError,
  revocationListSchema,
  type TrustContext,
  verifyRevocationList,
} from "../protocol";
import { getStatePaths } from "./paths";

export const MAX_RECENT_REPLAY_IDS = 4096;

const STATE_DIR_MODE = 0o700;
const SECRET_FILE_MODE = 0o600;

export class StateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StateError";
  }
}

const envFlagsSchema = z.object({
  TEGRAD_ALLOW_INSECURE: z.string().optional(),
});

const rawConfigSchema = z.object({
  api_url: z.string().min(1),
  link_url: z.string().min(1).optional(),
});

export interface AgentConfig {
  readonly apiUrl: string;
  readonly linkUrl?: string;
}

const identityFileSchema = z.object({
  v: z.literal(1),
  public_key: base64UrlSchema,
  secret_key: base64UrlSchema,
});

const trustFileSchema = z.object({
  v: z.literal(1),
  accounts: z.array(
    z.object({
      public_key: base64UrlSchema,
    }),
  ),
});

const replayFileSchema = z.object({
  v: z.literal(1),
  last_counter: z.record(keyIdSchema, z.number().int().nonnegative()),
  recent_ids: z.array(base64UrlSchema),
});

const revocationAccountEntrySchema = z.object({
  issued_at: z.number().int().nonnegative(),
  revoked: z.array(base64UrlSchema),
});

const revocationsFileSchema = z.object({
  v: z.literal(1),
  accounts: z.record(keyIdSchema, revocationAccountEntrySchema),
});

export interface RevocationAccountState {
  readonly issued_at: number;
  readonly revoked: readonly string[];
}

export interface RevocationsState {
  readonly v: 1;
  readonly accounts: Readonly<Record<string, RevocationAccountState>>;
}

export interface AtomicWriteOptions {
  readonly mode?: number;
  readonly dirMode?: number;
  readonly writeContent?: (fd: number, content: string) => void;
}

function isPosix(platform: NodeJS.Platform = process.platform): boolean {
  return platform !== "win32";
}

function ensureDir(dirPath: string, mode: number = STATE_DIR_MODE): void {
  mkdirSync(dirPath, { recursive: true, mode });
  if (isPosix()) {
    chmodSync(dirPath, mode);
  }
}

export function assertStrictPermissions(filePath: string): void {
  if (!isPosix()) {
    return;
  }
  const mode = statSync(filePath).mode & 0o777;
  if ((mode & ~SECRET_FILE_MODE) !== 0) {
    throw new StateError(
      `Refusing to read ${filePath}: permissions ${mode.toString(8).padStart(4, "0")} are more permissive than 0600`,
    );
  }
}

export function writeFileAtomic(
  filePath: string,
  content: string,
  options: AtomicWriteOptions = {},
): void {
  const dir = dirname(filePath);
  const mode = options.mode ?? SECRET_FILE_MODE;
  const dirMode = options.dirMode ?? STATE_DIR_MODE;
  ensureDir(dir, dirMode);

  const suffix = nodeRandomBytes(8).toString("hex");
  const tmpPath = join(dir, `.tmp-${basename(filePath)}-${process.pid}-${suffix}`);
  let fd: number | undefined;

  try {
    fd = openSync(tmpPath, "wx", mode);
    if (options.writeContent) {
      options.writeContent(fd, content);
    } else {
      writeFileSync(fd, content, "utf8");
    }
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;

    if (isPosix()) {
      chmodSync(tmpPath, mode);
    }

    renameSync(tmpPath, filePath);
  } catch (err) {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        // ignore close failure on cleanup
      }
    }
    try {
      if (existsSync(tmpPath)) {
        unlinkSync(tmpPath);
      }
    } catch {
      // ignore cleanup failure
    }
    throw err;
  }
}

function readJsonFile(filePath: string, label: string): unknown {
  let raw: string;
  try {
    raw = readFileSync(filePath, "utf8");
  } catch (err) {
    throw new StateError(
      `Failed to read ${label} at ${filePath}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  try {
    return JSON.parse(raw) as unknown;
  } catch {
    throw new StateError(`Invalid JSON in ${label} at ${filePath}`);
  }
}

export function isInsecureAllowed(
  env: Readonly<Record<string, string | undefined>> = process.env,
): boolean {
  const parsed = envFlagsSchema.parse({ TEGRAD_ALLOW_INSECURE: env.TEGRAD_ALLOW_INSECURE });
  return parsed.TEGRAD_ALLOW_INSECURE === "1";
}

export function validateApiUrl(apiUrl: string, allowInsecure: boolean): string {
  let parsed: URL;
  try {
    parsed = new URL(apiUrl);
  } catch {
    throw new StateError(`Invalid api_url in config.json: "${apiUrl}"`);
  }

  if (parsed.username || parsed.password) {
    throw new StateError("api_url must not contain embedded credentials");
  }

  if (parsed.protocol === "https:") {
    return parsed.toString();
  }

  if (
    allowInsecure &&
    parsed.protocol === "http:" &&
    (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1")
  ) {
    return parsed.toString();
  }

  throw new StateError(
    `api_url must use https:// (got ${parsed.protocol}//${parsed.host}); set TEGRAD_ALLOW_INSECURE=1 for http://localhost or http://127.0.0.1 in development`,
  );
}

export function validateLinkUrl(linkUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(linkUrl);
  } catch {
    throw new StateError(`Invalid link_url: "${linkUrl}"`);
  }

  if (parsed.username || parsed.password) {
    throw new StateError("link_url must not contain embedded credentials");
  }

  if (parsed.protocol !== "https:") {
    throw new StateError(`link_url must use https:// (got ${parsed.protocol}//${parsed.host})`);
  }

  if (parsed.hash.length > 0) {
    throw new StateError("link_url must not contain a URL fragment");
  }

  return parsed.toString();
}

export interface LoadConfigOptions {
  readonly allowInsecure?: boolean;
  readonly env?: Readonly<Record<string, string | undefined>>;
}

export function loadConfig(stateDir: string, options: LoadConfigOptions = {}): AgentConfig {
  const { configPath } = getStatePaths(stateDir);
  if (!existsSync(configPath)) {
    throw new StateError(`Missing config.json at ${configPath}`);
  }

  const raw = readJsonFile(configPath, "config.json");
  const parsed = rawConfigSchema.safeParse(raw);
  if (!parsed.success) {
    throw new StateError(`Invalid config.json at ${configPath}`);
  }

  const allowInsecure = options.allowInsecure ?? isInsecureAllowed(options.env);
  const apiUrl = validateApiUrl(parsed.data.api_url, allowInsecure);
  const linkUrl =
    parsed.data.link_url !== undefined ? validateLinkUrl(parsed.data.link_url) : undefined;
  return {
    apiUrl,
    ...(linkUrl !== undefined ? { linkUrl } : {}),
  };
}

function parseIdentityFile(filePath: string): SigningKeyPair {
  assertStrictPermissions(filePath);
  const raw = readJsonFile(filePath, "identity.json");
  const parsed = identityFileSchema.safeParse(raw);
  if (!parsed.success) {
    throw new StateError(`Invalid identity.json at ${filePath}`);
  }

  let publicKey: Uint8Array;
  let secretKey: Uint8Array;
  try {
    publicKey = fromBase64Url(parsed.data.public_key);
    secretKey = fromBase64Url(parsed.data.secret_key);
  } catch {
    throw new StateError(`Invalid key encoding in identity.json at ${filePath}`);
  }

  if (
    publicKey.length !== SIGNING_PUBLIC_KEY_BYTES ||
    secretKey.length !== SIGNING_SECRET_KEY_BYTES
  ) {
    throw new StateError(`Invalid key length in identity.json at ${filePath}`);
  }

  return { publicKey, secretKey };
}

export async function loadIdentityIfExists(stateDir: string): Promise<SigningKeyPair | null> {
  await ready();
  const { identityPath } = getStatePaths(stateDir);
  if (!existsSync(identityPath)) {
    return null;
  }
  return parseIdentityFile(identityPath);
}

export async function loadOrCreateIdentity(stateDir: string): Promise<SigningKeyPair> {
  await ready();
  const { identityPath } = getStatePaths(stateDir);
  if (existsSync(identityPath)) {
    return parseIdentityFile(identityPath);
  }

  const keyPair = generateSigningKeyPair();
  const content = `${JSON.stringify(
    {
      v: 1,
      public_key: toBase64Url(keyPair.publicKey),
      secret_key: toBase64Url(keyPair.secretKey),
    },
    null,
    2,
  )}\n`;

  writeFileAtomic(identityPath, content, {
    mode: SECRET_FILE_MODE,
    dirMode: STATE_DIR_MODE,
  });

  return keyPair;
}

function loadTrustSync(trustPath: string): PublicKey[] {
  if (!existsSync(trustPath)) {
    return [];
  }

  const raw = readJsonFile(trustPath, "trust.json");
  const parsed = trustFileSchema.safeParse(raw);
  if (!parsed.success) {
    throw new StateError(`Invalid trust.json at ${trustPath}`);
  }

  const keys: PublicKey[] = [];
  for (const entry of parsed.data.accounts) {
    let keyBytes: Uint8Array;
    try {
      keyBytes = fromBase64Url(entry.public_key);
    } catch {
      throw new StateError(`Invalid public_key encoding in trust.json at ${trustPath}`);
    }
    if (keyBytes.length !== SIGNING_PUBLIC_KEY_BYTES) {
      throw new StateError(`Invalid public_key length in trust.json at ${trustPath}`);
    }
    keys.push(keyBytes);
  }

  return keys;
}

export async function loadTrust(stateDir: string): Promise<PublicKey[]> {
  await ready();
  const { trustPath } = getStatePaths(stateDir);
  return loadTrustSync(trustPath);
}

export async function addTrustedAccount(
  stateDir: string,
  publicKey: PublicKey,
): Promise<{ readonly added: boolean; readonly accountId: KeyId }> {
  await ready();
  if (publicKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new StateError(`Account public key must be ${SIGNING_PUBLIC_KEY_BYTES} bytes`);
  }

  const { trustPath } = getStatePaths(stateDir);
  const existing = loadTrustSync(trustPath);
  const accountId = fingerprint(publicKey);

  for (const key of existing) {
    if (fingerprint(key) === accountId) {
      return { added: false, accountId };
    }
  }

  const accounts = [...existing, publicKey].map((key) => ({
    public_key: toBase64Url(key),
  }));
  const content = `${JSON.stringify({ v: 1, accounts }, null, 2)}\n`;
  writeFileAtomic(trustPath, content, {
    mode: SECRET_FILE_MODE,
    dirMode: STATE_DIR_MODE,
  });

  return { added: true, accountId };
}

function unlinkIfExists(filePath: string): void {
  if (existsSync(filePath)) {
    unlinkSync(filePath);
  }
}

export function clearTrust(stateDir: string): void {
  const { trustPath } = getStatePaths(stateDir);
  unlinkIfExists(trustPath);
}

export function resetTrustState(stateDir: string): void {
  const { trustPath, revocationsPath, replayPath } = getStatePaths(stateDir);
  unlinkIfExists(trustPath);
  unlinkIfExists(revocationsPath);
  unlinkIfExists(replayPath);
}

export function loadRevocations(stateDir: string): RevocationsState {
  const { revocationsPath } = getStatePaths(stateDir);
  if (!existsSync(revocationsPath)) {
    return { v: 1, accounts: {} };
  }

  const raw = readJsonFile(revocationsPath, "revocations.json");
  const parsed = revocationsFileSchema.safeParse(raw);
  if (!parsed.success) {
    throw new StateError(`Invalid revocations.json at ${revocationsPath}`);
  }

  return parsed.data;
}

export async function applyRevocationList(
  stateDir: string,
  list: unknown,
): Promise<{ readonly account: KeyId; readonly count: number }> {
  await ready();

  if (typeof list === "object" && list !== null && "v" in list) {
    const version = (list as { v: unknown }).v;
    if (version !== PROTOCOL_VERSION) {
      throw new ProtocolError("unsupported_version", "Unsupported protocol version");
    }
  }

  const parsed = revocationListSchema.safeParse(list);
  if (!parsed.success) {
    throw new ProtocolError("invalid_format", "Malformed revocation list");
  }

  const trustedKeys = await loadTrust(stateDir);
  const accountPublicKey =
    trustedKeys.find((key) => fingerprint(key) === parsed.data.account) ?? null;
  if (accountPublicKey === null) {
    throw new ProtocolError("untrusted_signer", "Revocation list account is not trusted");
  }

  const verified = verifyRevocationList(list, accountPublicKey);
  const current = loadRevocations(stateDir);
  const existing = current.accounts[verified.account];

  if (existing !== undefined) {
    if (verified.issued_at <= existing.issued_at) {
      throw new ProtocolError(
        "revocation_stale",
        "Revocation list issued_at must be greater than existing list",
      );
    }
    const nextSet = new Set(verified.revoked);
    for (const revokedId of existing.revoked) {
      if (!nextSet.has(revokedId)) {
        throw new ProtocolError(
          "revocation_not_superset",
          "Revocation list must be a superset of previously revoked sessions",
        );
      }
    }
  }

  const dedupedRevoked: string[] = [];
  const seen = new Set<string>();
  for (const id of verified.revoked) {
    if (!seen.has(id)) {
      seen.add(id);
      dedupedRevoked.push(id);
    }
  }

  const nextAccounts: Record<string, RevocationAccountState> = {
    ...current.accounts,
    [verified.account]: {
      issued_at: verified.issued_at,
      revoked: dedupedRevoked,
    },
  };

  const { revocationsPath } = getStatePaths(stateDir);
  const content = `${JSON.stringify({ v: 1, accounts: nextAccounts }, null, 2)}\n`;
  writeFileAtomic(revocationsPath, content, {
    mode: SECRET_FILE_MODE,
    dirMode: STATE_DIR_MODE,
  });

  return {
    account: verified.account,
    count: dedupedRevoked.length,
  };
}

interface ReplayStateData {
  readonly lastCounters: Map<KeyId, number>;
  readonly recentIds: string[];
  readonly recentIdSet: Set<string>;
}

function loadReplayState(replayPath: string, maxRecentIds: number): ReplayStateData {
  const lastCounters = new Map<KeyId, number>();
  const recentIds: string[] = [];
  const recentIdSet = new Set<string>();

  if (!existsSync(replayPath)) {
    return { lastCounters, recentIds, recentIdSet };
  }

  const raw = readJsonFile(replayPath, "replay.json");
  const parsed = replayFileSchema.safeParse(raw);
  if (!parsed.success) {
    throw new StateError(`Invalid replay.json at ${replayPath}`);
  }

  for (const [signer, counter] of Object.entries(parsed.data.last_counter)) {
    lastCounters.set(signer as KeyId, counter);
  }

  const trimmed =
    parsed.data.recent_ids.length > maxRecentIds
      ? parsed.data.recent_ids.slice(parsed.data.recent_ids.length - maxRecentIds)
      : parsed.data.recent_ids;

  for (const id of trimmed) {
    if (!recentIdSet.has(id)) {
      recentIdSet.add(id);
      recentIds.push(id);
    }
  }

  return { lastCounters, recentIds, recentIdSet };
}

function persistReplayState(replayPath: string, state: ReplayStateData): void {
  const lastCounterObj: Record<string, number> = {};
  for (const [signer, counter] of state.lastCounters.entries()) {
    lastCounterObj[signer] = counter;
  }

  const payload = `${JSON.stringify({
    v: 1,
    last_counter: lastCounterObj,
    recent_ids: state.recentIds,
  })}\n`;

  writeFileAtomic(replayPath, payload, {
    mode: SECRET_FILE_MODE,
    dirMode: STATE_DIR_MODE,
  });
}

export interface FileTrustContextOptions {
  readonly stateDir: string;
  readonly agentKeyPair: SigningKeyPair;
  readonly trustedAccountKeys: readonly PublicKey[];
  readonly revokedSessionIds?: Iterable<string>;
  readonly now?: () => number;
  readonly maxRecentIds?: number;
}

export interface FileTrustContext extends TrustContext {
  setRevokedSessionIds(ids: Iterable<string>): void;
  applyRevocationList(list: unknown): Promise<{ readonly account: KeyId; readonly count: number }>;
  flush(): void;
}

export function createFileTrustContext(options: FileTrustContextOptions): FileTrustContext {
  const { trustPath, revocationsPath, replayPath } = getStatePaths(options.stateDir);
  const maxRecentIds = options.maxRecentIds ?? MAX_RECENT_REPLAY_IDS;
  const fallbackTrusted = new Map<KeyId, PublicKey>();
  for (const key of options.trustedAccountKeys) {
    fallbackTrusted.set(fingerprint(key), key);
  }

  let sawTrustFile = existsSync(trustPath);
  let sawReplayFile = existsSync(replayPath);
  let manualRevoked = new Set<string>(options.revokedSessionIds);
  const clock = options.now ?? (() => Date.now());
  const replay = loadReplayState(replayPath, maxRecentIds);

  return {
    agentKeyPair: options.agentKeyPair,

    isTrustedAccountKey(id: KeyId): PublicKey | null {
      if (existsSync(trustPath)) {
        sawTrustFile = true;
        const keys = loadTrustSync(trustPath);
        for (const key of keys) {
          if (fingerprint(key) === id) {
            return key;
          }
        }
        return null;
      }
      if (sawTrustFile) {
        return null;
      }
      return fallbackTrusted.get(id) ?? null;
    },

    isSessionRevoked(certificateId: string): boolean {
      if (manualRevoked.has(certificateId)) {
        return true;
      }
      if (!existsSync(revocationsPath)) {
        return false;
      }
      const state = loadRevocations(options.stateDir);
      for (const entry of Object.values(state.accounts)) {
        if (entry.revoked.includes(certificateId)) {
          return true;
        }
      }
      return false;
    },

    setRevokedSessionIds(ids: Iterable<string>): void {
      manualRevoked = new Set<string>(ids);
    },

    applyRevocationList(
      list: unknown,
    ): Promise<{ readonly account: KeyId; readonly count: number }> {
      return applyRevocationList(options.stateDir, list);
    },

    now(): number {
      return clock();
    },

    claimCommand(signer: KeyId, id: string, counter: number): boolean {
      if (sawReplayFile && !existsSync(replayPath)) {
        replay.lastCounters.clear();
        replay.recentIds.length = 0;
        replay.recentIdSet.clear();
        sawReplayFile = false;
      }

      if (replay.recentIdSet.has(id)) {
        return false;
      }
      const prev = replay.lastCounters.get(signer);
      if (prev !== undefined && counter <= prev) {
        return false;
      }

      replay.recentIdSet.add(id);
      replay.recentIds.push(id);
      while (replay.recentIds.length > maxRecentIds) {
        const oldest = replay.recentIds.shift();
        if (oldest !== undefined) {
          replay.recentIdSet.delete(oldest);
        }
      }
      replay.lastCounters.set(signer, counter);
      persistReplayState(replayPath, replay);
      sawReplayFile = true;
      return true;
    },

    flush(): void {
      persistReplayState(replayPath, replay);
      sawReplayFile = true;
    },
  };
}
