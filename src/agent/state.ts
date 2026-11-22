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
import { base64UrlSchema, type KeyId, keyIdSchema, type TrustContext } from "../protocol";
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
});

export interface AgentConfig {
  readonly apiUrl: string;
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
  return { apiUrl };
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

export async function loadTrust(stateDir: string): Promise<PublicKey[]> {
  await ready();
  const { trustPath } = getStatePaths(stateDir);
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
  flush(): void;
}

export function createFileTrustContext(options: FileTrustContextOptions): FileTrustContext {
  const { replayPath } = getStatePaths(options.stateDir);
  const maxRecentIds = options.maxRecentIds ?? MAX_RECENT_REPLAY_IDS;
  const trusted = new Map<KeyId, PublicKey>();
  for (const key of options.trustedAccountKeys) {
    trusted.set(fingerprint(key), key);
  }

  let revoked = new Set<string>(options.revokedSessionIds);
  const clock = options.now ?? (() => Date.now());
  const replay = loadReplayState(replayPath, maxRecentIds);

  return {
    agentKeyPair: options.agentKeyPair,

    isTrustedAccountKey(id: KeyId): PublicKey | null {
      return trusted.get(id) ?? null;
    },

    isSessionRevoked(certificateId: string): boolean {
      return revoked.has(certificateId);
    },

    setRevokedSessionIds(ids: Iterable<string>): void {
      revoked = new Set<string>(ids);
    },

    now(): number {
      return clock();
    },

    claimCommand(signer: KeyId, id: string, counter: number): boolean {
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
      return true;
    },

    flush(): void {
      persistReplayState(replayPath, replay);
    },
  };
}
