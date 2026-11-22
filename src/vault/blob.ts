// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
import {
  assertKdfParams,
  canonicalize,
  fromBase64Url,
  KDF_ALG_ARGON2ID13,
  type KdfParams,
  SIGNING_PUBLIC_KEY_BYTES,
} from "../crypto";
import { base64UrlSchema, type KeyId, keyIdSchema } from "../protocol";
import { VaultError } from "./errors";

export const VAULT_VERSION = 1 as const;

export const vaultKdfSchema = z.object({
  alg: z.literal(KDF_ALG_ARGON2ID13),
  opslimit: z.number().int().positive(),
  memlimit: z.number().int().positive(),
  salt: base64UrlSchema,
});

export const vaultBlobSchema = z.object({
  v: z.literal(VAULT_VERSION),
  account: keyIdSchema,
  public_key: base64UrlSchema,
  created_at: z.number().int().nonnegative(),
  password: z.object({
    kdf: vaultKdfSchema,
    wrapped_secret: base64UrlSchema,
  }),
  recovery: z.object({
    wrapped_secret: base64UrlSchema,
  }),
});

export type VaultKdf = z.infer<typeof vaultKdfSchema>;
export type VaultBlob = z.infer<typeof vaultBlobSchema>;

export interface ParsedVaultBlob {
  readonly blob: VaultBlob;
  readonly publicKeyBytes: Uint8Array;
  readonly kdfParams: KdfParams;
  readonly passwordWrapped: Uint8Array;
  readonly recoveryWrapped: Uint8Array;
}

export function parseVaultBlob(input: unknown): ParsedVaultBlob {
  const parsed = vaultBlobSchema.safeParse(input);
  if (!parsed.success) {
    throw new VaultError("invalid_blob", "Malformed vault blob");
  }

  const blob = parsed.data;

  let publicKeyBytes: Uint8Array;
  let saltBytes: Uint8Array;
  let passwordWrapped: Uint8Array;
  let recoveryWrapped: Uint8Array;
  try {
    publicKeyBytes = fromBase64Url(blob.public_key);
    saltBytes = fromBase64Url(blob.password.kdf.salt);
    passwordWrapped = fromBase64Url(blob.password.wrapped_secret);
    recoveryWrapped = fromBase64Url(blob.recovery.wrapped_secret);
  } catch {
    throw new VaultError("invalid_blob", "Invalid base64url encoding in vault blob");
  }

  if (publicKeyBytes.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new VaultError("invalid_blob", "Invalid account public key length in vault blob");
  }

  const kdfParams: KdfParams = {
    alg: blob.password.kdf.alg,
    opslimit: blob.password.kdf.opslimit,
    memlimit: blob.password.kdf.memlimit,
    salt: saltBytes,
  };

  try {
    assertKdfParams(kdfParams);
  } catch {
    throw new VaultError("invalid_blob", "Vault blob KDF parameters do not meet minimum floor");
  }

  return {
    blob,
    publicKeyBytes,
    kdfParams,
    passwordWrapped,
    recoveryWrapped,
  };
}

export function buildPasswordAad(fields: {
  readonly v: typeof VAULT_VERSION;
  readonly account: KeyId;
  readonly public_key: string;
  readonly kdf: VaultKdf;
}): Uint8Array {
  return canonicalize({
    context: "tegra-vault-v1:password",
    v: fields.v,
    account: fields.account,
    public_key: fields.public_key,
    kdf: {
      alg: fields.kdf.alg,
      opslimit: fields.kdf.opslimit,
      memlimit: fields.kdf.memlimit,
      salt: fields.kdf.salt,
    },
  });
}

export function buildRecoveryAad(fields: {
  readonly v: typeof VAULT_VERSION;
  readonly account: KeyId;
  readonly public_key: string;
}): Uint8Array {
  return canonicalize({
    context: "tegra-vault-v1:recovery",
    v: fields.v,
    account: fields.account,
    public_key: fields.public_key,
  });
}
