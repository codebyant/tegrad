// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { hash, memzero, randomBytes } from "../crypto";
import { VaultError } from "./errors";

export const RECOVERY_CODE_BYTES = 32;

const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const DATA_CHAR_COUNT = 52; // ceil(256 / 5) = 52 symbols (4 trailing zero bits)
const TOTAL_CHAR_COUNT = DATA_CHAR_COUNT + 1; // + 1 check character
const GROUP_SIZE = 4;

const CROCKFORD_LOOKUP = new Int8Array(128).fill(-1);
for (let i = 0; i < CROCKFORD_ALPHABET.length; i++) {
  CROCKFORD_LOOKUP[CROCKFORD_ALPHABET.charCodeAt(i)] = i;
}
// Standard Crockford base32 normalization for visually similar characters
CROCKFORD_LOOKUP["I".charCodeAt(0)] = 1;
CROCKFORD_LOOKUP["L".charCodeAt(0)] = 1;
CROCKFORD_LOOKUP["O".charCodeAt(0)] = 0;

const utf8Encoder = new TextEncoder();
const DOMAIN_RECOVERY_KEY = utf8Encoder.encode("tegra-vault-v1:recovery-key\0");

// Polynomial checksum over GF(32) with irreducible polynomial x^5 + x^2 + 1 (0x25).
// Detects 100% of single-character substitutions and 100% of adjacent transpositions.
function computeCheckSymbol(symbols: readonly number[]): number {
  let acc = 0;
  for (let i = 0; i < symbols.length; i++) {
    const sym = symbols[i] ?? 0;
    const shifted = acc << 1;
    acc = (shifted >= 32 ? shifted ^ 0x25 : shifted) ^ sym;
  }
  return acc & 0x1f;
}

export function generateRecoveryCodeBytes(): Uint8Array {
  return randomBytes(RECOVERY_CODE_BYTES);
}

export function formatRecoveryCode(bytes: Uint8Array): string {
  if (bytes.length !== RECOVERY_CODE_BYTES) {
    throw new RangeError(`Recovery code must be ${RECOVERY_CODE_BYTES} bytes`);
  }

  const symbols: number[] = [];
  let bitBuffer = 0;
  let bitsLeft = 0;

  for (let i = 0; i < bytes.length; i++) {
    bitBuffer = (bitBuffer << 8) | (bytes[i] ?? 0);
    bitsLeft += 8;
    while (bitsLeft >= 5) {
      bitsLeft -= 5;
      symbols.push((bitBuffer >>> bitsLeft) & 0x1f);
    }
  }

  if (bitsLeft > 0) {
    symbols.push((bitBuffer << (5 - bitsLeft)) & 0x1f);
  }

  const check = computeCheckSymbol(symbols);

  const groups: string[] = [];
  for (let i = 0; i < symbols.length; i += GROUP_SIZE) {
    let group = "";
    for (let j = i; j < i + GROUP_SIZE && j < symbols.length; j++) {
      group += CROCKFORD_ALPHABET[symbols[j] ?? 0] ?? "";
    }
    groups.push(group);
  }

  const checkChar = CROCKFORD_ALPHABET[check] ?? "";
  return `${groups.join("-")}-${checkChar}`;
}

export function parseRecoveryCode(code: string): Uint8Array {
  const cleaned = code.replace(/[\s-]+/g, "").toUpperCase();
  if (cleaned.length !== TOTAL_CHAR_COUNT) {
    throw new VaultError("invalid_recovery_code", "Invalid recovery code format");
  }

  const symbols: number[] = new Array<number>(DATA_CHAR_COUNT);
  for (let i = 0; i < DATA_CHAR_COUNT; i++) {
    const charCode = cleaned.charCodeAt(i);
    if (charCode >= 128) {
      throw new VaultError("invalid_recovery_code", "Invalid recovery code character");
    }
    const val = CROCKFORD_LOOKUP[charCode] ?? -1;
    if (val < 0) {
      throw new VaultError("invalid_recovery_code", "Invalid recovery code character");
    }
    symbols[i] = val;
  }

  const checkCharCode = cleaned.charCodeAt(DATA_CHAR_COUNT);
  if (checkCharCode >= 128) {
    throw new VaultError("invalid_recovery_code", "Invalid recovery code check character");
  }
  const providedCheck = CROCKFORD_LOOKUP[checkCharCode] ?? -1;
  if (providedCheck < 0) {
    throw new VaultError("invalid_recovery_code", "Invalid recovery code check character");
  }

  if (computeCheckSymbol(symbols) !== providedCheck) {
    throw new VaultError("invalid_recovery_code", "Recovery code verification failed");
  }

  const out = new Uint8Array(RECOVERY_CODE_BYTES);
  let bitBuffer = 0;
  let bitsLeft = 0;
  let outIdx = 0;

  for (let i = 0; i < DATA_CHAR_COUNT; i++) {
    bitBuffer = (bitBuffer << 5) | (symbols[i] ?? 0);
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      bitsLeft -= 8;
      if (outIdx < RECOVERY_CODE_BYTES) {
        out[outIdx++] = (bitBuffer >>> bitsLeft) & 0xff;
      }
    }
  }

  // Remaining 4 trailing bits must be zero for canonical encoding
  const trailingMask = (1 << bitsLeft) - 1;
  if ((bitBuffer & trailingMask) !== 0) {
    throw new VaultError("invalid_recovery_code", "Non-canonical recovery code");
  }

  return out;
}

export function deriveRecoveryKey(codeBytes: Uint8Array): Uint8Array {
  if (codeBytes.length !== RECOVERY_CODE_BYTES) {
    throw new RangeError(`Recovery code must be ${RECOVERY_CODE_BYTES} bytes`);
  }
  const input = new Uint8Array(DOMAIN_RECOVERY_KEY.length + codeBytes.length);
  input.set(DOMAIN_RECOVERY_KEY, 0);
  input.set(codeBytes, DOMAIN_RECOVERY_KEY.length);
  try {
    return hash(input);
  } finally {
    memzero(input);
  }
}
