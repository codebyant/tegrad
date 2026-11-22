// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

const BASE64URL_LOOKUP = new Int8Array(128).fill(-1);
for (let i = 0; i < BASE64URL_ALPHABET.length; i++) {
  BASE64URL_LOOKUP[BASE64URL_ALPHABET.charCodeAt(i)] = i;
}

export function toBase64Url(bytes: Uint8Array): string {
  let out = "";
  const len = bytes.length;
  let i = 0;

  for (; i + 2 < len; i += 3) {
    const b0 = bytes[i] ?? 0;
    const b1 = bytes[i + 1] ?? 0;
    const b2 = bytes[i + 2] ?? 0;
    const triple = (b0 << 16) | (b1 << 8) | b2;
    out +=
      (BASE64URL_ALPHABET[(triple >>> 18) & 0x3f] ?? "") +
      (BASE64URL_ALPHABET[(triple >>> 12) & 0x3f] ?? "") +
      (BASE64URL_ALPHABET[(triple >>> 6) & 0x3f] ?? "") +
      (BASE64URL_ALPHABET[triple & 0x3f] ?? "");
  }

  const remaining = len - i;
  if (remaining === 1) {
    const b0 = bytes[i] ?? 0;
    out +=
      (BASE64URL_ALPHABET[(b0 >>> 2) & 0x3f] ?? "") + (BASE64URL_ALPHABET[(b0 << 4) & 0x3f] ?? "");
  } else if (remaining === 2) {
    const b0 = bytes[i] ?? 0;
    const b1 = bytes[i + 1] ?? 0;
    out +=
      (BASE64URL_ALPHABET[(b0 >>> 2) & 0x3f] ?? "") +
      (BASE64URL_ALPHABET[((b0 << 4) | (b1 >>> 4)) & 0x3f] ?? "") +
      (BASE64URL_ALPHABET[(b1 << 2) & 0x3f] ?? "");
  }

  return out;
}

export function fromBase64Url(text: string): Uint8Array {
  const len = text.length;
  const rem = len % 4;
  if (rem === 1) {
    throw new Error("Invalid base64url length");
  }

  const byteLen = Math.floor((len * 3) / 4);
  const out = new Uint8Array(byteLen);
  let outIdx = 0;
  let i = 0;

  const decodeChar = (idx: number): number => {
    const code = text.charCodeAt(idx);
    if (code >= 128) throw new Error("Invalid base64url character");
    const val = BASE64URL_LOOKUP[code] ?? -1;
    if (val < 0) throw new Error("Invalid base64url character");
    return val;
  };

  for (; i + 3 < len; i += 4) {
    const c0 = decodeChar(i);
    const c1 = decodeChar(i + 1);
    const c2 = decodeChar(i + 2);
    const c3 = decodeChar(i + 3);
    const triple = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;
    out[outIdx++] = (triple >>> 16) & 0xff;
    out[outIdx++] = (triple >>> 8) & 0xff;
    out[outIdx++] = triple & 0xff;
  }

  if (rem === 2) {
    const c0 = decodeChar(i);
    const c1 = decodeChar(i + 1);
    if ((c1 & 0x0f) !== 0) {
      throw new Error("Non-canonical base64url trailing bits");
    }
    out[outIdx++] = (c0 << 2) | (c1 >>> 4);
  } else if (rem === 3) {
    const c0 = decodeChar(i);
    const c1 = decodeChar(i + 1);
    const c2 = decodeChar(i + 2);
    if ((c2 & 0x03) !== 0) {
      throw new Error("Non-canonical base64url trailing bits");
    }
    out[outIdx++] = (c0 << 2) | (c1 >>> 4);
    out[outIdx++] = ((c1 & 0x0f) << 4) | (c2 >>> 2);
  }

  return out;
}

export function toBase32(bytes: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bitsLeft = 0;

  for (let i = 0; i < bytes.length; i++) {
    buffer = (buffer << 8) | (bytes[i] ?? 0);
    bitsLeft += 8;
    while (bitsLeft >= 5) {
      bitsLeft -= 5;
      out += BASE32_ALPHABET[(buffer >>> bitsLeft) & 0x1f] ?? "";
    }
  }

  if (bitsLeft > 0) {
    out += BASE32_ALPHABET[(buffer << (5 - bitsLeft)) & 0x1f] ?? "";
  }

  return out;
}
