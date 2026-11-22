// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { beforeAll, describe, expect, test } from "bun:test";
import {
  aeadDecrypt,
  aeadEncrypt,
  assertKdfParams,
  canonicalize,
  deriveKeyFromPassword,
  fingerprint,
  fromBase64Url,
  generateSalt,
  generateSigningKeyPair,
  generateSymmetricKey,
  KDF_FLOOR,
  KDF_MODERATE,
  openSealed,
  ready,
  sealTo,
  sign,
  signingKeyPairFromSeed,
  toBase32,
  toBase64Url,
  verify,
} from "./index";

beforeAll(async () => {
  await ready();
});

describe("encoding", () => {
  test("base64url round-trip without padding", () => {
    for (let len = 0; len <= 10; len++) {
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) bytes[i] = (i * 37 + 13) & 0xff;
      const encoded = toBase64Url(bytes);
      expect(encoded.includes("=")).toBe(false);
      expect(encoded.includes("+")).toBe(false);
      expect(encoded.includes("/")).toBe(false);
      expect(fromBase64Url(encoded)).toEqual(bytes);
    }
  });

  test("fromBase64Url rejects invalid inputs", () => {
    expect(() => fromBase64Url("abc=")).toThrow();
    expect(() => fromBase64Url("a")).toThrow();
    expect(() => fromBase64Url("ab+c")).toThrow();
    expect(() => fromBase64Url("ab/c")).toThrow();
    expect(() => fromBase64Url("ab c")).toThrow();
    expect(() => fromBase64Url("AB")).toThrow(); // non-canonical trailing bits
  });

  test("toBase32 encodes lowercase RFC 4648 without padding", () => {
    const enc = new TextEncoder();
    expect(toBase32(enc.encode(""))).toBe("");
    expect(toBase32(enc.encode("f"))).toBe("my");
    expect(toBase32(enc.encode("fo"))).toBe("mzxq");
    expect(toBase32(enc.encode("foo"))).toBe("mzxw6");
    expect(toBase32(enc.encode("foob"))).toBe("mzxw6yq");
    expect(toBase32(enc.encode("fooba"))).toBe("mzxw6ytb");
    expect(toBase32(enc.encode("foobar"))).toBe("mzxw6ytboi");
  });
});

describe("fixed vectors", () => {
  test("signingKeyPairFromSeed and fingerprint are deterministic", () => {
    const seedA = new Uint8Array(32).fill(0x11);
    const seedB = new Uint8Array(32).fill(0x22);

    const kpA = signingKeyPairFromSeed(seedA);
    const kpB = signingKeyPairFromSeed(seedB);

    expect(toBase64Url(kpA.publicKey)).toBe("0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc");
    expect(toBase64Url(kpB.publicKey)).toBe("oJql9HpnWYAv-VX43C0qFKXJnSO-l_hkEn_5ODRVpPA");

    const fpA = fingerprint(kpA.publicKey);
    const fpB = fingerprint(kpB.publicKey);
    expect(fpA).toBe("2o6xl7gxm5sqizy645pzlypnplng2fun");
    expect(fpB).toBe("7sgisx6bisee5ge2gkt4x67uondk2ojg");
    expect(fpA.length).toBe(32);
    expect(fpB.length).toBe(32);
  });

  test("Argon2id fixed vector with floor parameters", () => {
    const salt = new Uint8Array(16).fill(0x42);
    const derived = deriveKeyFromPassword("tegra-test-password", {
      ...KDF_FLOOR,
      salt,
    });
    expect(toBase64Url(derived)).toBe("UxQEU4EnrisI0GgKMdR0R_SKEu-zItfkz1agjIz3cUc");
  });
});

describe("signing, sealed box, and AEAD", () => {
  test("Ed25519 sign and verify", () => {
    const kp = generateSigningKeyPair();
    const msg = new TextEncoder().encode("hello tegra");
    const sig = sign(msg, kp.secretKey);

    expect(verify(msg, sig, kp.publicKey)).toBe(true);

    const tamperedSig = new Uint8Array(sig);
    tamperedSig[0] = (tamperedSig[0] ?? 0) ^ 0xff;
    expect(verify(msg, tamperedSig, kp.publicKey)).toBe(false);
    expect(verify(msg, new Uint8Array(10), kp.publicKey)).toBe(false);
    expect(verify(msg, sig, new Uint8Array(10))).toBe(false);
  });

  test("sealed box round-trip with Ed25519 keys", () => {
    const recipient = generateSigningKeyPair();
    const other = generateSigningKeyPair();
    const plaintext = new TextEncoder().encode("secret payload");

    const sealed = sealTo(plaintext, recipient.publicKey);
    expect(openSealed(sealed, recipient)).toEqual(plaintext);
    expect(() => openSealed(sealed, other)).toThrow();
  });

  test("AEAD XChaCha20-Poly1305 round-trip with and without AAD", () => {
    const key = generateSymmetricKey();
    const plaintext = new TextEncoder().encode("vault contents");
    const aad = new TextEncoder().encode("vault-v1");

    const ct1 = aeadEncrypt(plaintext, key);
    expect(aeadDecrypt(ct1, key)).toEqual(plaintext);

    const ct2 = aeadEncrypt(plaintext, key, aad);
    expect(aeadDecrypt(ct2, key, aad)).toEqual(plaintext);
    expect(() => aeadDecrypt(ct2, key)).toThrow();
    expect(() => aeadDecrypt(ct2, key, new TextEncoder().encode("wrong"))).toThrow();
  });
});

describe("KDF validation", () => {
  test("assertKdfParams accepts floor and moderate presets", () => {
    const salt = generateSalt();
    expect(() => assertKdfParams({ ...KDF_FLOOR, salt })).not.toThrow();
    expect(() => assertKdfParams({ ...KDF_MODERATE, salt })).not.toThrow();
  });

  test("assertKdfParams rejects below floor, wrong alg, or bad salt", () => {
    const salt = generateSalt();
    expect(() => assertKdfParams({ ...KDF_FLOOR, opslimit: 2, salt })).toThrow();
    expect(() => assertKdfParams({ ...KDF_FLOOR, memlimit: 64 * 1024 * 1024, salt })).toThrow();
    expect(() => assertKdfParams({ ...KDF_FLOOR, alg: "argon2i13", salt })).toThrow();
    expect(() => assertKdfParams({ ...KDF_FLOOR, salt: new Uint8Array(8) })).toThrow();
  });
});

describe("canonicalize", () => {
  const decode = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

  test("sorts object keys, omits undefined properties, normalizes -0", () => {
    const input = {
      z: 1,
      a: { d: true, b: -0, c: undefined },
      m: [1, "x", null],
      skip: undefined,
    };
    expect(decode(canonicalize(input))).toBe('{"a":{"b":0,"d":true},"m":[1,"x",null],"z":1}');
  });

  test("rejects NaN, Infinity, bare undefined, and non-JSON types", () => {
    expect(() => canonicalize(Number.NaN)).toThrow();
    expect(() => canonicalize(Number.POSITIVE_INFINITY)).toThrow();
    expect(() => canonicalize(Number.NEGATIVE_INFINITY)).toThrow();
    expect(() => canonicalize(undefined)).toThrow();
    expect(() => canonicalize([1, undefined])).toThrow();
    expect(() => canonicalize(() => {})).toThrow();
    expect(() => canonicalize(Symbol("x"))).toThrow();
    expect(() => canonicalize(10n)).toThrow();
    expect(() => canonicalize(new Date())).toThrow();
    expect(() => canonicalize(new Uint8Array([1, 2]))).toThrow();

    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(() => canonicalize(circular)).toThrow();
  });
});
