// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runSignRelease } from "../../scripts/sign-release";
import { runCli } from "../cli/main";
import {
  fromBase64Url,
  generateSigningKeyPair,
  ready,
  signingKeyPairFromSeed,
  toBase64Url,
} from "../crypto";
import {
  computeBytesSha256,
  ed25519PublicKeyFromPem,
  ed25519PublicKeyToPem,
  formatSha256Sums,
  getReleasePublicKey,
  isPlaceholderReleaseKey,
  MANIFEST_SCHEMA_VERSION,
  parseReleaseSigningKey,
  signManifest,
  signSha256Sums,
  TEST_RELEASE_PUBLIC_KEY_BASE64URL,
  type UnsignedReleaseManifest,
  UpdateError,
  verifyManifest,
  verifyReleaseBinary,
  verifySha256Sums,
} from "./index";

// Deterministic test-only seed matching placeholder RELEASE_PUBLIC_KEY_BASE64URL.
// Never store production signing keys or seeds in source code.
const TEST_RELEASE_SEED = new Uint8Array(32).fill(0x42);
const ALLOW_TEST_KEY_ENV = { TEGRAD_ALLOW_TEST_RELEASE_KEY: "1" } as const;

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "tegrad-manifest-test-"));
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

function makeSampleUnsignedManifest(
  x64Bytes: Uint8Array,
  arm64Bytes: Uint8Array,
  overrides: Partial<UnsignedReleaseManifest> = {},
): UnsignedReleaseManifest {
  return {
    v: MANIFEST_SCHEMA_VERSION,
    channel: "stable",
    version: "0.2.0",
    tag: "v0.2.0",
    published_at: 1_795_300_000_000,
    assets: {
      "linux-x64": {
        url: "https://github.com/codebyant/tegrad/releases/download/v0.2.0/tegrad-linux-x64",
        sha256: computeBytesSha256(x64Bytes),
        size: x64Bytes.byteLength,
      },
      "linux-arm64": {
        url: "https://github.com/codebyant/tegrad/releases/download/v0.2.0/tegrad-linux-arm64",
        sha256: computeBytesSha256(arm64Bytes),
        size: arm64Bytes.byteLength,
      },
    },
    ...overrides,
  };
}

function flipFirstBitBase64Url(b64u: string): string {
  const bytes = fromBase64Url(b64u);
  const copy = new Uint8Array(bytes);
  copy[0] = (copy[0] ?? 0) ^ 0x01;
  return toBase64Url(copy);
}

describe("release key and PEM encoding", () => {
  test("placeholder release public key matches test seed and round-trips through Ed25519 SPKI PEM", () => {
    const testKeyPair = signingKeyPairFromSeed(TEST_RELEASE_SEED);
    const otherKeyPair = generateSigningKeyPair();
    const embedded = getReleasePublicKey();
    expect(toBase64Url(embedded)).toBe(TEST_RELEASE_PUBLIC_KEY_BASE64URL);
    expect(toBase64Url(embedded)).toBe(toBase64Url(testKeyPair.publicKey));
    expect(isPlaceholderReleaseKey(embedded)).toBe(true);
    expect(isPlaceholderReleaseKey(TEST_RELEASE_PUBLIC_KEY_BASE64URL)).toBe(true);
    expect(isPlaceholderReleaseKey(otherKeyPair.publicKey)).toBe(false);
    expect(isPlaceholderReleaseKey(toBase64Url(otherKeyPair.publicKey))).toBe(false);

    const pem = ed25519PublicKeyToPem(embedded);
    expect(pem).toContain("-----BEGIN PUBLIC KEY-----");
    expect(toBase64Url(ed25519PublicKeyFromPem(pem))).toBe(toBase64Url(embedded));

    const fromSeed = parseReleaseSigningKey(toBase64Url(TEST_RELEASE_SEED));
    expect(toBase64Url(fromSeed.publicKey)).toBe(toBase64Url(embedded));
    const fromSecret = parseReleaseSigningKey(toBase64Url(testKeyPair.secretKey));
    expect(toBase64Url(fromSecret.publicKey)).toBe(toBase64Url(embedded));
  });

  test("verifyManifest and verifyReleaseBinary fail closed with placeholder_release_key unless TEGRAD_ALLOW_TEST_RELEASE_KEY=1, while non-placeholder keys succeed without the env var", async () => {
    const dir = makeTempDir();
    const testKeyPair = signingKeyPairFromSeed(TEST_RELEASE_SEED);
    const prodKeyPair = generateSigningKeyPair();
    const x64 = new TextEncoder().encode("x64-binary-payload");
    const arm64 = new TextEncoder().encode("arm64-binary-payload");
    const x64Path = join(dir, "tegrad-linux-x64");
    writeFileSync(x64Path, x64);

    const testSigned = signManifest(makeSampleUnsignedManifest(x64, arm64), testKeyPair.secretKey);
    const prodSigned = signManifest(makeSampleUnsignedManifest(x64, arm64), prodKeyPair.secretKey);

    // Without TEGRAD_ALLOW_TEST_RELEASE_KEY=1, test key is refused
    expect(() => verifyManifest(testSigned, { env: {} })).toThrow(UpdateError);
    try {
      verifyManifest(testSigned, { env: {} });
      throw new Error("Expected placeholder_release_key");
    } catch (err) {
      expect(err).toBeInstanceOf(UpdateError);
      expect((err as UpdateError).code).toBe("placeholder_release_key");
    }

    await expect(
      verifyReleaseBinary({
        binaryPath: x64Path,
        manifestContent: JSON.stringify(testSigned),
        arch: "linux-x64",
        env: {},
      }),
    ).rejects.toMatchObject({ code: "placeholder_release_key" });

    // CLI verify-update also refuses without TEGRAD_ALLOW_TEST_RELEASE_KEY=1
    const manifestPath = join(dir, "stable.json");
    writeFileSync(manifestPath, JSON.stringify(testSigned), "utf8");
    let refusedErr = "";
    const refusedCode = await runCli(
      ["verify-update", "--binary", x64Path, "--manifest", manifestPath],
      {
        env: {},
        verifyUpdateOptions: { arch: "linux-x64" },
        stdout: () => {},
        stderr: (t) => {
          refusedErr += t;
        },
      },
    );
    expect(refusedCode).toBe(1);
    expect(refusedErr).toContain("TEGRAD_ALLOW_TEST_RELEASE_KEY=1");

    // With TEGRAD_ALLOW_TEST_RELEASE_KEY=1, test key is accepted
    expect(verifyManifest(testSigned, { env: ALLOW_TEST_KEY_ENV }).version).toBe("0.2.0");
    const allowedCode = await runCli(
      ["verify-update", "--binary", x64Path, "--manifest", manifestPath],
      {
        env: ALLOW_TEST_KEY_ENV,
        verifyUpdateOptions: { arch: "linux-x64" },
        stdout: () => {},
        stderr: () => {},
      },
    );
    expect(allowedCode).toBe(0);

    // Non-placeholder key works normally without TEGRAD_ALLOW_TEST_RELEASE_KEY=1
    expect(verifyManifest(prodSigned, { publicKey: prodKeyPair.publicKey, env: {} }).version).toBe(
      "0.2.0",
    );
    const prodRes = await verifyReleaseBinary({
      binaryPath: x64Path,
      manifestContent: JSON.stringify(prodSigned),
      arch: "linux-x64",
      publicKey: prodKeyPair.publicKey,
      env: {},
    });
    expect(prodRes.ok).toBe(true);
  });
});

describe("Ed25519 release manifest and SHA256SUMS signing/verification", () => {
  test("valid signed manifest passes verification and tampered fields fail closed", () => {
    const keyPair = signingKeyPairFromSeed(TEST_RELEASE_SEED);
    const attacker = generateSigningKeyPair();
    const x64 = new TextEncoder().encode("x64-binary-payload");
    const arm64 = new TextEncoder().encode("arm64-binary-payload");

    const signed = signManifest(makeSampleUnsignedManifest(x64, arm64), keyPair.secretKey);
    const verified = verifyManifest(signed, { expectedChannel: "stable", env: ALLOW_TEST_KEY_ENV });
    expect(verified.version).toBe("0.2.0");

    // 1-bit flip in signature
    expect(() =>
      verifyManifest(
        { ...signed, sig: flipFirstBitBase64Url(signed.sig) },
        { env: ALLOW_TEST_KEY_ENV },
      ),
    ).toThrow(UpdateError);

    // Tampered version
    expect(() =>
      verifyManifest({ ...signed, version: "0.2.1", tag: "v0.2.1" }, { env: ALLOW_TEST_KEY_ENV }),
    ).toThrow(UpdateError);

    // Tampered asset URL
    expect(() =>
      verifyManifest(
        {
          ...signed,
          assets: {
            ...signed.assets,
            "linux-x64": {
              ...signed.assets["linux-x64"],
              url: "https://evil.example/tegrad-linux-x64",
            },
          },
        },
        { env: ALLOW_TEST_KEY_ENV },
      ),
    ).toThrow(UpdateError);

    // Tampered asset sha256 (1 nibble changed)
    const badHash =
      (signed.assets["linux-x64"].sha256.startsWith("0") ? "1" : "0") +
      signed.assets["linux-x64"].sha256.slice(1);
    expect(() =>
      verifyManifest(
        {
          ...signed,
          assets: {
            ...signed.assets,
            "linux-x64": {
              ...signed.assets["linux-x64"],
              sha256: badHash,
            },
          },
        },
        { env: ALLOW_TEST_KEY_ENV },
      ),
    ).toThrow(UpdateError);

    // Signed by attacker key
    const attackerSigned = signManifest(makeSampleUnsignedManifest(x64, arm64), attacker.secretKey);
    try {
      verifyManifest(attackerSigned, { publicKey: keyPair.publicKey, env: ALLOW_TEST_KEY_ENV });
      throw new Error("Expected bad_manifest_signature");
    } catch (err) {
      expect(err).toBeInstanceOf(UpdateError);
      expect((err as UpdateError).code).toBe("bad_manifest_signature");
    }

    // Channel mismatch fails closed
    try {
      verifyManifest(signed, {
        publicKey: keyPair.publicKey,
        expectedChannel: "beta",
        env: ALLOW_TEST_KEY_ENV,
      });
      throw new Error("Expected channel_mismatch");
    } catch (err) {
      expect(err).toBeInstanceOf(UpdateError);
      expect((err as UpdateError).code).toBe("channel_mismatch");
    }
  });

  test("SHA256SUMS signing rejects tampered bytes, wrong key, and cross-domain signature reuse", () => {
    const keyPair = signingKeyPairFromSeed(TEST_RELEASE_SEED);
    const attacker = generateSigningKeyPair();
    const sums = formatSha256Sums([
      { sha256: computeBytesSha256(new Uint8Array([1, 2, 3])), filename: "tegrad-linux-x64" },
      { sha256: computeBytesSha256(new Uint8Array([4, 5, 6])), filename: "tegrad-linux-arm64" },
    ]);

    const sig = signSha256Sums(sums, keyPair.secretKey);
    expect(verifySha256Sums(sums, sig, keyPair.publicKey)).toBe(true);
    expect(verifySha256Sums(`${sums}\n`, sig, keyPair.publicKey)).toBe(false);
    expect(verifySha256Sums(sums, flipFirstBitBase64Url(sig), keyPair.publicKey)).toBe(false);
    expect(verifySha256Sums(sums, sig, attacker.publicKey)).toBe(false);
  });

  test("scripts/sign-release.ts signs SHA256SUMS + channel manifest and verifyReleaseBinary + CLI verify-update succeed", async () => {
    const dir = makeTempDir();
    const x64Bytes = new TextEncoder().encode("fake-tegrad-linux-x64-elf-bytes");
    const arm64Bytes = new TextEncoder().encode("fake-tegrad-linux-arm64-elf-bytes");
    const x64Path = join(dir, "tegrad-linux-x64");
    const arm64Path = join(dir, "tegrad-linux-arm64");
    writeFileSync(x64Path, x64Bytes);
    writeFileSync(arm64Path, arm64Bytes);

    const res = await runSignRelease(
      [
        "--tag",
        "v0.3.0-beta.2",
        "--assets-dir",
        dir,
        "--base-url",
        "https://github.com/codebyant/tegrad/releases/download/v0.3.0-beta.2",
        "--published-at",
        "1795300000000",
      ],
      { RELEASE_SIGNING_KEY: toBase64Url(TEST_RELEASE_SEED) },
    );

    expect(res.channel).toBe("beta");
    expect(res.manifestPath.endsWith("beta.json")).toBe(true);

    const manifestText = readFileSync(res.manifestPath, "utf8");
    const sumsText = readFileSync(res.sumsPath, "utf8");
    const sigText = readFileSync(res.sigPath, "utf8");

    const v1 = await verifyReleaseBinary({
      binaryPath: x64Path,
      manifestContent: manifestText,
      arch: "linux-x64",
      expectedChannel: "beta",
      env: ALLOW_TEST_KEY_ENV,
    });
    expect(v1.ok).toBe(true);
    expect(v1.mode).toBe("manifest");

    const v2 = await verifyReleaseBinary({
      binaryPath: arm64Path,
      sha256SumsContent: sumsText,
      sha256SumsSig: sigText,
      expectedAssetName: "tegrad-linux-arm64",
      env: ALLOW_TEST_KEY_ENV,
    });
    expect(v2.ok).toBe(true);
    expect(v2.mode).toBe("sums");

    // CLI verify-update succeeds for both manifest and sums modes
    let cliOut = "";
    let cliErr = "";
    const code1 = await runCli(
      ["verify-update", "--binary", x64Path, "--manifest", res.manifestPath, "--channel", "beta"],
      {
        env: ALLOW_TEST_KEY_ENV,
        verifyUpdateOptions: { arch: "linux-x64" },
        stdout: (t) => {
          cliOut += t;
        },
        stderr: (t) => {
          cliErr += t;
        },
      },
    );
    expect(code1).toBe(0);
    expect(cliErr).toBe("");
    expect(cliOut).toContain("Verified v0.3.0-beta.2");

    const code2 = await runCli(
      [
        "verify-update",
        "--binary",
        arm64Path,
        "--sums",
        res.sumsPath,
        "--sig",
        res.sigPath,
        "--asset",
        "tegrad-linux-arm64",
      ],
      {
        env: ALLOW_TEST_KEY_ENV,
        stdout: () => {},
        stderr: () => {},
      },
    );
    expect(code2).toBe(0);

    // Corrupt 1 byte in binary -> CLI verify-update returns 1
    writeFileSync(x64Path, new TextEncoder().encode("fake-tegrad-linux-x64-elf-byteX"));
    let failErr = "";
    const failCode = await runCli(
      ["verify-update", "--binary", x64Path, "--manifest", res.manifestPath],
      {
        env: ALLOW_TEST_KEY_ENV,
        verifyUpdateOptions: { arch: "linux-x64" },
        stdout: () => {},
        stderr: (t) => {
          failErr += t;
        },
      },
    );
    expect(failCode).toBe(1);
    expect(failErr).toContain("SHA-256 mismatch");
  });
});
