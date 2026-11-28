// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateRawSync } from "node:zlib";
import { type FileErrorCode, FileManagerError } from "./errors";
import {
  crc32,
  createZipBuffer,
  safeUnzipBuffer,
  safeUnzipFile,
  safeZipFiles,
  type ZipEntryInput,
} from "./zip";

function expectFileError(fn: () => unknown, code: FileErrorCode): void {
  try {
    fn();
    throw new Error(`Expected FileManagerError(${code}), but succeeded`);
  } catch (err) {
    expect(err).toBeInstanceOf(FileManagerError);
    expect((err as FileManagerError).code).toBe(code);
  }
}

function createDirLink(target: string, linkPath: string): void {
  if (process.platform === "win32") {
    symlinkSync(target, linkPath, "junction");
  } else {
    symlinkSync(target, linkPath, "dir");
  }
}

/**
 * Builds a raw single-entry ZIP where header fields can be intentionally spoofed
 * (for testing spoofed uncompressedSize, bad CRC, bad compression method, encrypted flag, etc.).
 */
function buildForgedSingleEntryZip(params: {
  readonly cdName: string;
  readonly lfhName?: string;
  readonly payload: Uint8Array;
  readonly method: number;
  readonly flags?: number;
  readonly declaredCrc?: number;
  readonly declaredUncompressedSize: number;
  readonly declaredCompressedSize?: number;
  readonly externalAttr?: number;
}): Uint8Array {
  const encoder = new TextEncoder();
  const cdNameBytes = encoder.encode(params.cdName);
  const lfhNameBytes = encoder.encode(params.lfhName ?? params.cdName);
  const flags = params.flags ?? 0x0800;
  const crc = params.declaredCrc ?? 0;
  const compSize = params.declaredCompressedSize ?? params.payload.byteLength;
  const uncompSize = params.declaredUncompressedSize;
  const externalAttr = params.externalAttr ?? (0o100644 << 16) >>> 0;

  const lfh = new Uint8Array(30 + lfhNameBytes.byteLength);
  const lfhView = new DataView(lfh.buffer);
  lfhView.setUint32(0, 0x04034b50, true);
  lfhView.setUint16(4, 20, true);
  lfhView.setUint16(6, flags, true);
  lfhView.setUint16(8, params.method, true);
  lfhView.setUint32(14, crc, true);
  lfhView.setUint32(18, compSize, true);
  lfhView.setUint32(22, uncompSize, true);
  lfhView.setUint16(26, lfhNameBytes.byteLength, true);
  lfh.set(lfhNameBytes, 30);

  const cdOffset = lfh.byteLength + params.payload.byteLength;
  const cdh = new Uint8Array(46 + cdNameBytes.byteLength);
  const cdhView = new DataView(cdh.buffer);
  cdhView.setUint32(0, 0x02014b50, true);
  cdhView.setUint16(4, 0x0314, true);
  cdhView.setUint16(6, 20, true);
  cdhView.setUint16(8, flags, true);
  cdhView.setUint16(10, params.method, true);
  cdhView.setUint32(16, crc, true);
  cdhView.setUint32(20, compSize, true);
  cdhView.setUint32(24, uncompSize, true);
  cdhView.setUint16(28, cdNameBytes.byteLength, true);
  cdhView.setUint32(38, externalAttr, true);
  cdhView.setUint32(42, 0, true);
  cdh.set(cdNameBytes, 46);

  const eocd = new Uint8Array(22);
  const eocdView = new DataView(eocd.buffer);
  eocdView.setUint32(0, 0x06054b50, true);
  eocdView.setUint16(8, 1, true);
  eocdView.setUint16(10, 1, true);
  eocdView.setUint32(12, cdh.byteLength, true);
  eocdView.setUint32(16, cdOffset, true);

  const out = new Uint8Array(cdOffset + cdh.byteLength + eocd.byteLength);
  out.set(lfh, 0);
  out.set(params.payload, lfh.byteLength);
  out.set(cdh, cdOffset);
  out.set(eocd, cdOffset + cdh.byteLength);
  return out;
}

describe("safe zip and unzip", () => {
  let rootTmp: string;
  let serversDir: string;
  let outsideDir: string;
  const serverId = "srv-zip";
  let serverDir: string;

  beforeEach(() => {
    rootTmp = mkdtempSync(join(tmpdir(), "tegrad-zip-"));
    serversDir = join(rootTmp, "servers");
    outsideDir = join(rootTmp, "outside");
    serverDir = join(serversDir, serverId);
    mkdirSync(serverDir, { recursive: true });
    mkdirSync(outsideDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(rootTmp, { recursive: true, force: true });
  });

  test("crc32 matches IEEE 802.3 standard vector", () => {
    const check = crc32(new TextEncoder().encode("123456789"));
    expect(check).toBe(0xcbf43926);
  });

  test("roundtrips zip -> unzip with multiple files, nested dirs, empty file, and binary data", () => {
    mkdirSync(join(serverDir, "world", "region"), { recursive: true });
    writeFileSync(join(serverDir, "server.properties"), "motd=Tegra Server\n");
    writeFileSync(join(serverDir, "world", "level.dat"), new Uint8Array([0, 1, 2, 255, 128, 42]));
    writeFileSync(join(serverDir, "world", "empty.txt"), "");
    writeFileSync(join(serverDir, "world", "region", "r.0.0.mca"), "region-data-".repeat(200));

    const zipResult = safeZipFiles({
      serversBaseDir: serversDir,
      serverId,
      paths: ["server.properties", "world"],
      destPath: "backup.zip",
    });

    expect(zipResult.destPath).toBe("backup.zip");
    expect(zipResult.entryCount).toBeGreaterThanOrEqual(4);
    expect(existsSync(join(serverDir, "backup.zip"))).toBe(true);

    const unzipResult = safeUnzipFile({
      serversBaseDir: serversDir,
      serverId,
      zipPath: "backup.zip",
      destPath: "restored",
    });

    expect(unzipResult.destPath).toBe("restored");
    expect(readFileSync(join(serverDir, "restored", "server.properties"), "utf8")).toBe(
      "motd=Tegra Server\n",
    );
    expect(new Uint8Array(readFileSync(join(serverDir, "restored", "world", "level.dat")))).toEqual(
      new Uint8Array([0, 1, 2, 255, 128, 42]),
    );
    expect(readFileSync(join(serverDir, "restored", "world", "empty.txt"), "utf8")).toBe("");
    expect(readFileSync(join(serverDir, "restored", "world", "region", "r.0.0.mca"), "utf8")).toBe(
      "region-data-".repeat(200),
    );
  });

  test("rejects zip-slip entries without creating anything outside OR inside", () => {
    const evilNames = [
      "../escape.txt",
      "sub/../../escape.txt",
      "/abs/path.txt",
      "back\\slash.txt",
      "C:/Windows/evil.txt",
      "foo\0bar.txt",
      ".runtime/evil.jar",
      "NUL.txt",
      "sub/CON",
    ];

    for (const evilName of evilNames) {
      // Include a benign entry BEFORE the evil entry to prove Phase 1 aborts before writing anything.
      const zipBuf = createZipBuffer([
        { name: "benign.txt", data: new TextEncoder().encode("should-not-be-written") },
        { name: evilName, data: new TextEncoder().encode("pwned") },
      ]);

      expectFileError(
        () =>
          safeUnzipBuffer({
            serversBaseDir: serversDir,
            serverId,
            buffer: zipBuf,
          }),
        "zip_slip",
      );

      expect(readdirSync(serverDir)).toEqual([]);
      expect(existsSync(join(serversDir, "escape.txt"))).toBe(false);
    }
  });

  test("rejects ZIP containing UNIX symlink entry (S_IFLNK) before extracting anything", () => {
    const zipBuf = createZipBuffer([
      { name: "safe.txt", data: new TextEncoder().encode("ok") },
      {
        name: "evil-link",
        data: new TextEncoder().encode("/etc/passwd"),
        unixMode: 0o120777,
      },
    ]);

    expectFileError(
      () =>
        safeUnzipBuffer({
          serversBaseDir: serversDir,
          serverId,
          buffer: zipBuf,
        }),
      "zip_symlink_entry",
    );

    expect(readdirSync(serverDir)).toEqual([]);
  });

  test("rejects extracting through an existing symlink/junction in destination", () => {
    createDirLink(outsideDir, join(serverDir, "plugins"));
    const zipBuf = createZipBuffer([
      { name: "plugins/pwn.txt", data: new TextEncoder().encode("escaped") },
    ]);

    expectFileError(
      () =>
        safeUnzipBuffer({
          serversBaseDir: serversDir,
          serverId,
          buffer: zipBuf,
        }),
      "symlink_forbidden",
    );

    expect(existsSync(join(outsideDir, "pwn.txt"))).toBe(false);
  });

  test("safeZipFiles refuses to archive a symlink/junction", () => {
    mkdirSync(join(serverDir, "mods"));
    createDirLink(outsideDir, join(serverDir, "mods", "linked"));

    expectFileError(
      () =>
        safeZipFiles({
          serversBaseDir: serversDir,
          serverId,
          paths: ["mods"],
          destPath: "out.zip",
        }),
      "symlink_forbidden",
    );
    expect(existsSync(join(serverDir, "out.zip"))).toBe(false);
  });

  test("defends against zip bomb with high declared compression ratio", () => {
    // 512 KiB of zeroes compresses to ~550 bytes -> ratio ~950 > 100
    const bombData = new Uint8Array(512 * 1024);
    const zipBuf = createZipBuffer([{ name: "bomb.bin", data: bombData }]);

    expectFileError(
      () =>
        safeUnzipBuffer({
          serversBaseDir: serversDir,
          serverId,
          buffer: zipBuf,
        }),
      "zip_compression_ratio_exceeded",
    );
    expect(readdirSync(serverDir)).toEqual([]);
  });

  test("defends against zip bomb with declared size exceeding total or entry limit", () => {
    const data = new TextEncoder().encode("x".repeat(4096));
    const zipBuf = createZipBuffer([
      { name: "a.txt", data, store: true },
      { name: "b.txt", data, store: true },
    ]);

    expectFileError(
      () =>
        safeUnzipBuffer({
          serversBaseDir: serversDir,
          serverId,
          buffer: zipBuf,
          maxEntryBytes: 2048,
        }),
      "zip_entry_too_large",
    );

    expectFileError(
      () =>
        safeUnzipBuffer({
          serversBaseDir: serversDir,
          serverId,
          buffer: zipBuf,
          maxUncompressedBytes: 5000,
        }),
      "zip_too_large",
    );
  });

  test("defends against spoofed-header zip bomb where header claims 100 bytes but deflate expands to 4 MiB", () => {
    const realPayload = new Uint8Array(4 * 1024 * 1024); // 4 MiB of zeros
    const deflated = deflateRawSync(realPayload);
    const deflatedBytes = new Uint8Array(deflated.buffer, deflated.byteOffset, deflated.byteLength);

    // Header lies and claims uncompressedSize = 100!
    const forgedZip = buildForgedSingleEntryZip({
      cdName: "spoofed.bin",
      payload: deflatedBytes,
      method: 8,
      declaredCrc: crc32(realPayload),
      declaredUncompressedSize: 100,
    });

    expectFileError(
      () =>
        safeUnzipBuffer({
          serversBaseDir: serversDir,
          serverId,
          buffer: forgedZip,
          maxCompressionRatio: 10,
          ratioMinBytes: 64 * 1024,
        }),
      "zip_compression_ratio_exceeded",
    );
    expect(readdirSync(serverDir)).toEqual([]);
  });

  test("rejects spoofed uncompressedSize even when under maxOutputLength", () => {
    const actual = new TextEncoder().encode("this is twenty bytes");
    const deflated = deflateRawSync(actual);
    const forgedZip = buildForgedSingleEntryZip({
      cdName: "mismatch.txt",
      payload: new Uint8Array(deflated.buffer, deflated.byteOffset, deflated.byteLength),
      method: 8,
      declaredCrc: crc32(actual),
      declaredUncompressedSize: 5,
    });

    expectFileError(
      () =>
        safeUnzipBuffer({
          serversBaseDir: serversDir,
          serverId,
          buffer: forgedZip,
        }),
      "zip_invalid",
    );
    expect(readdirSync(serverDir)).toEqual([]);
  });

  test("rejects archives exceeding maxEntries", () => {
    const entries: ZipEntryInput[] = [];
    for (let i = 0; i < 6; i++) {
      entries.push({ name: `f${i}.txt`, data: new TextEncoder().encode("x") });
    }
    const zipBuf = createZipBuffer(entries);

    expectFileError(
      () =>
        safeUnzipBuffer({
          serversBaseDir: serversDir,
          serverId,
          buffer: zipBuf,
          maxEntries: 5,
        }),
      "zip_too_many_entries",
    );
    expect(readdirSync(serverDir)).toEqual([]);
  });

  test("rejects corrupted CRC-32 checksum", () => {
    const data = new TextEncoder().encode("hello world");
    const deflated = deflateRawSync(data);
    const forgedZip = buildForgedSingleEntryZip({
      cdName: "badcrc.txt",
      payload: new Uint8Array(deflated.buffer, deflated.byteOffset, deflated.byteLength),
      method: 8,
      declaredCrc: (crc32(data) ^ 0x12345678) >>> 0,
      declaredUncompressedSize: data.byteLength,
    });

    expectFileError(
      () =>
        safeUnzipBuffer({
          serversBaseDir: serversDir,
          serverId,
          buffer: forgedZip,
        }),
      "zip_crc_mismatch",
    );
    expect(readdirSync(serverDir)).toEqual([]);
  });

  test("rejects Local/Central filename mismatch and unsupported compression/encryption", () => {
    const data = new TextEncoder().encode("hello");
    const desyncZip = buildForgedSingleEntryZip({
      cdName: "safe.txt",
      lfhName: "../evil.txt",
      payload: data,
      method: 0,
      declaredCrc: crc32(data),
      declaredUncompressedSize: data.byteLength,
    });
    expectFileError(
      () =>
        safeUnzipBuffer({
          serversBaseDir: serversDir,
          serverId,
          buffer: desyncZip,
        }),
      "zip_invalid",
    );

    const encryptedZip = buildForgedSingleEntryZip({
      cdName: "secret.txt",
      payload: data,
      method: 0,
      flags: 0x0001,
      declaredCrc: crc32(data),
      declaredUncompressedSize: data.byteLength,
    });
    expectFileError(
      () =>
        safeUnzipBuffer({
          serversBaseDir: serversDir,
          serverId,
          buffer: encryptedZip,
        }),
      "zip_unsupported_method",
    );

    const weirdMethodZip = buildForgedSingleEntryZip({
      cdName: "bzip.txt",
      payload: data,
      method: 12,
      declaredCrc: crc32(data),
      declaredUncompressedSize: data.byteLength,
    });
    expectFileError(
      () =>
        safeUnzipBuffer({
          serversBaseDir: serversDir,
          serverId,
          buffer: weirdMethodZip,
        }),
      "zip_unsupported_method",
    );
  });
});
