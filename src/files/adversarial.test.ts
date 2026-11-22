// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import {
  closeSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateRawSync } from "node:zlib";
import { createCommandQueue, type TransportCommandFrame } from "../agent/jobs";
import { createLogger } from "../agent/logger";
import { fingerprint, generateSigningKeyPair, ready } from "../crypto";
import {
  createCoreRegistry,
  createInMemoryTrustContext,
  createSignedCommand,
  openAgentMessage,
  PROTOCOL_VERSION,
  type SignedCommand,
  signSessionCertificate,
  type TransportFrame,
} from "../protocol";
import {
  resolveConfinedPath,
  UPLOAD_STAGING_DIR_NAME,
  UPLOAD_STAGING_FILE_PREFIX,
} from "./confinement";
import { type FileErrorCode, FileManagerError } from "./errors";
import { FileManager, MAX_READ_WRITE_BYTES, registerFileCommandHandlers } from "./manager";
import { sha256Hex } from "./transfers";
import { crc32, createZipBuffer, safeUnzipBuffer, safeZipFiles } from "./zip";

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

interface RawZipEntrySpec {
  readonly cdName: string;
  readonly lfhName?: string;
  readonly payload: Uint8Array;
  readonly method: number;
  readonly cdFlags?: number;
  readonly lfhFlags?: number;
  readonly crc?: number;
  readonly declaredCompressedSize?: number;
  readonly declaredUncompressedSize: number;
  readonly externalAttr?: number;
  readonly localHeaderOffsetOverride?: number;
}

function buildMultiEntryZip(specs: readonly RawZipEntrySpec[]): {
  readonly buffer: Uint8Array;
  readonly cdOffset: number;
  readonly cdSize: number;
} {
  const encoder = new TextEncoder();
  const lfhBlocks: Uint8Array[] = [];
  const cdhBlocks: Uint8Array[] = [];
  const computedOffsets: number[] = [];
  let offset = 0;

  for (const spec of specs) {
    const lfhNameBytes = encoder.encode(spec.lfhName ?? spec.cdName);
    const lfh = new Uint8Array(30 + lfhNameBytes.byteLength);
    const lfhView = new DataView(lfh.buffer);
    const compSize = spec.declaredCompressedSize ?? spec.payload.byteLength;
    const crc = spec.crc ?? 0;

    lfhView.setUint32(0, 0x04034b50, true);
    lfhView.setUint16(4, 20, true);
    lfhView.setUint16(6, spec.lfhFlags ?? 0x0800, true);
    lfhView.setUint16(8, spec.method, true);
    lfhView.setUint32(14, crc, true);
    lfhView.setUint32(18, compSize, true);
    lfhView.setUint32(22, spec.declaredUncompressedSize, true);
    lfhView.setUint16(26, lfhNameBytes.byteLength, true);
    lfh.set(lfhNameBytes, 30);

    computedOffsets.push(offset);
    lfhBlocks.push(lfh, spec.payload);
    offset += lfh.byteLength + spec.payload.byteLength;
  }

  const cdOffset = offset;
  let cdSize = 0;

  for (let i = 0; i < specs.length; i++) {
    const spec = specs[i];
    const computedOffset = computedOffsets[i];
    if (spec === undefined || computedOffset === undefined) {
      continue;
    }
    const cdNameBytes = encoder.encode(spec.cdName);
    const cdh = new Uint8Array(46 + cdNameBytes.byteLength);
    const cdhView = new DataView(cdh.buffer);
    const compSize = spec.declaredCompressedSize ?? spec.payload.byteLength;
    const crc = spec.crc ?? 0;

    cdhView.setUint32(0, 0x02014b50, true);
    cdhView.setUint16(4, 0x0314, true);
    cdhView.setUint16(6, 20, true);
    cdhView.setUint16(8, spec.cdFlags ?? 0x0800, true);
    cdhView.setUint16(10, spec.method, true);
    cdhView.setUint32(16, crc, true);
    cdhView.setUint32(20, compSize, true);
    cdhView.setUint32(24, spec.declaredUncompressedSize, true);
    cdhView.setUint16(28, cdNameBytes.byteLength, true);
    cdhView.setUint32(38, spec.externalAttr ?? (0o100644 << 16) >>> 0, true);
    cdhView.setUint32(42, spec.localHeaderOffsetOverride ?? computedOffset, true);
    cdh.set(cdNameBytes, 46);

    cdhBlocks.push(cdh);
    cdSize += cdh.byteLength;
  }

  const eocd = new Uint8Array(22);
  const eocdView = new DataView(eocd.buffer);
  eocdView.setUint32(0, 0x06054b50, true);
  eocdView.setUint16(8, specs.length, true);
  eocdView.setUint16(10, specs.length, true);
  eocdView.setUint32(12, cdSize, true);
  eocdView.setUint32(16, cdOffset, true);

  const total = cdOffset + cdSize + eocd.byteLength;
  const out = new Uint8Array(total);
  let cursor = 0;
  for (const part of lfhBlocks) {
    out.set(part, cursor);
    cursor += part.byteLength;
  }
  for (const part of cdhBlocks) {
    out.set(part, cursor);
    cursor += part.byteLength;
  }
  out.set(eocd, cursor);
  return { buffer: out, cdOffset, cdSize };
}

beforeAll(async () => {
  await ready();
});

describe("adversarial file confinement and archive security", () => {
  let rootTmp: string;
  let serversDir: string;
  let outsideDir: string;
  const serverId = "srv-adv";
  let serverDir: string;
  let manager: FileManager;

  beforeEach(() => {
    rootTmp = mkdtempSync(join(tmpdir(), "tegrad-adv-"));
    serversDir = join(rootTmp, "servers");
    outsideDir = join(rootTmp, "outside");
    serverDir = join(serversDir, serverId);
    mkdirSync(serverDir, { recursive: true });
    mkdirSync(outsideDir, { recursive: true });
    manager = new FileManager({ serversBaseDir: serversDir });
  });

  afterEach(() => {
    manager.dispose();
    rmSync(rootTmp, { recursive: true, force: true });
  });

  test("upload staging directory cannot be listed, read, written, deleted, moved, zipped, or overwritten via FileManager", () => {
    const part0 = new TextEncoder().encode("authentic-part-0-");
    const part1 = new TextEncoder().encode("authentic-part-1");
    const full = new Uint8Array(part0.byteLength + part1.byteLength);
    full.set(part0, 0);
    full.set(part1, part0.byteLength);
    const expectedHash = sha256Hex(full);

    const began = manager.uploadBegin({
      server_id: serverId,
      path: "plugins/authentic.jar",
      total_size: full.byteLength,
      sha256: expectedHash,
      part_size: 64,
    });

    manager.uploadPart({
      server_id: serverId,
      upload_id: began.upload_id,
      part_index: 0,
      data_base64: Buffer.from(part0).toString("base64"),
    });

    // Staging directory must stay hidden from directory listing.
    expect(manager.list({ server_id: serverId }).entries).toEqual([]);

    const forbiddenPaths = [
      UPLOAD_STAGING_DIR_NAME,
      `${UPLOAD_STAGING_DIR_NAME}/${began.upload_id}`,
      UPLOAD_STAGING_DIR_NAME.toUpperCase(),
      `nested/${UPLOAD_STAGING_DIR_NAME}/x`,
      `${UPLOAD_STAGING_FILE_PREFIX}${began.upload_id}`,
    ];

    for (const target of forbiddenPaths) {
      expectFileError(() => manager.stat({ server_id: serverId, path: target }), "path_traversal");
      expectFileError(() => manager.read({ server_id: serverId, path: target }), "path_traversal");
      expectFileError(
        () => manager.write({ server_id: serverId, path: target, content: "tampered!" }),
        "path_traversal",
      );
      expectFileError(
        () => manager.delete({ server_id: serverId, path: target, recursive: true }),
        "path_traversal",
      );
      expectFileError(
        () => manager.move({ server_id: serverId, from_path: target, to_path: "stolen.bin" }),
        "path_traversal",
      );
      expectFileError(
        () => manager.copy({ server_id: serverId, from_path: target, to_path: "copied.bin" }),
        "path_traversal",
      );
      expectFileError(
        () => manager.zip({ server_id: serverId, paths: [target], dest_path: "leak.zip" }),
        "path_traversal",
      );
      expectFileError(
        () => manager.downloadBegin({ server_id: serverId, path: target }),
        "path_traversal",
      );
    }

    // Also reject writing into staging via rename, move destination, zip destination, or unzip.
    manager.write({ server_id: serverId, path: "benign.txt", content: "hi" });
    expectFileError(
      () =>
        manager.rename({
          server_id: serverId,
          path: "benign.txt",
          new_name: UPLOAD_STAGING_DIR_NAME,
        }),
      "path_traversal",
    );
    expectFileError(
      () =>
        manager.move({
          server_id: serverId,
          from_path: "benign.txt",
          to_path: `${UPLOAD_STAGING_DIR_NAME}/${began.upload_id}`,
        }),
      "path_traversal",
    );

    const maliciousZip = createZipBuffer([
      {
        name: `${UPLOAD_STAGING_DIR_NAME}/${began.upload_id}`,
        data: new TextEncoder().encode("zip-overwrite"),
      },
    ]);
    expectFileError(
      () =>
        safeUnzipBuffer({
          serversBaseDir: serversDir,
          serverId,
          buffer: maliciousZip,
        }),
      "zip_slip",
    );

    // Complete upload legitimately and confirm clean staging teardown.
    manager.uploadPart({
      server_id: serverId,
      upload_id: began.upload_id,
      part_index: 1,
      data_base64: Buffer.from(part1).toString("base64"),
    });
    const committed = manager.uploadCommit({
      server_id: serverId,
      upload_id: began.upload_id,
    });
    expect(committed.sha256).toBe(expectedHash);
    expect(new Uint8Array(readFileSync(join(serverDir, "plugins", "authentic.jar")))).toEqual(full);
    expect(existsSync(join(serverDir, UPLOAD_STAGING_DIR_NAME))).toBe(false);
  });

  test("upload detects staging file replacement or symlinked staging directory before commit", () => {
    const payload = new TextEncoder().encode("valid-upload-bytes");
    const began = manager.uploadBegin({
      server_id: serverId,
      path: "safe.bin",
      total_size: payload.byteLength,
      sha256: sha256Hex(payload),
    });
    manager.uploadPart({
      server_id: serverId,
      upload_id: began.upload_id,
      part_index: 0,
      data_base64: Buffer.from(payload).toString("base64"),
    });

    // Replace staging file externally on disk with a different inode.
    const stagingFile = join(serverDir, UPLOAD_STAGING_DIR_NAME, began.upload_id);
    unlinkSync(stagingFile);
    writeFileSync(stagingFile, "tampered-payload!!");

    expectFileError(
      () => manager.uploadCommit({ server_id: serverId, upload_id: began.upload_id }),
      "toctou_detected",
    );
    expect(existsSync(join(serverDir, "safe.bin"))).toBe(false);
    expect(existsSync(join(serverDir, UPLOAD_STAGING_DIR_NAME))).toBe(false);

    // Planting a symlink at .tegrad-uploads before uploadBegin must fail closed.
    createDirLink(outsideDir, join(serverDir, UPLOAD_STAGING_DIR_NAME));
    expectFileError(
      () =>
        manager.uploadBegin({
          server_id: serverId,
          path: "safe2.bin",
          total_size: payload.byteLength,
          sha256: sha256Hex(payload),
        }),
      "symlink_forbidden",
    );
  });

  test("blocks multi-extension Windows reserved names, invisible Unicode chars, and colons/drive segments", () => {
    const badNames = [
      "NUL.tar.gz",
      "com1.json.bak",
      "lpt9.tar.bz2",
      "PRN.a.b.c",
      "CONIN$.txt",
      "CONOUT$.log",
      "CLOCK$.dat",
      "CON .txt",
      "NUL  .tar.gz",
      "COM\u00B9.txt",
      "LPT\u00B2.cfg",
      "NUL\u200B.txt",
      "file\u200Cname.txt",
      "file\u200Dname.txt",
      "\uFEFFeula.txt",
      "server\u202Etxt.jar",
      "soft\u00ADhyphen.txt",
      "c1\u0085ctrl.txt",
      "line\u2028sep.txt",
      "para\u2029sep.txt",
      ".runtime\u200B",
      ".\u200B.",
      "sub/C:/Windows/win.ini",
      "C:relative.txt",
      "file.txt:ads",
      "file.txt::$DATA",
    ];

    for (const bad of badNames) {
      expect(() =>
        resolveConfinedPath({
          serversBaseDir: serversDir,
          serverId,
          relPath: bad,
        }),
      ).toThrow(FileManagerError);
    }

    manager.write({ server_id: serverId, path: "rename-src.txt", content: "ok" });
    for (const badNewName of [
      UPLOAD_STAGING_DIR_NAME,
      "NUL.tar.gz",
      "a\u200Bb.txt",
      "a:b.txt",
      ".tmp-upload-abc",
    ]) {
      expect(() =>
        manager.rename({
          server_id: serverId,
          path: "rename-src.txt",
          new_name: badNewName,
        }),
      ).toThrow(FileManagerError);
    }
  });

  test("rejects case-insensitive self-copy, self-move, and self-zip, and enforces copy limits atomically", () => {
    manager.mkdir({ server_id: serverId, path: "World/region" });
    manager.write({ server_id: serverId, path: "World/level.dat", content: "level" });
    manager.write({ server_id: serverId, path: "World/region/a.mca", content: "region" });

    if (process.platform === "win32" || process.platform === "darwin") {
      expectFileError(
        () => manager.copy({ server_id: serverId, from_path: "World", to_path: "world/backup" }),
        "invalid_path",
      );
      expectFileError(
        () => manager.move({ server_id: serverId, from_path: "World", to_path: "world/moved" }),
        "invalid_path",
      );
      expectFileError(
        () =>
          safeZipFiles({
            serversBaseDir: serversDir,
            serverId,
            paths: ["World"],
            destPath: "world/out.zip",
          }),
        "invalid_path",
      );
    }

    // Pre-scan enforces maxCopyFiles before creating destination directory.
    const limited = new FileManager({
      serversBaseDir: serversDir,
      maxCopyFiles: 1,
      maxCopyBytes: 1000,
    });
    try {
      expectFileError(
        () => limited.copy({ server_id: serverId, from_path: "World", to_path: "WorldCopy" }),
        "copy_limit_exceeded",
      );
      expect(existsSync(join(serverDir, "WorldCopy"))).toBe(false);
    } finally {
      limited.dispose();
    }
  });

  test("copy streams files larger than 2 MiB via chunked upload without hitting OOM", () => {
    // 2.5 MiB binary pattern > MAX_READ_WRITE_BYTES (2 MiB) and > 64 KiB scratch buffer
    const totalSize = 2560 * 1024;
    const payload = new Uint8Array(totalSize);
    for (let i = 0; i < payload.byteLength; i++) {
      payload[i] = (i * 31) & 0xff;
    }
    const partSize = 1024 * 1024;
    const expectedHash = sha256Hex(payload);
    const began = manager.uploadBegin({
      server_id: serverId,
      path: "big.bin",
      total_size: totalSize,
      sha256: expectedHash,
      part_size: partSize,
    });
    let partIdx = 0;
    for (let offset = 0; offset < totalSize; offset += partSize) {
      const slice = payload.subarray(offset, Math.min(totalSize, offset + partSize));
      manager.uploadPart({
        server_id: serverId,
        upload_id: began.upload_id,
        part_index: partIdx++,
        data_base64: Buffer.from(slice).toString("base64"),
      });
    }
    manager.uploadCommit({ server_id: serverId, upload_id: began.upload_id });

    const copied = manager.copy({
      server_id: serverId,
      from_path: "big.bin",
      to_path: "big-copy.bin",
    });
    expect(copied.files_copied).toBe(1);
    expect(copied.bytes_copied).toBe(payload.byteLength);
    expect(new Uint8Array(readFileSync(join(serverDir, "big-copy.bin")))).toEqual(payload);
  });

  test("recursive delete aborts before deleting sibling files when a nested symlink exists", () => {
    manager.mkdir({ server_id: serverId, path: "tree/nested" });
    manager.write({ server_id: serverId, path: "tree/keep-me.txt", content: "intact" });
    createDirLink(outsideDir, join(serverDir, "tree", "nested", "escape"));

    expectFileError(
      () => manager.delete({ server_id: serverId, path: "tree", recursive: true }),
      "symlink_forbidden",
    );
    expect(readFileSync(join(serverDir, "tree", "keep-me.txt"), "utf8")).toBe("intact");
  });

  test("unzip rejects case-insensitive file/directory collisions and duplicate directories before writing", () => {
    const collidingFiles = createZipBuffer([
      { name: "A.txt", data: new TextEncoder().encode("upper") },
      { name: "a.txt", data: new TextEncoder().encode("lower") },
    ]);
    expectFileError(
      () => safeUnzipBuffer({ serversBaseDir: serversDir, serverId, buffer: collidingFiles }),
      "zip_invalid",
    );
    expect(readdirSync(serverDir)).toEqual([]);

    const collidingDirAndFile = createZipBuffer([
      { name: "Mods/", data: new Uint8Array(0), isDirectory: true },
      { name: "mods", data: new TextEncoder().encode("file-over-dir") },
    ]);
    expectFileError(
      () => safeUnzipBuffer({ serversBaseDir: serversDir, serverId, buffer: collidingDirAndFile }),
      "zip_invalid",
    );
    expect(readdirSync(serverDir)).toEqual([]);

    const collidingDirCasing = createZipBuffer([
      { name: "Config/", data: new Uint8Array(0), isDirectory: true },
      { name: "config/server.yml", data: new TextEncoder().encode("port: 25565") },
    ]);
    expectFileError(
      () => safeUnzipBuffer({ serversBaseDir: serversDir, serverId, buffer: collidingDirCasing }),
      "zip_invalid",
    );
    expect(readdirSync(serverDir)).toEqual([]);

    const duplicateExplicitDirs = createZipBuffer([
      { name: "logs/", data: new Uint8Array(0), isDirectory: true },
      { name: "logs/", data: new Uint8Array(0), isDirectory: true },
    ]);
    expectFileError(
      () =>
        safeUnzipBuffer({ serversBaseDir: serversDir, serverId, buffer: duplicateExplicitDirs }),
      "zip_invalid",
    );
    expect(readdirSync(serverDir)).toEqual([]);
  });

  test("unzip rejects overlapping entry offsets, zero-compressed-size deflate, out-of-bounds CD, and special UNIX modes atomically", () => {
    const benignPayload = new TextEncoder().encode("benign");
    const sharedPayload = new TextEncoder().encode("shared");

    // 1. Overlapping offsets (two entries pointing to localHeaderOffset = 0)
    const overlapping = buildMultiEntryZip([
      {
        cdName: "first.txt",
        payload: sharedPayload,
        method: 0,
        crc: crc32(sharedPayload),
        declaredUncompressedSize: sharedPayload.byteLength,
      },
      {
        cdName: "second.txt",
        payload: new Uint8Array(0),
        method: 0,
        crc: crc32(sharedPayload),
        declaredCompressedSize: sharedPayload.byteLength,
        declaredUncompressedSize: sharedPayload.byteLength,
        localHeaderOffsetOverride: 0,
      },
    ]);
    expectFileError(
      () => safeUnzipBuffer({ serversBaseDir: serversDir, serverId, buffer: overlapping.buffer }),
      "zip_invalid",
    );
    expect(readdirSync(serverDir)).toEqual([]);

    // 2. Deflate entry with compressedSize = 0 (preceded by valid entry to verify Phase 1 atomicity)
    const zeroCompressedDeflate = buildMultiEntryZip([
      {
        cdName: "benign.txt",
        payload: benignPayload,
        method: 0,
        crc: crc32(benignPayload),
        declaredUncompressedSize: benignPayload.byteLength,
      },
      {
        cdName: "empty-deflate.txt",
        payload: new Uint8Array(0),
        method: 8,
        crc: crc32(new Uint8Array(0)),
        declaredCompressedSize: 0,
        declaredUncompressedSize: 0,
      },
    ]);
    expectFileError(
      () =>
        safeUnzipBuffer({
          serversBaseDir: serversDir,
          serverId,
          buffer: zeroCompressedDeflate.buffer,
        }),
      "zip_invalid",
    );
    expect(readdirSync(serverDir)).toEqual([]);

    // 3. Truncated / out-of-bounds Central Directory offset & size
    const baseZip = createZipBuffer([{ name: "ok.txt", data: benignPayload }]);
    const corruptedCd = new Uint8Array(baseZip);
    const corruptedView = new DataView(corruptedCd.buffer);
    // Corrupt cdOffset in EOCD to point beyond EOCD
    corruptedView.setUint32(corruptedCd.byteLength - 6, corruptedCd.byteLength + 100, true);
    expectFileError(
      () => safeUnzipBuffer({ serversBaseDir: serversDir, serverId, buffer: corruptedCd }),
      "zip_invalid",
    );

    // 4. Truncated archive (LFH payload extends into Central Directory)
    const truncatedPayloadZip = buildMultiEntryZip([
      {
        cdName: "benign.txt",
        payload: benignPayload,
        method: 0,
        crc: crc32(benignPayload),
        declaredUncompressedSize: benignPayload.byteLength,
      },
      {
        cdName: "truncated.txt",
        payload: new Uint8Array(4),
        method: 0,
        crc: crc32(new Uint8Array(100)),
        declaredCompressedSize: 100,
        declaredUncompressedSize: 100,
      },
    ]);
    expectFileError(
      () =>
        safeUnzipBuffer({
          serversBaseDir: serversDir,
          serverId,
          buffer: truncatedPayloadZip.buffer,
        }),
      "zip_invalid",
    );
    expect(readdirSync(serverDir)).toEqual([]);

    // 5. Special UNIX entry types (FIFO, socket, char device) and LFH encryption mismatch
    for (const specialMode of [0o010644, 0o020644, 0o060644, 0o140755]) {
      const specialZip = buildMultiEntryZip([
        {
          cdName: "special",
          payload: new Uint8Array(0),
          method: 0,
          crc: crc32(new Uint8Array(0)),
          declaredUncompressedSize: 0,
          externalAttr: (specialMode << 16) >>> 0,
        },
      ]);
      expectFileError(
        () => safeUnzipBuffer({ serversBaseDir: serversDir, serverId, buffer: specialZip.buffer }),
        "zip_invalid",
      );
    }

    const lfhEncryptedZip = buildMultiEntryZip([
      {
        cdName: "sneaky-encrypted.txt",
        payload: benignPayload,
        method: 0,
        cdFlags: 0x0800,
        lfhFlags: 0x0801,
        crc: crc32(benignPayload),
        declaredUncompressedSize: benignPayload.byteLength,
      },
    ]);
    expectFileError(
      () =>
        safeUnzipBuffer({ serversBaseDir: serversDir, serverId, buffer: lfhEncryptedZip.buffer }),
      "zip_unsupported_method",
    );
  });

  test("unzip succeeds when 0-byte deflated entry follows entries that consume exact maxUncompressedBytes", () => {
    const exactPayload = new TextEncoder().encode("x".repeat(128));
    const deflatedEmpty = deflateRawSync(new Uint8Array(0));
    const deflatedFull = deflateRawSync(exactPayload);

    const zip = buildMultiEntryZip([
      {
        cdName: "full.txt",
        payload: new Uint8Array(
          deflatedFull.buffer,
          deflatedFull.byteOffset,
          deflatedFull.byteLength,
        ),
        method: 8,
        crc: crc32(exactPayload),
        declaredUncompressedSize: exactPayload.byteLength,
      },
      {
        cdName: "empty.txt",
        payload: new Uint8Array(
          deflatedEmpty.buffer,
          deflatedEmpty.byteOffset,
          deflatedEmpty.byteLength,
        ),
        method: 8,
        crc: crc32(new Uint8Array(0)),
        declaredUncompressedSize: 0,
      },
    ]);

    const res = safeUnzipBuffer({
      serversBaseDir: serversDir,
      serverId,
      buffer: zip.buffer,
      maxUncompressedBytes: 128,
    });
    expect(res.totalBytes).toBe(128);
    expect(readFileSync(join(serverDir, "full.txt"), "utf8")).toBe("x".repeat(128));
    expect(readFileSync(join(serverDir, "empty.txt"), "utf8")).toBe("");
  });

  test("does not leak file descriptors across read/write/download/upload error paths", () => {
    // 1. Oversized file read fails and releases fd immediately (file can be deleted on Windows).
    writeFileSync(join(serverDir, "huge.bin"), Buffer.alloc(MAX_READ_WRITE_BYTES + 1, 0x41));
    expectFileError(
      () => manager.read({ server_id: serverId, path: "huge.bin" }),
      "file_too_large",
    );
    expect(() => manager.delete({ server_id: serverId, path: "huge.bin" })).not.toThrow();

    // 2. Invalid encoding fails cleanly.
    expectFileError(
      () =>
        manager.write({
          server_id: serverId,
          path: "bad.txt",
          content: "abc",
          encoding: "hex" as unknown as "utf8",
        }),
      "invalid_encoding",
    );

    // 3. Download session errors release fd on close.
    manager.write({ server_id: serverId, path: "dl.txt", content: "download-me" });
    const dl = manager.downloadBegin({ server_id: serverId, path: "dl.txt", part_size: 4 });
    expectFileError(
      () =>
        manager.downloadPart({
          server_id: serverId,
          download_id: dl.download_id,
          part_index: 99,
        }),
      "part_out_of_order",
    );
    manager.downloadClose({ server_id: serverId, download_id: dl.download_id });
    expect(() => manager.delete({ server_id: serverId, path: "dl.txt" })).not.toThrow();

    // 4. Protocol CommandQueue emits files.error on invalid encoding / zip_slip.
    const account = generateSigningKeyPair();
    const session = generateSigningKeyPair();
    const agent = generateSigningKeyPair();
    const agentId = fingerprint(agent.publicKey);
    const now = 1_700_000_000_000;
    const sessionCert = signSessionCertificate({
      sessionPublicKey: session.publicKey,
      accountKeyPair: account,
      notBefore: now - 60_000,
      notAfter: now + 3_600_000,
    });
    const trust = createInMemoryTrustContext({
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
    const localMgr = new FileManager({ serversBaseDir: serversDir });
    registerFileCommandHandlers(queue, localMgr);

    const wrap = (body: SignedCommand): TransportCommandFrame => ({
      v: PROTOCOL_VERSION,
      kind: "command",
      route: { agent: agentId },
      body,
    });

    const badB64Cmd = createSignedCommand(
      {
        type: "files.write",
        body: {
          server_id: serverId,
          path: "bad-b64.bin",
          content: "not!valid!base64",
          encoding: "base64",
        },
        agentPublicKey: agent.publicKey,
        signer: session,
        session: sessionCert,
        counter: 1,
        now,
      },
      registry,
    );

    return queue
      .enqueue(wrap(badB64Cmd))
      .then(() => {
        const ev = sent[0];
        const ack = sent[1];
        expect(ev?.kind).toBe("event");
        if (ev?.kind === "event") {
          const opened = openAgentMessage(ev.body, agent.publicKey, account);
          expect(opened.header.type).toBe("files.error");
          expect((opened.body as { code: string }).code).toBe("invalid_encoding");
        }
        expect(ack?.kind === "ack" && !ack.body.ok && ack.body.code === "handler_error").toBe(true);
      })
      .finally(() => {
        localMgr.dispose();
        // Verify no open fd lingers inside confinement helper
        const f = join(serverDir, "cleanup-check.txt");
        writeFileSync(f, "ok");
        const resolved = resolveConfinedPath({
          serversBaseDir: serversDir,
          serverId,
          relPath: "cleanup-check.txt",
        });
        expect(resolved.relativePath).toBe("cleanup-check.txt");
        closeSync(openSync(resolved.fullPath, "r"));
      });
  });
});
