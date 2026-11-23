// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test";
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
import { z } from "zod";
import { createCommandQueue, type TransportCommandFrame } from "../agent/jobs";
import { createLogger } from "../agent/logger";
import { openTestEvent } from "../agent/test-events";
import { fingerprint, generateSigningKeyPair, ready } from "../crypto";
import {
  CommandRegistry,
  createCoreRegistry,
  createInMemoryTrustContext,
  createSignedCommand,
  defineCommand,
  FILES_COMMANDS,
  openCommand,
  PROTOCOL_VERSION,
  ProtocolError,
  type SignedCommand,
  signSessionCertificate,
  type TransportFrame,
} from "../protocol";
import { openConfinedFileForRead, wrapIoError } from "./confinement";
import { type FileErrorCode, FileManagerError } from "./errors";
import { FileManager, MAX_READ_WRITE_BYTES, registerFileCommandHandlers } from "./manager";
import { sha256Hex } from "./transfers";

function expectFileError(fn: () => unknown, code: FileErrorCode): void {
  try {
    fn();
    throw new Error(`Expected FileManagerError(${code}), but succeeded`);
  } catch (err) {
    expect(err).toBeInstanceOf(FileManagerError);
    expect((err as FileManagerError).code).toBe(code);
  }
}

async function expectFileErrorAsync(
  fn: () => Promise<unknown>,
  code: FileErrorCode,
): Promise<void> {
  try {
    await fn();
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

function tryCreateFileSymlink(target: string, linkPath: string): boolean {
  try {
    symlinkSync(target, linkPath, "file");
    return true;
  } catch (err) {
    const code =
      typeof err === "object" && err !== null && "code" in err
        ? (err as { code?: unknown }).code
        : undefined;
    if (process.platform === "win32" && code === "EPERM") {
      return false;
    }
    throw err;
  }
}

function wrapCommand(agentId: string, body: SignedCommand): TransportCommandFrame {
  return {
    v: PROTOCOL_VERSION,
    kind: "command",
    route: { agent: agentId },
    body,
  };
}

function makeSilentLogger() {
  return createLogger({
    level: "error",
    stdout: () => {},
    stderr: () => {},
  });
}

beforeAll(async () => {
  await ready();
});

describe("FileManager", () => {
  let rootTmp: string;
  let serversDir: string;
  let outsideDir: string;
  const serverId = "mc-prod-1";
  let serverDir: string;
  let manager: FileManager;

  beforeEach(() => {
    rootTmp = mkdtempSync(join(tmpdir(), "tegrad-fm-"));
    serversDir = join(rootTmp, "servers");
    outsideDir = join(rootTmp, "outside");
    serverDir = join(serversDir, serverId);
    mkdirSync(serverDir, { recursive: true });
    mkdirSync(outsideDir, { recursive: true });
    writeFileSync(join(outsideDir, "host-secret.txt"), "do-not-leak");
    manager = new FileManager({ serversBaseDir: serversDir });
  });

  afterEach(() => {
    manager.dispose();
    rmSync(rootTmp, { recursive: true, force: true });
  });

  test("supports full CRUD, mkdir, rename, move, copy, delete, list, and stat", async () => {
    manager.mkdir({ server_id: serverId, path: "config/nested" });
    manager.write({
      server_id: serverId,
      path: "config/nested/app.yml",
      content: "difficulty: hard\n",
    });

    const readUtf8 = await manager.read({ server_id: serverId, path: "config/nested/app.yml" });
    expect(readUtf8.content).toBe("difficulty: hard\n");
    expect(readUtf8.size).toBe(17);

    const readB64 = await manager.read({
      server_id: serverId,
      path: "config/nested/app.yml",
      encoding: "base64",
    });
    expect(Buffer.from(readB64.content, "base64").toString("utf8")).toBe("difficulty: hard\n");

    const statExisting = manager.stat({ server_id: serverId, path: "config/nested/app.yml" });
    expect(statExisting.exists).toBe(true);
    expect(statExisting.type).toBe("file");
    expect(statExisting.size).toBe(17);

    const statMissing = manager.stat({ server_id: serverId, path: "does-not-exist.txt" });
    expect(statMissing).toEqual({ path: "does-not-exist.txt", exists: false });

    const renamed = manager.rename({
      server_id: serverId,
      path: "config/nested/app.yml",
      new_name: "settings.yml",
    });
    expect(renamed).toEqual({
      from_path: "config/nested/app.yml",
      to_path: "config/nested/settings.yml",
    });

    const copied = await manager.copy({
      server_id: serverId,
      from_path: "config",
      to_path: "config-backup",
    });
    expect(copied.files_copied).toBe(1);
    expect(copied.bytes_copied).toBe(17);

    manager.move({
      server_id: serverId,
      from_path: "config-backup/nested/settings.yml",
      to_path: "moved.yml",
    });
    expect((await manager.read({ server_id: serverId, path: "moved.yml" })).content).toBe(
      "difficulty: hard\n",
    );

    const listed = manager.list({ server_id: serverId });
    expect(listed.entries.map((e) => `${e.name}:${e.type}`)).toEqual([
      "config:directory",
      "config-backup:directory",
      "moved.yml:file",
    ]);

    // Deleting non-empty directory without recursive fails
    expectFileError(
      () => manager.delete({ server_id: serverId, path: "config", recursive: false }),
      "is_a_directory",
    );
    // Recursive delete succeeds
    manager.delete({ server_id: serverId, path: "config", recursive: true });
    expect(manager.stat({ server_id: serverId, path: "config" }).exists).toBe(false);
  });

  test("enforces strict 2 MiB ceiling on read and write", async () => {
    const exactLimit = "A".repeat(MAX_READ_WRITE_BYTES);
    const overLimit = "A".repeat(MAX_READ_WRITE_BYTES + 1);

    const wrote = manager.write({
      server_id: serverId,
      path: "exact-2mib.txt",
      content: exactLimit,
    });
    expect(wrote.size).toBe(MAX_READ_WRITE_BYTES);
    expect(readdirSync(serverDir).filter((n) => n.startsWith(".tmp-"))).toEqual([]);

    const readBack = await manager.read({ server_id: serverId, path: "exact-2mib.txt" });
    expect(readBack.size).toBe(MAX_READ_WRITE_BYTES);

    // 2 MiB + 1 byte fails on write (utf8 and base64)
    expectFileError(
      () => manager.write({ server_id: serverId, path: "too-big.txt", content: overLimit }),
      "file_too_large",
    );
    expectFileError(
      () =>
        manager.write({
          server_id: serverId,
          path: "too-big-b64.bin",
          content: Buffer.alloc(MAX_READ_WRITE_BYTES + 1, 0x42).toString("base64"),
          encoding: "base64",
        }),
      "file_too_large",
    );

    // Pre-existing file of 2 MiB + 1 byte fails on read
    writeFileSync(join(serverDir, "large-on-disk.bin"), Buffer.alloc(MAX_READ_WRITE_BYTES + 1));
    await expectFileErrorAsync(
      () => manager.read({ server_id: serverId, path: "large-on-disk.bin" }),
      "file_too_large",
    );
  });

  test("refuses deleting server root or .runtime", () => {
    for (const target of ["", "."]) {
      expectFileError(
        () => manager.delete({ server_id: serverId, path: target, recursive: true }),
        "root_operation_forbidden",
      );
    }
    expectFileError(
      () => manager.delete({ server_id: serverId, path: "/", recursive: true }),
      "path_traversal",
    );
    expectFileError(
      () => manager.delete({ server_id: serverId, path: ".runtime", recursive: true }),
      "path_traversal",
    );
    expect(existsSync(serverDir)).toBe(true);
  });

  test("refuses symlinks/junctions across all operations and hides them in list", async () => {
    createDirLink(outsideDir, join(serverDir, "escape-dir"));
    mkdirSync(join(serverDir, "normal"));
    createDirLink(outsideDir, join(serverDir, "normal", "nested-link"));
    writeFileSync(join(serverDir, "regular.txt"), "ok");

    // list ignores symlinks/junctions without following them
    const listed = manager.list({ server_id: serverId });
    expect(listed.entries.map((e) => e.name)).toEqual(["normal", "regular.txt"]);

    // stat, read, write, delete, copy, move, mkdir, zip, unzip all refuse junction/symlink
    expectFileError(
      () => manager.stat({ server_id: serverId, path: "escape-dir" }),
      "symlink_forbidden",
    );
    await expectFileErrorAsync(
      () => manager.read({ server_id: serverId, path: "escape-dir/host-secret.txt" }),
      "symlink_forbidden",
    );
    expectFileError(
      () =>
        manager.write({
          server_id: serverId,
          path: "escape-dir/pwn.txt",
          content: "pwn",
        }),
      "symlink_forbidden",
    );
    expectFileError(
      () => manager.delete({ server_id: serverId, path: "escape-dir", recursive: true }),
      "symlink_forbidden",
    );
    expectFileError(
      () => manager.delete({ server_id: serverId, path: "normal", recursive: true }),
      "symlink_forbidden",
    );
    await expectFileErrorAsync(
      () =>
        manager.copy({
          server_id: serverId,
          from_path: "normal",
          to_path: "normal-copy",
        }),
      "symlink_forbidden",
    );
    expectFileError(
      () =>
        manager.move({
          server_id: serverId,
          from_path: "escape-dir",
          to_path: "moved-link",
        }),
      "symlink_forbidden",
    );
    expectFileError(
      () => manager.mkdir({ server_id: serverId, path: "escape-dir/sub" }),
      "symlink_forbidden",
    );
    await expectFileErrorAsync(
      () =>
        manager.zip({
          server_id: serverId,
          paths: ["normal"],
          dest_path: "bad.zip",
        }),
      "symlink_forbidden",
    );

    // Also test file symlink if OS permits creating one
    const fileSymPath = join(serverDir, "secret-file-link.txt");
    if (tryCreateFileSymlink(join(outsideDir, "host-secret.txt"), fileSymPath)) {
      await expectFileErrorAsync(
        () => manager.read({ server_id: serverId, path: "secret-file-link.txt" }),
        "symlink_forbidden",
      );
      expectFileError(
        () =>
          manager.write({
            server_id: serverId,
            path: "secret-file-link.txt",
            content: "overwrite",
          }),
        "symlink_forbidden",
      );
      expectFileError(
        () => manager.stat({ server_id: serverId, path: "secret-file-link.txt" }),
        "symlink_forbidden",
      );
      expectFileError(
        () => manager.delete({ server_id: serverId, path: "secret-file-link.txt" }),
        "symlink_forbidden",
      );
    }

    // Outside secret file remains untouched!
    expect(readFileSync(join(outsideDir, "host-secret.txt"), "utf8")).toBe("do-not-leak");
  });

  test("copy enforces file count and byte limits and prevents self-nesting", async () => {
    const limited = new FileManager({
      serversBaseDir: serversDir,
      maxCopyFiles: 2,
      maxCopyBytes: 100,
    });
    limited.mkdir({ server_id: serverId, path: "src" });
    limited.write({ server_id: serverId, path: "src/a.txt", content: "a".repeat(60) });
    limited.write({ server_id: serverId, path: "src/b.txt", content: "b".repeat(60) });

    await expectFileErrorAsync(
      () => limited.copy({ server_id: serverId, from_path: "src", to_path: "src/sub" }),
      "invalid_path",
    );
    await expectFileErrorAsync(
      () => limited.copy({ server_id: serverId, from_path: "src", to_path: "dst" }),
      "copy_limit_exceeded",
    );
    limited.dispose();
  });

  test("chunked upload reconstructs multi-part file when SHA-256 matches and cleans up staging", () => {
    const part0 = new TextEncoder().encode("first-part-content-");
    const part1 = new TextEncoder().encode("second-part-content-");
    const part2 = new TextEncoder().encode("final-part!");
    const full = new Uint8Array(part0.byteLength + part1.byteLength + part2.byteLength);
    full.set(part0, 0);
    full.set(part1, part0.byteLength);
    full.set(part2, part0.byteLength + part1.byteLength);
    const expectedHash = sha256Hex(full);

    const began = manager.uploadBegin({
      server_id: serverId,
      path: "mods/example.jar",
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
    manager.uploadPart({
      server_id: serverId,
      upload_id: began.upload_id,
      part_index: 1,
      data_base64: Buffer.from(part1).toString("base64"),
    });
    manager.uploadPart({
      server_id: serverId,
      upload_id: began.upload_id,
      part_index: 2,
      data_base64: Buffer.from(part2).toString("base64"),
    });

    const committed = manager.uploadCommit({
      server_id: serverId,
      upload_id: began.upload_id,
    });

    expect(committed.path).toBe("mods/example.jar");
    expect(committed.size).toBe(full.byteLength);
    expect(committed.sha256).toBe(expectedHash);
    expect(new Uint8Array(readFileSync(join(serverDir, "mods", "example.jar")))).toEqual(full);
    expect(readdirSync(serverDir).filter((n) => n.startsWith(".tmp-"))).toEqual([]);
  });

  test("chunked upload rejects wrong SHA-256, deletes staging, and leaves destination untouched", () => {
    writeFileSync(join(serverDir, "existing.bin"), "original-content");
    const payload = new TextEncoder().encode("malicious-replacement");
    const wrongHash = "0".repeat(64);

    const began = manager.uploadBegin({
      server_id: serverId,
      path: "existing.bin",
      total_size: payload.byteLength,
      sha256: wrongHash,
    });
    manager.uploadPart({
      server_id: serverId,
      upload_id: began.upload_id,
      part_index: 0,
      data_base64: Buffer.from(payload).toString("base64"),
    });

    expectFileError(
      () => manager.uploadCommit({ server_id: serverId, upload_id: began.upload_id }),
      "hash_mismatch",
    );

    expect(readFileSync(join(serverDir, "existing.bin"), "utf8")).toBe("original-content");
    expect(readdirSync(serverDir).filter((n) => n.startsWith(".tmp-"))).toEqual([]);
  });

  test("chunked upload rejects overflow bytes, out-of-order parts, and incomplete commits", () => {
    const payload = new TextEncoder().encode("1234567890");
    const began = manager.uploadBegin({
      server_id: serverId,
      path: "data.bin",
      total_size: 10,
      sha256: sha256Hex(payload),
    });

    // Out of order part_index
    expectFileError(
      () =>
        manager.uploadPart({
          server_id: serverId,
          upload_id: began.upload_id,
          part_index: 1,
          data_base64: Buffer.from("12345").toString("base64"),
        }),
      "part_out_of_order",
    );

    // Valid part 0 (6 bytes)
    manager.uploadPart({
      server_id: serverId,
      upload_id: began.upload_id,
      part_index: 0,
      data_base64: Buffer.from("123456").toString("base64"),
    });

    // Overflowing total_size (6 + 5 > 10)
    expectFileError(
      () =>
        manager.uploadPart({
          server_id: serverId,
          upload_id: began.upload_id,
          part_index: 1,
          data_base64: Buffer.from("78901").toString("base64"),
        }),
      "size_mismatch",
    );

    // Committing before all 10 bytes arrive fails and cleans up staging
    expectFileError(
      () => manager.uploadCommit({ server_id: serverId, upload_id: began.upload_id }),
      "size_mismatch",
    );
    expect(existsSync(join(serverDir, "data.bin"))).toBe(false);
    expect(readdirSync(serverDir).filter((n) => n.startsWith(".tmp-"))).toEqual([]);
  });

  test("chunked upload rejects symlink/junction planted between begin and commit and cleans staging", () => {
    const payload = new TextEncoder().encode("payload");
    const began = manager.uploadBegin({
      server_id: serverId,
      path: "planted-dir/target.txt",
      total_size: payload.byteLength,
      sha256: sha256Hex(payload),
    });
    manager.uploadPart({
      server_id: serverId,
      upload_id: began.upload_id,
      part_index: 0,
      data_base64: Buffer.from(payload).toString("base64"),
    });

    // Attacker plants a directory junction before commit
    createDirLink(outsideDir, join(serverDir, "planted-dir"));

    expectFileError(
      () => manager.uploadCommit({ server_id: serverId, upload_id: began.upload_id }),
      "symlink_forbidden",
    );
    expect(existsSync(join(outsideDir, "target.txt"))).toBe(false);
    expect(readdirSync(serverDir).filter((n) => n.startsWith(".tmp-"))).toEqual([]);
  });

  test("chunked download and ranged download reconstruct file with SHA-256", async () => {
    const content = new TextEncoder().encode("0123456789abcdefghijKLMNO");
    writeFileSync(join(serverDir, "world.bin"), content);

    const began = await manager.downloadBegin({
      server_id: serverId,
      path: "world.bin",
      part_size: 10,
    });
    expect(began.total_size).toBe(25);
    expect(began.total_parts).toBe(3);

    const chunks: Buffer[] = [];
    for (let i = 0; i < began.total_parts; i++) {
      const part = manager.downloadPart({
        server_id: serverId,
        download_id: began.download_id,
        part_index: i,
      });
      const decoded = Buffer.from(part.data_base64, "base64");
      expect(sha256Hex(new Uint8Array(decoded))).toBe(part.sha256);
      expect(part.eof).toBe(i === began.total_parts - 1);
      chunks.push(decoded);
    }
    manager.downloadClose({ server_id: serverId, download_id: began.download_id });
    expect(new Uint8Array(Buffer.concat(chunks))).toEqual(content);

    // Direct ranged download
    const range = await manager.download({
      server_id: serverId,
      path: "world.bin",
      offset: 10,
      length: 10,
    });
    expect(Buffer.from(range.data_base64, "base64").toString("utf8")).toBe("abcdefghij");
    expect(range.eof).toBe(false);
  });

  test("retries once via makeServerReadable on EACCES across read, download, copy, zip, and unzip", async () => {
    mkdirSync(join(serverDir, "world"), { recursive: true });
    writeFileSync(join(serverDir, "world", "level.dat"), "nbt-payload");

    const makeEacces = () => {
      const err = new Error("EACCES: permission denied") as NodeJS.ErrnoException;
      err.code = "EACCES";
      return wrapIoError(err, "Failed to open target file");
    };

    const runScenario = async (
      op: (fm: FileManager) => Promise<void>,
      persistFailure: boolean,
    ): Promise<readonly string[]> => {
      const readableCalls: string[] = [];
      let readableFixed = false;
      const fm = new FileManager({
        serversBaseDir: serversDir,
        makeServerReadableImpl: async (id) => {
          readableCalls.push(id);
          if (!persistFailure) {
            readableFixed = true;
          }
          return true;
        },
        openForReadImpl: (resolved) => {
          if (!readableFixed) {
            throw makeEacces();
          }
          return openConfinedFileForRead(resolved);
        },
      });
      try {
        await op(fm);
      } finally {
        fm.dispose();
      }
      return readableCalls;
    };

    // 1. files.read succeeds on single retry
    const readCalls = await runScenario(async (fm) => {
      const res = await fm.read({ server_id: serverId, path: "world/level.dat" });
      expect(res.content).toBe("nbt-payload");
    }, false);
    expect(readCalls).toEqual([serverId]);

    // 2. files.download (ranged) succeeds on single retry
    const dlRangeCalls = await runScenario(async (fm) => {
      const res = await fm.download({
        server_id: serverId,
        path: "world/level.dat",
        offset: 0,
        length: 11,
      });
      expect(Buffer.from(res.data_base64, "base64").toString("utf8")).toBe("nbt-payload");
    }, false);
    expect(dlRangeCalls).toEqual([serverId]);

    // 3. files.download.begin succeeds on single retry
    const dlBeginCalls = await runScenario(async (fm) => {
      const began = await fm.downloadBegin({ server_id: serverId, path: "world/level.dat" });
      expect(began.total_size).toBe(11);
      fm.downloadClose({ server_id: serverId, download_id: began.download_id });
    }, false);
    expect(dlBeginCalls).toEqual([serverId]);

    // 4. files.copy succeeds on single retry
    const copyCalls = await runScenario(async (fm) => {
      const res = await fm.copy({
        server_id: serverId,
        from_path: "world/level.dat",
        to_path: "world/level-copy.dat",
      });
      expect(res.files_copied).toBe(1);
    }, false);
    expect(copyCalls).toEqual([serverId]);

    // 5. files.zip succeeds on single retry
    const zipCalls = await runScenario(async (fm) => {
      const res = await fm.zip({
        server_id: serverId,
        paths: ["world/level.dat"],
        dest_path: "world.zip",
      });
      expect(res.entryCount).toBe(1);
    }, false);
    expect(zipCalls).toEqual([serverId]);

    // 6. files.unzip succeeds on single retry
    const unzipCalls = await runScenario(async (fm) => {
      const res = await fm.unzip({
        server_id: serverId,
        zip_path: "world.zip",
        dest_path: "extracted",
      });
      expect(res.entryCount).toBe(1);
    }, false);
    expect(unzipCalls).toEqual([serverId]);

    // 7. Persistent EACCES calls makeServerReadable only once and returns the original io_error
    const persistentCalls = await runScenario(async (fm) => {
      await expectFileErrorAsync(
        () => fm.read({ server_id: serverId, path: "world/level.dat" }),
        "io_error",
      );
    }, true);
    expect(persistentCalls).toEqual([serverId]);
  });
});

describe("protocol integration (CommandRegistry, openCommand, CommandQueue)", () => {
  let rootTmp: string;
  let serversDir: string;
  const serverId = "srv-proto";

  beforeEach(() => {
    rootTmp = mkdtempSync(join(tmpdir(), "tegrad-fm-proto-"));
    serversDir = join(rootTmp, "servers");
    mkdirSync(join(serversDir, serverId), { recursive: true });
  });

  afterEach(() => {
    rmSync(rootTmp, { recursive: true, force: true });
  });

  test("registers all FILES_COMMANDS in createCoreRegistry and enforces files.delete as sensitive", async () => {
    const registry = createCoreRegistry();
    for (const def of FILES_COMMANDS) {
      expect(registry.has(def.type)).toBe(true);
    }
    expect(registry.get("files.delete")?.sensitive).toBe(true);
    expect(registry.get("files.read")?.sensitive).toBe(false);
    expect(registry.get("files.write")?.sensitive).toBe(false);

    const account = generateSigningKeyPair();
    const session = generateSigningKeyPair();
    const agent = generateSigningKeyPair();
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

    // Session key CANNOT execute files.delete (sensitive: true)
    const sessionDeleteCmd = createSignedCommand(
      {
        type: "files.delete",
        body: { server_id: serverId, path: "world.txt" },
        agentPublicKey: agent.publicKey,
        signer: session,
        session: sessionCert,
        counter: 1,
        now,
      },
      registry,
    );

    try {
      await openCommand(sessionDeleteCmd, trust, registry);
      throw new Error("Expected sensitive_requires_account_key");
    } catch (err) {
      expect(err).toBeInstanceOf(ProtocolError);
      expect((err as ProtocolError).code).toBe("sensitive_requires_account_key");
    }

    // Account key CAN execute files.delete
    const accountDeleteCmd = createSignedCommand(
      {
        type: "files.delete",
        body: { server_id: serverId, path: "world.txt", recursive: false },
        agentPublicKey: agent.publicKey,
        signer: account,
        counter: 1,
        now,
      },
      registry,
    );
    const opened = await openCommand(accountDeleteCmd, trust, registry);
    expect(opened.header.type).toBe("files.delete");
    expect(opened.body).toEqual({ server_id: serverId, path: "world.txt", recursive: false });

    // Strict Zod schema rejects malicious server_id at protocol boundary (both client & agent)
    const permissiveRegistry = new CommandRegistry().register(
      defineCommand({
        type: "files.list",
        sensitive: false,
        minRole: "viewer",
        body: z.unknown(),
      }),
    );
    const badServerIdCmd = createSignedCommand(
      {
        type: "files.list",
        body: { server_id: "../tegrad", path: "" },
        agentPublicKey: agent.publicKey,
        signer: session,
        session: sessionCert,
        counter: 2,
        now,
      },
      permissiveRegistry,
    );
    try {
      await openCommand(badServerIdCmd, trust, registry);
      throw new Error("Expected invalid_body");
    } catch (err) {
      expect(err).toBeInstanceOf(ProtocolError);
      expect((err as ProtocolError).code).toBe("invalid_body");
    }
  });

  test("executes signed files.* commands through CommandQueue and seals result events", async () => {
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
      logger: makeSilentLogger(),
    });
    const manager = new FileManager({ serversBaseDir: serversDir });
    registerFileCommandHandlers(queue, manager);

    try {
      // 1. files.write signed by session key
      const writeCmd = createSignedCommand(
        {
          type: "files.write",
          body: { server_id: serverId, path: "eula.txt", content: "eula=true\n" },
          agentPublicKey: agent.publicKey,
          signer: session,
          session: sessionCert,
          counter: 1,
          now,
        },
        registry,
      );
      await queue.enqueue(wrapCommand(agentId, writeCmd));

      const writeEvent = sent[0];
      const writeAck = sent[1];
      expect(writeEvent?.kind).toBe("event");
      if (writeEvent?.kind === "event") {
        const opened = openTestEvent(writeEvent.body, agent.publicKey, account);
        expect(opened.header.type).toBe("files.write.result");
        expect(opened.body).toEqual({ path: "eula.txt", size: 10 });
      }
      expect(writeAck?.kind === "ack" && writeAck.body.ok).toBe(true);

      // 2. files.read signed by session key
      const readCmd = createSignedCommand(
        {
          type: "files.read",
          body: { server_id: serverId, path: "eula.txt" },
          agentPublicKey: agent.publicKey,
          signer: session,
          session: sessionCert,
          counter: 2,
          now,
        },
        registry,
      );
      await queue.enqueue(wrapCommand(agentId, readCmd));

      const readEvent = sent[2];
      expect(readEvent?.kind).toBe("event");
      if (readEvent?.kind === "event") {
        const opened = openTestEvent(readEvent.body, agent.publicKey, account);
        expect(opened.header.type).toBe("files.read.result");
        expect(opened.body).toEqual({
          path: "eula.txt",
          encoding: "utf8",
          content: "eula=true\n",
          size: 10,
        });
      }

      // 3. files.read with path traversal emits files.error event and handler_error ack
      const traversalCmd = createSignedCommand(
        {
          type: "files.read",
          body: { server_id: serverId, path: "../secret.txt" },
          agentPublicKey: agent.publicKey,
          signer: session,
          session: sessionCert,
          counter: 3,
          now,
        },
        registry,
      );
      await queue.enqueue(wrapCommand(agentId, traversalCmd));
      const errEvent = sent[4];
      const errAck = sent[5];
      expect(errEvent?.kind).toBe("event");
      if (errEvent?.kind === "event") {
        const opened = openTestEvent(errEvent.body, agent.publicKey, account);
        expect(opened.header.type).toBe("files.error");
        expect((opened.body as { code: string }).code).toBe("path_traversal");
      }
      expect(
        errAck?.kind === "ack" && !errAck.body.ok && errAck.body.code === "handler_error",
      ).toBe(true);

      // 4. files.delete signed by account key
      const deleteCmd = createSignedCommand(
        {
          type: "files.delete",
          body: { server_id: serverId, path: "eula.txt" },
          agentPublicKey: agent.publicKey,
          signer: account,
          counter: 1,
          now,
        },
        registry,
      );
      await queue.enqueue(wrapCommand(agentId, deleteCmd));

      const deleteEvent = sent[6];
      const deleteAck = sent[7];
      expect(deleteEvent?.kind).toBe("event");
      if (deleteEvent?.kind === "event") {
        const opened = openTestEvent(deleteEvent.body, agent.publicKey, account);
        expect(opened.header.type).toBe("files.delete.result");
        expect(opened.body).toEqual({ path: "eula.txt", deleted: true });
      }
      expect(deleteAck?.kind === "ack" && deleteAck.body.ok).toBe(true);
    } finally {
      manager.dispose();
    }
  });
});
