// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  closeSync,
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
import {
  MAX_COMPONENT_BYTES,
  MAX_PATH_BYTES,
  mkdirConfined,
  openConfinedFileForRead,
  resolveConfinedPath,
  validateServerId,
  validateSingleFileName,
  writeConfinedFileAtomic,
} from "./confinement";
import { type FileErrorCode, FileManagerError } from "./errors";

function expectFileError(fn: () => unknown, code: FileErrorCode): void {
  try {
    fn();
    throw new Error(`Expected FileManagerError(${code}), but succeeded`);
  } catch (err) {
    expect(err).toBeInstanceOf(FileManagerError);
    expect((err as FileManagerError).code).toBe(code);
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

function createDirLink(target: string, linkPath: string): void {
  if (process.platform === "win32") {
    symlinkSync(target, linkPath, "junction");
  } else {
    symlinkSync(target, linkPath, "dir");
  }
}

describe("confinement", () => {
  let rootTmp: string;
  let serversDir: string;
  let outsideDir: string;
  const serverId = "srv-1";
  let serverDir: string;

  beforeEach(() => {
    rootTmp = mkdtempSync(join(tmpdir(), "tegrad-confine-"));
    serversDir = join(rootTmp, "servers");
    outsideDir = join(rootTmp, "outside");
    serverDir = join(serversDir, serverId);
    mkdirSync(serverDir, { recursive: true });
    mkdirSync(outsideDir, { recursive: true });
    writeFileSync(join(outsideDir, "secret.txt"), "top-secret");
  });

  afterEach(() => {
    rmSync(rootTmp, { recursive: true, force: true });
  });

  test("validates server_id strictly and rejects malicious identifiers", () => {
    expect(validateServerId("a")).toBe("a");
    expect(validateServerId("srv-1")).toBe("srv-1");
    expect(validateServerId("0123-abc-xyz")).toBe("0123-abc-xyz");
    expect(validateServerId("a".repeat(63))).toBe("a".repeat(63));

    const badIds = [
      "",
      "../tegrad",
      ".runtime",
      "UPPER",
      "srv_1",
      "-leading",
      "a".repeat(64),
      "srv/1",
      "srv\\1",
      "srv\0",
      "..",
      ".",
    ];
    for (const bad of badIds) {
      expectFileError(() => validateServerId(bad), "invalid_server_id");
    }
  });

  test("blocks directory traversal, backslashes, absolute paths, and encoded separators", () => {
    const attacks = [
      "..",
      "../etc/passwd",
      "a/b/../../../etc/passwd",
      "..%2f..",
      "..%2fetc%2fpasswd",
      "a/..%5csecret",
      "\\..\\..",
      "a\\b",
      "/etc/passwd",
      "/",
      "C:\\Windows\\System32",
      "C:/Windows/System32",
      "\\\\server\\share",
      "a/./b",
      "./a",
      "sub/..",
    ];

    for (const attack of attacks) {
      expect(() =>
        resolveConfinedPath({
          serversBaseDir: serversDir,
          serverId,
          relPath: attack,
          allowRoot: false,
        }),
      ).toThrow(FileManagerError);
    }
  });

  test("blocks NUL bytes, control chars, non-NFC Unicode, excessive length, and empty segments", () => {
    expectFileError(
      () =>
        resolveConfinedPath({
          serversBaseDir: serversDir,
          serverId,
          relPath: "foo\0bar.txt",
        }),
      "invalid_path",
    );

    for (const ctrl of ["a\nb.txt", "a\rb.txt", "a\x01b.txt", "a\x1fb.txt", "a\x7fb.txt"]) {
      expectFileError(
        () =>
          resolveConfinedPath({
            serversBaseDir: serversDir,
            serverId,
            relPath: ctrl,
          }),
        "invalid_path",
      );
    }

    // NFD decomposed "café.txt" must be rejected; NFC composed is allowed.
    const nfd = "cafe\u0301.txt";
    const nfc = nfd.normalize("NFC");
    expect(nfd).not.toBe(nfc);
    expectFileError(
      () =>
        resolveConfinedPath({
          serversBaseDir: serversDir,
          serverId,
          relPath: nfd,
        }),
      "invalid_path",
    );
    const resolvedNfc = resolveConfinedPath({
      serversBaseDir: serversDir,
      serverId,
      relPath: nfc,
    });
    expect(resolvedNfc.relativePath).toBe(nfc);

    // Path > 1024 bytes
    const tooLongPath = `${"a".repeat(200)}/${"b".repeat(200)}/${"c".repeat(200)}/${"d".repeat(200)}/${"e".repeat(250)}`;
    expect(Buffer.byteLength(tooLongPath, "utf8")).toBeGreaterThan(MAX_PATH_BYTES);
    expectFileError(
      () =>
        resolveConfinedPath({
          serversBaseDir: serversDir,
          serverId,
          relPath: tooLongPath,
        }),
      "invalid_path",
    );

    // Component > 255 bytes
    const tooLongComp = "a".repeat(MAX_COMPONENT_BYTES + 1);
    expectFileError(
      () =>
        resolveConfinedPath({
          serversBaseDir: serversDir,
          serverId,
          relPath: tooLongComp,
        }),
      "invalid_path",
    );

    // Empty segments
    expectFileError(
      () =>
        resolveConfinedPath({
          serversBaseDir: serversDir,
          serverId,
          relPath: "a//b",
        }),
      "invalid_path",
    );
    expectFileError(
      () =>
        resolveConfinedPath({
          serversBaseDir: serversDir,
          serverId,
          relPath: "a/",
        }),
      "invalid_path",
    );
  });

  test("blocks reserved Windows device names and trailing dots or spaces", () => {
    const reserved = [
      "CON",
      "con",
      "PRN",
      "AUX",
      "aux.json",
      "NUL",
      "NUL.txt",
      "COM1",
      "com9.log",
      "LPT1",
      "lpt9",
      "CONIN$",
      "CONOUT$",
      "CLOCK$",
      "sub/NUL.txt",
      "foo.",
      "bar ",
      "dir./file.txt",
      "dir /file.txt",
    ];

    for (const candidate of reserved) {
      expectFileError(
        () =>
          resolveConfinedPath({
            serversBaseDir: serversDir,
            serverId,
            relPath: candidate,
          }),
        "invalid_path",
      );
    }
  });

  test("blocks .runtime at any nesting level and root operations when allowRoot is false", () => {
    for (const p of [".runtime", ".runtime/java", "nested/.runtime/bin"]) {
      expectFileError(
        () =>
          resolveConfinedPath({
            serversBaseDir: serversDir,
            serverId,
            relPath: p,
          }),
        "path_traversal",
      );
    }

    for (const rootPath of ["", "."]) {
      expectFileError(
        () =>
          resolveConfinedPath({
            serversBaseDir: serversDir,
            serverId,
            relPath: rootPath,
            allowRoot: false,
          }),
        "root_operation_forbidden",
      );
      const allowed = resolveConfinedPath({
        serversBaseDir: serversDir,
        serverId,
        relPath: rootPath,
        allowRoot: true,
      });
      expect(allowed.relativePath).toBe("");
      expect(allowed.segments).toEqual([]);
    }
  });

  test("validates single file names for rename", () => {
    expect(validateSingleFileName("server.properties")).toBe("server.properties");
    for (const bad of ["", "a/b", "a\\b", "..", ".", ".runtime", "NUL.txt", "foo.", "foo\0"]) {
      expect(() => validateSingleFileName(bad)).toThrow(FileManagerError);
    }
  });

  test("rejects symlink/junction as server root, intermediate directory, or file", () => {
    // 1. Server root itself is a junction/symlink
    const linkedServerId = "srv-linked";
    createDirLink(outsideDir, join(serversDir, linkedServerId));
    expectFileError(
      () =>
        resolveConfinedPath({
          serversBaseDir: serversDir,
          serverId: linkedServerId,
          relPath: "secret.txt",
        }),
      "symlink_forbidden",
    );

    // 2. Intermediate directory symlink/junction pointing outside
    const escapeDir = join(serverDir, "escape-dir");
    createDirLink(outsideDir, escapeDir);
    expectFileError(
      () =>
        resolveConfinedPath({
          serversBaseDir: serversDir,
          serverId,
          relPath: "escape-dir/secret.txt",
        }),
      "symlink_forbidden",
    );
    expectFileError(
      () =>
        mkdirConfined({
          serversBaseDir: serversDir,
          serverId,
          relPath: "escape-dir/nested/newdir",
        }),
      "symlink_forbidden",
    );

    // 3. Intermediate directory symlink/junction pointing inside server
    const realSub = join(serverDir, "real-sub");
    mkdirSync(realSub);
    createDirLink(realSub, join(serverDir, "inner-link"));
    expectFileError(
      () =>
        resolveConfinedPath({
          serversBaseDir: serversDir,
          serverId,
          relPath: "inner-link/file.txt",
        }),
      "symlink_forbidden",
    );

    // 4. File symlink pointing outside (skipped gracefully on Windows without Developer Mode)
    const fileLinkPath = join(serverDir, "secret-link.txt");
    if (tryCreateFileSymlink(join(outsideDir, "secret.txt"), fileLinkPath)) {
      expectFileError(
        () =>
          resolveConfinedPath({
            serversBaseDir: serversDir,
            serverId,
            relPath: "secret-link.txt",
          }),
        "symlink_forbidden",
      );
    }
  });

  test("openConfinedFileForRead validates file identity and rejects non-files", () => {
    const resolved = resolveConfinedPath({
      serversBaseDir: serversDir,
      serverId,
      relPath: "hello.txt",
    });
    writeConfinedFileAtomic(resolved, new TextEncoder().encode("hello world"));

    const { fd, stats } = openConfinedFileForRead(resolved);
    try {
      expect(stats.isFile()).toBe(true);
      expect(stats.size).toBe(11);
    } finally {
      closeSync(fd);
    }

    mkdirSync(join(serverDir, "subdir"));
    const dirResolved = resolveConfinedPath({
      serversBaseDir: serversDir,
      serverId,
      relPath: "subdir",
    });
    expectFileError(() => openConfinedFileForRead(dirResolved), "is_a_directory");
  });

  test("writeConfinedFileAtomic is atomic and leaves no .tmp- files on success or failure", () => {
    const resolved = resolveConfinedPath({
      serversBaseDir: serversDir,
      serverId,
      relPath: "config.yml",
    });

    writeConfinedFileAtomic(resolved, new TextEncoder().encode("v1"));
    expect(readFileSync(resolved.fullPath, "utf8")).toBe("v1");
    expect(readdirSync(serverDir).filter((n) => n.startsWith(".tmp-"))).toEqual([]);

    // Simulated mid-write crash leaves existing file intact and removes .tmp-
    expect(() =>
      writeConfinedFileAtomic(resolved, new TextEncoder().encode("v2-corrupt"), {
        writeHook() {
          throw new Error("simulated disk failure");
        },
      }),
    ).toThrow(FileManagerError);

    expect(readFileSync(resolved.fullPath, "utf8")).toBe("v1");
    expect(readdirSync(serverDir).filter((n) => n.startsWith(".tmp-"))).toEqual([]);
    expect(existsSync(resolved.fullPath)).toBe(true);
  });
});
