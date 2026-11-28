// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  existsSync,
  lstatSync,
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
import { ensureConsoleLog } from "./console-log";
import type { PermissionContext } from "./permissions";

const context: PermissionContext = { gid: null };

describe("ensureConsoleLog", () => {
  let dir: string;
  let logs: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "tegrad-console-"));
    logs = join(dir, "logs");
    mkdirSync(logs);
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  test("creates the file when it is missing", () => {
    ensureConsoleLog(dir, context);
    expect(existsSync(join(logs, "console.log"))).toBe(true);
  });

  test("keeps an existing file and its content", () => {
    writeFileSync(join(logs, "console.log"), "line\n");
    ensureConsoleLog(dir, context);
    expect(readFileSync(join(logs, "console.log"), "utf8")).toBe("line\n");
  });

  test("sets aside a file that belongs to another user and creates a fresh one", () => {
    writeFileSync(join(logs, "console.log"), "old\n");
    const owner = lstatSync(join(logs, "console.log")).uid;
    ensureConsoleLog(dir, context, { uid: owner + 1, now: () => 123 });
    expect(readFileSync(join(logs, "console.log"), "utf8")).toBe("");
    expect(readFileSync(join(logs, "console.123.log"), "utf8")).toBe("old\n");
  });

  test.skipIf(process.platform === "win32")("replaces a planted symbolic link", () => {
    const target = join(dir, "secret.txt");
    writeFileSync(target, "secret");
    symlinkSync(target, join(logs, "console.log"));
    ensureConsoleLog(dir, context);
    expect(lstatSync(join(logs, "console.log")).isSymbolicLink()).toBe(false);
    expect(readFileSync(target, "utf8")).toBe("secret");
    expect(readdirSync(logs)).toEqual(["console.log"]);
  });
});
