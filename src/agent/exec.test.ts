// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { describe, expect, test } from "bun:test";
import { runFixed } from "./exec";

describe("runFixed", () => {
  test("executes a portable command with argv array and returns stdout", async () => {
    const res = await runFixed(process.execPath, ["--version"]);
    expect(res.code).toBe(0);
    expect(res.timedOut).toBe(false);
    expect(res.truncated).toBe(false);
    expect(res.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });

  test("does not pass arguments through a shell", async () => {
    const marker = "$(echo shell-executed); echo injected";
    const res = await runFixed(process.execPath, [
      "-e",
      "process.stdout.write(process.argv[1])",
      marker,
    ]);
    expect(res.code).toBe(0);
    expect(res.stdout).toBe(marker);
  });

  test("returns non-zero exit code and stderr when command fails", async () => {
    const res = await runFixed(process.execPath, [
      "-e",
      'process.stderr.write("boom"); process.exit(7);',
    ]);
    expect(res.code).toBe(7);
    expect(res.stderr).toBe("boom");
    expect(res.timedOut).toBe(false);
  });

  test("enforces maxOutputBytes cap on stdout", async () => {
    const res = await runFixed(
      process.execPath,
      ["-e", 'process.stdout.write("A".repeat(4096));'],
      { maxOutputBytes: 128 },
    );
    expect(res.truncated).toBe(true);
    expect(Buffer.byteLength(res.stdout, "utf8")).toBeLessThanOrEqual(128);
  });

  test("enforces timeoutMs and kills long-running child process", async () => {
    const res = await runFixed(process.execPath, ["-e", "setTimeout(() => {}, 10000);"], {
      timeoutMs: 150,
    });
    expect(res.timedOut).toBe(true);
    expect(res.code).toBe(-1);
  });
});
