// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getStatePaths } from "../agent";
import { versionLine } from "../version";
import { runCli } from "./main";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "tegrad-cli-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

async function invokeCli(argv: readonly string[], env: Record<string, string | undefined> = {}) {
  let stdout = "";
  let stderr = "";
  const code = await runCli(argv, {
    env,
    stdout: (text) => {
      stdout += text;
    },
    stderr: (text) => {
      stderr += text;
    },
  });
  return { code, stdout, stderr };
}

describe("CLI", () => {
  test("--version and -v print version line and exit 0", async () => {
    const r1 = await invokeCli(["--version"]);
    expect(r1.code).toBe(0);
    expect(r1.stdout).toBe(`${versionLine()}\n`);

    const r2 = await invokeCli(["-v"]);
    expect(r2.code).toBe(0);
    expect(r2.stdout).toBe(`${versionLine()}\n`);
  });

  test("--help and -h print usage and exit 0", async () => {
    const r1 = await invokeCli(["--help"]);
    expect(r1.code).toBe(0);
    expect(r1.stdout).toContain("Usage: tegrad");

    const r2 = await invokeCli(["-h"]);
    expect(r2.code).toBe(0);
    expect(r2.stdout).toContain("Usage: tegrad");
  });

  test("unknown subcommand exits with code 2", async () => {
    const res = await invokeCli(["does-not-exist"]);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain("Usage: tegrad");
  });

  test("link and link --reset respond 'not implemented' with exit code 2", async () => {
    const r1 = await invokeCli(["link"]);
    expect(r1.code).toBe(2);
    expect(r1.stderr.trim()).toBe("not implemented");

    const r2 = await invokeCli(["link", "--reset"]);
    expect(r2.code).toBe(2);
    expect(r2.stderr.trim()).toBe("not implemented");
  });

  test("identity creates keypair and prints only fingerprint; status reports local state", async () => {
    const dir = makeTempDir();
    const env = { TEGRAD_STATE_DIR: dir };

    const beforeStatus = await invokeCli(["status"], env);
    expect(beforeStatus.code).toBe(0);
    expect(beforeStatus.stdout).toContain(`state_dir: ${dir}`);
    expect(beforeStatus.stdout).toContain("fingerprint: not initialized");
    expect(beforeStatus.stdout).toContain("config: missing");
    expect(beforeStatus.stdout).toContain("trusted_accounts: 0");

    const id1 = await invokeCli(["identity"], env);
    expect(id1.code).toBe(0);
    const fp = id1.stdout.trim();
    expect(fp).toMatch(/^[a-z2-7]{32}$/);

    const id2 = await invokeCli(["identity"], env);
    expect(id2.code).toBe(0);
    expect(id2.stdout.trim()).toBe(fp);

    const { configPath } = getStatePaths(dir);
    writeFileSync(configPath, JSON.stringify({ api_url: "https://api.tegra.example" }), "utf8");

    const afterStatus = await invokeCli(["status"], env);
    expect(afterStatus.code).toBe(0);
    expect(afterStatus.stdout).toContain(`fingerprint: ${fp}`);
    expect(afterStatus.stdout).toContain("config: present");
    expect(afterStatus.stdout).toContain("trusted_accounts: 0");
  });

  test("run fails clearly when config.json is missing", async () => {
    const dir = makeTempDir();
    const res = await invokeCli(["run"], { TEGRAD_STATE_DIR: dir });
    expect(res.code).toBe(1);
    expect(res.stderr).toContain("config.json");
  });
});
