// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, describe, expect, test } from "bun:test";
import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  mkdirSync,
  mkdtempSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isLinkRefusal, openBeneath } from "./open-beneath";
import { finalizeServerPath, SERVER_TREE_PLAN, secureTree } from "./permissions";

const linux = process.platform === "linux";
const dirs: string[] = [];

function layout(): { root: string; server: string; secret: string } {
  const base = mkdtempSync(join(tmpdir(), "tegrad-beneath-"));
  dirs.push(base);
  const root = join(base, "servers");
  const server = join(root, "srv");
  const secret = join(base, "state");
  mkdirSync(join(server, "real"), { recursive: true });
  mkdirSync(secret);
  writeFileSync(join(secret, "identity.json"), "secret");
  chmodSync(join(secret, "identity.json"), 0o600);
  writeFileSync(join(secret, "console.log"), "secret");
  chmodSync(join(secret, "console.log"), 0o600);
  // The server swapped its logs folder for a link to the agent's state.
  symlinkSync(secret, join(server, "logs"));
  return { root, server, secret };
}

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe.skipIf(!linux)("openBeneath", () => {
  test("refuses a link in an intermediate folder", () => {
    const { root, server } = layout();
    let error: unknown;
    try {
      closeSync(openBeneath(root, join(server, "logs", "console.log"), fsConstants.O_RDONLY));
    } catch (err) {
      error = err;
    }
    expect(isLinkRefusal(error)).toBe(true);
  });

  test("opens a regular path under the root", () => {
    const { root, server } = layout();
    writeFileSync(join(server, "real", "a.txt"), "a");
    closeSync(openBeneath(root, join(server, "real", "a.txt"), fsConstants.O_RDONLY));
  });
});

describe.skipIf(!linux)("permission changes never leave the server folder", () => {
  const gid = process.getgid?.() ?? 0;

  test("finalizeServerPath ignores a target reached through a linked folder", () => {
    const { root, server, secret } = layout();
    finalizeServerPath(join(server, "logs", "console.log"), 0o660, { gid, serversRoot: root });
    expect(statSync(join(secret, "console.log")).mode & 0o777).toBe(0o600);
  });

  test("secureTree does not walk into a linked folder", () => {
    const { root, server, secret } = layout();
    writeFileSync(join(server, "real", "a.txt"), "a");
    chmodSync(join(server, "real", "a.txt"), 0o600);
    secureTree(server, SERVER_TREE_PLAN, { gid, serversRoot: root });
    expect(statSync(join(server, "real", "a.txt")).mode & 0o777).toBe(0o660);
    expect(statSync(join(secret, "identity.json")).mode & 0o777).toBe(0o600);
    expect(statSync(join(secret, "console.log")).mode & 0o777).toBe(0o600);
  });

  test("secureTree on a path whose parent is a link changes nothing", () => {
    const { root, server, secret } = layout();
    secureTree(join(server, "logs"), SERVER_TREE_PLAN, { gid, serversRoot: root });
    expect(statSync(secret).mode & 0o777).not.toBe(0o770);
    expect(statSync(join(secret, "identity.json")).mode & 0o777).toBe(0o600);
  });
});
