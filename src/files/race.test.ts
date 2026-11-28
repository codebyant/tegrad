// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, describe, expect, test } from "bun:test";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  renameSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { archiveServerDirectory } from "../backup/archive";
import { openDirBeneath } from "../server/open-beneath";
import { FileManager } from "./manager";
import { readZipEntryFromBuffer } from "./zip";

// Mod code runs inside the server folder and can swap any folder for a symbolic link
// at any moment, including in the middle of an agent operation. These tests run a
// separate process that keeps swapping a folder for a link to a fake agent state and
// back, while the agent repeats the operation. The state must never be read, listed,
// written or deleted.

const linux = process.platform === "linux";
const SERVER_ID = "srv-race";
const SECRET = "agent-identity-secret";
const RACE_MS = 1_500;
const roots: string[] = [];

interface Layout {
  readonly serversDir: string;
  readonly serverDir: string;
  readonly stateDir: string;
}

function layout(): Layout {
  const base = mkdtempSync(join(tmpdir(), "tegrad-race-"));
  roots.push(base);
  const serversDir = join(base, "servers");
  const serverDir = join(serversDir, SERVER_ID);
  const stateDir = join(base, "state");
  mkdirSync(serverDir, { recursive: true });
  mkdirSync(stateDir);
  writeFileSync(join(stateDir, "identity.json"), SECRET);
  return { serversDir, serverDir, stateDir };
}

const SWAPPER = `
const fs = require("node:fs");
const p = process.env.SW_PATH, real = p + ".real", target = process.env.SW_TARGET;
const end = Date.now() + Number(process.env.SW_MS);
while (Date.now() < end) {
  try { fs.renameSync(p, real); } catch {}
  try { fs.symlinkSync(target, p); } catch {}
  // Hold each state for a varying moment so some swaps span two agent calls.
  const hold = Math.random() * 40;
  for (let i = 0; i < hold; i++) fs.statSync(target);
  try { fs.unlinkSync(p); } catch {}
  try { fs.renameSync(real, p); } catch {}
  for (let i = 0; i < hold; i++) fs.statSync(target);
}
`;

/** Keeps swapping `path` (a folder) for a link to `target` until stopped. */
function startSwapper(path: string, target: string): { stop(): Promise<void> } {
  const proc = Bun.spawn([process.execPath, "-e", SWAPPER], {
    env: { ...process.env, SW_PATH: path, SW_TARGET: target, SW_MS: String(RACE_MS * 4) },
    stdout: "ignore",
    stderr: "ignore",
  });
  return {
    async stop() {
      proc.kill();
      await proc.exited;
      const st = lstatSync(path, { throwIfNoEntry: false });
      if (st?.isSymbolicLink()) unlinkSync(path);
      if (existsSync(`${path}.real`) && !existsSync(path)) renameSync(`${path}.real`, path);
    },
  };
}

async function race(
  swapPath: string,
  target: string,
  attempt: () => void | Promise<void>,
): Promise<number> {
  const swapper = startSwapper(swapPath, target);
  let attempts = 0;
  try {
    const end = Date.now() + RACE_MS;
    while (Date.now() < end) {
      attempts++;
      try {
        await attempt();
      } catch {
        // Failures (folder missing, link refused) are expected while swapping.
      }
    }
  } finally {
    await swapper.stop();
  }
  return attempts;
}

function stateUntouched(stateDir: string): void {
  expect(readdirSync(stateDir).sort()).toEqual(["identity.json"]);
}

afterEach(() => {
  for (const dir of roots.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe.skipIf(!linux)("an open folder keeps pointing at the original folder", () => {
  test("listing through the handle ignores a swap made after opening", () => {
    const { serversDir, serverDir, stateDir } = layout();
    mkdirSync(join(serverDir, "logs"));
    writeFileSync(join(serverDir, "logs", "latest.log"), "log");

    const dir = openDirBeneath(serversDir, join(serverDir, "logs"));
    try {
      renameSync(join(serverDir, "logs"), join(serverDir, "logs.moved"));
      symlinkSync(stateDir, join(serverDir, "logs"));
      expect(dir.list()).toEqual(["latest.log"]);
      expect(dir.lstatChild("identity.json")).toBeUndefined();
    } finally {
      dir.close();
    }
  });

  test("opening refuses a link at any level", () => {
    const { serversDir, serverDir, stateDir } = layout();
    symlinkSync(stateDir, join(serverDir, "logs"));
    expect(() => openDirBeneath(serversDir, join(serverDir, "logs"))).toThrow();
  });
});

describe.skipIf(!linux)("agent operations under a live folder swap", () => {
  test("A: a backup never packs the agent state", async () => {
    const { serversDir, serverDir, stateDir } = layout();
    mkdirSync(join(serverDir, "logs"));
    // Same name as the agent's file, so a single swap at the wrong moment is enough.
    writeFileSync(join(serverDir, "logs", "identity.json"), "server copy");
    let leaked = false;
    const attempts = await race(join(serverDir, "logs"), stateDir, () => {
      const result = archiveServerDirectory({ serversBaseDir: serversDir, serverId: SERVER_ID });
      const data = readZipEntryFromBuffer({
        buffer: result.buffer,
        entryName: "logs/identity.json",
      });
      if (data !== null && Buffer.from(data).toString("utf8").includes(SECRET)) leaked = true;
    });
    expect(attempts).toBeGreaterThan(10);
    expect(leaked).toBe(false);
  });

  test("B: a recursive delete never removes the agent state", async () => {
    const { serversDir, serverDir, stateDir } = layout();
    const manager = new FileManager({ serversBaseDir: serversDir, serverGroupId: null });
    const victim = join(serverDir, "victim");
    const attempts = await race(join(victim, "inner"), stateDir, () => {
      // Built through the agent itself: plain writes here would follow the swap too.
      manager.mkdir({ server_id: SERVER_ID, path: "victim/inner" });
      manager.write({ server_id: SERVER_ID, path: "victim/inner/a.txt", content: "a" });
      manager.delete({ server_id: SERVER_ID, path: "victim", recursive: true });
    });
    manager.dispose();
    expect(attempts).toBeGreaterThan(10);
    stateUntouched(stateDir);
  });

  test("B: a move never takes the agent state", async () => {
    const { serversDir, serverDir, stateDir } = layout();
    const manager = new FileManager({ serversBaseDir: serversDir, serverGroupId: null });
    mkdirSync(join(serverDir, "box"));
    const attempts = await race(join(serverDir, "box"), stateDir, () => {
      manager.write({ server_id: SERVER_ID, path: "box/identity.json", content: "mine" });
      manager.move({ server_id: SERVER_ID, from_path: "box/identity.json", to_path: "moved.json" });
      rmSync(join(serverDir, "moved.json"), { force: true });
    });
    manager.dispose();
    expect(attempts).toBeGreaterThan(10);
    stateUntouched(stateDir);
  });

  test("C: a write never lands in the agent state", async () => {
    const { serversDir, serverDir, stateDir } = layout();
    const manager = new FileManager({ serversBaseDir: serversDir, serverGroupId: null });
    mkdirSync(join(serverDir, "config"));
    const attempts = await race(join(serverDir, "config"), stateDir, () => {
      manager.write({ server_id: SERVER_ID, path: "config/planted.txt", content: "x" });
    });
    manager.dispose();
    expect(attempts).toBeGreaterThan(10);
    stateUntouched(stateDir);
  });

  test("D: a read never returns the agent state", async () => {
    const { serversDir, serverDir, stateDir } = layout();
    const manager = new FileManager({ serversBaseDir: serversDir, serverGroupId: null });
    mkdirSync(join(serverDir, "logs"));
    writeFileSync(join(serverDir, "logs", "identity.json"), "server copy");
    let leaked = false;
    const attempts = await race(join(serverDir, "logs"), stateDir, async () => {
      const result = await manager.read({ server_id: SERVER_ID, path: "logs/identity.json" });
      if (result.content.includes(SECRET)) leaked = true;
    });
    manager.dispose();
    expect(attempts).toBeGreaterThan(10);
    expect(leaked).toBe(false);
  });

  test("D: a listing never shows the agent state", async () => {
    const { serversDir, serverDir, stateDir } = layout();
    const manager = new FileManager({ serversBaseDir: serversDir, serverGroupId: null });
    mkdirSync(join(serverDir, "logs"));
    let leaked = false;
    const attempts = await race(join(serverDir, "logs"), stateDir, () => {
      const result = manager.list({ server_id: SERVER_ID, path: "logs" });
      if (result.entries.some((entry) => entry.name === "identity.json")) leaked = true;
    });
    manager.dispose();
    expect(attempts).toBeGreaterThan(10);
    expect(leaked).toBe(false);
  });
});
