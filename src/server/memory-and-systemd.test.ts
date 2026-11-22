// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ProtocolError } from "../protocol";
import {
  checkMemoryForServer,
  computeMemoryMaxMb,
  getUnitStatus,
  parseMeminfo,
  parseSystemdShowOutput,
  type RunFixedLike,
  readMeminfo,
  startServerUnit,
  stopServerUnit,
} from "./index";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
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

describe("memory calculation from /proc/meminfo", () => {
  test("parses /proc/meminfo and accepts server that fits within budget", () => {
    const dir = makeTempDir("tegrad-mem-");
    const meminfoPath = join(dir, "meminfo");
    writeFileSync(
      meminfoPath,
      [
        "MemTotal:        8388608 kB", // 8192 MB
        "MemFree:         2097152 kB",
        "MemAvailable:    6291456 kB", // 6144 MB
        "Buffers:          131072 kB",
      ].join("\n"),
    );

    const info = readMeminfo(meminfoPath);
    expect(info).toEqual({ memTotalMb: 8192, memAvailableMb: 6144 });

    // Running 4096 + requested 2048 = 6144 <= 8192 - 1024 (7168), and 2048 <= 6144
    expect(() =>
      checkMemoryForServer({
        requestedMemoryMb: 2048,
        runningServersMemoryMb: 4096,
        meminfo: info,
      }),
    ).not.toThrow();
  });

  test("rejects with insufficient_memory when sum exceeds MemTotal - 1024 MB", () => {
    const info = parseMeminfo("MemTotal: 8388608 kB\nMemAvailable: 7340032 kB\n");
    // 8192 - 1024 = 7168 max; 4096 + 4096 = 8192 > 7168
    try {
      checkMemoryForServer({
        requestedMemoryMb: 4096,
        runningServersMemoryMb: 4096,
        meminfo: info,
      });
      throw new Error("Expected insufficient_memory");
    } catch (err) {
      expect(err).toBeInstanceOf(ProtocolError);
      expect((err as ProtocolError).code).toBe("insufficient_memory");
    }
  });

  test("rejects with insufficient_memory when requested memory exceeds MemAvailable", () => {
    const info = parseMeminfo("MemTotal: 16777216 kB\nMemAvailable: 1572864 kB\n");
    // Available = 1536 MB, requested = 2048 MB
    try {
      checkMemoryForServer({
        requestedMemoryMb: 2048,
        runningServersMemoryMb: 0,
        meminfo: info,
      });
      throw new Error("Expected insufficient_memory");
    } catch (err) {
      expect(err).toBeInstanceOf(ProtocolError);
      expect((err as ProtocolError).code).toBe("insufficient_memory");
    }
  });
});

describe("systemd control", () => {
  test("parses systemctl show output including [not set] and numeric MemoryCurrent", () => {
    expect(
      parseSystemdShowOutput(
        "ActiveState=active\nSubState=running\nMainPID=4242\nMemoryCurrent=1073741824\n",
      ),
    ).toEqual({
      activeState: "active",
      subState: "running",
      mainPid: 4242,
      memoryCurrentBytes: 1_073_741_824,
    });

    expect(
      parseSystemdShowOutput(
        "ActiveState=inactive\nSubState=dead\nMainPID=0\nMemoryCurrent=[not set]\n",
      ),
    ).toEqual({
      activeState: "inactive",
      subState: "dead",
      mainPid: 0,
      memoryCurrentBytes: null,
    });
  });

  test("startServerUnit calls systemctl start and set-property with MemoryMax = ceil(mem * 1.25)M", async () => {
    const calls: { cmd: string; args: readonly string[] }[] = [];
    const runFixedImpl: RunFixedLike = async (cmd, args) => {
      calls.push({ cmd, args });
      return { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
    };

    expect(computeMemoryMaxMb(2048)).toBe(2560);
    expect(computeMemoryMaxMb(1500)).toBe(1875);

    await startServerUnit("srv-1", 2048, { runFixedImpl });

    expect(calls).toEqual([
      { cmd: "systemctl", args: ["start", "tegrad-server@srv-1.service"] },
      {
        cmd: "systemctl",
        args: ["set-property", "--runtime", "tegrad-server@srv-1.service", "MemoryMax=2560M"],
      },
    ]);
  });

  test("stopServerUnit sends 'stop' to FIFO, waits for inactive, and stops socket", async () => {
    const fifoWrites: { path: string; data: string }[] = [];
    const calls: { cmd: string; args: readonly string[] }[] = [];
    let pollCount = 0;
    let fakeNow = 1000;

    const runFixedImpl: RunFixedLike = async (cmd, args) => {
      calls.push({ cmd, args });
      if (args[0] === "show") {
        pollCount++;
        const state = pollCount >= 2 ? "inactive" : "active";
        return {
          code: 0,
          stdout: `ActiveState=${state}\nSubState=dead\nMainPID=0\nMemoryCurrent=[not set]\n`,
          stderr: "",
          timedOut: false,
          truncated: false,
        };
      }
      return { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
    };

    const status = await stopServerUnit("srv-1", {
      runDir: "/run/tegrad-server",
      runFixedImpl,
      writeFifoImpl: (path, data) => fifoWrites.push({ path, data }),
      pollIntervalMs: 10,
      stopTimeoutMs: 500,
      now: () => fakeNow,
      sleepImpl: async (ms) => {
        fakeNow += ms;
      },
    });

    expect(fifoWrites).toHaveLength(1);
    expect(fifoWrites[0]?.data).toBe("stop\n");
    expect(status.activeState).toBe("inactive");
    expect(calls[calls.length - 1]).toEqual({
      cmd: "systemctl",
      args: ["stop", "tegrad-server@srv-1.socket"],
    });
  });

  test("stopServerUnit falls back to systemctl stop when timeout elapses", async () => {
    const calls: { cmd: string; args: readonly string[] }[] = [];
    let forcedStopped = false;
    let fakeNow = 0;

    const runFixedImpl: RunFixedLike = async (cmd, args) => {
      calls.push({ cmd, args });
      if (args[0] === "stop" && args[1] === "tegrad-server@srv-1.service") {
        forcedStopped = true;
      }
      if (args[0] === "show") {
        return {
          code: 0,
          stdout: `ActiveState=${forcedStopped ? "inactive" : "active"}\nSubState=running\nMainPID=100\nMemoryCurrent=1000\n`,
          stderr: "",
          timedOut: false,
          truncated: false,
        };
      }
      return { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
    };

    const finalStatus = await stopServerUnit("srv-1", {
      runDir: "/run/tegrad-server",
      runFixedImpl,
      writeFifoImpl: () => {
        throw new ProtocolError("server_stopped", "no reader");
      },
      pollIntervalMs: 50,
      stopTimeoutMs: 100,
      now: () => fakeNow,
      sleepImpl: async (ms) => {
        fakeNow += ms;
      },
    });

    expect(finalStatus.activeState).toBe("inactive");
    expect(
      calls.some((c) => c.args[0] === "stop" && c.args[1] === "tegrad-server@srv-1.service"),
    ).toBe(true);
    expect(
      calls.some((c) => c.args[0] === "stop" && c.args[1] === "tegrad-server@srv-1.socket"),
    ).toBe(true);
  });

  test("getUnitStatus validates server_id before calling systemctl", async () => {
    let called = false;
    const runFixedImpl: RunFixedLike = async () => {
      called = true;
      return { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
    };

    try {
      await getUnitStatus("../bad", runFixedImpl);
      throw new Error("Expected invalid_body");
    } catch (err) {
      expect(err).toBeInstanceOf(ProtocolError);
      expect((err as ProtocolError).code).toBe("invalid_body");
    }
    expect(called).toBe(false);
  });
});
