// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { describe, expect, test } from "bun:test";
import { createLogger } from "../agent/logger";
import { ProtocolError } from "../protocol";
import { formatPermsUnit } from "./id";
import type { RunFixedLike } from "./java";
import { DEFAULT_PERMS_TIMEOUT_MS, makeServerReadable } from "./readable";

function createCaptureLogger() {
  const warnings: string[] = [];
  const logger = createLogger({
    level: "warn",
    stdout: (line) => warnings.push(line),
    stderr: (line) => warnings.push(line),
  });
  return { logger, warnings };
}

describe("makeServerReadable", () => {
  test("invokes systemctl start --wait with literal args and returns true on success", async () => {
    const calls: {
      readonly command: string;
      readonly args: readonly string[];
      readonly timeoutMs: number | undefined;
    }[] = [];

    const runFixedImpl: RunFixedLike = async (command, args, opts) => {
      calls.push({ command, args: [...args], timeoutMs: opts?.timeoutMs });
      return { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
    };

    const ok = await makeServerReadable("survival-1", { runFixedImpl });
    expect(ok).toBe(true);
    expect(calls).toEqual([
      {
        command: "systemctl",
        args: ["start", "--wait", "tegrad-perms@survival-1.service"],
        timeoutMs: DEFAULT_PERMS_TIMEOUT_MS,
      },
    ]);
    expect(formatPermsUnit("survival-1")).toBe("tegrad-perms@survival-1.service");
  });

  test("rejects invalid server IDs before running systemctl", async () => {
    let called = false;
    const runFixedImpl: RunFixedLike = async () => {
      called = true;
      return { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
    };

    for (const badId of ["", "-leading", "UPPER", "has_underscore", "../escape", "a".repeat(64)]) {
      await expect(makeServerReadable(badId, { runFixedImpl })).rejects.toMatchObject({
        name: "ProtocolError",
        code: "invalid_body",
      });
    }
    expect(called).toBe(false);
  });

  test("serializes concurrent calls for the same server and allows parallel calls across different servers", async () => {
    const events: string[] = [];
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let firstStarted!: () => void;
    const firstStartedPromise = new Promise<void>((resolve) => {
      firstStarted = resolve;
    });

    let srv1Count = 0;
    const runFixedImpl: RunFixedLike = async (_command, args) => {
      const unit = args[2] ?? "";
      if (unit === "tegrad-perms@srv-1.service") {
        srv1Count += 1;
        const idx = srv1Count;
        events.push(`start:srv-1:${idx}`);
        if (idx === 1) {
          firstStarted();
          await firstGate;
        }
        events.push(`end:srv-1:${idx}`);
      } else {
        events.push(`start:${unit}`);
        events.push(`end:${unit}`);
      }
      return { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
    };

    const p1 = makeServerReadable("srv-1", { runFixedImpl });
    await firstStartedPromise;
    const p2 = makeServerReadable("srv-1", { runFixedImpl });
    const pOther = makeServerReadable("srv-2", { runFixedImpl });

    // Different server completes while srv-1 call #1 is still running.
    await pOther;
    expect(events).toEqual([
      "start:srv-1:1",
      "start:tegrad-perms@srv-2.service",
      "end:tegrad-perms@srv-2.service",
    ]);

    releaseFirst();
    await Promise.all([p1, p2]);
    expect(events).toEqual([
      "start:srv-1:1",
      "start:tegrad-perms@srv-2.service",
      "end:tegrad-perms@srv-2.service",
      "end:srv-1:1",
      "start:srv-1:2",
      "end:srv-1:2",
    ]);
  });

  test("degrades with a warning instead of throwing when the unit or systemctl does not exist", async () => {
    const { logger, warnings } = createCaptureLogger();

    const notFoundByCode: RunFixedLike = async () => ({
      code: 5,
      stdout: "",
      stderr: "Failed to start tegrad-perms@dev.service: Unit tegrad-perms@dev.service not found.",
      timedOut: false,
      truncated: false,
    });
    expect(await makeServerReadable("dev", { runFixedImpl: notFoundByCode, logger })).toBe(false);

    const notFoundByStderr: RunFixedLike = async () => ({
      code: 1,
      stdout: "",
      stderr: "Unit tegrad-perms@dev.service could not be found.",
      timedOut: false,
      truncated: false,
    });
    expect(await makeServerReadable("dev", { runFixedImpl: notFoundByStderr, logger })).toBe(false);

    const enoentImpl: RunFixedLike = async () => {
      const err = new Error("spawn systemctl ENOENT") as NodeJS.ErrnoException;
      err.code = "ENOENT";
      throw err;
    };
    expect(await makeServerReadable("dev", { runFixedImpl: enoentImpl, logger })).toBe(false);

    // Without runFixedImpl, missing unit file on Linux or non-Linux platform degrades with warning.
    expect(
      await makeServerReadable("dev", { platform: "linux", unitExists: () => false, logger }),
    ).toBe(false);
    expect(await makeServerReadable("dev", { platform: "win32", logger })).toBe(false);

    expect(warnings.length).toBeGreaterThanOrEqual(5);
  });

  test("throws ProtocolError(perms_unavailable) on non-not-found failure or timeout, without blocking queued calls", async () => {
    let attempt = 0;
    const runFixedImpl: RunFixedLike = async () => {
      attempt += 1;
      if (attempt === 1) {
        return {
          code: 1,
          stdout: "",
          stderr: "Access denied",
          timedOut: false,
          truncated: false,
        };
      }
      if (attempt === 2) {
        return {
          code: -1,
          stdout: "",
          stderr: "",
          timedOut: true,
          truncated: false,
        };
      }
      return { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false };
    };

    const p1 = makeServerReadable("srv-err", { runFixedImpl });
    const p2 = makeServerReadable("srv-err", { runFixedImpl });
    const p3 = makeServerReadable("srv-err", { runFixedImpl });

    const [r1, r2, r3] = await Promise.allSettled([p1, p2, p3]);
    expect(r1.status).toBe("rejected");
    if (r1.status === "rejected") {
      expect(r1.reason).toBeInstanceOf(ProtocolError);
      expect((r1.reason as ProtocolError).code).toBe("perms_unavailable");
    }
    expect(r2.status).toBe("rejected");
    if (r2.status === "rejected") {
      expect(r2.reason).toBeInstanceOf(ProtocolError);
      expect((r2.reason as ProtocolError).code).toBe("perms_unavailable");
    }
    expect(r3).toEqual({ status: "fulfilled", value: true });
  });
});
