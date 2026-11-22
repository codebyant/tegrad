// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { describe, expect, test } from "bun:test";
import { createLogger, resolveLogLevel } from "./logger";

describe("logger", () => {
  test("writes JSON lines to stdout for debug/info/warn and stderr for error", () => {
    const out: string[] = [];
    const err: string[] = [];
    const logger = createLogger({
      level: "debug",
      now: () => 1_700_000_000_000,
      stdout: (line) => out.push(line),
      stderr: (line) => err.push(line),
    });

    logger.debug("dbg", { step: 1 });
    logger.info("hello", { agentId: "abc" });
    logger.warn("careful");
    logger.error("boom", { code: "handler_error" });

    expect(out.length).toBe(3);
    expect(err.length).toBe(1);

    const parsedInfo = JSON.parse(out[1] ?? "") as Record<string, unknown>;
    expect(parsedInfo.ts).toBe("2023-11-14T22:13:20.000Z");
    expect(parsedInfo.level).toBe("info");
    expect(parsedInfo.msg).toBe("hello");
    expect(parsedInfo.agentId).toBe("abc");

    const parsedErr = JSON.parse(err[0] ?? "") as Record<string, unknown>;
    expect(parsedErr.level).toBe("error");
    expect(parsedErr.msg).toBe("boom");
    expect(parsedErr.code).toBe("handler_error");
  });

  test("redacts sensitive keys recursively", () => {
    const out: string[] = [];
    const logger = createLogger({
      level: "debug",
      stdout: (line) => out.push(line),
      stderr: () => {},
    });

    logger.info("auth", {
      secret: "s1",
      secret_key: "s2",
      apiKey: "s3",
      authToken: "s4",
      userPassword: "s5",
      commandPayload: "s6",
      nested: {
        private_key: "s7",
        safe: "ok",
      },
      items: [{ access_token: "s8", count: 2 }],
    });

    const line = out[0] ?? "";
    for (const leaked of ["s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"]) {
      expect(line).not.toContain(leaked);
    }

    const parsed = JSON.parse(line) as Record<string, unknown>;
    expect(parsed.secret).toBe("[redacted]");
    expect(parsed.secret_key).toBe("[redacted]");
    expect(parsed.apiKey).toBe("[redacted]");
    expect(parsed.authToken).toBe("[redacted]");
    expect(parsed.userPassword).toBe("[redacted]");
    expect(parsed.commandPayload).toBe("[redacted]");
    expect(parsed.nested).toEqual({ private_key: "[redacted]", safe: "ok" });
    expect(parsed.items).toEqual([{ access_token: "[redacted]", count: 2 }]);
  });

  test("respects TEGRAD_LOG_LEVEL filtering", () => {
    expect(resolveLogLevel({})).toBe("info");
    expect(resolveLogLevel({ TEGRAD_LOG_LEVEL: "warn" })).toBe("warn");
    expect(resolveLogLevel({ TEGRAD_LOG_LEVEL: "invalid" })).toBe("info");

    const out: string[] = [];
    const logger = createLogger({
      env: { TEGRAD_LOG_LEVEL: "warn" },
      stdout: (line) => out.push(line),
      stderr: () => {},
    });

    logger.debug("skip");
    logger.info("skip");
    logger.warn("keep");

    expect(out.length).toBe(1);
    expect(JSON.parse(out[0] ?? "").msg).toBe("keep");
  });
});
