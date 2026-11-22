// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { describe, expect, test } from "bun:test";
import {
  channelFromTag,
  compareVersions,
  formatNightlyTag,
  parseReleaseTag,
  parseVersion,
  shouldUpdate,
  tryParseVersion,
  UpdateError,
} from "./index";

describe("channels and version parsing", () => {
  test("derives stable, beta, and nightly channels from valid tags and versions", () => {
    expect(channelFromTag("v1.0.0")).toBe("stable");
    expect(channelFromTag("1.0.0")).toBe("stable");
    expect(channelFromTag("v0.2.0-beta.1")).toBe("beta");
    expect(channelFromTag("0.2.0-beta.12")).toBe("beta");
    expect(channelFromTag("v0.2.0-nightly.202611220600")).toBe("nightly");
    expect(channelFromTag("0.2.0-nightly.202611220600")).toBe("nightly");

    const parsed = parseReleaseTag("v0.2.0-nightly.202611220600");
    expect(parsed).toEqual({
      raw: "0.2.0-nightly.202611220600",
      tag: "v0.2.0-nightly.202611220600",
      major: 0,
      minor: 2,
      patch: 0,
      channel: "nightly",
      prereleaseNumber: 202611220600,
      nightlyTimestamp: "202611220600",
    });
  });

  test("rejects malformed or unsupported tag/version formats", () => {
    const invalidInputs = [
      "",
      "v1.0",
      "v1.0.0.0",
      "v01.0.0",
      "v1.0.0-alpha.1",
      "v1.0.0-rc.1",
      "v1.0.0-beta",
      "v1.0.0-beta.01",
      "v1.0.0-beta.-1",
      "v1.0.0-nightly.20261122",
      "v1.0.0-nightly.202613010600",
      "v1.0.0-nightly.202602300600",
      "v1.0.0-nightly.202611222500",
      "v1.0.0+build.1",
      "latest",
      "../v1.0.0",
      "v1.0.0;rm -rf /",
    ];

    for (const bad of invalidInputs) {
      expect(() => parseVersion(bad)).toThrow(UpdateError);
      expect(tryParseVersion(bad)).toBeNull();
    }

    expect(() => parseReleaseTag("1.0.0")).toThrow(UpdateError);
  });

  test("compares versions with strict semver and prerelease precedence", () => {
    expect(compareVersions("0.2.0", "0.1.9")).toBe(1);
    expect(compareVersions("1.0.0", "0.99.99")).toBe(1);
    expect(compareVersions("0.2.0", "0.2.0")).toBe(0);
    expect(compareVersions("0.2.0", "v0.2.0")).toBe(0);

    // Same base: stable > nightly > beta
    expect(compareVersions("0.2.0", "0.2.0-nightly.202611220600")).toBe(1);
    expect(compareVersions("0.2.0-nightly.202611220600", "0.2.0-beta.99")).toBe(1);
    expect(compareVersions("0.2.0", "0.2.0-beta.1")).toBe(1);
    expect(compareVersions("0.2.0-beta.1", "0.2.0")).toBe(-1);

    // Within beta: numeric ordering (beta.10 > beta.2)
    expect(compareVersions("0.2.0-beta.10", "0.2.0-beta.2")).toBe(1);
    expect(compareVersions("0.2.0-beta.2", "0.2.0-beta.10")).toBe(-1);

    // Within nightly: chronological UTC timestamp ordering
    expect(compareVersions("0.2.0-nightly.202611230600", "0.2.0-nightly.202611220600")).toBe(1);
    expect(compareVersions("0.2.0-nightly.202611220600", "0.2.0-nightly.202611230600")).toBe(-1);
  });

  test("shouldUpdate blocks downgrades by default and permits them only when allowDowngrade is true", () => {
    expect(shouldUpdate("0.1.0", "0.2.0")).toBe(true);
    expect(shouldUpdate("0.2.0-beta.1", "0.2.0")).toBe(true);
    expect(shouldUpdate("0.2.0", "0.2.0")).toBe(false);
    expect(shouldUpdate("0.2.0", "0.2.0", { allowDowngrade: true })).toBe(false);

    // Downgrade blocked by default
    expect(shouldUpdate("0.2.0", "0.1.9")).toBe(false);
    expect(shouldUpdate("0.2.0-nightly.202611220600", "0.2.0-beta.1")).toBe(false);
    expect(shouldUpdate("0.2.0", "0.2.0-beta.1")).toBe(false);

    // Explicitly requested channel switch / downgrade
    expect(shouldUpdate("0.2.0", "0.1.9", { allowDowngrade: true })).toBe(true);
    expect(
      shouldUpdate("0.2.0-nightly.202611220600", "0.2.0-beta.1", { allowDowngrade: true }),
    ).toBe(true);
  });

  test("formatNightlyTag emits UTC YYYYMMDDHHmm tag", () => {
    const dt = new Date(Date.UTC(2026, 10, 22, 6, 5, 30));
    expect(formatNightlyTag("0.2.0-beta.1", dt)).toBe("v0.2.0-nightly.202611220605");
  });
});
