// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { describe, expect, test } from "bun:test";
import {
  buildOriginSyncChanges,
  emptyOriginSyncState,
  isClientOnly,
  isRedistributionRestricted,
  isServerContentPath,
  modIdentityKey,
  nextOriginSyncState,
  type PlanMod,
  redistributionFromModrinthLicense,
  shouldCopyOnCreate,
  worldArchivePath,
} from "./sync-plan";

const both = { client: "required", server: "required" } as const;
const clientOnly = { client: "required", server: "unsupported" } as const;

function mod(key: string, sha1: string, overrides: Partial<PlanMod> = {}): PlanMod {
  return {
    key,
    filename: `${key}.jar`,
    enabled: true,
    name: key,
    sha1,
    environment: both,
    ...overrides,
  };
}

describe("server pack paths", () => {
  test("keeps server content and drops client and internal data", () => {
    expect(isServerContentPath("config/create.toml")).toBe(true);
    expect(isServerContentPath("kubejs/server_scripts/a.js")).toBe(true);
    expect(isServerContentPath("server.properties")).toBe(true);
    expect(isServerContentPath("options.txt")).toBe(false);
    expect(isServerContentPath("resourcepacks/pack.zip")).toBe(false);
    expect(isServerContentPath("saves/World/level.dat")).toBe(false);
    expect(isServerContentPath("mods/a.jar")).toBe(false);
    expect(isServerContentPath(".tegra/state.json")).toBe(false);
    expect(isServerContentPath(".runtime/run.pid")).toBe(false);
    expect(isServerContentPath("tegrad-server.json")).toBe(false);
    expect(isServerContentPath("latest.log")).toBe(false);
    expect(isServerContentPath("hs_err_pid123.log")).toBe(false);
  });

  test("copies saves only when asked", () => {
    expect(shouldCopyOnCreate("saves/World/level.dat", false)).toBe(false);
    expect(shouldCopyOnCreate("saves/World/level.dat", true)).toBe(true);
    expect(shouldCopyOnCreate("mods/a.jar", false)).toBe(true);
    expect(shouldCopyOnCreate("screenshots/a.png", true)).toBe(false);
  });

  test("maps a singleplayer world to the server world folder", () => {
    expect(worldArchivePath("My World", "saves/My World/region/r.0.0.mca")).toBe(
      "world/region/r.0.0.mca",
    );
    expect(worldArchivePath("My World", "saves/Other/level.dat")).toBeNull();
  });
});

describe("mod identity and licenses", () => {
  test("prefers provider id, then name, then filename", () => {
    expect(
      modIdentityKey({ filename: "a.jar", modInfo: { modId: "AANobbMI", name: "Sodium" } }),
    ).toBe("id:aanobbmi");
    expect(modIdentityKey({ filename: "a.jar", modInfo: { name: "Sodium" } })).toBe("name:sodium");
    expect(modIdentityKey({ filename: "Sodium-1.0.jar.disabled" })).toBe("file:sodium-1.0.jar");
  });

  test("treats all rights reserved as restricted and custom licenses as unknown", () => {
    expect(redistributionFromModrinthLicense("MIT").allowed).toBe(true);
    expect(isRedistributionRestricted(redistributionFromModrinthLicense("MIT"))).toBe(false);
    expect(redistributionFromModrinthLicense("LicenseRef-All-Rights-Reserved").allowed).toBe(false);
    expect(
      isRedistributionRestricted(
        redistributionFromModrinthLicense("LicenseRef-All-Rights-Reserved"),
      ),
    ).toBe(true);
    expect(redistributionFromModrinthLicense("LicenseRef-Custom").allowed).toBeNull();
    expect(redistributionFromModrinthLicense(undefined).allowed).toBeNull();
  });

  test("detects client-only environment", () => {
    expect(isClientOnly(clientOnly)).toBe(true);
    expect(isClientOnly(both)).toBe(false);
    expect(isClientOnly(null)).toBe(false);
  });
});

describe("origin 3-way sync diff", () => {
  test("adds new mods, updates changed ones, removes dropped origin mods, and preserves user mods", () => {
    const state = { ...emptyOriginSyncState(), synced_mod_keys: ["a", "b", "gone"] };
    const changes = buildOriginSyncChanges({
      sourceMods: [mod("a", "1"), mod("b", "2-new"), mod("c", "3")],
      targetMods: [mod("a", "1"), mod("b", "2-old"), mod("gone", "4"), mod("essentials", "5")],
      sourceFiles: [],
      targetFiles: [],
      state,
    });
    expect(changes.mods.map((change) => [change.key, change.kind])).toEqual([
      ["b", "updated"],
      ["c", "added"],
      ["gone", "removed"],
    ]);
  });

  test("never brings back mods the user excluded or removed locally", () => {
    const state = {
      ...emptyOriginSyncState(),
      excluded_mod_keys: ["rejected"],
      synced_mod_keys: ["deleted"],
    };
    const changes = buildOriginSyncChanges({
      sourceMods: [mod("rejected", "1"), mod("deleted", "2")],
      targetMods: [],
      sourceFiles: [],
      targetFiles: [],
      state,
    });
    expect(changes.mods).toMatchObject([
      { key: "deleted", excluded_reason: "removed_locally", selected_by_default: false },
      { key: "rejected", excluded_reason: "excluded", selected_by_default: false },
    ]);
  });

  test("flags client-only additions and ignores disabled source mods", () => {
    const changes = buildOriginSyncChanges({
      sourceMods: [
        mod("sodium", "1", { environment: clientOnly }),
        mod("off", "2", { enabled: false }),
      ],
      targetMods: [],
      sourceFiles: [],
      targetFiles: [],
      state: emptyOriginSyncState(),
    });
    expect(changes.mods).toMatchObject([
      { key: "sodium", client_only: true, selected_by_default: true },
    ]);
  });

  test("lists added, changed, and removed config files while preserving local removals and user files", () => {
    const state = {
      ...emptyOriginSyncState(),
      synced_files: ["config/a.toml", "config/b.toml", "config/dropped.toml"],
      removed_origin_files: ["config/user-deleted.toml"],
    };
    const changes = buildOriginSyncChanges({
      sourceMods: [],
      targetMods: [],
      sourceFiles: [
        { path: "config/a.toml", sha1: "1", size_bytes: 1 },
        { path: "config/b.toml", sha1: "2", size_bytes: 1 },
        { path: "config/c.toml", sha1: "3", size_bytes: 1 },
        { path: "config/user-deleted.toml", sha1: "4", size_bytes: 1 },
      ],
      targetFiles: [
        { path: "config/a.toml", sha1: "1", size_bytes: 1 },
        { path: "config/b.toml", sha1: "x", size_bytes: 1 },
        { path: "config/dropped.toml", sha1: "5", size_bytes: 1 },
        { path: "config/user-added.toml", sha1: "6", size_bytes: 1 },
      ],
      state,
    });
    expect(changes.files).toEqual([
      { path: "config/b.toml", kind: "changed", size_bytes: 1, selected_by_default: true },
      { path: "config/c.toml", kind: "added", size_bytes: 1, selected_by_default: true },
      { path: "config/dropped.toml", kind: "removed", size_bytes: 1, selected_by_default: true },
      {
        path: "config/user-deleted.toml",
        kind: "added",
        size_bytes: 1,
        excluded_reason: "removed_locally",
        selected_by_default: false,
      },
    ]);
  });

  test("records rejected additions and re-included mods in the next state", () => {
    const state = { ...emptyOriginSyncState(), excluded_mod_keys: ["back"] };
    const sourceMods = [mod("new", "1"), mod("back", "2")];
    const changes = buildOriginSyncChanges({
      sourceMods,
      targetMods: [],
      sourceFiles: [],
      targetFiles: [],
      state,
    });
    const next = nextOriginSyncState({
      state,
      modChanges: changes.mods,
      selectedModKeys: new Set(["back"]),
      sourceMods,
      versionId: "v2",
      nowIso: "2026-09-27T00:00:00.000Z",
    });
    expect(next.excluded_mod_keys).toEqual(["new"]);
    expect(next.synced_mod_keys).toEqual(["back", "new"]);
    expect(next.last_synced_version_id).toBe("v2");
  });
});
