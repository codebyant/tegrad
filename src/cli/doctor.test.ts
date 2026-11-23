// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { describe, expect, test } from "bun:test";
import { getStatePaths } from "../agent";
import { renderNetworkDropIn } from "../install/units";
import { DEFAULT_DOCTOR_PATHS, type DoctorOptions, runDoctor } from "./doctor";

const VALID_PASSWD = [
  "root:x:0:0:root:/root:/bin/bash",
  "tegrad:x:991:991::/var/lib/tegrad:/usr/sbin/nologin",
  "tegrad-srv:x:992:992::/nonexistent:/usr/sbin/nologin",
].join("\n");

const VALID_GROUP = ["root:x:0:", "tegrad:x:991:", "tegrad-srv:x:992:tegrad"].join("\n");

const VALID_DROPIN = renderNetworkDropIn({ resolvers: ["127.0.0.53"] });

const VALID_POLKIT_RULE = [
  "polkit.addRule(function(action, subject) {",
  '  if (action.id === "org.freedesktop.systemd1.manage-units" && subject.user === "tegrad") {',
  '    var unit = action.lookup("unit");',
  '    if (typeof unit === "string" && /^(tegrad-server@[a-z0-9][a-z0-9-]{0,62}\\.(service|socket)|tegrad-perms@[a-z0-9][a-z0-9-]{0,62}\\.service)$/.test(unit)) {',
  "      return polkit.Result.YES;",
  "    }",
  "  }",
  "  return polkit.Result.NOT_HANDLED;",
  "});",
].join("\n");

function makeHealthyLinuxOptions(overrides: Partial<DoctorOptions> = {}): {
  readonly options: DoctorOptions;
  readonly getOutput: () => string;
} {
  let output = "";
  const stateDir = "/var/lib/tegrad";
  const statePaths = getStatePaths(stateDir);
  const existingFiles = new Set<string>([
    stateDir,
    statePaths.identityPath,
    statePaths.configPath,
    DEFAULT_DOCTOR_PATHS.tegradServicePath,
    DEFAULT_DOCTOR_PATHS.updatePathUnitPath,
    DEFAULT_DOCTOR_PATHS.updateServiceUnitPath,
    DEFAULT_DOCTOR_PATHS.serverServicePath,
    DEFAULT_DOCTOR_PATHS.serverSocketPath,
    DEFAULT_DOCTOR_PATHS.permsServicePath,
    DEFAULT_DOCTOR_PATHS.tmpfilesPath,
    DEFAULT_DOCTOR_PATHS.polkitRulePath,
    DEFAULT_DOCTOR_PATHS.networkDropInPath,
    "/srv/tegrad-servers",
  ]);
  const modes = new Map<string, number>([
    [stateDir, 0o40700],
    [statePaths.identityPath, 0o100600],
    [statePaths.configPath, 0o100600],
  ]);
  const texts = new Map<string, string>([
    [DEFAULT_DOCTOR_PATHS.passwdPath, VALID_PASSWD],
    [DEFAULT_DOCTOR_PATHS.groupPath, VALID_GROUP],
    [DEFAULT_DOCTOR_PATHS.polkitRulePath, VALID_POLKIT_RULE],
    [DEFAULT_DOCTOR_PATHS.networkDropInPath, VALID_DROPIN],
  ]);

  const options: DoctorOptions = {
    platform: "linux",
    stateDir,
    serversDir: "/srv/tegrad-servers",
    inspectServers: () => [],
    geteuid: () => 991,
    exists: (p) => existingFiles.has(p),
    statMode: (p) => {
      const m = modes.get(p);
      if (m === undefined) throw new Error(`ENOENT: ${p}`);
      return m;
    },
    readText: (p) => {
      const t = texts.get(p);
      if (t === undefined) throw new Error(`ENOENT: ${p}`);
      return t;
    },
    runCommand: async (command, args) => {
      if (command === "systemctl" && args[0] === "is-active" && args[1] === "tegrad.service") {
        return { code: 0, stdout: "active\n", stderr: "" };
      }
      return { code: 1, stdout: "", stderr: "unexpected command" };
    },
    stdout: (text) => {
      output += text;
    },
    ...overrides,
  };

  return { options, getOutput: () => output };
}

describe("tegrad doctor", () => {
  test("on non-Linux platforms prints notice and exits 0 without running checks", async () => {
    let output = "";
    const code = await runDoctor({
      platform: "win32",
      stdout: (t) => {
        output += t;
      },
    });
    expect(code).toBe(0);
    expect(output).toContain("Linux");
    expect(output).not.toContain("FALHA");
  });

  test("returns 0 and prints OK for all checks on a healthy Linux installation", async () => {
    const { options, getOutput } = makeHealthyLinuxOptions();
    const code = await runDoctor(options);
    expect(code).toBe(0);
    expect(getOutput()).not.toContain("FALHA");
    expect(getOutput()).toContain("OK    user:");
    expect(getOutput()).toContain("OK    state_dir:");
    expect(getOutput()).toContain("OK    secret_permissions:");
    expect(getOutput()).toContain("OK    unit_perms_service:");
    expect(getOutput()).toContain("OK    polkit_perms_rule:");
    expect(getOutput()).toContain("OK    network_dropin:");
    expect(getOutput()).toContain("OK    group_isolation:");
    expect(getOutput()).toContain("OK    group_membership:");
    expect(getOutput()).toContain("OK    systemd_service:");
    expect(getOutput()).toContain("OK    server_permissions:");
  });

  test("fails server_permissions and names the offending path when files are not usable by the server group", async () => {
    const { options, getOutput } = makeHealthyLinuxOptions({
      inspectServers: () => [
        { path: "/srv/tegrad-servers/s1/start.sh", problem: "group is 990, expected 991" },
      ],
    });
    const code = await runDoctor(options);
    expect(code).toBe(1);
    expect(getOutput()).toContain("FALHA server_permissions:");
    expect(getOutput()).toContain("/srv/tegrad-servers/s1/start.sh");
  });

  test("fails server_permissions when the servers directory is missing", async () => {
    const { options, getOutput } = makeHealthyLinuxOptions({ serversDir: "/nowhere" });
    const code = await runDoctor(options);
    expect(code).toBe(1);
    expect(getOutput()).toContain("FALHA server_permissions: /nowhere does not exist");
  });

  test("fails when running as root (euid 0)", async () => {
    const { options, getOutput } = makeHealthyLinuxOptions({ geteuid: () => 0 });
    const code = await runDoctor(options);
    expect(code).toBe(1);
    expect(getOutput()).toContain("FALHA user: running as root");
  });

  test("fails when state directory mode is not 0700", async () => {
    const { options, getOutput } = makeHealthyLinuxOptions({
      statMode: (p) => (p === "/var/lib/tegrad" ? 0o40755 : 0o100600),
    });
    const code = await runDoctor(options);
    expect(code).toBe(1);
    expect(getOutput()).toContain("FALHA state_dir:");
  });

  test("fails when a secret file mode is more permissive than 0600", async () => {
    const { options, getOutput } = makeHealthyLinuxOptions({
      statMode: (p) => {
        if (p === "/var/lib/tegrad") return 0o40700;
        if (p.endsWith("identity.json")) return 0o100644;
        return 0o100600;
      },
    });
    const code = await runDoctor(options);
    expect(code).toBe(1);
    expect(getOutput()).toContain("FALHA secret_permissions:");
  });

  test("fails when network drop-in is missing required IPAddressDeny ranges", async () => {
    const { options, getOutput } = makeHealthyLinuxOptions({
      readText: (p) => {
        if (p === DEFAULT_DOCTOR_PATHS.passwdPath) return VALID_PASSWD;
        if (p === DEFAULT_DOCTOR_PATHS.groupPath) return VALID_GROUP;
        if (p === DEFAULT_DOCTOR_PATHS.polkitRulePath) return VALID_POLKIT_RULE;
        return "[Service]\nIPAddressDeny=10.0.0.0/8\n";
      },
    });
    const code = await runDoctor(options);
    expect(code).toBe(1);
    expect(getOutput()).toContain("FALHA network_dropin:");
  });

  test("fails when tegrad-srv is in group tegrad or tegrad is not in tegrad-srv", async () => {
    const badGroup = ["root:x:0:", "tegrad:x:991:tegrad-srv", "tegrad-srv:x:992:"].join("\n");
    const { options, getOutput } = makeHealthyLinuxOptions({
      readText: (p) => {
        if (p === DEFAULT_DOCTOR_PATHS.passwdPath) return VALID_PASSWD;
        if (p === DEFAULT_DOCTOR_PATHS.groupPath) return badGroup;
        if (p === DEFAULT_DOCTOR_PATHS.polkitRulePath) return VALID_POLKIT_RULE;
        return VALID_DROPIN;
      },
    });
    const code = await runDoctor(options);
    expect(code).toBe(1);
    expect(getOutput()).toContain("FALHA group_isolation:");
    expect(getOutput()).toContain("FALHA group_membership:");
  });

  test("fails when tegrad.service is inactive", async () => {
    const { options, getOutput } = makeHealthyLinuxOptions({
      runCommand: async () => ({ code: 3, stdout: "inactive\n", stderr: "" }),
    });
    const code = await runDoctor(options);
    expect(code).toBe(1);
    expect(getOutput()).toContain("FALHA systemd_service:");
  });

  test("fails when tegrad-update.path or tegrad-update.service is missing", async () => {
    const { options, getOutput } = makeHealthyLinuxOptions({
      exists: (p) =>
        p !== DEFAULT_DOCTOR_PATHS.updatePathUnitPath &&
        p !== DEFAULT_DOCTOR_PATHS.updateServiceUnitPath,
    });
    const code = await runDoctor(options);
    expect(code).toBe(1);
    expect(getOutput()).toContain("FALHA unit_update_path:");
    expect(getOutput()).toContain("FALHA unit_update_service:");
  });

  test("fails when tegrad-perms@.service is missing or polkit rule does not allow it", async () => {
    const oldRule =
      "polkit.addRule(function(a, s) { if (/^tegrad-server@[a-z0-9][a-z0-9-]{0,62}\\.(service|socket)$/.test(unit)) return polkit.Result.YES; });";
    const { options, getOutput } = makeHealthyLinuxOptions({
      exists: (p) => p !== DEFAULT_DOCTOR_PATHS.permsServicePath,
      readText: (p) => {
        if (p === DEFAULT_DOCTOR_PATHS.passwdPath) return VALID_PASSWD;
        if (p === DEFAULT_DOCTOR_PATHS.groupPath) return VALID_GROUP;
        if (p === DEFAULT_DOCTOR_PATHS.polkitRulePath) return oldRule;
        return VALID_DROPIN;
      },
    });
    const code = await runDoctor(options);
    expect(code).toBe(1);
    expect(getOutput()).toContain("FALHA unit_perms_service:");
    expect(getOutput()).toContain("FALHA polkit_perms_rule:");
  });
});
