// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { existsSync, readFileSync, statSync } from "node:fs";
import { getStatePaths, type RunFixedResult, resolveStateDir, runFixed } from "../agent";
import { NETWORK_DENY_RANGES } from "../install/units";

export interface DoctorCheckResult {
  readonly name: string;
  readonly ok: boolean;
  readonly detail: string;
}

export interface DoctorPaths {
  readonly passwdPath: string;
  readonly groupPath: string;
  readonly tegradServicePath: string;
  readonly updatePathUnitPath: string;
  readonly updateServiceUnitPath: string;
  readonly serverServicePath: string;
  readonly serverSocketPath: string;
  readonly tmpfilesPath: string;
  readonly polkitRulePath: string;
  readonly networkDropInPath: string;
}

export const DEFAULT_DOCTOR_PATHS: DoctorPaths = {
  passwdPath: "/etc/passwd",
  groupPath: "/etc/group",
  tegradServicePath: "/etc/systemd/system/tegrad.service",
  updatePathUnitPath: "/etc/systemd/system/tegrad-update.path",
  updateServiceUnitPath: "/etc/systemd/system/tegrad-update.service",
  serverServicePath: "/etc/systemd/system/tegrad-server@.service",
  serverSocketPath: "/etc/systemd/system/tegrad-server@.socket",
  tmpfilesPath: "/etc/tmpfiles.d/tegrad.conf",
  polkitRulePath: "/etc/polkit-1/rules.d/50-tegrad.rules",
  networkDropInPath: "/etc/systemd/system/tegrad-server@.service.d/10-network.conf",
};

export interface DoctorOptions {
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly platform?: NodeJS.Platform;
  readonly stateDir?: string;
  readonly paths?: Partial<DoctorPaths>;
  readonly geteuid?: () => number;
  readonly statMode?: (filePath: string) => number;
  readonly exists?: (filePath: string) => boolean;
  readonly readText?: (filePath: string) => string;
  readonly runCommand?: (
    command: string,
    args: readonly string[],
  ) => Promise<Pick<RunFixedResult, "code" | "stdout" | "stderr">>;
  readonly stdout?: (text: string) => void;
}

interface PasswdEntry {
  readonly username: string;
  readonly uid: number;
  readonly gid: number;
}

interface GroupEntry {
  readonly name: string;
  readonly gid: number;
  readonly members: readonly string[];
}

export function parseEtcPasswd(content: string): Map<string, PasswdEntry> {
  const entries = new Map<string, PasswdEntry>();
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith("#")) continue;
    const fields = trimmed.split(":");
    const username = fields[0];
    const uidStr = fields[2];
    const gidStr = fields[3];
    if (username === undefined || uidStr === undefined || gidStr === undefined) continue;
    const uid = Number(uidStr);
    const gid = Number(gidStr);
    if (!Number.isInteger(uid) || !Number.isInteger(gid)) continue;
    entries.set(username, { username, uid, gid });
  }
  return entries;
}

export function parseEtcGroup(content: string): Map<string, GroupEntry> {
  const entries = new Map<string, GroupEntry>();
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith("#")) continue;
    const fields = trimmed.split(":");
    const name = fields[0];
    const gidStr = fields[2];
    const membersField = fields[3] ?? "";
    if (name === undefined || gidStr === undefined) continue;
    const gid = Number(gidStr);
    if (!Number.isInteger(gid)) continue;
    const members = membersField
      .split(",")
      .map((m) => m.trim())
      .filter((m) => m.length > 0);
    entries.set(name, { name, gid, members });
  }
  return entries;
}

function isUserInGroup(
  username: string,
  groupName: string,
  passwd: Map<string, PasswdEntry>,
  groups: Map<string, GroupEntry>,
): boolean {
  const user = passwd.get(username);
  const group = groups.get(groupName);
  if (user === undefined || group === undefined) {
    return false;
  }
  if (user.gid === group.gid) {
    return true;
  }
  return group.members.includes(username);
}

function formatMode(mode: number): string {
  return (mode & 0o7777).toString(8).padStart(4, "0");
}

function extractIpAddressDenyTokens(content: string): Set<string> {
  const tokens = new Set<string>();
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.startsWith("#") || line.startsWith(";")) continue;
    if (line.startsWith("IPAddressDeny=")) {
      const value = line.slice("IPAddressDeny=".length).trim();
      for (const tok of value.split(/\s+/)) {
        if (tok.length > 0) {
          tokens.add(tok);
        }
      }
    }
  }
  return tokens;
}

export async function runDoctor(options: DoctorOptions = {}): Promise<number> {
  const platform = options.platform ?? process.platform;
  const stdout = options.stdout ?? ((text: string) => process.stdout.write(text));

  if (platform !== "linux") {
    stdout("tegrad doctor only applies to Linux hosts.\n");
    return 0;
  }

  const env = options.env ?? process.env;
  const stateDir = options.stateDir ?? resolveStateDir(env, platform);
  const paths: DoctorPaths = { ...DEFAULT_DOCTOR_PATHS, ...(options.paths ?? {}) };
  const exists = options.exists ?? ((p: string) => existsSync(p));
  const readText = options.readText ?? ((p: string) => readFileSync(p, "utf8"));
  const statMode = options.statMode ?? ((p: string) => statSync(p).mode);
  const geteuid = options.geteuid ?? (() => process.geteuid?.() ?? -1);
  const runCommand =
    options.runCommand ??
    ((command: string, args: readonly string[]) =>
      runFixed(command, args, { timeoutMs: 5_000, maxOutputBytes: 4096 }));

  const results: DoctorCheckResult[] = [];

  let passwd = new Map<string, PasswdEntry>();
  let groups = new Map<string, GroupEntry>();
  let passwdLoaded = false;
  let groupLoaded = false;

  try {
    passwd = parseEtcPasswd(readText(paths.passwdPath));
    passwdLoaded = true;
  } catch {
    passwdLoaded = false;
  }

  try {
    groups = parseEtcGroup(readText(paths.groupPath));
    groupLoaded = true;
  } catch {
    groupLoaded = false;
  }

  // 1. Running as tegrad (and not root)
  const euid = geteuid();
  const tegradUser = passwd.get("tegrad");
  if (euid === 0) {
    results.push({
      name: "user",
      ok: false,
      detail: "running as root (euid 0); expected user 'tegrad'",
    });
  } else if (!passwdLoaded || tegradUser === undefined) {
    results.push({
      name: "user",
      ok: false,
      detail: `user 'tegrad' not found in ${paths.passwdPath}`,
    });
  } else if (euid !== tegradUser.uid) {
    results.push({
      name: "user",
      ok: false,
      detail: `running as euid ${euid}; expected 'tegrad' (uid ${tegradUser.uid})`,
    });
  } else {
    results.push({
      name: "user",
      ok: true,
      detail: `running as tegrad (uid ${euid})`,
    });
  }

  // 2. State directory mode 0700
  if (!exists(stateDir)) {
    results.push({
      name: "state_dir",
      ok: false,
      detail: `${stateDir} does not exist`,
    });
  } else {
    try {
      const mode = statMode(stateDir) & 0o777;
      if (mode === 0o700) {
        results.push({
          name: "state_dir",
          ok: true,
          detail: `${stateDir} mode 0700`,
        });
      } else {
        results.push({
          name: "state_dir",
          ok: false,
          detail: `${stateDir} mode is ${formatMode(mode)}, expected 0700`,
        });
      }
    } catch (err) {
      results.push({
        name: "state_dir",
        ok: false,
        detail: `failed to stat ${stateDir}: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }

  // 3. Secret files mode 0600
  const statePaths = getStatePaths(stateDir);
  const secretFiles = [
    statePaths.identityPath,
    statePaths.configPath,
    statePaths.trustPath,
    statePaths.revocationsPath,
    statePaths.replayPath,
  ];
  const badSecretFiles: string[] = [];
  let checkedSecretFiles = 0;
  for (const filePath of secretFiles) {
    if (!exists(filePath)) continue;
    checkedSecretFiles++;
    try {
      const mode = statMode(filePath) & 0o777;
      if (mode !== 0o600) {
        badSecretFiles.push(`${filePath} (${formatMode(mode)})`);
      }
    } catch {
      badSecretFiles.push(`${filePath} (unreadable stat)`);
    }
  }
  if (badSecretFiles.length > 0) {
    results.push({
      name: "secret_permissions",
      ok: false,
      detail: `expected 0600, found: ${badSecretFiles.join(", ")}`,
    });
  } else {
    results.push({
      name: "secret_permissions",
      ok: true,
      detail:
        checkedSecretFiles > 0
          ? `${checkedSecretFiles} state file(s) with mode 0600`
          : "no state files present yet",
    });
  }

  // 4. Units and tmpfiles exist
  const requiredFiles: readonly { readonly label: string; readonly path: string }[] = [
    { label: "unit_tegrad", path: paths.tegradServicePath },
    { label: "unit_update_path", path: paths.updatePathUnitPath },
    { label: "unit_update_service", path: paths.updateServiceUnitPath },
    { label: "unit_server_service", path: paths.serverServicePath },
    { label: "unit_server_socket", path: paths.serverSocketPath },
    { label: "tmpfiles", path: paths.tmpfilesPath },
    { label: "polkit_rule", path: paths.polkitRulePath },
  ];
  for (const item of requiredFiles) {
    const present = exists(item.path);
    results.push({
      name: item.label,
      ok: present,
      detail: present ? `${item.path} present` : `${item.path} missing`,
    });
  }

  // 5. Network drop-in exists and contains all expected IPAddressDeny ranges
  if (!exists(paths.networkDropInPath)) {
    results.push({
      name: "network_dropin",
      ok: false,
      detail: `${paths.networkDropInPath} missing`,
    });
  } else {
    try {
      const content = readText(paths.networkDropInPath);
      const denyTokens = extractIpAddressDenyTokens(content);
      const missingRanges = NETWORK_DENY_RANGES.filter((range) => !denyTokens.has(range));
      if (missingRanges.length > 0) {
        results.push({
          name: "network_dropin",
          ok: false,
          detail: `${paths.networkDropInPath} missing IPAddressDeny ranges: ${missingRanges.join(", ")}`,
        });
      } else {
        results.push({
          name: "network_dropin",
          ok: true,
          detail: `${paths.networkDropInPath} denies all private/loopback ranges`,
        });
      }
    } catch (err) {
      results.push({
        name: "network_dropin",
        ok: false,
        detail: `failed to read ${paths.networkDropInPath}: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }

  // 6. Group membership isolation: tegrad-srv NOT in tegrad; tegrad IN tegrad-srv
  if (!passwdLoaded || !groupLoaded) {
    results.push({
      name: "group_isolation",
      ok: false,
      detail: `could not read ${paths.passwdPath} or ${paths.groupPath}`,
    });
    results.push({
      name: "group_membership",
      ok: false,
      detail: `could not read ${paths.passwdPath} or ${paths.groupPath}`,
    });
  } else {
    const srvExists = passwd.has("tegrad-srv");
    const srvInTegrad = isUserInGroup("tegrad-srv", "tegrad", passwd, groups);
    if (!srvExists) {
      results.push({
        name: "group_isolation",
        ok: false,
        detail: `user 'tegrad-srv' not found in ${paths.passwdPath}`,
      });
    } else if (srvInTegrad) {
      results.push({
        name: "group_isolation",
        ok: false,
        detail: "user 'tegrad-srv' must NOT be a member of group 'tegrad'",
      });
    } else {
      results.push({
        name: "group_isolation",
        ok: true,
        detail: "user 'tegrad-srv' is not in group 'tegrad'",
      });
    }

    const tegradInSrv = isUserInGroup("tegrad", "tegrad-srv", passwd, groups);
    if (tegradInSrv) {
      results.push({
        name: "group_membership",
        ok: true,
        detail: "user 'tegrad' is in group 'tegrad-srv'",
      });
    } else {
      results.push({
        name: "group_membership",
        ok: false,
        detail: "user 'tegrad' must be a member of group 'tegrad-srv'",
      });
    }
  }

  // 7. systemd unit status via runFixed (literal arguments only)
  try {
    const res = await runCommand("systemctl", ["is-active", "tegrad.service"]);
    const statusText = res.stdout.trim() || res.stderr.trim() || `exit ${res.code}`;
    results.push({
      name: "systemd_service",
      ok: res.code === 0 && statusText === "active",
      detail: `tegrad.service is ${statusText}`,
    });
  } catch (err) {
    results.push({
      name: "systemd_service",
      ok: false,
      detail: `failed to query systemctl: ${err instanceof Error ? err.message : String(err)}`,
    });
  }

  let allOk = true;
  for (const item of results) {
    const tag = item.ok ? "OK" : "FALHA";
    if (!item.ok) allOk = false;
    stdout(`${tag.padEnd(5)} ${item.name}: ${item.detail}\n`);
  }

  return allOk ? 0 : 1;
}
