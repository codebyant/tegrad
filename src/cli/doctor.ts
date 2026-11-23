// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { getStatePaths, type RunFixedResult, resolveStateDir, runFixed } from "../agent";
import type { PublicKey } from "../crypto";
import { NETWORK_DENY_RANGES } from "../install/units";
import {
  inspectServersRoot,
  inspectTree,
  type PermissionProblem,
  SERVER_GROUP_NAME,
  SERVER_TREE_PLAN,
  SHARED_TREE_PLAN,
} from "../server/permissions";
import { getReleasePublicKey, isPlaceholderReleaseKey } from "../update";

export const NETWORK_ISOLATION_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

export const networkIsolationRecordSchema = z
  .object({
    checked_at: z.union([z.string().min(1), z.number().int().nonnegative()]),
    effective: z.boolean().nullable(),
  })
  .strict();

export type NetworkIsolationRecord = z.infer<typeof networkIsolationRecordSchema>;

export type DoctorCheckStatus = "OK" | "WARN" | "INCONCLUSIVO" | "FALHA";

export interface DoctorCheckResult {
  readonly name: string;
  readonly ok: boolean;
  readonly status?: DoctorCheckStatus;
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
  readonly permsServicePath: string;
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
  permsServicePath: "/etc/systemd/system/tegrad-perms@.service",
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
  /** Directory that holds the server folders (defaults to TEGRAD_SERVERS_DIR or /var/lib/tegrad-servers). */
  readonly serversDir?: string;
  /** Replaces the file-system walk of the server-permission check (tests). */
  readonly inspectServers?: (
    serversDir: string,
    serverGid: number | null,
  ) => readonly PermissionProblem[];
  /** Override embedded release public key (tests). */
  readonly releasePublicKey?: PublicKey;
  /** Override current timestamp in ms (tests). */
  readonly now?: () => number;
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

function polkitRuleAllowsPermsUnit(content: string): boolean {
  const regexMatches = content.matchAll(/\/([^/\r\n]+)\/\.test\(/g);
  for (const match of regexMatches) {
    const pattern = match[1];
    if (pattern === undefined) continue;
    try {
      const re = new RegExp(pattern);
      if (
        re.test("tegrad-perms@test.service") &&
        !re.test("tegrad-perms@test.socket") &&
        !re.test("sshd.service")
      ) {
        return true;
      }
    } catch {
      // Ignore malformed regex literal
    }
  }
  return false;
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

function parseCheckedAtMs(value: string | number): number | null {
  if (typeof value === "number") {
    return Number.isSafeInteger(value) && value >= 0 ? value : null;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

export function checkNetworkIsolationStatus(
  filePath: string,
  exists: (p: string) => boolean,
  readText: (p: string) => string,
  nowMs: number,
): DoctorCheckResult {
  if (!exists(filePath)) {
    return {
      name: "network_isolation",
      ok: false,
      status: "INCONCLUSIVO",
      detail: `${filePath} not found (never tested; run install.sh to verify cgroup BPF IPAddressDeny enforcement)`,
    };
  }

  let rawJson: unknown;
  try {
    rawJson = JSON.parse(readText(filePath)) as unknown;
  } catch {
    return {
      name: "network_isolation",
      ok: false,
      status: "INCONCLUSIVO",
      detail: `${filePath} could not be read or is not valid JSON (re-run install.sh)`,
    };
  }

  const parsed = networkIsolationRecordSchema.safeParse(rawJson);
  if (!parsed.success) {
    return {
      name: "network_isolation",
      ok: false,
      status: "INCONCLUSIVO",
      detail: `${filePath} has an unexpected format (re-run install.sh)`,
    };
  }

  const checkedAtMs = parseCheckedAtMs(parsed.data.checked_at);
  if (checkedAtMs === null) {
    return {
      name: "network_isolation",
      ok: false,
      status: "INCONCLUSIVO",
      detail: `${filePath} has an invalid checked_at timestamp (re-run install.sh)`,
    };
  }

  if (parsed.data.effective === null) {
    return {
      name: "network_isolation",
      ok: false,
      status: "INCONCLUSIVO",
      detail:
        "network isolation self-test was skipped during installation (re-run install.sh with python3 or nc available)",
    };
  }

  const ageMs = nowMs - checkedAtMs;
  if (ageMs > NETWORK_ISOLATION_MAX_AGE_MS) {
    return {
      name: "network_isolation",
      ok: false,
      status: "INCONCLUSIVO",
      detail: `last network isolation check is older than 30 days (${new Date(checkedAtMs).toISOString()}); re-run install.sh to refresh`,
    };
  }

  if (!parsed.data.effective) {
    return {
      name: "network_isolation",
      ok: false,
      status: "FALHA",
      detail:
        "systemd IPAddressDeny is NOT effective on this kernel/container (cgroup BPF unavailable, e.g. LXC); servers can reach private networks",
    };
  }

  return {
    name: "network_isolation",
    ok: true,
    status: "OK",
    detail: `systemd IPAddressDeny verified effective (checked ${new Date(checkedAtMs).toISOString()})`,
  };
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
    statePaths.membersPath,
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
    { label: "unit_perms_service", path: paths.permsServicePath },
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

  // 4b. Polkit rule permits tegrad-perms@<id>.service
  if (!exists(paths.polkitRulePath)) {
    results.push({
      name: "polkit_perms_rule",
      ok: false,
      detail: `${paths.polkitRulePath} missing`,
    });
  } else {
    try {
      const ruleContent = readText(paths.polkitRulePath);
      if (polkitRuleAllowsPermsUnit(ruleContent)) {
        results.push({
          name: "polkit_perms_rule",
          ok: true,
          detail: `${paths.polkitRulePath} allows tegrad-perms@<id>.service`,
        });
      } else {
        results.push({
          name: "polkit_perms_rule",
          ok: false,
          detail: `${paths.polkitRulePath} does not allow tegrad-perms@<id>.service`,
        });
      }
    } catch (err) {
      results.push({
        name: "polkit_perms_rule",
        ok: false,
        detail: `failed to read ${paths.polkitRulePath}: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
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

  // 8. Server files belong to the server group, with group access and setgid on the servers root
  const serversDir =
    options.serversDir ?? env.TEGRAD_SERVERS_DIR?.trim() ?? "/var/lib/tegrad-servers";
  if (!exists(serversDir)) {
    results.push({
      name: "server_permissions",
      ok: false,
      detail: `${serversDir} does not exist`,
    });
  } else {
    const serverGid = groupLoaded ? (groups.get(SERVER_GROUP_NAME)?.gid ?? null) : null;
    try {
      const inspect =
        options.inspectServers ??
        ((dir: string, gid: number | null) => {
          const found: PermissionProblem[] = [];
          found.push(...inspectServersRoot(dir, gid));
          for (const entry of readdirSync(dir, { withFileTypes: true })) {
            if (!entry.isDirectory()) continue;
            const full = join(dir, entry.name);
            const plan = entry.name === ".runtime" ? SHARED_TREE_PLAN : SERVER_TREE_PLAN;
            found.push(...inspectTree(full, plan, gid, 5));
            if (found.length >= 10) break;
          }
          return found;
        });
      const problems = inspect(serversDir, serverGid);
      if (serverGid === null) {
        results.push({
          name: "server_permissions",
          ok: false,
          detail: `group '${SERVER_GROUP_NAME}' not found; cannot check server files`,
        });
      } else if (problems.length > 0) {
        const shown = problems
          .slice(0, 5)
          .map((p) => `${p.path} (${p.problem})`)
          .join("; ");
        results.push({
          name: "server_permissions",
          ok: false,
          detail: `${problems.length} problem(s), e.g. ${shown}. The server user '${SERVER_GROUP_NAME}' may not be able to start servers`,
        });
      } else {
        results.push({
          name: "server_permissions",
          ok: true,
          detail: `server files use group '${SERVER_GROUP_NAME}' with group access and no access for others`,
        });
      }
    } catch (err) {
      results.push({
        name: "server_permissions",
        ok: false,
        detail: `failed to inspect ${serversDir}: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }

  // 9. Active network isolation result recorded by install.sh
  const now = options.now ?? (() => Date.now());
  results.push(
    checkNetworkIsolationStatus(statePaths.networkIsolationPath, exists, readText, now()),
  );

  // 10. Embedded release signing key (warn if build uses the public test key)
  const releaseKey = options.releasePublicKey ?? getReleasePublicKey();
  if (isPlaceholderReleaseKey(releaseKey)) {
    results.push({
      name: "release_key",
      ok: false,
      status: "WARN",
      detail: "binary embeds the public test release key; auto-update is disabled in this build",
    });
  } else {
    results.push({
      name: "release_key",
      ok: true,
      status: "OK",
      detail: "production release public key embedded",
    });
  }

  let hasFailure = false;
  for (const item of results) {
    const status: DoctorCheckStatus = item.status ?? (item.ok ? "OK" : "FALHA");
    if (status === "FALHA") hasFailure = true;
    stdout(`${status.padEnd(5)} ${item.name}: ${item.detail}\n`);
  }

  return hasFailure ? 1 : 0;
}
