// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { describe, expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  isPrivateOrLoopbackIp,
  NETWORK_DENY_RANGES,
  parseCidr,
  parseIpAddress,
  parseResolvConf,
  renderNetworkDropIn,
} from "./units";

const REPO_ROOT = resolve(import.meta.dir, "../..");
const INSTALL_DIR = join(REPO_ROOT, "install");

function readInstallFile(relPath: string): string {
  return readFileSync(join(INSTALL_DIR, relPath), "utf8");
}

function parseIniDirectives(content: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith("#") || line.startsWith(";") || line.startsWith("[")) {
      continue;
    }
    const eq = line.indexOf("=");
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    const val = line.slice(eq + 1).trim();
    const existing = map.get(key) ?? [];
    existing.push(val);
    map.set(key, existing);
  }
  return map;
}

function findPosixSh(): string | null {
  if (process.platform !== "win32") {
    return Bun.which("sh") ?? (existsSync("/bin/sh") ? "/bin/sh" : null);
  }
  const onPath = Bun.which("sh");
  if (onPath) return onPath;
  const gitSh = "C:\\Program Files\\Git\\bin\\sh.exe";
  if (existsSync(gitSh)) return gitSh;
  return null;
}

describe("IP and CIDR parsing / network drop-in rendering", () => {
  test("parseIpAddress accepts valid IPv4 and IPv6 and rejects invalid inputs", () => {
    expect(parseIpAddress("127.0.0.53")).toEqual({ version: 4, address: "127.0.0.53" });
    expect(parseIpAddress("192.168.1.1")).toEqual({ version: 4, address: "192.168.1.1" });
    expect(parseIpAddress("0.0.0.0")).toEqual({ version: 4, address: "0.0.0.0" });
    expect(parseIpAddress("255.255.255.255")).toEqual({ version: 4, address: "255.255.255.255" });
    expect(parseIpAddress("::1")).toEqual({ version: 6, address: "::1" });
    expect(parseIpAddress("fe80::1")).toEqual({ version: 6, address: "fe80::1" });
    expect(parseIpAddress("fd12:3456:789a::1")).toEqual({
      version: 6,
      address: "fd12:3456:789a::1",
    });
    expect(parseIpAddress("2001:4860:4860::8888")).toEqual({
      version: 6,
      address: "2001:4860:4860::8888",
    });
    expect(parseIpAddress("2001:0db8:0000:0000:0000:ff00:0042:8329")).toEqual({
      version: 6,
      address: "2001:0db8:0000:0000:0000:ff00:0042:8329",
    });

    // Invalid inputs
    expect(parseIpAddress("")).toBeNull();
    expect(parseIpAddress("256.0.0.1")).toBeNull();
    expect(parseIpAddress("192.168.01.1")).toBeNull();
    expect(parseIpAddress("1.2.3")).toBeNull();
    expect(parseIpAddress("1.2.3.4.5")).toBeNull();
    expect(parseIpAddress("fe80::1%eth0")).toBeNull();
    expect(parseIpAddress("1::2::3")).toBeNull();
    expect(parseIpAddress(":::1")).toBeNull();
    expect(parseIpAddress("192.168.1.1;rm -rf /")).toBeNull();
  });

  test("parseCidr accepts valid IPv4/IPv6 CIDRs and rejects invalid ones", () => {
    expect(parseCidr("192.168.1.0/24")).toEqual({
      version: 4,
      address: "192.168.1.0",
      prefix: 24,
      cidr: "192.168.1.0/24",
    });
    expect(parseCidr("10.0.0.0/8")).toEqual({
      version: 4,
      address: "10.0.0.0",
      prefix: 8,
      cidr: "10.0.0.0/8",
    });
    expect(parseCidr("fd00::/8")).toEqual({
      version: 6,
      address: "fd00::",
      prefix: 8,
      cidr: "fd00::/8",
    });
    expect(parseCidr("::1/128")).toEqual({
      version: 6,
      address: "::1",
      prefix: 128,
      cidr: "::1/128",
    });

    expect(parseCidr("192.168.1.0")).toBeNull();
    expect(parseCidr("192.168.1.0/33")).toBeNull();
    expect(parseCidr("192.168.1.0/08")).toBeNull();
    expect(parseCidr("fd00::/129")).toBeNull();
    expect(parseCidr("192.168.1.0/24/1")).toBeNull();
    expect(parseCidr("not-an-ip/24")).toBeNull();
  });

  test("isPrivateOrLoopbackIp classifies private, loopback, CGNAT, and public IPs accurately", () => {
    expect(isPrivateOrLoopbackIp("10.0.0.1")).toBe(true);
    expect(isPrivateOrLoopbackIp("172.16.0.1")).toBe(true);
    expect(isPrivateOrLoopbackIp("172.31.255.254")).toBe(true);
    expect(isPrivateOrLoopbackIp("172.15.0.1")).toBe(false);
    expect(isPrivateOrLoopbackIp("172.32.0.1")).toBe(false);
    expect(isPrivateOrLoopbackIp("192.168.1.1")).toBe(true);
    expect(isPrivateOrLoopbackIp("169.254.169.254")).toBe(true);
    expect(isPrivateOrLoopbackIp("100.64.0.1")).toBe(true);
    expect(isPrivateOrLoopbackIp("100.127.255.254")).toBe(true);
    expect(isPrivateOrLoopbackIp("100.128.0.1")).toBe(false);
    expect(isPrivateOrLoopbackIp("127.0.0.53")).toBe(true);
    expect(isPrivateOrLoopbackIp("1.1.1.1")).toBe(false);
    expect(isPrivateOrLoopbackIp("8.8.8.8")).toBe(false);

    expect(isPrivateOrLoopbackIp("::1")).toBe(true);
    expect(isPrivateOrLoopbackIp("0:0:0:0:0:0:0:1")).toBe(true);
    expect(isPrivateOrLoopbackIp("fc00::1")).toBe(true);
    expect(isPrivateOrLoopbackIp("fd12::1")).toBe(true);
    expect(isPrivateOrLoopbackIp("fe80::1")).toBe(true);
    expect(isPrivateOrLoopbackIp("febf::1")).toBe(true);
    expect(isPrivateOrLoopbackIp("fec0::1")).toBe(false);
    expect(isPrivateOrLoopbackIp("2606:4700:4700::1111")).toBe(false);
  });

  test("parseResolvConf extracts valid nameservers and discards malformed lines", () => {
    const sample = [
      "# comment",
      "search lan.local",
      "nameserver 127.0.0.53",
      "nameserver\t192.168.1.1 # router",
      "nameserver not-an-ip",
      "nameserver 192.168.01.1",
      "nameserver fe80::1%eth0",
      "nameserver fd00::53 ; inline comment",
      "nameserver 1.1.1.1",
      "options edns0 trust-ad",
    ].join("\n");

    expect(parseResolvConf(sample)).toEqual(["127.0.0.53", "192.168.1.1", "fd00::53", "1.1.1.1"]);
  });

  test("renderNetworkDropIn omits IPAddressAllow when only public resolvers are given", () => {
    const out = renderNetworkDropIn({ resolvers: ["1.1.1.1", "8.8.8.8"] });
    expect(out).toContain(`IPAddressDeny=${NETWORK_DENY_RANGES.join(" ")}`);
    expect(out).not.toContain("IPAddressAllow=");
  });

  test("renderNetworkDropIn includes private resolvers and allowLan CIDRs deduplicated", () => {
    const out = renderNetworkDropIn({
      resolvers: ["127.0.0.53", "192.168.1.1", "1.1.1.1", "127.0.0.53", "fd00::1"],
      allowLan: ["192.168.1.0/24", "192.168.1.0/24", "fd00::/8"],
    });
    expect(out).toContain(
      "IPAddressAllow=127.0.0.53 192.168.1.1 fd00::1 192.168.1.0/24 fd00::/8\n",
    );
  });

  test("renderNetworkDropIn rejects invalid resolver or allowLan entries", () => {
    expect(() => renderNetworkDropIn({ resolvers: ["bad-ip"] })).toThrow();
    expect(() => renderNetworkDropIn({ allowLan: ["192.168.1.0"] })).toThrow();
  });
});

describe("install/install.sh parity with renderNetworkDropIn", () => {
  const shPath = findPosixSh();
  const parityTest = shPath !== null ? test : test.skip;

  parityTest(
    "shell render_network_dropin matches TypeScript output on representative cases",
    async () => {
      if (shPath === null) return;
      const scriptPath = join(INSTALL_DIR, "install.sh").replace(/\\/g, "/");

      const cases: readonly { readonly resolvers: string[]; readonly allowLan: string[] }[] = [
        { resolvers: [], allowLan: [] },
        { resolvers: ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"], allowLan: [] },
        { resolvers: ["127.0.0.53", "192.168.1.1", "1.1.1.1"], allowLan: [] },
        {
          resolvers: ["127.0.0.53", "10.0.0.2", "fe80::1", "::1", "10.0.0.2"],
          allowLan: ["192.168.10.0/24", "fd00::/8"],
        },
      ];

      for (const c of cases) {
        const expected = renderNetworkDropIn(c);
        const proc = Bun.spawn(
          [
            shPath,
            "-c",
            'TEGRAD_INSTALL_SOURCE_ONLY=1 . "$1" && render_network_dropin "$2" "$3"',
            "--",
            scriptPath,
            c.resolvers.join(" "),
            c.allowLan.join(" "),
          ],
          {
            stdin: "ignore",
            stdout: "pipe",
            stderr: "pipe",
          },
        );
        const [stdout, stderr, code] = await Promise.all([
          new Response(proc.stdout).text(),
          new Response(proc.stderr).text(),
          proc.exited,
        ]);
        expect(stderr).toBe("");
        expect(code).toBe(0);
        expect(stdout.replace(/\r\n/g, "\n")).toBe(expected);
      }
    },
  );
});

describe("Security regression checks on install/ assets", () => {
  test("tegrad.service enforces unprivileged user and sandbox directives", () => {
    const content = readInstallFile("units/tegrad.service");
    const directives = parseIniDirectives(content);

    expect(directives.get("User")).toEqual(["tegrad"]);
    expect(directives.get("User")).not.toContain("root");
    expect(directives.get("Group")).toEqual(["tegrad"]);
    expect(directives.get("NoNewPrivileges")).toEqual(["yes"]);
    expect(directives.get("ProtectSystem")).toEqual(["strict"]);
    expect(directives.get("ProtectHome")).toEqual(["yes"]);
    expect(directives.get("PrivateTmp")).toEqual(["yes"]);
    expect(directives.get("PrivateDevices")).toEqual(["yes"]);
    expect(directives.get("ProtectKernelTunables")).toEqual(["yes"]);
    expect(directives.get("ProtectKernelModules")).toEqual(["yes"]);
    expect(directives.get("ProtectControlGroups")).toEqual(["yes"]);
    expect(directives.get("RestrictSUIDSGID")).toEqual(["yes"]);
    expect(directives.get("RestrictNamespaces")).toEqual(["yes"]);
    expect(directives.get("LockPersonality")).toEqual(["yes"]);
    expect(directives.get("CapabilityBoundingSet")).toEqual([""]);
    expect(directives.get("SystemCallArchitectures")).toEqual(["native"]);
    expect(directives.get("UMask")).toEqual(["0077"]);
    expect(directives.get("RestrictAddressFamilies")?.[0]).toContain("AF_UNIX");
  });

  test("tegrad-server@.service isolates untrusted Minecraft servers without breaking JVM or networking", () => {
    const content = readInstallFile("units/tegrad-server@.service");
    const directives = parseIniDirectives(content);

    expect(directives.get("User")).toEqual(["tegrad-srv"]);
    expect(directives.get("Group")).toEqual(["tegrad-srv"]);
    expect(directives.get("NoNewPrivileges")).toEqual(["yes"]);
    expect(directives.get("ProtectSystem")).toEqual(["strict"]);
    expect(directives.get("ProtectHome")).toEqual(["yes"]);
    expect(directives.get("PrivateTmp")).toEqual(["yes"]);
    expect(directives.get("PrivateDevices")).toEqual(["yes"]);
    expect(directives.get("ProtectKernelTunables")).toEqual(["yes"]);
    expect(directives.get("ProtectKernelModules")).toEqual(["yes"]);
    expect(directives.get("ProtectKernelLogs")).toEqual(["yes"]);
    expect(directives.get("ProtectControlGroups")).toEqual(["yes"]);
    expect(directives.get("ProtectProc")).toEqual(["invisible"]);
    expect(directives.get("ProcSubset")).toEqual(["pid"]);
    expect(directives.get("RestrictSUIDSGID")).toEqual(["yes"]);
    expect(directives.get("RestrictNamespaces")).toEqual(["yes"]);
    expect(directives.get("RestrictRealtime")).toEqual(["yes"]);
    expect(directives.get("LockPersonality")).toEqual(["yes"]);
    expect(directives.get("CapabilityBoundingSet")).toEqual([""]);
    expect(directives.get("SystemCallFilter")).toEqual(["@system-service"]);
    expect(directives.get("SystemCallErrorNumber")).toEqual(["EPERM"]);
    expect(directives.get("SystemCallArchitectures")).toEqual(["native"]);
    expect(directives.get("UMask")).toEqual(["0007"]);

    // Must NOT break JVM or server networking
    expect(directives.get("MemoryDenyWriteExecute")).toBeUndefined();
    expect(directives.get("PrivateNetwork")).toBeUndefined();

    // ReadWritePaths must NEVER grant access to /var/lib/tegrad or @TEGRAD_STATE_DIR@
    const rwTokens = (directives.get("ReadWritePaths") ?? [])
      .flatMap((line) => line.split(/\s+/))
      .filter((t) => t.length > 0);
    expect(rwTokens.length).toBeGreaterThan(0);
    for (const token of rwTokens) {
      const rendered = token
        .replaceAll("@TEGRAD_STATE_DIR@", "/var/lib/tegrad")
        .replaceAll("@TEGRAD_SERVERS_DIR@", "/var/lib/tegrad-servers");
      expect(rendered).not.toBe("/var/lib/tegrad");
      expect(rendered.startsWith("/var/lib/tegrad/")).toBe(false);
    }
  });

  test("tegrad-server@.socket and tmpfiles.d configure FIFO ownership and permissions", () => {
    const socketContent = readInstallFile("units/tegrad-server@.socket");
    const directives = parseIniDirectives(socketContent);

    expect(directives.get("SocketUser")).toEqual(["tegrad-srv"]);
    expect(directives.get("SocketGroup")).toEqual(["tegrad"]);
    expect(directives.get("SocketMode")).toEqual(["0660"]);
    expect(directives.get("ListenFIFO")).toEqual(["@TEGRAD_RUN_DIR@/%i.stdin"]);

    const tmpfilesContent = readInstallFile("tmpfiles/tegrad.conf");
    expect(tmpfilesContent).toContain("d @TEGRAD_RUN_DIR@ 0750 root tegrad -");
  });

  test("polkit rule restricts tegrad strictly to tegrad-server@ units", () => {
    const rule = readInstallFile("polkit/50-tegrad.rules");

    expect(rule).toContain('action.id === "org.freedesktop.systemd1.manage-units"');
    expect(rule).toContain('subject.user === "tegrad"');
    expect(rule).toContain("/^tegrad-server@[a-z0-9][a-z0-9-]{0,62}\\.(service|socket)$/");
    expect(rule).toContain("polkit.Result.YES");
    expect(rule).toContain("polkit.Result.NOT_HANDLED");
  });

  test("install.sh avoids eval, guards every rm -rf with parameter-expansion :?, and uses set -eu", () => {
    const script = readInstallFile("install.sh");
    const lines = script.split(/\r?\n/);

    expect(lines[0]).toBe("#!/bin/sh");
    expect(script).toContain("set -eu");
    expect(script).toContain("TODO(signature)");

    for (const line of lines) {
      const stripped = line.trim();
      if (stripped.startsWith("#")) continue;

      // Never invoke eval
      expect(stripped).not.toMatch(/(^|[;&|(\s])eval(\s|$)/);

      // Every rm -rf must use ${VAR:?}
      if (/\brm\s+-[a-zA-Z]*r[a-zA-Z]*f|\brm\s+-[a-zA-Z]*f[a-zA-Z]*r/.test(stripped)) {
        expect(stripped).toMatch(/\$\{[A-Za-z_][A-Za-z0-9_]*:\?\}/);
      }
    }
  });
});
