// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

export interface LinkCliOptions {
  readonly add: boolean;
  readonly reset: boolean;
  readonly yes: boolean;
  readonly allowUnverified: boolean;
}

export type ParsedCliCommand =
  | { readonly kind: "run" }
  | { readonly kind: "status" }
  | { readonly kind: "identity" }
  | { readonly kind: "doctor" }
  | { readonly kind: "link"; readonly options: LinkCliOptions }
  | { readonly kind: "version" }
  | { readonly kind: "help" }
  | { readonly kind: "unknown"; readonly token: string };

export function parseCliArgs(argv: readonly string[]): ParsedCliCommand {
  const first = argv[0];
  if (first === undefined) {
    return { kind: "help" };
  }

  if (first === "--version" || first === "-v") {
    return { kind: "version" };
  }

  if (first === "--help" || first === "-h" || first === "help") {
    return { kind: "help" };
  }

  if (first === "run" && argv.length === 1) {
    return { kind: "run" };
  }

  if (first === "status" && argv.length === 1) {
    return { kind: "status" };
  }

  if (first === "identity" && argv.length === 1) {
    return { kind: "identity" };
  }

  if (first === "doctor" && argv.length === 1) {
    return { kind: "doctor" };
  }

  if (first === "link") {
    let add = false;
    let reset = false;
    let yes = false;
    let allowUnverified = false;

    for (let i = 1; i < argv.length; i++) {
      const flag = argv[i];
      if (flag === "--add") {
        add = true;
      } else if (flag === "--reset") {
        reset = true;
      } else if (flag === "--yes" || flag === "-y") {
        yes = true;
      } else if (flag === "--allow-unverified") {
        allowUnverified = true;
      } else {
        return { kind: "unknown", token: argv.join(" ") };
      }
    }

    return {
      kind: "link",
      options: { add, reset, yes, allowUnverified },
    };
  }

  return { kind: "unknown", token: argv.join(" ") };
}

export function formatUsage(versionLineText: string): string {
  return [
    versionLineText,
    "",
    "Usage: tegrad <command>",
    "",
    "Commands:",
    "  run        Connect to the control server and process commands",
    "  link       Pair this agent with a Tegra account (--add, --reset, --yes, --allow-unverified)",
    "  status     Show local state directory, identity, config, and trust status",
    "  identity   Create the agent identity if missing and print its fingerprint",
    "  doctor     Check Linux installation, permissions, units, polkit, and network isolation",
    "",
    "Options:",
    "  -v, --version   Print version and exit",
    "  -h, --help      Print this help message and exit",
    "",
  ].join("\n");
}
