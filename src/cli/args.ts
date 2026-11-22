// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

export type ParsedCliCommand =
  | { readonly kind: "run" }
  | { readonly kind: "status" }
  | { readonly kind: "identity" }
  | { readonly kind: "link" }
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

  if (first === "link") {
    return { kind: "link" };
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
    "  status     Show local state directory, identity, config, and trust status",
    "  identity   Create the agent identity if missing and print its fingerprint",
    "",
    "Options:",
    "  -v, --version   Print version and exit",
    "  -h, --help      Print this help message and exit",
    "",
  ].join("\n");
}
