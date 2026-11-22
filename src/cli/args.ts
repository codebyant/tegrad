// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

export interface LinkCliOptions {
  readonly add: boolean;
  readonly reset: boolean;
  readonly yes: boolean;
  readonly allowUnverified: boolean;
}

export interface VerifyUpdateCliOptions {
  readonly binary: string;
  readonly manifest?: string;
  readonly sums?: string;
  readonly sig?: string;
  readonly asset?: string;
  readonly channel?: "stable" | "beta" | "nightly";
}

export interface ApplyUpdateCliOptions {
  readonly allowDowngrade: boolean;
}

export type ParsedCliCommand =
  | { readonly kind: "run" }
  | { readonly kind: "status" }
  | { readonly kind: "identity" }
  | { readonly kind: "doctor" }
  | { readonly kind: "link"; readonly options: LinkCliOptions }
  | { readonly kind: "verify-update"; readonly options: VerifyUpdateCliOptions }
  | { readonly kind: "apply-update"; readonly options: ApplyUpdateCliOptions }
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

  if (first === "verify-update") {
    let binary: string | undefined;
    let manifest: string | undefined;
    let sums: string | undefined;
    let sig: string | undefined;
    let asset: string | undefined;
    let channel: "stable" | "beta" | "nightly" | undefined;

    for (let i = 1; i < argv.length; i++) {
      const flag = argv[i];
      const next = argv[i + 1];
      if (flag === "--binary" && next !== undefined) {
        binary = next;
        i++;
      } else if (flag === "--manifest" && next !== undefined) {
        manifest = next;
        i++;
      } else if (flag === "--sums" && next !== undefined) {
        sums = next;
        i++;
      } else if (flag === "--sig" && next !== undefined) {
        sig = next;
        i++;
      } else if (flag === "--asset" && next !== undefined) {
        asset = next;
        i++;
      } else if (
        flag === "--channel" &&
        (next === "stable" || next === "beta" || next === "nightly")
      ) {
        channel = next;
        i++;
      } else {
        return { kind: "unknown", token: argv.join(" ") };
      }
    }

    const hasManifest = manifest !== undefined;
    const hasSums = sums !== undefined || sig !== undefined;
    if (binary === undefined) {
      return { kind: "unknown", token: argv.join(" ") };
    }
    if (hasManifest && hasSums) {
      return { kind: "unknown", token: argv.join(" ") };
    }
    if (!hasManifest && (sums === undefined || sig === undefined)) {
      return { kind: "unknown", token: argv.join(" ") };
    }

    return {
      kind: "verify-update",
      options: {
        binary,
        ...(manifest !== undefined ? { manifest } : {}),
        ...(sums !== undefined ? { sums } : {}),
        ...(sig !== undefined ? { sig } : {}),
        ...(asset !== undefined ? { asset } : {}),
        ...(channel !== undefined ? { channel } : {}),
      },
    };
  }

  if (first === "apply-update") {
    let allowDowngrade = false;
    for (let i = 1; i < argv.length; i++) {
      const flag = argv[i];
      if (flag === "--allow-downgrade") {
        allowDowngrade = true;
      } else {
        return { kind: "unknown", token: argv.join(" ") };
      }
    }
    return {
      kind: "apply-update",
      options: { allowDowngrade },
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
    "  run            Connect to the control server and process commands",
    "  link           Pair this agent with a Tegra account (--add, --reset, --yes, --allow-unverified)",
    "  status         Show local state directory, identity, config, and trust status",
    "  identity       Create the agent identity if missing and print its fingerprint",
    "  doctor         Check Linux installation, permissions, units, polkit, and network isolation",
    "  verify-update  Verify a signed release manifest or SHA256SUMS against a binary",
    "  apply-update   Verify and atomically apply a staged update with health check and rollback",
    "",
    "Options:",
    "  -v, --version   Print version and exit",
    "  -h, --help      Print this help message and exit",
    "",
  ].join("\n");
}
