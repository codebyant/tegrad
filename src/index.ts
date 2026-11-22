// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { versionLine } from "./version";

const args = process.argv.slice(2);

if (args.includes("--version") || args.includes("-v")) {
  process.stdout.write(`${versionLine()}\n`);
} else {
  process.stdout.write(`${versionLine()}\nUsage: tegrad [--version]\n`);
}
