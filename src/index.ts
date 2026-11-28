// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { runCli } from "./cli/main";

const exitCode = await runCli(process.argv.slice(2));
if (exitCode !== 0) {
  process.exit(exitCode);
}
