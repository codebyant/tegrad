// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { rm } from "node:fs/promises";

const OUT_DIR = "lib";

async function run(command: string[]): Promise<void> {
  const proc = Bun.spawn(command, { stdout: "inherit", stderr: "inherit" });
  const code = await proc.exited;
  if (code !== 0) {
    process.stderr.write(`Command failed (${code}): ${command.join(" ")}\n`);
    process.exit(code);
  }
}

await rm(OUT_DIR, { recursive: true, force: true });

// One build with code splitting so crypto, protocol and vault share a single copy of the
// module-level state (for example the libsodium initialization flag).
const result = await Bun.build({
  entrypoints: ["src/crypto/index.ts", "src/protocol/index.ts", "src/vault/index.ts"],
  outdir: OUT_DIR,
  format: "esm",
  target: "browser",
  splitting: true,
  minify: false,
  external: ["libsodium-wrappers-sumo", "zod"],
  naming: { entry: "[dir]/[name].js", chunk: "chunks/[name]-[hash].js" },
});

if (!result.success) {
  for (const log of result.logs) {
    process.stderr.write(`${String(log)}\n`);
  }
  process.exit(1);
}

await run(["bunx", "tsc", "-p", "tsconfig.lib.json"]);
