// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { Glob } from "bun";

const LINE_1 = "// SPDX-License-Identifier: AGPL-3.0-only";
const LINE_2 = "// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>";

const missing: string[] = [];

for await (const path of new Glob("{src,scripts}/**/*.{ts,tsx,js,mjs}").scan(".")) {
  const lines = (await Bun.file(path).text()).split(/\r?\n/);
  if (lines[0] !== LINE_1 || lines[1] !== LINE_2) missing.push(path);
}

if (missing.length > 0) {
  process.stderr.write(
    `Missing or wrong license header:\n${missing.map((p) => `  ${p}`).join("\n")}\n`,
  );
  process.exit(1);
}
