// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { expect, test } from "bun:test";
import { Glob } from "bun";

const FORBIDDEN_INBOUND_PATTERNS: readonly { name: string; regex: RegExp }[] = [
  { name: "Bun.serve", regex: /\bBun\.serve\b/ },
  { name: "createServer", regex: /\bcreateServer\b/ },
  { name: ".listen(", regex: /\.listen\s*\(/ },
  { name: "new Bun.TCPSocket", regex: /\bnew\s+Bun\.TCPSocket\b/ },
  { name: "Bun.listen", regex: /\bBun\.listen\b/ },
];

test("src/agent and src/cli never open an inbound port", async () => {
  const violations: string[] = [];
  let checkedCount = 0;

  for await (const path of new Glob("src/{agent,cli}/**/*.ts").scan(".")) {
    if (path.endsWith(".test.ts")) continue;
    checkedCount++;
    const content = await Bun.file(path).text();
    for (const rule of FORBIDDEN_INBOUND_PATTERNS) {
      if (rule.regex.test(content)) {
        violations.push(`${path}: matched ${rule.name}`);
      }
    }
  }

  expect(checkedCount).toBeGreaterThan(0);
  expect(violations).toEqual([]);
});
