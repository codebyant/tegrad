// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { expect, test } from "bun:test";
import { Glob } from "bun";

const FORBIDDEN_PATTERNS: readonly { name: string; regex: RegExp }[] = [
  { name: "node:* import", regex: /from\s+["']node:[^"']+["']|import\s+["']node:[^"']+["']/ },
  { name: "bun:* import", regex: /from\s+["']bun:[^"']+["']|import\s+["']bun:[^"']+["']/ },
  { name: "Buffer global", regex: /\bBuffer\b/ },
  { name: "process global", regex: /\bprocess\b/ },
  { name: "Bun global", regex: /\bBun\b/ },
  { name: "fs import", regex: /from\s+["']fs["']|from\s+["']fs\/promises["']/ },
];

test("src/crypto, src/protocol, and src/vault are isomorphic (no Node/Bun-only APIs)", async () => {
  const violations: string[] = [];
  let checkedCount = 0;

  for await (const path of new Glob("src/{crypto,protocol,vault}/**/*.ts").scan(".")) {
    if (path.endsWith(".test.ts")) continue;
    checkedCount++;
    const content = await Bun.file(path).text();
    for (const rule of FORBIDDEN_PATTERNS) {
      if (rule.regex.test(content)) {
        violations.push(`${path}: matched ${rule.name}`);
      }
    }
  }

  expect(checkedCount).toBeGreaterThan(0);
  expect(violations).toEqual([]);
});
