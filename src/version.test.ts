// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { expect, test } from "bun:test";
import { VERSION, versionLine } from "./version";

test("versionLine includes the version", () => {
  expect(versionLine()).toBe(`tegrad ${VERSION}`);
});
