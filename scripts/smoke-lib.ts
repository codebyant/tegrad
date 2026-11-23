// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

// Exercises the built library (lib/) the way a consumer would: crypto, protocol and vault must
// share one initialized libsodium instance.
import { ready } from "tegrad/crypto";
import { createCoreRegistry, PROTOCOL_VERSION } from "tegrad/protocol";
import { createVault, unlockVault } from "tegrad/vault";

await ready();

const password = "correct horse battery staple 7!";
const { blob, unlocked } = createVault({
  password,
  kdf: { alg: "argon2id13", opslimit: 3, memlimit: 128 * 1024 * 1024 },
});
const again = unlockVault(blob, password);

if (PROTOCOL_VERSION !== 1 || again.account !== unlocked.account) {
  process.stderr.write("lib smoke test failed: vault round trip\n");
  process.exit(1);
}
if (createCoreRegistry().get("agent.ping") === undefined) {
  process.stderr.write("lib smoke test failed: core registry\n");
  process.exit(1);
}
process.stdout.write("lib smoke test ok\n");
