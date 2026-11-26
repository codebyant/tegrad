// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

// Exercises the built library (lib/) the way a consumer would: crypto, protocol and vault must
// share one initialized libsodium instance.
import { ready } from "tegrad/crypto";
import {
  createCoreRegistry,
  hostInfoResultSchema,
  PROTOCOL_VERSION,
  serverBackupUploadEventSchema,
  serverChangeRuntimeBodySchema,
  serverStatsResultSchema,
  subscriptionTopicSchema,
} from "tegrad/protocol";
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
if (
  createCoreRegistry().get("host.info") === undefined ||
  !hostInfoResultSchema.safeParse({
    memory_total_mb: 8192,
    memory_available_mb: 6144,
    cpu_count: 4,
    reserved_memory_mb: 1024,
  }).success
) {
  process.stderr.write("lib smoke test failed: host.info\n");
  process.exit(1);
}
if (
  createCoreRegistry().get("server.stats") === undefined ||
  !serverStatsResultSchema.safeParse({
    server_id: "survival",
    running: true,
    memory_used_mb: 1024,
    memory_limit_mb: 2048,
    cpu_percent: 42.5,
    cpu_count: 4,
    uptime_seconds: 120,
  }).success
) {
  process.stderr.write("lib smoke test failed: server.stats\n");
  process.exit(1);
}
if (
  createCoreRegistry().get("server.change_runtime") === undefined ||
  !serverChangeRuntimeBodySchema.safeParse({
    server_id: "survival",
    minecraft_version: "1.21.4",
    loader: "fabric",
  }).success
) {
  process.stderr.write("lib smoke test failed: server.change_runtime\n");
  process.exit(1);
}
if (
  !subscriptionTopicSchema.safeParse("server.backup").success ||
  !serverBackupUploadEventSchema.safeParse({
    server_id: "survival",
    backup_id: "bkp-20261126-000000-abcd1234",
    destination: "tegra_cloud",
    state: "uploading",
    sent_bytes: 512,
    total_bytes: 1024,
  }).success
) {
  process.stderr.write("lib smoke test failed: server.backup\n");
  process.exit(1);
}
process.stdout.write("lib smoke test ok\n");
