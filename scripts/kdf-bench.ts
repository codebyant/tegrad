// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import {
  deriveKeyFromPassword,
  generateSalt,
  KDF_FLOOR,
  KDF_MODERATE,
  type KdfPreset,
  memzero,
  ready,
} from "../src/crypto";

const ITERATIONS = 3;

function formatMiB(bytes: number): string {
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function benchPreset(name: string, preset: KdfPreset): void {
  const salt = generateSalt();
  const durations: number[] = [];
  let peakRss = process.memoryUsage().rss;
  const baselineRss = peakRss;

  for (let i = 0; i < ITERATIONS; i++) {
    const start = performance.now();
    const key = deriveKeyFromPassword("correct-horse-battery-staple-42!", {
      ...preset,
      salt,
    });
    const elapsed = performance.now() - start;
    const rssAfter = process.memoryUsage().rss;
    if (rssAfter > peakRss) {
      peakRss = rssAfter;
    }
    memzero(key);
    durations.push(elapsed);
  }

  const avgMs = durations.reduce((a, b) => a + b, 0) / durations.length;
  const minMs = Math.min(...durations);
  const maxMs = Math.max(...durations);

  process.stdout.write(
    `${name} (opslimit=${preset.opslimit}, memlimit=${formatMiB(preset.memlimit)}):\n`,
  );
  process.stdout.write(
    `  time: avg=${avgMs.toFixed(1)}ms min=${minMs.toFixed(1)}ms max=${maxMs.toFixed(1)}ms (${ITERATIONS} runs)\n`,
  );
  process.stdout.write(
    `  rss:  baseline=${formatMiB(baselineRss)} peak=${formatMiB(peakRss)} delta=${formatMiB(Math.max(0, peakRss - baselineRss))}\n`,
  );
}

await ready();

process.stdout.write(`KDF benchmark on Bun ${Bun.version} (${process.platform}/${process.arch})\n`);
benchPreset("KDF_FLOOR", KDF_FLOOR);
benchPreset("KDF_MODERATE", KDF_MODERATE);
