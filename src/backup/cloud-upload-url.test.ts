// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createBackupManager } from "./index";
import type { CloudUploadTarget } from "./manager";

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir !== undefined) {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

function setup() {
  const root = mkdtempSync(join(tmpdir(), "tegrad-cloud-url-"));
  tempDirs.push(root);
  const serversDir = join(root, "servers");
  mkdirSync(join(serversDir, "cloudsrv", "world"), { recursive: true });
  writeFileSync(join(serversDir, "cloudsrv", "world", "level.dat"), "world-data", "utf8");
  return { root, serversDir };
}

function startStorage() {
  const received: { method: string; headers: Headers; bytes: number }[] = [];
  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      received.push({
        method: req.method,
        headers: req.headers,
        bytes: (await req.arrayBuffer()).byteLength,
      });
      return new Response(null, { status: 200 });
    },
  });
  return { server, received };
}

describe("Tegra Cloud upload URL from the control API", () => {
  test("every upload asks the provider for a URL and sends the headers it returns", async () => {
    const { root, serversDir } = setup();
    const { server, received } = startStorage();
    try {
      const requests: { server_id: string; size_bytes: number }[] = [];
      const manager = createBackupManager({
        stateDir: join(root, "state"),
        serversBaseDir: serversDir,
        localBackupsDir: join(root, "backups"),
        allowInsecure: true,
        cloudUploadUrlProvider: async (request): Promise<CloudUploadTarget> => {
          requests.push(request);
          return {
            put_url: `http://127.0.0.1:${server.port}/object?sig=secret-token`,
            headers: {
              "x-signed-header": "value-1",
              "Content-Length": "1",
              Host: "evil.example",
              "bad header": "x",
            },
            expires_at: Date.now() + 60_000,
            max_bytes: 10 * 1024 * 1024,
          };
        },
      });
      manager.setConfig({
        server_id: "cloudsrv",
        local: { enabled: false },
        tegra_cloud: { enabled: true },
      });

      const created = await manager.createBackup({ server_id: "cloudsrv" });
      expect(created.destinations[0]).toMatchObject({ destination: "tegra_cloud", ok: true });
      expect(requests).toEqual([{ server_id: "cloudsrv", size_bytes: created.size_bytes }]);

      const put = received[0];
      expect(put?.method).toBe("PUT");
      expect(put?.bytes).toBe(created.size_bytes);
      expect(put?.headers.get("x-signed-header")).toBe("value-1");
      expect(put?.headers.get("x-tegra-backup-sha256")).toBe(created.sha256);
      // Headers the transport owns cannot be overridden by the API response.
      expect(put?.headers.get("content-length")).toBe(String(created.size_bytes));
      expect(put?.headers.get("host")).not.toBe("evil.example");

      // A second (scheduled-style) backup asks again.
      await manager.createBackup({ server_id: "cloudsrv", trigger: "scheduled" });
      expect(requests).toHaveLength(2);
    } finally {
      void server.stop(true);
    }
  });

  test("the provider wins over a URL sent inside a command", async () => {
    const { root, serversDir } = setup();
    const { server, received } = startStorage();
    const other = startStorage();
    try {
      const manager = createBackupManager({
        stateDir: join(root, "state"),
        serversBaseDir: serversDir,
        localBackupsDir: join(root, "backups"),
        allowInsecure: true,
        cloudUploadUrlProvider: async () => ({
          put_url: `http://127.0.0.1:${server.port}/object`,
          headers: {},
          expires_at: Date.now() + 60_000,
          max_bytes: 10 * 1024 * 1024,
        }),
      });
      manager.setConfig({
        server_id: "cloudsrv",
        local: { enabled: false },
        tegra_cloud: { enabled: true },
      });
      const created = await manager.createBackup({
        server_id: "cloudsrv",
        tegra_cloud_upload_url: `http://127.0.0.1:${other.server.port}/elsewhere`,
      });
      expect(created.destinations[0]?.ok).toBe(true);
      expect(received).toHaveLength(1);
      expect(other.received).toHaveLength(0);
    } finally {
      void server.stop(true);
      void other.server.stop(true);
    }
  });

  test("a backup larger than max_bytes is not uploaded and a provider failure only fails that destination", async () => {
    const { root, serversDir } = setup();
    const { server, received } = startStorage();
    try {
      let mode: "too_big" | "fail" = "too_big";
      const manager = createBackupManager({
        stateDir: join(root, "state"),
        serversBaseDir: serversDir,
        localBackupsDir: join(root, "backups"),
        allowInsecure: true,
        cloudUploadUrlProvider: async () => {
          if (mode === "fail") {
            throw new Error("request to https://api.tegra.example/x?sig=top-secret failed");
          }
          return {
            put_url: `http://127.0.0.1:${server.port}/object`,
            headers: {},
            expires_at: Date.now() + 60_000,
            max_bytes: 1,
          };
        },
      });
      manager.setConfig({
        server_id: "cloudsrv",
        local: { enabled: true },
        tegra_cloud: { enabled: true },
      });

      const tooBig = await manager.createBackup({ server_id: "cloudsrv" });
      const cloud = tooBig.destinations.find((d) => d.destination === "tegra_cloud");
      const local = tooBig.destinations.find((d) => d.destination === "local");
      expect(cloud?.ok).toBe(false);
      expect(local?.ok).toBe(true);
      expect(received).toHaveLength(0);

      mode = "fail";
      const failed = await manager.createBackup({ server_id: "cloudsrv" });
      const failedCloud = failed.destinations.find((d) => d.destination === "tegra_cloud");
      expect(failedCloud?.ok).toBe(false);
      expect(failed.destinations.find((d) => d.destination === "local")?.ok).toBe(true);
      expect(JSON.stringify(failedCloud)).not.toContain("top-secret");
      expect(received).toHaveLength(0);
    } finally {
      void server.stop(true);
    }
  });
});
