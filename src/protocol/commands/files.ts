// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { z } from "zod";
import { type CommandRegistry, defineCommand } from "../registry";
import { serverIdSchema } from "./server";

export const SERVER_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;
export const SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/;

export const fileEncodingSchema = z.enum(["utf8", "base64"]);
export const sha256HexSchema = z
  .string()
  .regex(SHA256_HEX_PATTERN, "Expected 64 lowercase hex characters");

export const filesListCommand = defineCommand({
  type: "files.list",
  level: "session",
  minRole: "viewer",
  body: z
    .object({
      server_id: serverIdSchema,
      path: z.string().optional(),
    })
    .strict(),
});

export const filesStatCommand = defineCommand({
  type: "files.stat",
  level: "session",
  minRole: "viewer",
  body: z
    .object({
      server_id: serverIdSchema,
      path: z.string(),
    })
    .strict(),
});

export const filesReadCommand = defineCommand({
  type: "files.read",
  level: "session",
  minRole: "editor",
  body: z
    .object({
      server_id: serverIdSchema,
      path: z.string().min(1),
      encoding: fileEncodingSchema.optional(),
    })
    .strict(),
});

export const filesWriteCommand = defineCommand({
  type: "files.write",
  level: "session",
  minRole: "editor",
  body: z
    .object({
      server_id: serverIdSchema,
      path: z.string().min(1),
      content: z.string(),
      encoding: fileEncodingSchema.optional(),
    })
    .strict(),
});

export const filesMkdirCommand = defineCommand({
  type: "files.mkdir",
  level: "session",
  minRole: "editor",
  body: z
    .object({
      server_id: serverIdSchema,
      path: z.string().min(1),
    })
    .strict(),
});

export const filesRenameCommand = defineCommand({
  type: "files.rename",
  level: "session",
  minRole: "editor",
  body: z
    .object({
      server_id: serverIdSchema,
      path: z.string().min(1),
      new_name: z.string().min(1),
    })
    .strict(),
});

export const filesMoveCommand = defineCommand({
  type: "files.move",
  level: "session",
  minRole: "editor",
  body: z
    .object({
      server_id: serverIdSchema,
      from_path: z.string().min(1),
      to_path: z.string().min(1),
    })
    .strict(),
});

export const filesCopyCommand = defineCommand({
  type: "files.copy",
  level: "session",
  minRole: "editor",
  body: z
    .object({
      server_id: serverIdSchema,
      from_path: z.string().min(1),
      to_path: z.string().min(1),
    })
    .strict(),
});

export const filesDeleteCommand = defineCommand({
  type: "files.delete",
  level: "session",
  minRole: "editor",
  body: z
    .object({
      server_id: serverIdSchema,
      path: z.string().min(1),
      recursive: z.boolean().optional(),
    })
    .strict(),
});

export const filesUploadBeginCommand = defineCommand({
  type: "files.upload.begin",
  level: "session",
  minRole: "editor",
  body: z
    .object({
      server_id: serverIdSchema,
      path: z.string().min(1),
      total_size: z.number().int().nonnegative(),
      sha256: sha256HexSchema,
      part_size: z.number().int().positive().optional(),
    })
    .strict(),
});

export const filesUploadPartCommand = defineCommand({
  type: "files.upload.part",
  level: "session",
  minRole: "editor",
  body: z
    .object({
      server_id: serverIdSchema,
      upload_id: z.string().min(1),
      part_index: z.number().int().nonnegative(),
      data_base64: z.string(),
    })
    .strict(),
});

export const filesUploadCommitCommand = defineCommand({
  type: "files.upload.commit",
  level: "session",
  minRole: "editor",
  body: z
    .object({
      server_id: serverIdSchema,
      upload_id: z.string().min(1),
    })
    .strict(),
});

export const filesUploadAbortCommand = defineCommand({
  type: "files.upload.abort",
  level: "session",
  minRole: "editor",
  body: z
    .object({
      server_id: serverIdSchema,
      upload_id: z.string().min(1),
    })
    .strict(),
});

export const filesDownloadBeginCommand = defineCommand({
  type: "files.download.begin",
  level: "session",
  minRole: "editor",
  body: z
    .object({
      server_id: serverIdSchema,
      path: z.string().min(1),
      part_size: z.number().int().positive().optional(),
    })
    .strict(),
});

export const filesDownloadPartCommand = defineCommand({
  type: "files.download.part",
  level: "session",
  minRole: "editor",
  body: z
    .object({
      server_id: serverIdSchema,
      download_id: z.string().min(1),
      part_index: z.number().int().nonnegative(),
    })
    .strict(),
});

export const filesDownloadCloseCommand = defineCommand({
  type: "files.download.close",
  level: "session",
  minRole: "editor",
  body: z
    .object({
      server_id: serverIdSchema,
      download_id: z.string().min(1),
    })
    .strict(),
});

export const filesDownloadCommand = defineCommand({
  type: "files.download",
  level: "session",
  minRole: "editor",
  body: z
    .object({
      server_id: serverIdSchema,
      path: z.string().min(1),
      offset: z.number().int().nonnegative(),
      length: z.number().int().positive(),
    })
    .strict(),
});

export const filesZipCommand = defineCommand({
  type: "files.zip",
  level: "session",
  minRole: "editor",
  body: z
    .object({
      server_id: serverIdSchema,
      paths: z.array(z.string().min(1)).min(1),
      dest_path: z.string().min(1),
    })
    .strict(),
});

export const filesUnzipCommand = defineCommand({
  type: "files.unzip",
  level: "session",
  minRole: "editor",
  body: z
    .object({
      server_id: serverIdSchema,
      zip_path: z.string().min(1),
      dest_path: z.string().optional(),
    })
    .strict(),
});

export const FILES_COMMANDS = [
  filesListCommand,
  filesStatCommand,
  filesReadCommand,
  filesWriteCommand,
  filesMkdirCommand,
  filesRenameCommand,
  filesMoveCommand,
  filesCopyCommand,
  filesDeleteCommand,
  filesUploadBeginCommand,
  filesUploadPartCommand,
  filesUploadCommitCommand,
  filesUploadAbortCommand,
  filesDownloadBeginCommand,
  filesDownloadPartCommand,
  filesDownloadCloseCommand,
  filesDownloadCommand,
  filesZipCommand,
  filesUnzipCommand,
] as const;

export function registerFilesCommands(registry: CommandRegistry): CommandRegistry {
  return registry.registerAll(FILES_COMMANDS);
}
