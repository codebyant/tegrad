// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

export type FileErrorCode =
  | "invalid_server_id"
  | "server_not_found"
  | "invalid_path"
  | "path_traversal"
  | "symlink_forbidden"
  | "root_operation_forbidden"
  | "not_found"
  | "already_exists"
  | "not_a_file"
  | "not_a_directory"
  | "is_a_directory"
  | "file_too_large"
  | "copy_limit_exceeded"
  | "toctou_detected"
  | "invalid_encoding"
  | "upload_not_found"
  | "upload_limit_exceeded"
  | "part_too_large"
  | "part_out_of_order"
  | "size_mismatch"
  | "hash_mismatch"
  | "download_not_found"
  | "download_limit_exceeded"
  | "zip_invalid"
  | "zip_slip"
  | "zip_symlink_entry"
  | "zip_too_many_entries"
  | "zip_too_large"
  | "zip_entry_too_large"
  | "zip_compression_ratio_exceeded"
  | "zip_crc_mismatch"
  | "zip_unsupported_method"
  | "io_error";

export class FileManagerError extends Error {
  readonly code: FileErrorCode;

  constructor(code: FileErrorCode, message: string, options?: { readonly cause?: unknown }) {
    super(message, options);
    this.name = "FileManagerError";
    this.code = code;
  }
}
