import { z } from "zod";
import { type CommandRegistry } from "../registry";
export declare const SERVER_ID_PATTERN: RegExp;
export declare const SHA256_HEX_PATTERN: RegExp;
export declare const fileEncodingSchema: z.ZodEnum<{
    base64: "base64";
    utf8: "utf8";
}>;
export declare const sha256HexSchema: z.ZodString;
export declare const filesListCommand: import("..").CommandDefinition<"files.list", {
    server_id: string;
    path?: string | undefined;
}>;
export declare const filesStatCommand: import("..").CommandDefinition<"files.stat", {
    server_id: string;
    path: string;
}>;
export declare const filesReadCommand: import("..").CommandDefinition<"files.read", {
    server_id: string;
    path: string;
    encoding?: "base64" | "utf8" | undefined;
}>;
export declare const filesWriteCommand: import("..").CommandDefinition<"files.write", {
    server_id: string;
    path: string;
    content: string;
    encoding?: "base64" | "utf8" | undefined;
}>;
export declare const filesMkdirCommand: import("..").CommandDefinition<"files.mkdir", {
    server_id: string;
    path: string;
}>;
export declare const filesRenameCommand: import("..").CommandDefinition<"files.rename", {
    server_id: string;
    path: string;
    new_name: string;
}>;
export declare const filesMoveCommand: import("..").CommandDefinition<"files.move", {
    server_id: string;
    from_path: string;
    to_path: string;
}>;
export declare const filesCopyCommand: import("..").CommandDefinition<"files.copy", {
    server_id: string;
    from_path: string;
    to_path: string;
}>;
export declare const filesDeleteCommand: import("..").CommandDefinition<"files.delete", {
    server_id: string;
    path: string;
    recursive?: boolean | undefined;
}>;
export declare const filesUploadBeginCommand: import("..").CommandDefinition<"files.upload.begin", {
    server_id: string;
    path: string;
    total_size: number;
    sha256: string;
    part_size?: number | undefined;
}>;
export declare const filesUploadPartCommand: import("..").CommandDefinition<"files.upload.part", {
    server_id: string;
    upload_id: string;
    part_index: number;
    data_base64: string;
}>;
export declare const filesUploadCommitCommand: import("..").CommandDefinition<"files.upload.commit", {
    server_id: string;
    upload_id: string;
}>;
export declare const filesUploadAbortCommand: import("..").CommandDefinition<"files.upload.abort", {
    server_id: string;
    upload_id: string;
}>;
export declare const filesDownloadBeginCommand: import("..").CommandDefinition<"files.download.begin", {
    server_id: string;
    path: string;
    part_size?: number | undefined;
}>;
export declare const filesDownloadPartCommand: import("..").CommandDefinition<"files.download.part", {
    server_id: string;
    download_id: string;
    part_index: number;
}>;
export declare const filesDownloadCloseCommand: import("..").CommandDefinition<"files.download.close", {
    server_id: string;
    download_id: string;
}>;
export declare const filesDownloadCommand: import("..").CommandDefinition<"files.download", {
    server_id: string;
    path: string;
    offset: number;
    length: number;
}>;
export declare const filesZipCommand: import("..").CommandDefinition<"files.zip", {
    server_id: string;
    paths: string[];
    dest_path: string;
}>;
export declare const filesUnzipCommand: import("..").CommandDefinition<"files.unzip", {
    server_id: string;
    zip_path: string;
    dest_path?: string | undefined;
}>;
export declare const FILES_COMMANDS: readonly [import("..").CommandDefinition<"files.list", {
    server_id: string;
    path?: string | undefined;
}>, import("..").CommandDefinition<"files.stat", {
    server_id: string;
    path: string;
}>, import("..").CommandDefinition<"files.read", {
    server_id: string;
    path: string;
    encoding?: "base64" | "utf8" | undefined;
}>, import("..").CommandDefinition<"files.write", {
    server_id: string;
    path: string;
    content: string;
    encoding?: "base64" | "utf8" | undefined;
}>, import("..").CommandDefinition<"files.mkdir", {
    server_id: string;
    path: string;
}>, import("..").CommandDefinition<"files.rename", {
    server_id: string;
    path: string;
    new_name: string;
}>, import("..").CommandDefinition<"files.move", {
    server_id: string;
    from_path: string;
    to_path: string;
}>, import("..").CommandDefinition<"files.copy", {
    server_id: string;
    from_path: string;
    to_path: string;
}>, import("..").CommandDefinition<"files.delete", {
    server_id: string;
    path: string;
    recursive?: boolean | undefined;
}>, import("..").CommandDefinition<"files.upload.begin", {
    server_id: string;
    path: string;
    total_size: number;
    sha256: string;
    part_size?: number | undefined;
}>, import("..").CommandDefinition<"files.upload.part", {
    server_id: string;
    upload_id: string;
    part_index: number;
    data_base64: string;
}>, import("..").CommandDefinition<"files.upload.commit", {
    server_id: string;
    upload_id: string;
}>, import("..").CommandDefinition<"files.upload.abort", {
    server_id: string;
    upload_id: string;
}>, import("..").CommandDefinition<"files.download.begin", {
    server_id: string;
    path: string;
    part_size?: number | undefined;
}>, import("..").CommandDefinition<"files.download.part", {
    server_id: string;
    download_id: string;
    part_index: number;
}>, import("..").CommandDefinition<"files.download.close", {
    server_id: string;
    download_id: string;
}>, import("..").CommandDefinition<"files.download", {
    server_id: string;
    path: string;
    offset: number;
    length: number;
}>, import("..").CommandDefinition<"files.zip", {
    server_id: string;
    paths: string[];
    dest_path: string;
}>, import("..").CommandDefinition<"files.unzip", {
    server_id: string;
    zip_path: string;
    dest_path?: string | undefined;
}>];
export declare function registerFilesCommands(registry: CommandRegistry): CommandRegistry;
