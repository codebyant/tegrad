import { type PublicKey, type SigningKeyPair } from "../crypto";
import type { CommandRegistry } from "./registry";
import { type CommandHeader, type KeyId, type SessionCertificate, type SignedCommand } from "./schemas";
import type { TrustContext } from "./trust";
export declare const COMMAND_ID_BYTES = 16;
export declare const DEFAULT_COMMAND_TTL_MS: number;
export declare const MAX_COMMAND_TTL_MS: number;
export declare const MAX_CLOCK_SKEW_MS: number;
export interface CreateSignedCommandParams {
    readonly type: string;
    readonly body: unknown;
    readonly agentPublicKey: PublicKey;
    readonly signer: SigningKeyPair;
    readonly session?: SessionCertificate;
    readonly counter: number;
    readonly now: number;
    readonly ttlMs?: number;
    readonly id?: string;
}
export interface OpenedCommand<TBody = unknown> {
    readonly header: CommandHeader;
    readonly body: TBody;
    readonly signerType: "account" | "session";
    readonly accountId: KeyId;
    readonly sessionId?: string;
}
export declare function createSignedCommand(params: CreateSignedCommandParams, registry: CommandRegistry): SignedCommand;
export declare function openCommand(command: unknown, trust: TrustContext, registry: CommandRegistry): Promise<OpenedCommand>;
