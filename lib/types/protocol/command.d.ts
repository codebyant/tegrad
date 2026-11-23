import { type PublicKey, type SigningKeyPair } from "../crypto";
import type { CommandRegistry } from "./registry";
import { type Role } from "./roles";
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
    /**
     * Ed25519 public key that the agent's replies and events are sealed to.
     * Defaults to the account key. A session signer must use its own key.
     */
    readonly replyTo?: PublicKey;
}
export interface OpenedCommand<TBody = unknown> {
    readonly header: CommandHeader;
    readonly body: TBody;
    readonly signerType: "account" | "session";
    readonly accountId: KeyId;
    readonly sessionId?: string;
    /** `not_after` of the signing session certificate, when the signer is a session. */
    readonly sessionNotAfter?: number;
    /** Key from the command's `reply_to`, when present. Replies go here instead of the account key. */
    readonly replyTo?: PublicKey;
    /** Role of the signing account on the command's server (`"*"` for agent commands). */
    readonly role: Role;
}
export declare function createSignedCommand(params: CreateSignedCommandParams, registry: CommandRegistry): SignedCommand;
export declare function openCommand(command: unknown, trust: TrustContext, registry: CommandRegistry): Promise<OpenedCommand>;
