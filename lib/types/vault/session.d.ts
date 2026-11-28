import { type PublicKey, type SigningKeyPair } from "../crypto";
import { type CommandRegistry, type RevocationList, type SessionCertificate, type SignedCommand } from "../protocol";
import type { UnlockedVault } from "./vault";
export declare const SESSION_DURATION_MS: {
    readonly "24h": number;
    readonly "7d": number;
    readonly "30d": number;
    readonly remember: number;
};
export type SessionDuration = keyof typeof SESSION_DURATION_MS;
export interface Session {
    readonly keyPair: SigningKeyPair;
    readonly certificate: SessionCertificate;
}
export interface IssueSessionOptions {
    readonly duration: SessionDuration;
    readonly now?: number;
    readonly id?: string;
}
export interface VaultCommandParams {
    /** Public key that receives the replies. Sessions default to their own key. */
    readonly replyTo?: PublicKey;
    readonly type: string;
    readonly body: unknown;
    readonly agentPublicKey: PublicKey;
    readonly counter: number;
    readonly now: number;
    readonly registry: CommandRegistry;
    readonly ttlMs?: number;
    readonly id?: string;
}
export interface SignRevocationParams {
    readonly revoked: readonly string[];
    readonly now: number;
}
export declare function issueSession(unlocked: UnlockedVault, options: IssueSessionOptions): Session;
export interface IssueElevatedSessionOptions {
    readonly now?: number;
    readonly id?: string;
    /** Validity of the certificate; defaults to and may not exceed the agent's 1 h cap. */
    readonly validityMs?: number;
}
/**
 * Issues the key for the sudo window. Keep it in memory only and drop it when the
 * window closes (the launcher closes it after 15 minutes without a sudo command); the
 * agent refuses it after its certificate expires, at most 1 h after issue.
 */
export declare function issueElevatedSession(unlocked: UnlockedVault, options?: IssueElevatedSessionOptions): Session;
export declare function isElevatedSession(session: Session): boolean;
export declare function serializeSession(session: Session): string;
export declare function parseSession(text: string): Session;
export declare function sessionExpiresAt(session: Session): number;
export declare function isSessionExpired(session: Session, now?: number): boolean;
export declare function createCommandFromSession(session: Session, params: VaultCommandParams): SignedCommand;
export declare function createSensitiveCommand(unlocked: UnlockedVault, params: VaultCommandParams): SignedCommand;
export declare function signRevocation(unlocked: UnlockedVault, params: SignRevocationParams): RevocationList;
