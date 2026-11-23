import { type PublicKey, type SigningKeyPair } from "../crypto";
import type { KeyId } from "./schemas";
export interface TrustContext {
    readonly agentKeyPair: SigningKeyPair;
    isTrustedAccountKey(id: KeyId): PublicKey | null;
    isSessionRevoked(certificateId: string): boolean;
    now(): number;
    claimCommand(signer: KeyId, id: string, counter: number): boolean;
}
export interface InMemoryTrustContextOptions {
    readonly agentKeyPair: SigningKeyPair;
    readonly trustedAccountKeys: readonly PublicKey[];
    readonly revokedSessionIds?: Iterable<string>;
    readonly now?: () => number;
}
export interface InMemoryTrustContext extends TrustContext {
    revokeSession(certificateId: string): void;
    setNow(clock: () => number): void;
}
export declare function createInMemoryTrustContext(options: InMemoryTrustContextOptions): InMemoryTrustContext;
