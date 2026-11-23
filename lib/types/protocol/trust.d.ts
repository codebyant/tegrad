import { type PublicKey, type SigningKeyPair } from "../crypto";
import { type MemberEntry, type Role } from "./roles";
import type { KeyId } from "./schemas";
export interface TrustContext {
    readonly agentKeyPair: SigningKeyPair;
    isTrustedAccountKey(id: KeyId): PublicKey | null;
    isSessionRevoked(certificateId: string): boolean;
    /**
     * Role of an account on a server (`"*"` for agent-level commands), or null
     * when the account has no access. Owners come from the trust list; other
     * roles come from accepted role grants.
     */
    roleFor(account: KeyId, serverId: string): Role | null;
    now(): number;
    claimCommand(signer: KeyId, id: string, counter: number): boolean;
}
export interface InMemoryTrustContextOptions {
    readonly agentKeyPair: SigningKeyPair;
    readonly trustedAccountKeys: readonly PublicKey[];
    readonly revokedSessionIds?: Iterable<string>;
    readonly members?: readonly MemberEntry[];
    readonly now?: () => number;
}
export interface MemberStore {
    listMembers(): readonly MemberEntry[];
    setMember(entry: MemberEntry): void;
    revokeMembers(account: KeyId, servers?: readonly string[]): number;
}
export interface InMemoryTrustContext extends TrustContext, MemberStore {
    revokeSession(certificateId: string): void;
    setNow(clock: () => number): void;
}
export declare function createInMemoryTrustContext(options: InMemoryTrustContextOptions): InMemoryTrustContext;
