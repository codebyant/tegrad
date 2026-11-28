import { z } from "zod";
import { type PublicKey, type SigningKeyPair } from "../crypto";
import { type KeyId } from "./schemas";
export declare const PAIRING_CODE_LENGTH = 10;
export declare const PAIRING_SECRET_BYTES = 16;
export declare const DEFAULT_TRUST_GRANT_TTL_MS: number;
export declare const MAX_TRUST_GRANT_TTL_MS: number;
export declare const pairingCodeSchema: z.ZodString;
export declare const trustGrantSchema: z.ZodObject<{
    v: z.ZodLiteral<1>;
    kind: z.ZodLiteral<"agent-pairing">;
    account_key: z.ZodString;
    agent: z.ZodString;
    issued_at: z.ZodNumber;
    expires_at: z.ZodNumber;
    proof: z.ZodOptional<z.ZodString>;
    sig: z.ZodString;
}, z.core.$strip>;
export type TrustGrant = z.infer<typeof trustGrantSchema>;
export interface PairingFragment {
    readonly code: string;
    readonly secret?: string;
    readonly agentFingerprint?: KeyId;
}
export interface BuildPairingFragmentParams {
    readonly code: string;
    readonly secret: string;
    readonly agentFingerprint: KeyId;
}
export interface SignTrustGrantParams {
    readonly accountKeyPair: SigningKeyPair;
    readonly agentPublicKey: PublicKey;
    readonly secret?: string | Uint8Array;
    readonly issuedAt: number;
    readonly ttlMs?: number;
}
export interface VerifyTrustGrantOptions {
    readonly agentPublicKey: PublicKey;
    readonly secret?: string | Uint8Array;
    readonly now: number;
    readonly requireProof: boolean;
}
export interface VerifiedTrustGrant {
    readonly accountPublicKey: PublicKey;
    readonly accountId: KeyId;
    readonly proven: boolean;
}
export declare function generatePairingCode(): string;
export declare function generatePairingSecret(): string;
export declare function buildPairingFragment(params: BuildPairingFragmentParams): string;
export declare function parsePairingFragment(text: string): PairingFragment;
export declare function signTrustGrant(params: SignTrustGrantParams): TrustGrant;
export declare function verifyTrustGrant(grant: unknown, options: VerifyTrustGrantOptions): VerifiedTrustGrant;
