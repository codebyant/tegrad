import { type PublicKey, type SigningKeyPair } from "../crypto";
import { type SessionCertificate } from "./schemas";
/**
 * Longest validity the agent accepts for an elevated certificate. The launcher closes
 * the sudo window after a shorter idle time and drops the key; this cap is what holds
 * even against a client that keeps the key around.
 */
export declare const MAX_ELEVATED_SESSION_MS: number;
export interface SignSessionCertificateParams {
    readonly sessionPublicKey: PublicKey;
    readonly accountKeyPair: SigningKeyPair;
    readonly notBefore: number;
    readonly notAfter: number;
    readonly id?: string;
    readonly elevated?: boolean;
}
export interface VerifiedSessionCertificate {
    readonly certificate: SessionCertificate;
    readonly sessionPublicKey: PublicKey;
    readonly elevated: boolean;
}
export declare function signSessionCertificate(params: SignSessionCertificateParams): SessionCertificate;
export declare function verifySessionCertificate(certificate: unknown, accountPublicKey: PublicKey, atTime?: number): VerifiedSessionCertificate;
