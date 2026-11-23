import { type PublicKey, type SigningKeyPair } from "../crypto";
import { type SessionCertificate } from "./schemas";
export interface SignSessionCertificateParams {
    readonly sessionPublicKey: PublicKey;
    readonly accountKeyPair: SigningKeyPair;
    readonly notBefore: number;
    readonly notAfter: number;
    readonly id?: string;
}
export interface VerifiedSessionCertificate {
    readonly certificate: SessionCertificate;
    readonly sessionPublicKey: PublicKey;
}
export declare function signSessionCertificate(params: SignSessionCertificateParams): SessionCertificate;
export declare function verifySessionCertificate(certificate: unknown, accountPublicKey: PublicKey, atTime?: number): VerifiedSessionCertificate;
