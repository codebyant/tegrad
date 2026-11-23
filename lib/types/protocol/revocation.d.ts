import { type PublicKey, type SigningKeyPair } from "../crypto";
import { type RevocationList } from "./schemas";
export interface SignRevocationListParams {
    readonly accountKeyPair: SigningKeyPair;
    readonly issuedAt: number;
    readonly revoked: readonly string[];
}
export declare function signRevocationList(params: SignRevocationListParams): RevocationList;
export declare function verifyRevocationList(list: unknown, accountPublicKey: PublicKey): RevocationList;
