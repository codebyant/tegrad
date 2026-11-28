export declare const SIGNING_PUBLIC_KEY_BYTES = 32;
export declare const SIGNING_SECRET_KEY_BYTES = 64;
export declare const SIGNING_SEED_BYTES = 32;
export declare const SIGNATURE_BYTES = 64;
export declare const FINGERPRINT_HASH_BYTES = 32;
export declare const FINGERPRINT_TRUNCATED_BYTES = 20;
export type PublicKey = Uint8Array;
export type SecretKey = Uint8Array;
export interface SigningKeyPair {
    readonly publicKey: PublicKey;
    readonly secretKey: SecretKey;
}
export declare function generateSigningKeyPair(): SigningKeyPair;
export declare function signingKeyPairFromSeed(seed: Uint8Array): SigningKeyPair;
export declare function sign(message: Uint8Array, secretKey: SecretKey): Uint8Array;
export declare function verify(message: Uint8Array, signature: Uint8Array, publicKey: PublicKey): boolean;
export declare function fingerprint(publicKey: PublicKey): string;
