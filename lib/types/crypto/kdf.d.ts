export declare const KDF_ALG_ARGON2ID13: "argon2id13";
export declare const KDF_SALT_BYTES = 16;
export declare const KDF_KEY_BYTES = 32;
export interface KdfPreset {
    readonly alg: typeof KDF_ALG_ARGON2ID13;
    readonly opslimit: number;
    readonly memlimit: number;
}
export interface KdfParams extends KdfPreset {
    readonly salt: Uint8Array;
}
export declare const KDF_FLOOR: KdfPreset;
export declare const KDF_MODERATE: KdfPreset;
export declare function generateSalt(): Uint8Array;
export declare function assertKdfParams(params: unknown): asserts params is KdfParams;
export declare function deriveKeyFromPassword(password: string | Uint8Array, params: KdfParams, keyLength?: number): Uint8Array;
