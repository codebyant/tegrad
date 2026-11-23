export declare const SYMMETRIC_KEY_BYTES = 32;
export declare const AEAD_NONCE_BYTES = 24;
export declare const AEAD_TAG_BYTES = 16;
export declare function generateSymmetricKey(): Uint8Array;
export declare function aeadEncrypt(plaintext: Uint8Array, key: Uint8Array, associatedData?: Uint8Array): Uint8Array;
export declare function aeadDecrypt(ciphertext: Uint8Array, key: Uint8Array, associatedData?: Uint8Array): Uint8Array;
