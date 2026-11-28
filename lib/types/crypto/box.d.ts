import { type PublicKey, type SigningKeyPair } from "./signing";
export declare function sealTo(plaintext: Uint8Array, recipientSigningPublicKey: PublicKey): Uint8Array;
export declare function openSealed(ciphertext: Uint8Array, recipientSigningKeyPair: SigningKeyPair): Uint8Array;
