import sodium from "libsodium-wrappers-sumo";
export declare function ready(): Promise<void>;
export declare function getSodium(): typeof sodium;
export declare function randomBytes(length: number): Uint8Array;
export declare function memzero(buffer: Uint8Array): void;
