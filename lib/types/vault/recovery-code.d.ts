export declare const RECOVERY_CODE_BYTES = 32;
export declare function generateRecoveryCodeBytes(): Uint8Array;
export declare function formatRecoveryCode(bytes: Uint8Array): string;
export declare function parseRecoveryCode(code: string): Uint8Array;
export declare function deriveRecoveryKey(codeBytes: Uint8Array): Uint8Array;
