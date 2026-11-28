export type VaultErrorCode = "weak_password" | "wrong_password" | "unlock_failed" | "invalid_blob" | "invalid_recovery_code" | "locked" | "invalid_session";
export declare class VaultError extends Error {
    readonly code: VaultErrorCode;
    constructor(code: VaultErrorCode, message: string);
}
