import { type KdfPreset, type PublicKey, type SigningKeyPair } from "../crypto";
import type { KeyId } from "../protocol";
import { type VaultBlob } from "./blob";
export interface UnlockedVault {
    readonly account: KeyId;
    readonly publicKey: PublicKey;
    readonly keyPair: SigningKeyPair;
    lock(): void;
}
export interface CreateVaultParams {
    readonly password: string;
    readonly now?: number;
    readonly kdf?: KdfPreset;
    readonly userInputs?: readonly string[];
}
export interface CreateVaultResult {
    readonly blob: VaultBlob;
    readonly recoveryCode: string;
    readonly unlocked: UnlockedVault;
}
export interface ChangePasswordOptions {
    readonly now?: number;
    readonly kdf?: KdfPreset;
    readonly userInputs?: readonly string[];
}
export interface RotateRecoveryCodeResult {
    readonly blob: VaultBlob;
    readonly recoveryCode: string;
}
export declare function createVault(params: CreateVaultParams): CreateVaultResult;
export declare function unlockVault(blob: unknown, password: string): UnlockedVault;
export declare function unlockVaultWithRecovery(blob: unknown, recoveryCode: string): UnlockedVault;
export declare function withUnlockedVault<T>(blob: unknown, password: string, fn: (unlocked: UnlockedVault) => T | Promise<T>): Promise<T>;
export declare function changePassword(blob: unknown, oldPassword: string, newPassword: string, options?: ChangePasswordOptions): VaultBlob;
export declare function rotateRecoveryCode(blob: unknown, password: string): RotateRecoveryCodeResult;
export declare function resetPasswordWithRecovery(blob: unknown, recoveryCode: string, newPassword: string, options?: ChangePasswordOptions): VaultBlob;
