import { z } from "zod";
import { type KdfParams } from "../crypto";
import { type KeyId } from "../protocol";
export declare const VAULT_VERSION: 1;
export declare const vaultKdfSchema: z.ZodObject<{
    alg: z.ZodLiteral<"argon2id13">;
    opslimit: z.ZodNumber;
    memlimit: z.ZodNumber;
    salt: z.ZodString;
}, z.core.$strip>;
export declare const vaultBlobSchema: z.ZodObject<{
    v: z.ZodLiteral<1>;
    account: z.ZodString;
    public_key: z.ZodString;
    created_at: z.ZodNumber;
    password: z.ZodObject<{
        kdf: z.ZodObject<{
            alg: z.ZodLiteral<"argon2id13">;
            opslimit: z.ZodNumber;
            memlimit: z.ZodNumber;
            salt: z.ZodString;
        }, z.core.$strip>;
        wrapped_secret: z.ZodString;
    }, z.core.$strip>;
    recovery: z.ZodObject<{
        wrapped_secret: z.ZodString;
    }, z.core.$strip>;
}, z.core.$strip>;
export type VaultKdf = z.infer<typeof vaultKdfSchema>;
export type VaultBlob = z.infer<typeof vaultBlobSchema>;
export interface ParsedVaultBlob {
    readonly blob: VaultBlob;
    readonly publicKeyBytes: Uint8Array;
    readonly kdfParams: KdfParams;
    readonly passwordWrapped: Uint8Array;
    readonly recoveryWrapped: Uint8Array;
}
export declare function parseVaultBlob(input: unknown): ParsedVaultBlob;
export declare function buildPasswordAad(fields: {
    readonly v: typeof VAULT_VERSION;
    readonly account: KeyId;
    readonly public_key: string;
    readonly kdf: VaultKdf;
}): Uint8Array;
export declare function buildRecoveryAad(fields: {
    readonly v: typeof VAULT_VERSION;
    readonly account: KeyId;
    readonly public_key: string;
}): Uint8Array;
