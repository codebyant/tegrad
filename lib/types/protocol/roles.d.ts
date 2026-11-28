import { z } from "zod";
import { type PublicKey, type SigningKeyPair } from "../crypto";
import { type KeyId } from "./schemas";
export declare const ROLES: readonly ["viewer", "operator", "editor", "admin", "owner"];
export type Role = (typeof ROLES)[number];
export declare const roleSchema: z.ZodEnum<{
    admin: "admin";
    editor: "editor";
    operator: "operator";
    owner: "owner";
    viewer: "viewer";
}>;
export declare const GRANTABLE_ROLES: readonly ["viewer", "operator", "editor", "admin"];
export type GrantableRole = (typeof GRANTABLE_ROLES)[number];
export declare const grantableRoleSchema: z.ZodEnum<{
    admin: "admin";
    editor: "editor";
    operator: "operator";
    viewer: "viewer";
}>;
export declare const ROLE_LEVEL: Readonly<Record<Role, number>>;
export declare function roleAtLeast(role: Role | null | undefined, minimum: Role): boolean;
export declare function maxRole<T extends Role>(a: T | null, b: T | null): T | null;
export declare const ALL_SERVERS: "*";
export declare const MAX_GRANT_SERVERS = 256;
export declare const MAX_MEMBERS = 64;
export declare const roleGrantSchema: z.ZodObject<{
    v: z.ZodLiteral<1>;
    kind: z.ZodLiteral<"server-role">;
    account_key: z.ZodString;
    agent: z.ZodString;
    servers: z.ZodUnion<readonly [z.ZodLiteral<"*">, z.ZodArray<z.ZodString>]>;
    role: z.ZodEnum<{
        admin: "admin";
        editor: "editor";
        operator: "operator";
        viewer: "viewer";
    }>;
    issued_at: z.ZodNumber;
    expires_at: z.ZodOptional<z.ZodNumber>;
    sig: z.ZodString;
}, z.core.$strict>;
export type RoleGrant = z.infer<typeof roleGrantSchema>;
export declare const MAX_GRANT_CLOCK_SKEW_MS: number;
export interface SignRoleGrantParams {
    readonly granter: SigningKeyPair;
    readonly accountPublicKey: PublicKey;
    readonly agent: KeyId;
    readonly servers: readonly string[] | typeof ALL_SERVERS;
    readonly role: GrantableRole;
    readonly issuedAt: number;
    readonly expiresAt?: number;
}
export declare function signRoleGrant(params: SignRoleGrantParams): RoleGrant;
export interface VerifyRoleGrantOptions {
    readonly agent: KeyId;
    readonly now: number;
}
export interface VerifiedRoleGrant {
    readonly grant: RoleGrant;
    readonly accountPublicKey: PublicKey;
    readonly accountId: KeyId;
}
export declare function verifyRoleGrant(grant: unknown, granterPublicKey: PublicKey, options: VerifyRoleGrantOptions): VerifiedRoleGrant;
/** A role grant that an agent has accepted, as kept in its member table. */
export declare const memberEntrySchema: z.ZodObject<{
    account_key: z.ZodString;
    account: z.ZodString;
    granted_by: z.ZodString;
    role: z.ZodEnum<{
        admin: "admin";
        editor: "editor";
        operator: "operator";
        viewer: "viewer";
    }>;
    servers: z.ZodUnion<readonly [z.ZodLiteral<"*">, z.ZodArray<z.ZodString>]>;
    issued_at: z.ZodNumber;
    expires_at: z.ZodOptional<z.ZodNumber>;
}, z.core.$strict>;
export type MemberEntry = z.infer<typeof memberEntrySchema>;
/**
 * Member-table logic shared by the in-memory and the file-backed trust
 * contexts. Owners are not members: they come from the trust list.
 */
export declare class RoleTable {
    #private;
    constructor(entries?: readonly MemberEntry[]);
    entries(): readonly MemberEntry[];
    accountCount(): number;
    keyFor(account: KeyId, now: number): PublicKey | null;
    /**
     * Role of `account` on `serverId`. Agent-level scope (`"*"`) resolves to the
     * highest role granted on all servers; an account that only has per-server
     * grants gets `viewer` there, which allows agent-level reads (what they
     * return is filtered per server).
     */
    roleFor(account: KeyId, serverId: string, now: number): GrantableRole | null;
    set(entry: MemberEntry): void;
    /**
     * Removes grants of `account`. Without `servers`, all of them. With
     * `servers`, those ids are removed from per-server grants; a grant that
     * covers all servers is only removed by a revoke without `servers`.
     * Returns how many grants were changed or removed.
     */
    revoke(account: KeyId, servers?: readonly string[]): number;
}
