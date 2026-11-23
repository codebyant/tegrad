import { type PublicKey, type SigningKeyPair } from "../crypto";
import { type KeyId, type TransportFrame } from "./schemas";
export declare const AGENT_AUTH_MAX_SKEW_MS = 60000;
export declare const AGENT_HTTP_MAX_SKEW_MS = 60000;
export declare const AGENT_HTTP_HEADER_AGENT = "X-Tegra-Agent";
export declare const AGENT_HTTP_HEADER_TS = "X-Tegra-Ts";
export declare const AGENT_HTTP_HEADER_SIG = "X-Tegra-Sig";
export type HelloFrame = Extract<TransportFrame, {
    kind: "hello";
}>;
export type AuthFrame = Extract<TransportFrame, {
    kind: "auth";
}>;
/** Fresh nonce for a `hello` frame. */
export declare function generateAgentNonce(): string;
export declare function createHelloFrame(params: {
    readonly agent: KeyId;
    readonly serverTime: number;
    readonly nonce?: string;
}): HelloFrame;
/** Agent side: answers the API's `hello` challenge. */
export declare function signAgentAuth(params: {
    readonly agentKeyPair: SigningKeyPair;
    readonly hello: unknown;
    readonly ts: number;
}): AuthFrame;
export interface VerifyAgentAuthOptions {
    readonly agentPublicKey: PublicKey;
    /** The nonce the API sent in `hello` for this connection. */
    readonly expectedNonce: string;
    readonly now: number;
    readonly maxSkewMs?: number;
    /** Nonces already accepted; a repeated nonce is refused and a new one is recorded. */
    readonly usedNonces?: Set<string>;
}
/** API side: checks an `auth` frame against the challenge that was issued. */
export declare function verifyAgentAuth(frame: unknown, options: VerifyAgentAuthOptions): AuthFrame;
export type AgentRequestBody = Uint8Array | string | null | undefined;
export interface SignAgentRequestParams {
    readonly agentKeyPair: SigningKeyPair;
    readonly method: string;
    /** Request path including the query string, exactly as sent on the wire. */
    readonly pathWithQuery: string;
    readonly body?: AgentRequestBody;
    readonly ts: number;
}
/** Returns the `X-Tegra-Agent`, `X-Tegra-Ts` and `X-Tegra-Sig` headers. */
export declare function signAgentRequest(params: SignAgentRequestParams): Record<string, string>;
export interface VerifyAgentRequestParams {
    /** Case-insensitive header lookup (e.g. `(name) => request.headers.get(name)`). */
    readonly getHeader: (name: string) => string | null | undefined;
    readonly method: string;
    readonly pathWithQuery: string;
    readonly body?: AgentRequestBody;
    readonly agentPublicKey: PublicKey;
    readonly now: number;
    readonly maxSkewMs?: number;
}
export declare function verifyAgentRequest(params: VerifyAgentRequestParams): {
    readonly agent: KeyId;
};
