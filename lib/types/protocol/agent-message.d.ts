import { z } from "zod";
import { type PublicKey, type SigningKeyPair } from "../crypto";
import { type AgentMessage, type AgentMessageHeader } from "./schemas";
export interface SealAgentMessageParams {
    readonly type: string;
    readonly body: unknown;
    readonly agentKeyPair: SigningKeyPair;
    readonly recipientPublicKey: PublicKey;
    readonly sentAt: number;
    readonly seq: number;
    readonly id?: string;
}
export interface OpenedAgentMessage {
    readonly header: AgentMessageHeader;
    readonly body: unknown;
}
export declare function sealAgentMessage(params: SealAgentMessageParams): AgentMessage;
export declare function openAgentMessage(message: unknown, agentPublicKey: PublicKey, recipientKeyPair: SigningKeyPair): OpenedAgentMessage;
export interface AgentEventBody {
    readonly in_reply_to?: string;
    readonly data: unknown;
}
export declare const agentEventBodySchema: z.ZodObject<{
    in_reply_to: z.ZodOptional<z.ZodString>;
    data: z.ZodUnknown;
}, z.core.$strip>;
/** Builds the decrypted body every agent event carries: `{ in_reply_to?, data }`. */
export declare function wrapEventBody(inReplyTo: string | undefined, data: unknown): AgentEventBody;
export interface OpenedAgentEvent {
    readonly header: AgentMessageHeader;
    readonly inReplyTo: string | null;
    readonly data: unknown;
}
/** Opens an agent message and unwraps the `{ in_reply_to?, data }` event body. */
export declare function openAgentEvent(message: unknown, agentPublicKey: PublicKey, recipientKeyPair: SigningKeyPair): OpenedAgentEvent;
