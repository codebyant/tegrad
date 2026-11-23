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
