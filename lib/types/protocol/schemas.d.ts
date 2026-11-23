import { z } from "zod";
export declare const keyIdSchema: z.ZodString;
export type KeyId = z.infer<typeof keyIdSchema>;
export declare const base64UrlSchema: z.ZodString;
export declare const sessionCertificateSchema: z.ZodObject<{
    v: z.ZodLiteral<1>;
    session_key: z.ZodString;
    account: z.ZodString;
    not_before: z.ZodNumber;
    not_after: z.ZodNumber;
    id: z.ZodString;
    sig: z.ZodString;
}, z.core.$strip>;
export type SessionCertificate = z.infer<typeof sessionCertificateSchema>;
export declare const commandHeaderSchema: z.ZodObject<{
    v: z.ZodLiteral<1>;
    id: z.ZodString;
    type: z.ZodString;
    agent: z.ZodString;
    signer: z.ZodString;
    issued_at: z.ZodNumber;
    expires_at: z.ZodNumber;
    counter: z.ZodNumber;
}, z.core.$strip>;
export type CommandHeader = z.infer<typeof commandHeaderSchema>;
export declare const signedCommandSchema: z.ZodObject<{
    header: z.ZodObject<{
        v: z.ZodLiteral<1>;
        id: z.ZodString;
        type: z.ZodString;
        agent: z.ZodString;
        signer: z.ZodString;
        issued_at: z.ZodNumber;
        expires_at: z.ZodNumber;
        counter: z.ZodNumber;
    }, z.core.$strip>;
    payload: z.ZodString;
    session: z.ZodOptional<z.ZodObject<{
        v: z.ZodLiteral<1>;
        session_key: z.ZodString;
        account: z.ZodString;
        not_before: z.ZodNumber;
        not_after: z.ZodNumber;
        id: z.ZodString;
        sig: z.ZodString;
    }, z.core.$strip>>;
    sig: z.ZodString;
}, z.core.$strip>;
export type SignedCommand = z.infer<typeof signedCommandSchema>;
export declare const agentMessageHeaderSchema: z.ZodObject<{
    v: z.ZodLiteral<1>;
    id: z.ZodString;
    type: z.ZodString;
    agent: z.ZodString;
    recipient: z.ZodString;
    sent_at: z.ZodNumber;
    seq: z.ZodNumber;
}, z.core.$strip>;
export type AgentMessageHeader = z.infer<typeof agentMessageHeaderSchema>;
export declare const agentMessageSchema: z.ZodObject<{
    header: z.ZodObject<{
        v: z.ZodLiteral<1>;
        id: z.ZodString;
        type: z.ZodString;
        agent: z.ZodString;
        recipient: z.ZodString;
        sent_at: z.ZodNumber;
        seq: z.ZodNumber;
    }, z.core.$strip>;
    payload: z.ZodString;
    sig: z.ZodString;
}, z.core.$strip>;
export type AgentMessage = z.infer<typeof agentMessageSchema>;
export declare const revocationListSchema: z.ZodObject<{
    v: z.ZodLiteral<1>;
    account: z.ZodString;
    issued_at: z.ZodNumber;
    revoked: z.ZodArray<z.ZodString>;
    sig: z.ZodString;
}, z.core.$strip>;
export type RevocationList = z.infer<typeof revocationListSchema>;
export declare const transportCommandFrameSchema: z.ZodObject<{
    v: z.ZodLiteral<1>;
    kind: z.ZodLiteral<"command">;
    route: z.ZodObject<{
        agent: z.ZodString;
    }, z.core.$strip>;
    body: z.ZodObject<{
        header: z.ZodObject<{
            v: z.ZodLiteral<1>;
            id: z.ZodString;
            type: z.ZodString;
            agent: z.ZodString;
            signer: z.ZodString;
            issued_at: z.ZodNumber;
            expires_at: z.ZodNumber;
            counter: z.ZodNumber;
        }, z.core.$strip>;
        payload: z.ZodString;
        session: z.ZodOptional<z.ZodObject<{
            v: z.ZodLiteral<1>;
            session_key: z.ZodString;
            account: z.ZodString;
            not_before: z.ZodNumber;
            not_after: z.ZodNumber;
            id: z.ZodString;
            sig: z.ZodString;
        }, z.core.$strip>>;
        sig: z.ZodString;
    }, z.core.$strip>;
}, z.core.$strip>;
export declare const transportEventFrameSchema: z.ZodObject<{
    v: z.ZodLiteral<1>;
    kind: z.ZodLiteral<"event">;
    route: z.ZodObject<{
        agent: z.ZodString;
        recipient: z.ZodString;
    }, z.core.$strip>;
    body: z.ZodObject<{
        header: z.ZodObject<{
            v: z.ZodLiteral<1>;
            id: z.ZodString;
            type: z.ZodString;
            agent: z.ZodString;
            recipient: z.ZodString;
            sent_at: z.ZodNumber;
            seq: z.ZodNumber;
        }, z.core.$strip>;
        payload: z.ZodString;
        sig: z.ZodString;
    }, z.core.$strip>;
}, z.core.$strip>;
export declare const transportAckFrameSchema: z.ZodObject<{
    v: z.ZodLiteral<1>;
    kind: z.ZodLiteral<"ack">;
    route: z.ZodObject<{
        agent: z.ZodString;
    }, z.core.$strip>;
    body: z.ZodObject<{
        id: z.ZodString;
        ok: z.ZodBoolean;
        code: z.ZodOptional<z.ZodString>;
    }, z.core.$strip>;
}, z.core.$strip>;
export declare const transportPingFrameSchema: z.ZodObject<{
    v: z.ZodLiteral<1>;
    kind: z.ZodLiteral<"ping">;
    route: z.ZodObject<{
        agent: z.ZodString;
    }, z.core.$strip>;
    body: z.ZodObject<{
        ts: z.ZodNumber;
    }, z.core.$strip>;
}, z.core.$strip>;
export declare const transportFrameSchema: z.ZodDiscriminatedUnion<[z.ZodObject<{
    v: z.ZodLiteral<1>;
    kind: z.ZodLiteral<"command">;
    route: z.ZodObject<{
        agent: z.ZodString;
    }, z.core.$strip>;
    body: z.ZodObject<{
        header: z.ZodObject<{
            v: z.ZodLiteral<1>;
            id: z.ZodString;
            type: z.ZodString;
            agent: z.ZodString;
            signer: z.ZodString;
            issued_at: z.ZodNumber;
            expires_at: z.ZodNumber;
            counter: z.ZodNumber;
        }, z.core.$strip>;
        payload: z.ZodString;
        session: z.ZodOptional<z.ZodObject<{
            v: z.ZodLiteral<1>;
            session_key: z.ZodString;
            account: z.ZodString;
            not_before: z.ZodNumber;
            not_after: z.ZodNumber;
            id: z.ZodString;
            sig: z.ZodString;
        }, z.core.$strip>>;
        sig: z.ZodString;
    }, z.core.$strip>;
}, z.core.$strip>, z.ZodObject<{
    v: z.ZodLiteral<1>;
    kind: z.ZodLiteral<"event">;
    route: z.ZodObject<{
        agent: z.ZodString;
        recipient: z.ZodString;
    }, z.core.$strip>;
    body: z.ZodObject<{
        header: z.ZodObject<{
            v: z.ZodLiteral<1>;
            id: z.ZodString;
            type: z.ZodString;
            agent: z.ZodString;
            recipient: z.ZodString;
            sent_at: z.ZodNumber;
            seq: z.ZodNumber;
        }, z.core.$strip>;
        payload: z.ZodString;
        sig: z.ZodString;
    }, z.core.$strip>;
}, z.core.$strip>, z.ZodObject<{
    v: z.ZodLiteral<1>;
    kind: z.ZodLiteral<"ack">;
    route: z.ZodObject<{
        agent: z.ZodString;
    }, z.core.$strip>;
    body: z.ZodObject<{
        id: z.ZodString;
        ok: z.ZodBoolean;
        code: z.ZodOptional<z.ZodString>;
    }, z.core.$strip>;
}, z.core.$strip>, z.ZodObject<{
    v: z.ZodLiteral<1>;
    kind: z.ZodLiteral<"ping">;
    route: z.ZodObject<{
        agent: z.ZodString;
    }, z.core.$strip>;
    body: z.ZodObject<{
        ts: z.ZodNumber;
    }, z.core.$strip>;
}, z.core.$strip>], "kind">;
export type TransportFrame = z.infer<typeof transportFrameSchema>;
