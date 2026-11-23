import {
  HASH_BYTES,
  SIGNING_PUBLIC_KEY_BYTES,
  canonicalize,
  fingerprint,
  fromBase64Url,
  hash,
  openSealed,
  randomBytes,
  sealTo,
  sha256,
  sign,
  toBase64Url,
  verify
} from "./index-g1frygvt.js";

// src/protocol/errors.ts
class ProtocolError extends Error {
  code;
  constructor(code, message) {
    super(message);
    this.name = "ProtocolError";
    this.code = code;
  }
}

// src/protocol/domains.ts
var PROTOCOL_VERSION = 1;
var utf8Encoder = new TextEncoder;
var DOMAIN_COMMAND = utf8Encoder.encode("tegrad/command/v1\x00");
var DOMAIN_SESSION = utf8Encoder.encode("tegrad/session/v1\x00");
var DOMAIN_AGENT_MESSAGE = utf8Encoder.encode("tegrad/agent-message/v1\x00");
var DOMAIN_REVOCATION = utf8Encoder.encode("tegrad/revocation/v1\x00");
var DOMAIN_TRUST_GRANT = utf8Encoder.encode("tegrad/trust-grant/v1\x00");
var DOMAIN_PAIRING_PROOF = utf8Encoder.encode("tegrad/pairing-proof/v1\x00");
var DOMAIN_AGENT_AUTH = utf8Encoder.encode("tegrad/agent-auth/v1\x00");
var DOMAIN_AGENT_HTTP = utf8Encoder.encode("tegrad/agent-http/v1\x00");
var DOMAIN_ROLE_GRANT = utf8Encoder.encode("tegrad/role-grant/v1\x00");
function concatBytes(...parts) {
  let total = 0;
  for (const part of parts) {
    total += part.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
function assertSupportedVersion(value) {
  if (typeof value === "object" && value !== null && "v" in value) {
    const version = value.v;
    if (version !== PROTOCOL_VERSION) {
      throw new ProtocolError("unsupported_version", "Unsupported protocol version");
    }
  }
}

// src/protocol/schemas.ts
import { z } from "zod";
var keyIdSchema = z.string().regex(/^[a-z2-7]{32}$/, "Invalid KeyId");
var base64UrlSchema = z.string().min(1).regex(/^[A-Za-z0-9_-]+$/, "Invalid base64url");
var sessionCertificateSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  session_key: base64UrlSchema,
  account: keyIdSchema,
  not_before: z.number().int().nonnegative(),
  not_after: z.number().int().nonnegative(),
  id: base64UrlSchema,
  sig: base64UrlSchema
});
var commandHeaderSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  id: base64UrlSchema,
  type: z.string().min(1),
  agent: keyIdSchema,
  signer: keyIdSchema,
  issued_at: z.number().int().nonnegative(),
  expires_at: z.number().int().nonnegative(),
  counter: z.number().int().nonnegative(),
  reply_to: base64UrlSchema.optional()
});
var signedCommandSchema = z.object({
  header: commandHeaderSchema,
  payload: base64UrlSchema,
  session: sessionCertificateSchema.optional(),
  sig: base64UrlSchema
});
var agentMessageHeaderSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  id: base64UrlSchema,
  type: z.string().min(1),
  agent: keyIdSchema,
  recipient: keyIdSchema,
  sent_at: z.number().int().nonnegative(),
  seq: z.number().int().nonnegative()
});
var agentMessageSchema = z.object({
  header: agentMessageHeaderSchema,
  payload: base64UrlSchema,
  sig: base64UrlSchema
});
var revocationListSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  account: keyIdSchema,
  issued_at: z.number().int().nonnegative(),
  revoked: z.array(base64UrlSchema),
  sig: base64UrlSchema
});
var transportCommandFrameSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  kind: z.literal("command"),
  route: z.object({
    agent: keyIdSchema
  }),
  body: signedCommandSchema
});
var transportEventFrameSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  kind: z.literal("event"),
  route: z.object({
    agent: keyIdSchema,
    recipient: keyIdSchema
  }),
  body: agentMessageSchema
});
var transportAckFrameSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  kind: z.literal("ack"),
  route: z.object({
    agent: keyIdSchema
  }),
  body: z.object({
    id: base64UrlSchema,
    ok: z.boolean(),
    code: z.string().optional()
  })
});
var transportPingFrameSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  kind: z.literal("ping"),
  route: z.object({
    agent: keyIdSchema
  }),
  body: z.object({
    ts: z.number().int().nonnegative()
  })
});
var AGENT_NONCE_BYTES = 32;
var agentNonceSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/, "Invalid nonce (expected 32 bytes in base64url)");
var transportHelloFrameSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  kind: z.literal("hello"),
  route: z.object({
    agent: keyIdSchema
  }),
  body: z.object({
    nonce: agentNonceSchema,
    server_time: z.number().int().nonnegative()
  })
});
var transportAuthFrameSchema = z.object({
  v: z.literal(PROTOCOL_VERSION),
  kind: z.literal("auth"),
  route: z.object({
    agent: keyIdSchema
  }),
  body: z.object({
    nonce: agentNonceSchema,
    ts: z.number().int().nonnegative(),
    sig: base64UrlSchema
  })
});
var transportFrameSchema = z.discriminatedUnion("kind", [
  transportHelloFrameSchema,
  transportAuthFrameSchema,
  transportCommandFrameSchema,
  transportEventFrameSchema,
  transportAckFrameSchema,
  transportPingFrameSchema
]);

// src/protocol/agent-auth.ts
var AGENT_AUTH_MAX_SKEW_MS = 60000;
var AGENT_HTTP_MAX_SKEW_MS = 60000;
var AGENT_HTTP_HEADER_AGENT = "X-Tegra-Agent";
var AGENT_HTTP_HEADER_TS = "X-Tegra-Ts";
var AGENT_HTTP_HEADER_SIG = "X-Tegra-Sig";
var utf8Encoder2 = new TextEncoder;
function toHex(bytes) {
  let out = "";
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, "0");
  }
  return out;
}
function generateAgentNonce() {
  return toBase64Url(randomBytes(AGENT_NONCE_BYTES));
}
function createHelloFrame(params) {
  return transportHelloFrameSchema.parse({
    v: PROTOCOL_VERSION,
    kind: "hello",
    route: { agent: params.agent },
    body: { nonce: params.nonce ?? generateAgentNonce(), server_time: params.serverTime }
  });
}
function authSigningInput(agent, nonce, ts) {
  return concatBytes(DOMAIN_AGENT_AUTH, canonicalize({ agent, nonce, ts }));
}
function signAgentAuth(params) {
  const parsed = transportHelloFrameSchema.safeParse(params.hello);
  if (!parsed.success) {
    throw new ProtocolError("invalid_format", "Malformed hello frame");
  }
  const agent = fingerprint(params.agentKeyPair.publicKey);
  if (parsed.data.route.agent !== agent) {
    throw new ProtocolError("wrong_agent", "Hello frame is addressed to a different agent");
  }
  const nonce = parsed.data.body.nonce;
  const signature = sign(authSigningInput(agent, nonce, params.ts), params.agentKeyPair.secretKey);
  return transportAuthFrameSchema.parse({
    v: PROTOCOL_VERSION,
    kind: "auth",
    route: { agent },
    body: { nonce, ts: params.ts, sig: toBase64Url(signature) }
  });
}
function verifyAgentAuth(frame, options) {
  const parsed = transportAuthFrameSchema.safeParse(frame);
  if (!parsed.success) {
    throw new ProtocolError("invalid_format", "Malformed auth frame");
  }
  const { route, body } = parsed.data;
  const agent = fingerprint(options.agentPublicKey);
  if (route.agent !== agent) {
    throw new ProtocolError("wrong_agent", "Auth frame is addressed to a different agent");
  }
  if (!agentNonceSchema.safeParse(options.expectedNonce).success) {
    throw new ProtocolError("auth_invalid", "Invalid challenge nonce");
  }
  if (body.nonce !== options.expectedNonce) {
    throw new ProtocolError("auth_invalid", "Auth nonce does not match the challenge");
  }
  if (options.usedNonces?.has(body.nonce)) {
    throw new ProtocolError("replayed", "Auth nonce was already used");
  }
  const maxSkew = options.maxSkewMs ?? AGENT_AUTH_MAX_SKEW_MS;
  if (Math.abs(options.now - body.ts) > maxSkew) {
    throw new ProtocolError("auth_invalid", "Auth timestamp is outside the allowed window");
  }
  let signatureBytes;
  try {
    signatureBytes = fromBase64Url(body.sig);
  } catch {
    throw new ProtocolError("bad_signature", "Invalid auth signature encoding");
  }
  if (!verify(authSigningInput(agent, body.nonce, body.ts), signatureBytes, options.agentPublicKey)) {
    throw new ProtocolError("bad_signature", "Invalid auth signature");
  }
  options.usedNonces?.add(body.nonce);
  return parsed.data;
}
function bodyBytes(body) {
  if (body === null || body === undefined) {
    return new Uint8Array(0);
  }
  return typeof body === "string" ? utf8Encoder2.encode(body) : body;
}
function httpSigningInput(method, pathWithQuery, body, ts) {
  const bodyHash = toHex(sha256(bodyBytes(body)));
  return concatBytes(DOMAIN_AGENT_HTTP, utf8Encoder2.encode(`${method.toUpperCase()}
${pathWithQuery}
${bodyHash}
${ts}`));
}
function signAgentRequest(params) {
  if (!params.pathWithQuery.startsWith("/")) {
    throw new RangeError("pathWithQuery must start with /");
  }
  const signature = sign(httpSigningInput(params.method, params.pathWithQuery, params.body, params.ts), params.agentKeyPair.secretKey);
  return {
    [AGENT_HTTP_HEADER_AGENT]: fingerprint(params.agentKeyPair.publicKey),
    [AGENT_HTTP_HEADER_TS]: String(params.ts),
    [AGENT_HTTP_HEADER_SIG]: toBase64Url(signature)
  };
}
function verifyAgentRequest(params) {
  const agentHeader = params.getHeader(AGENT_HTTP_HEADER_AGENT);
  const tsHeader = params.getHeader(AGENT_HTTP_HEADER_TS);
  const sigHeader = params.getHeader(AGENT_HTTP_HEADER_SIG);
  if (!agentHeader || !tsHeader || !sigHeader) {
    throw new ProtocolError("request_invalid", "Missing agent signature headers");
  }
  const agent = keyIdSchema.safeParse(agentHeader);
  if (!agent.success || agent.data !== fingerprint(params.agentPublicKey)) {
    throw new ProtocolError("wrong_agent", "Request signed by a different agent");
  }
  if (!/^\d{1,16}$/.test(tsHeader)) {
    throw new ProtocolError("request_invalid", "Invalid request timestamp");
  }
  const ts = Number(tsHeader);
  const maxSkew = params.maxSkewMs ?? AGENT_HTTP_MAX_SKEW_MS;
  if (ts < params.now - maxSkew) {
    throw new ProtocolError("expired", "Request timestamp is too old");
  }
  if (ts > params.now + maxSkew) {
    throw new ProtocolError("not_yet_valid", "Request timestamp is in the future");
  }
  let signatureBytes;
  try {
    signatureBytes = fromBase64Url(sigHeader);
  } catch {
    throw new ProtocolError("bad_signature", "Invalid request signature encoding");
  }
  const input = httpSigningInput(params.method, params.pathWithQuery, params.body, ts);
  if (!verify(input, signatureBytes, params.agentPublicKey)) {
    throw new ProtocolError("bad_signature", "Invalid request signature");
  }
  return { agent: agent.data };
}
// src/protocol/agent-message.ts
import { z as z2 } from "zod";
var utf8Decoder = new TextDecoder("utf-8", { fatal: true });
function sealAgentMessage(params) {
  const header = {
    v: PROTOCOL_VERSION,
    id: params.id ?? toBase64Url(randomBytes(16)),
    type: params.type,
    agent: fingerprint(params.agentKeyPair.publicKey),
    recipient: fingerprint(params.recipientPublicKey),
    sent_at: params.sentAt,
    seq: params.seq
  };
  const payloadBytes = sealTo(canonicalize(params.body), params.recipientPublicKey);
  const signingInput = concatBytes(DOMAIN_AGENT_MESSAGE, canonicalize(header), payloadBytes);
  const signature = sign(signingInput, params.agentKeyPair.secretKey);
  return {
    header,
    payload: toBase64Url(payloadBytes),
    sig: toBase64Url(signature)
  };
}
function openAgentMessage(message, agentPublicKey, recipientKeyPair) {
  if (typeof message === "object" && message !== null && "header" in message) {
    assertSupportedVersion(message.header);
  }
  const parsed = agentMessageSchema.safeParse(message);
  if (!parsed.success) {
    throw new ProtocolError("invalid_format", "Malformed agent message");
  }
  const { header, payload, sig } = parsed.data;
  if (header.agent !== fingerprint(agentPublicKey)) {
    throw new ProtocolError("wrong_agent", "Agent message sender mismatch");
  }
  if (header.recipient !== fingerprint(recipientKeyPair.publicKey)) {
    throw new ProtocolError("wrong_recipient", "Agent message recipient mismatch");
  }
  let payloadBytes;
  try {
    payloadBytes = fromBase64Url(payload);
  } catch {
    throw new ProtocolError("invalid_format", "Invalid payload encoding");
  }
  let signatureBytes;
  try {
    signatureBytes = fromBase64Url(sig);
  } catch {
    throw new ProtocolError("bad_signature", "Invalid signature encoding");
  }
  const signingInput = concatBytes(DOMAIN_AGENT_MESSAGE, canonicalize(header), payloadBytes);
  if (!verify(signingInput, signatureBytes, agentPublicKey)) {
    throw new ProtocolError("bad_signature", "Invalid agent message signature");
  }
  let plaintext;
  try {
    plaintext = openSealed(payloadBytes, recipientKeyPair);
  } catch {
    throw new ProtocolError("decrypt_failed", "Failed to decrypt agent message payload");
  }
  let body;
  try {
    body = JSON.parse(utf8Decoder.decode(plaintext));
  } catch {
    throw new ProtocolError("invalid_body", "Agent message payload is not valid JSON");
  }
  return { header, body };
}
var agentEventBodySchema = z2.object({
  in_reply_to: base64UrlSchema.optional(),
  data: z2.unknown()
});
function wrapEventBody(inReplyTo, data) {
  return {
    ...inReplyTo !== undefined ? { in_reply_to: inReplyTo } : {},
    data
  };
}
function openAgentEvent(message, agentPublicKey, recipientKeyPair) {
  const opened = openAgentMessage(message, agentPublicKey, recipientKeyPair);
  const parsed = agentEventBodySchema.safeParse(opened.body);
  if (!parsed.success || typeof opened.body !== "object" || opened.body === null) {
    throw new ProtocolError("invalid_body", "Agent event body is malformed");
  }
  if (!("data" in opened.body)) {
    throw new ProtocolError("invalid_body", "Agent event body has no data");
  }
  return {
    header: opened.header,
    inReplyTo: parsed.data.in_reply_to ?? null,
    data: parsed.data.data
  };
}
// src/protocol/roles.ts
import { z as z3 } from "zod";
var ROLES = ["viewer", "operator", "editor", "admin", "owner"];
var roleSchema = z3.enum(ROLES);
var GRANTABLE_ROLES = ["viewer", "operator", "editor", "admin"];
var grantableRoleSchema = z3.enum(GRANTABLE_ROLES);
var ROLE_LEVEL = {
  viewer: 1,
  operator: 2,
  editor: 3,
  admin: 4,
  owner: 5
};
function roleAtLeast(role, minimum) {
  return role !== null && role !== undefined && ROLE_LEVEL[role] >= ROLE_LEVEL[minimum];
}
function maxRole(a, b) {
  if (a === null)
    return b;
  if (b === null)
    return a;
  return ROLE_LEVEL[a] >= ROLE_LEVEL[b] ? a : b;
}
var ALL_SERVERS = "*";
var MAX_GRANT_SERVERS = 256;
var MAX_MEMBERS = 64;
var grantServerIdSchema = z3.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/, "Invalid server id");
var grantServersSchema = z3.union([
  z3.literal(ALL_SERVERS),
  z3.array(grantServerIdSchema).min(1).max(MAX_GRANT_SERVERS)
]);
var roleGrantSchema = z3.object({
  v: z3.literal(PROTOCOL_VERSION),
  kind: z3.literal("server-role"),
  account_key: base64UrlSchema,
  agent: keyIdSchema,
  servers: grantServersSchema,
  role: grantableRoleSchema,
  issued_at: z3.number().int().nonnegative(),
  expires_at: z3.number().int().nonnegative().optional(),
  sig: base64UrlSchema
}).strict();
var MAX_GRANT_CLOCK_SKEW_MS = 5 * 60 * 1000;
function signRoleGrant(params) {
  if (params.accountPublicKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new RangeError(`Account public key must be ${SIGNING_PUBLIC_KEY_BYTES} bytes`);
  }
  if (!Number.isSafeInteger(params.issuedAt) || params.issuedAt < 0) {
    throw new RangeError("issuedAt must be a non-negative safe integer");
  }
  if (params.expiresAt !== undefined && (!Number.isSafeInteger(params.expiresAt) || params.expiresAt <= params.issuedAt)) {
    throw new RangeError("expiresAt must be a safe integer after issuedAt");
  }
  const unsigned = {
    v: PROTOCOL_VERSION,
    kind: "server-role",
    account_key: toBase64Url(params.accountPublicKey),
    agent: params.agent,
    servers: params.servers === ALL_SERVERS ? ALL_SERVERS : [...params.servers],
    role: params.role,
    issued_at: params.issuedAt,
    ...params.expiresAt !== undefined ? { expires_at: params.expiresAt } : {}
  };
  const signingInput = concatBytes(DOMAIN_ROLE_GRANT, canonicalize(unsigned));
  const signature = sign(signingInput, params.granter.secretKey);
  return roleGrantSchema.parse({ ...unsigned, sig: toBase64Url(signature) });
}
function verifyRoleGrant(grant, granterPublicKey, options) {
  assertSupportedVersion(grant);
  const parsed = roleGrantSchema.safeParse(grant);
  if (!parsed.success) {
    throw new ProtocolError("role_grant_invalid", "Malformed role grant");
  }
  const data = parsed.data;
  if (data.agent !== options.agent) {
    throw new ProtocolError("role_grant_invalid", "Role grant is addressed to a different agent");
  }
  if (data.issued_at > options.now + MAX_GRANT_CLOCK_SKEW_MS) {
    throw new ProtocolError("role_grant_invalid", "Role grant issued_at is in the future");
  }
  if (data.expires_at !== undefined && data.expires_at <= data.issued_at) {
    throw new ProtocolError("role_grant_invalid", "Role grant expiry is not after issuance");
  }
  if (data.expires_at !== undefined && options.now >= data.expires_at) {
    throw new ProtocolError("role_grant_invalid", "Role grant has expired");
  }
  if (data.servers !== ALL_SERVERS && new Set(data.servers).size !== data.servers.length) {
    throw new ProtocolError("role_grant_invalid", "Role grant lists a server more than once");
  }
  let accountPublicKey;
  let signatureBytes;
  try {
    accountPublicKey = fromBase64Url(data.account_key);
    signatureBytes = fromBase64Url(data.sig);
  } catch {
    throw new ProtocolError("role_grant_invalid", "Invalid base64url encoding in role grant");
  }
  if (accountPublicKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new ProtocolError("role_grant_invalid", "Invalid account key length in role grant");
  }
  const { sig: _sig, ...unsigned } = data;
  const signingInput = concatBytes(DOMAIN_ROLE_GRANT, canonicalize(unsigned));
  if (!verify(signingInput, signatureBytes, granterPublicKey)) {
    throw new ProtocolError("role_grant_invalid", "Invalid role grant signature");
  }
  return { grant: data, accountPublicKey, accountId: fingerprint(accountPublicKey) };
}
var memberEntrySchema = z3.object({
  account_key: base64UrlSchema,
  account: keyIdSchema,
  granted_by: keyIdSchema,
  role: grantableRoleSchema,
  servers: grantServersSchema,
  issued_at: z3.number().int().nonnegative(),
  expires_at: z3.number().int().nonnegative().optional()
}).strict();
function scopeKey(servers) {
  return servers === ALL_SERVERS ? ALL_SERVERS : [...servers].sort().join(",");
}
function isActive(entry, now) {
  return entry.expires_at === undefined || now < entry.expires_at;
}

class RoleTable {
  #entries;
  constructor(entries = []) {
    this.#entries = [...entries];
  }
  entries() {
    return [...this.#entries];
  }
  accountCount() {
    return new Set(this.#entries.map((entry) => entry.account)).size;
  }
  keyFor(account, now) {
    for (const entry of this.#entries) {
      if (entry.account === account && isActive(entry, now)) {
        try {
          return fromBase64Url(entry.account_key);
        } catch {
          return null;
        }
      }
    }
    return null;
  }
  roleFor(account, serverId, now) {
    let best = null;
    let anyActive = false;
    for (const entry of this.#entries) {
      if (entry.account !== account || !isActive(entry, now)) {
        continue;
      }
      anyActive = true;
      const covers = entry.servers === ALL_SERVERS || serverId !== ALL_SERVERS && entry.servers.includes(serverId);
      if (covers) {
        best = maxRole(best, entry.role);
      }
    }
    if (best === null && serverId === ALL_SERVERS && anyActive) {
      return "viewer";
    }
    return best;
  }
  set(entry) {
    const key = scopeKey(entry.servers);
    const next = this.#entries.filter((existing) => !(existing.account === entry.account && scopeKey(existing.servers) === key));
    next.push(entry);
    this.#entries = next;
  }
  revoke(account, servers) {
    let changed = 0;
    const next = [];
    for (const entry of this.#entries) {
      if (entry.account !== account) {
        next.push(entry);
        continue;
      }
      if (servers === undefined) {
        changed++;
        continue;
      }
      if (entry.servers === ALL_SERVERS) {
        next.push(entry);
        continue;
      }
      const remaining = entry.servers.filter((id) => !servers.includes(id));
      if (remaining.length === entry.servers.length) {
        next.push(entry);
        continue;
      }
      changed++;
      if (remaining.length > 0) {
        next.push({ ...entry, servers: remaining });
      }
    }
    this.#entries = next;
    return changed;
  }
}

// src/protocol/session.ts
function signSessionCertificate(params) {
  if (params.sessionPublicKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new RangeError(`Session public key must be ${SIGNING_PUBLIC_KEY_BYTES} bytes`);
  }
  if (!Number.isSafeInteger(params.notBefore) || !Number.isSafeInteger(params.notAfter)) {
    throw new RangeError("Session validity timestamps must be safe integers");
  }
  if (params.notBefore < 0 || params.notAfter <= params.notBefore) {
    throw new RangeError("Invalid session certificate validity window");
  }
  const unsigned = {
    v: PROTOCOL_VERSION,
    session_key: toBase64Url(params.sessionPublicKey),
    account: fingerprint(params.accountKeyPair.publicKey),
    not_before: params.notBefore,
    not_after: params.notAfter,
    id: params.id ?? toBase64Url(randomBytes(16))
  };
  const signingInput = concatBytes(DOMAIN_SESSION, canonicalize(unsigned));
  const signature = sign(signingInput, params.accountKeyPair.secretKey);
  return {
    ...unsigned,
    sig: toBase64Url(signature)
  };
}
function verifySessionCertificate(certificate, accountPublicKey, atTime) {
  assertSupportedVersion(certificate);
  const parsed = sessionCertificateSchema.safeParse(certificate);
  if (!parsed.success) {
    throw new ProtocolError("session_invalid", "Malformed session certificate");
  }
  const cert = parsed.data;
  if (cert.account !== fingerprint(accountPublicKey)) {
    throw new ProtocolError("session_invalid", "Session certificate account mismatch");
  }
  if (cert.not_after <= cert.not_before) {
    throw new ProtocolError("session_invalid", "Session certificate has invalid validity window");
  }
  if (atTime !== undefined && (atTime < cert.not_before || atTime >= cert.not_after)) {
    throw new ProtocolError("session_invalid", "Session certificate is not valid at this time");
  }
  let sessionPublicKey;
  let signatureBytes;
  try {
    sessionPublicKey = fromBase64Url(cert.session_key);
    signatureBytes = fromBase64Url(cert.sig);
  } catch {
    throw new ProtocolError("session_invalid", "Invalid base64url encoding in session certificate");
  }
  if (sessionPublicKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new ProtocolError("session_invalid", "Invalid session public key length");
  }
  const { sig: _sig, ...unsigned } = cert;
  const signingInput = concatBytes(DOMAIN_SESSION, canonicalize(unsigned));
  if (!verify(signingInput, signatureBytes, accountPublicKey)) {
    throw new ProtocolError("session_invalid", "Invalid session certificate signature");
  }
  return {
    certificate: cert,
    sessionPublicKey
  };
}

// src/protocol/command.ts
var COMMAND_ID_BYTES = 16;
var DEFAULT_COMMAND_TTL_MS = 5 * 60 * 1000;
var MAX_COMMAND_TTL_MS = 10 * 60 * 1000;
var MAX_CLOCK_SKEW_MS = 30 * 1000;
var utf8Decoder2 = new TextDecoder("utf-8", { fatal: true });
function createSignedCommand(params, registry) {
  const definition = registry.get(params.type);
  if (!definition) {
    throw new ProtocolError("unknown_command", "Unknown command type");
  }
  const parsedBody = definition.body.safeParse(params.body);
  if (!parsedBody.success) {
    throw new ProtocolError("invalid_body", "Command body failed schema validation");
  }
  if (params.replyTo !== undefined && params.replyTo.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new RangeError(`replyTo must be ${SIGNING_PUBLIC_KEY_BYTES} bytes`);
  }
  const ttlMs = params.ttlMs ?? DEFAULT_COMMAND_TTL_MS;
  const header = {
    v: PROTOCOL_VERSION,
    id: params.id ?? toBase64Url(randomBytes(COMMAND_ID_BYTES)),
    type: params.type,
    agent: fingerprint(params.agentPublicKey),
    signer: fingerprint(params.signer.publicKey),
    issued_at: params.now,
    expires_at: params.now + ttlMs,
    counter: params.counter,
    ...params.replyTo !== undefined ? { reply_to: toBase64Url(params.replyTo) } : {}
  };
  const payloadBytes = sealTo(canonicalize(parsedBody.data), params.agentPublicKey);
  const signingInput = concatBytes(DOMAIN_COMMAND, canonicalize(header), payloadBytes);
  const signature = sign(signingInput, params.signer.secretKey);
  const command = {
    header,
    payload: toBase64Url(payloadBytes),
    ...params.session !== undefined ? { session: params.session } : {},
    sig: toBase64Url(signature)
  };
  return command;
}
async function openCommand(command, trust, registry) {
  if (typeof command === "object" && command !== null) {
    if ("header" in command) {
      assertSupportedVersion(command.header);
    }
    if ("session" in command && command.session !== undefined) {
      assertSupportedVersion(command.session);
    }
  }
  const parsed = signedCommandSchema.safeParse(command);
  if (!parsed.success) {
    throw new ProtocolError("invalid_format", "Malformed signed command");
  }
  const { header, payload, session, sig } = parsed.data;
  let idBytes;
  try {
    idBytes = fromBase64Url(header.id);
  } catch {
    throw new ProtocolError("invalid_format", "Invalid command id encoding");
  }
  if (idBytes.length !== COMMAND_ID_BYTES) {
    throw new ProtocolError("invalid_format", "Invalid command id length");
  }
  let replyToKey;
  if (header.reply_to !== undefined) {
    try {
      replyToKey = fromBase64Url(header.reply_to);
    } catch {
      throw new ProtocolError("invalid_format", "Invalid reply_to encoding");
    }
    if (replyToKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
      throw new ProtocolError("invalid_format", "Invalid reply_to length");
    }
  }
  const localAgentId = fingerprint(trust.agentKeyPair.publicKey);
  if (header.agent !== localAgentId) {
    throw new ProtocolError("wrong_agent", "Command is addressed to a different agent");
  }
  const now = trust.now();
  if (header.expires_at <= header.issued_at) {
    throw new ProtocolError("expired", "Command expiration is not after issuance");
  }
  if (header.expires_at - header.issued_at > MAX_COMMAND_TTL_MS) {
    throw new ProtocolError("ttl_too_long", "Command lifetime exceeds maximum allowed window");
  }
  if (header.issued_at > now + MAX_CLOCK_SKEW_MS) {
    throw new ProtocolError("not_yet_valid", "Command issued_at is in the future");
  }
  if (now >= header.expires_at) {
    throw new ProtocolError("expired", "Command has expired");
  }
  let signerPublicKey;
  let signerType;
  let accountId;
  let sessionId;
  let sessionNotAfter;
  if (session !== undefined) {
    const accountPublicKey = trust.isTrustedAccountKey(session.account);
    if (accountPublicKey === null) {
      throw new ProtocolError("untrusted_signer", "Session certificate account key is not trusted");
    }
    if (trust.isSessionRevoked(session.id)) {
      throw new ProtocolError("session_revoked", "Session certificate has been revoked");
    }
    const verifiedSession = verifySessionCertificate(session, accountPublicKey, header.issued_at);
    if (fingerprint(verifiedSession.sessionPublicKey) !== header.signer) {
      throw new ProtocolError("session_invalid", "Session certificate key does not match command signer");
    }
    if (replyToKey !== undefined && fingerprint(replyToKey) !== header.signer) {
      throw new ProtocolError("wrong_recipient", "reply_to must equal the session key");
    }
    signerPublicKey = verifiedSession.sessionPublicKey;
    signerType = "session";
    accountId = session.account;
    sessionId = session.id;
    sessionNotAfter = verifiedSession.certificate.not_after;
  } else {
    const accountPublicKey = trust.isTrustedAccountKey(header.signer);
    if (accountPublicKey === null) {
      throw new ProtocolError("untrusted_signer", "Command signer is not a trusted account key");
    }
    signerPublicKey = accountPublicKey;
    signerType = "account";
    accountId = header.signer;
  }
  let payloadBytes;
  try {
    payloadBytes = fromBase64Url(payload);
  } catch {
    throw new ProtocolError("invalid_format", "Invalid payload encoding");
  }
  let signatureBytes;
  try {
    signatureBytes = fromBase64Url(sig);
  } catch {
    throw new ProtocolError("bad_signature", "Invalid signature encoding");
  }
  const signingInput = concatBytes(DOMAIN_COMMAND, canonicalize(header), payloadBytes);
  if (!verify(signingInput, signatureBytes, signerPublicKey)) {
    throw new ProtocolError("bad_signature", "Invalid command signature");
  }
  if (!trust.claimCommand(header.signer, header.id, header.counter)) {
    throw new ProtocolError("replayed", "Command replay or non-increasing counter detected");
  }
  let plaintext;
  try {
    plaintext = openSealed(payloadBytes, trust.agentKeyPair);
  } catch {
    throw new ProtocolError("decrypt_failed", "Failed to decrypt command payload");
  }
  const definition = registry.get(header.type);
  if (!definition) {
    throw new ProtocolError("unknown_command", "Unknown command type");
  }
  let rawBody;
  try {
    rawBody = JSON.parse(utf8Decoder2.decode(plaintext));
  } catch {
    throw new ProtocolError("invalid_body", "Decrypted command payload is not valid JSON");
  }
  const bodyResult = definition.body.safeParse(rawBody);
  if (!bodyResult.success) {
    throw new ProtocolError("invalid_body", "Command body failed schema validation");
  }
  if (definition.sensitive && signerType !== "account") {
    throw new ProtocolError("sensitive_requires_account_key", "Sensitive command must be signed directly by an account key");
  }
  const scope = typeof bodyResult.data === "object" && bodyResult.data !== null && "server_id" in bodyResult.data && typeof bodyResult.data.server_id === "string" ? bodyResult.data.server_id : "*";
  const role = trust.roleFor(accountId, scope);
  if (role === null || !roleAtLeast(role, definition.minRole)) {
    throw new ProtocolError("insufficient_role", "Account role is below the command's minimum");
  }
  return {
    header,
    body: bodyResult.data,
    signerType,
    accountId,
    role,
    ...sessionId !== undefined ? { sessionId } : {},
    ...sessionNotAfter !== undefined ? { sessionNotAfter } : {},
    ...replyToKey !== undefined ? { replyTo: replyToKey } : {}
  };
}
// src/protocol/commands/agent.ts
import { z as z5 } from "zod";

// src/protocol/registry.ts
function defineCommand(definition) {
  return {
    type: definition.type,
    sensitive: definition.sensitive,
    minRole: definition.minRole,
    body: definition.body
  };
}

class CommandRegistry {
  #commands = new Map;
  register(definition) {
    if (this.#commands.has(definition.type)) {
      throw new Error(`Command already registered: ${definition.type}`);
    }
    this.#commands.set(definition.type, definition);
    return this;
  }
  registerAll(definitions) {
    for (const definition of definitions) {
      this.register(definition);
    }
    return this;
  }
  get(type) {
    return this.#commands.get(type);
  }
  has(type) {
    return this.#commands.has(type);
  }
  types() {
    return [...this.#commands.keys()];
  }
}

// src/protocol/commands/server.ts
import { z as z4 } from "zod";
var SERVER_ID_REGEX = /^[a-z0-9][a-z0-9-]{0,62}$/;
var DEFAULT_SERVER_PORT = 25565;
var MAX_CONSOLE_LINE_LENGTH = 1024;
var MIN_SERVER_MEMORY_MB = 512;
var MAX_SERVER_MEMORY_MB = 1048576;
var MAX_JVM_ARGS = 64;
var serverIdSchema = z4.string().regex(SERVER_ID_REGEX, "server_id must match ^[a-z0-9][a-z0-9-]{0,62}$");
var serverLoaderSchema = z4.enum(["vanilla", "fabric", "forge", "neoforge", "quilt"]);
var serverPortSchema = z4.number().int().min(1024).max(65535);
var serverMemoryMbSchema = z4.number().int().min(MIN_SERVER_MEMORY_MB).max(MAX_SERVER_MEMORY_MB);
var consoleLineSchema = z4.string().min(1).max(MAX_CONSOLE_LINE_LENGTH).refine((value) => !/[\r\n\0]/.test(value), {
  message: "Console line must not contain newline, carriage return, or NUL characters"
});
var strictServerIdBodySchema = z4.object({
  server_id: serverIdSchema
}).strict();
var serverCreateBodySchema = z4.object({
  server_id: serverIdSchema,
  name: z4.string().trim().min(1).max(128),
  minecraft_version: z4.string().min(1).max(64),
  loader: serverLoaderSchema,
  loader_version: z4.string().min(1).max(64).optional(),
  memory_mb: serverMemoryMbSchema,
  jvm_args: z4.array(z4.string()).max(MAX_JVM_ARGS).optional(),
  port: serverPortSchema.optional(),
  eula_accepted: z4.boolean()
}).strict();
var serverUpdateSettingsBodySchema = z4.object({
  server_id: serverIdSchema,
  memory_mb: serverMemoryMbSchema.optional(),
  jvm_args: z4.array(z4.string()).max(MAX_JVM_ARGS).optional(),
  port: serverPortSchema.optional(),
  eula_accepted: z4.boolean().optional()
}).strict();
var serverConsoleSendBodySchema = z4.object({
  server_id: serverIdSchema,
  line: consoleLineSchema
}).strict();
var serverConsoleSubscribeBodySchema = z4.object({
  server_id: serverIdSchema,
  from_offset: z4.number().int().nonnegative().optional()
}).strict();
var serverCreateCommand = defineCommand({
  type: "server.create",
  sensitive: false,
  minRole: "admin",
  body: serverCreateBodySchema
});
var serverRestartCommand = defineCommand({
  type: "server.restart",
  sensitive: false,
  minRole: "operator",
  body: strictServerIdBodySchema
});
var serverStatusCommand = defineCommand({
  type: "server.status",
  sensitive: false,
  minRole: "viewer",
  body: strictServerIdBodySchema
});
var serverListCommand = defineCommand({
  type: "server.list",
  sensitive: false,
  minRole: "viewer",
  body: z4.object({}).strict()
});
var serverUpdateSettingsCommand = defineCommand({
  type: "server.update_settings",
  sensitive: false,
  minRole: "editor",
  body: serverUpdateSettingsBodySchema
});
var serverConsoleSendCommand = defineCommand({
  type: "server.console.send",
  sensitive: false,
  minRole: "operator",
  body: serverConsoleSendBodySchema
});
var serverConsoleSubscribeCommand = defineCommand({
  type: "server.console.subscribe",
  sensitive: false,
  minRole: "viewer",
  body: serverConsoleSubscribeBodySchema
});
var serverConsoleUnsubscribeCommand = defineCommand({
  type: "server.console.unsubscribe",
  sensitive: false,
  minRole: "viewer",
  body: strictServerIdBodySchema
});
var SERVER_COMMANDS = [
  serverCreateCommand,
  serverRestartCommand,
  serverStatusCommand,
  serverListCommand,
  serverUpdateSettingsCommand,
  serverConsoleSendCommand,
  serverConsoleSubscribeCommand,
  serverConsoleUnsubscribeCommand
];
function registerServerCommands(registry) {
  return registry.registerAll(SERVER_COMMANDS);
}

// src/protocol/commands/agent.ts
var SUBSCRIPTION_TOPICS = ["server.status"];
var subscriptionTopicSchema = z5.enum(SUBSCRIPTION_TOPICS);
var SERVER_STATES = ["stopped", "starting", "running", "stopping", "crashed"];
var serverStateSchema = z5.enum(SERVER_STATES);
var serverStatusChangedSchema = z5.object({
  server_id: serverIdSchema,
  state: serverStateSchema,
  at: z5.number().int().nonnegative()
});
var agentSubscribeBodySchema = z5.object({
  topics: z5.array(subscriptionTopicSchema).min(1).max(SUBSCRIPTION_TOPICS.length)
}).strict();
var agentMembersSetBodySchema = z5.object({
  grant: roleGrantSchema
}).strict();
var agentMembersRevokeBodySchema = z5.object({
  account: keyIdSchema,
  servers: z5.array(serverIdSchema).min(1).max(256).optional()
}).strict();
var agentSubscribeCommand = defineCommand({
  type: "agent.subscribe",
  sensitive: false,
  minRole: "viewer",
  body: agentSubscribeBodySchema
});
var agentUnsubscribeCommand = defineCommand({
  type: "agent.unsubscribe",
  sensitive: false,
  minRole: "viewer",
  body: agentSubscribeBodySchema
});
var agentMembersSetCommand = defineCommand({
  type: "agent.members.set",
  sensitive: true,
  minRole: "admin",
  body: agentMembersSetBodySchema
});
var agentMembersRevokeCommand = defineCommand({
  type: "agent.members.revoke",
  sensitive: true,
  minRole: "admin",
  body: agentMembersRevokeBodySchema
});
var AGENT_COMMANDS = [
  agentSubscribeCommand,
  agentUnsubscribeCommand,
  agentMembersSetCommand,
  agentMembersRevokeCommand
];
function registerAgentCommands(registry) {
  return registry.registerAll(AGENT_COMMANDS);
}
// src/protocol/commands/backup.ts
import { z as z6 } from "zod";
var BACKUP_ID_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/;
var MIN_BACKUP_INTERVAL_MINUTES = 5;
var MAX_BACKUP_INTERVAL_MINUTES = 43200;
var MIN_BACKUP_RETENTION_COUNT = 1;
var MAX_BACKUP_RETENTION_COUNT = 1000;
var backupIdSchema = z6.string().regex(BACKUP_ID_REGEX, "backup_id must match ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$");
var backupDestinationKindSchema = z6.enum(["local", "s3", "tegra_cloud"]);
var backupScheduleConfigSchema = z6.object({
  enabled: z6.boolean(),
  interval_minutes: z6.number().int().min(MIN_BACKUP_INTERVAL_MINUTES).max(MAX_BACKUP_INTERVAL_MINUTES),
  retention_count: z6.number().int().min(MIN_BACKUP_RETENTION_COUNT).max(MAX_BACKUP_RETENTION_COUNT)
}).strict();
var backupLocalConfigSchema = z6.object({
  enabled: z6.boolean(),
  retention_count: z6.number().int().min(MIN_BACKUP_RETENTION_COUNT).max(MAX_BACKUP_RETENTION_COUNT).optional()
}).strict();
var S3_BUCKET_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,253}[a-zA-Z0-9]?$/;
var S3_REGION_REGEX = /^[a-zA-Z0-9-]{1,64}$/;
var CONTROL_CHAR_REGEX = /\p{Cc}/u;
var s3BucketSchema = z6.string().min(1).max(255).regex(S3_BUCKET_REGEX, "Invalid S3 bucket name").refine((value) => !value.includes(".."), { message: "S3 bucket name must not contain '..'" });
var s3RegionSchema = z6.string().min(1).max(64).regex(S3_REGION_REGEX, "Invalid S3 region");
var s3PrefixSchema = z6.string().max(256).refine((value) => {
  if (CONTROL_CHAR_REGEX.test(value) || value.includes("\\") || value.includes("?") || value.includes("#")) {
    return false;
  }
  return !value.split("/").some((segment) => segment === "." || segment === "..");
}, { message: "Invalid S3 prefix" });
var backupS3ConfigSchema = z6.object({
  enabled: z6.boolean(),
  bucket: s3BucketSchema.optional(),
  region: s3RegionSchema.optional(),
  endpoint: z6.string().min(1).max(512).optional(),
  prefix: s3PrefixSchema.optional(),
  retention_count: z6.number().int().min(MIN_BACKUP_RETENTION_COUNT).max(MAX_BACKUP_RETENTION_COUNT).optional(),
  access_key_id: z6.string().min(1).max(256).optional(),
  secret_access_key: z6.string().min(1).max(256).optional(),
  session_token: z6.string().min(1).max(2048).optional()
}).strict();
var backupTegraCloudConfigSchema = z6.object({
  enabled: z6.boolean(),
  retention_count: z6.number().int().min(MIN_BACKUP_RETENTION_COUNT).max(MAX_BACKUP_RETENTION_COUNT).optional()
}).strict();
var serverBackupConfigSetBodySchema = z6.object({
  server_id: serverIdSchema,
  auto_before_change: z6.boolean().optional(),
  schedule: backupScheduleConfigSchema.optional(),
  local: backupLocalConfigSchema.optional(),
  s3: backupS3ConfigSchema.optional(),
  tegra_cloud: backupTegraCloudConfigSchema.optional()
}).strict();
var serverBackupCreateBodySchema = z6.object({
  server_id: serverIdSchema,
  note: z6.string().max(256).optional(),
  tegra_cloud_upload_url: z6.string().min(1).max(4096).optional()
}).strict();
var serverBackupListBodySchema = z6.object({
  server_id: serverIdSchema,
  destination: backupDestinationKindSchema.optional()
}).strict();
var serverBackupDeleteBodySchema = z6.object({
  server_id: serverIdSchema,
  backup_id: backupIdSchema,
  destination: backupDestinationKindSchema.optional()
}).strict();
var serverBackupRestoreBodySchema = z6.object({
  server_id: serverIdSchema,
  backup_id: backupIdSchema,
  destination: backupDestinationKindSchema.optional(),
  tegra_cloud_download_url: z6.string().min(1).max(4096).optional()
}).strict();
var serverBackupConfigSetCommand = defineCommand({
  type: "server.backup.config.set",
  sensitive: false,
  minRole: "editor",
  body: serverBackupConfigSetBodySchema
});
var serverBackupConfigGetCommand = defineCommand({
  type: "server.backup.config.get",
  sensitive: false,
  minRole: "viewer",
  body: z6.object({ server_id: serverIdSchema }).strict()
});
var serverBackupCreateCommand = defineCommand({
  type: "server.backup.create",
  sensitive: false,
  minRole: "editor",
  body: serverBackupCreateBodySchema
});
var serverBackupListCommand = defineCommand({
  type: "server.backup.list",
  sensitive: false,
  minRole: "viewer",
  body: serverBackupListBodySchema
});
var serverBackupDeleteCommand = defineCommand({
  type: "server.backup.delete",
  sensitive: true,
  minRole: "admin",
  body: serverBackupDeleteBodySchema
});
var serverBackupRestoreCommand = defineCommand({
  type: "server.backup.restore",
  sensitive: true,
  minRole: "admin",
  body: serverBackupRestoreBodySchema
});
var BACKUP_COMMANDS = [
  serverBackupConfigSetCommand,
  serverBackupConfigGetCommand,
  serverBackupCreateCommand,
  serverBackupListCommand,
  serverBackupDeleteCommand,
  serverBackupRestoreCommand
];
function registerBackupCommands(registry) {
  return registry.registerAll(BACKUP_COMMANDS);
}
// src/protocol/commands/core.ts
import { z as z11 } from "zod";

// src/protocol/commands/files.ts
import { z as z7 } from "zod";
var SERVER_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;
var SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/;
var fileEncodingSchema = z7.enum(["utf8", "base64"]);
var sha256HexSchema = z7.string().regex(SHA256_HEX_PATTERN, "Expected 64 lowercase hex characters");
var filesListCommand = defineCommand({
  type: "files.list",
  sensitive: false,
  minRole: "viewer",
  body: z7.object({
    server_id: serverIdSchema,
    path: z7.string().optional()
  }).strict()
});
var filesStatCommand = defineCommand({
  type: "files.stat",
  sensitive: false,
  minRole: "viewer",
  body: z7.object({
    server_id: serverIdSchema,
    path: z7.string()
  }).strict()
});
var filesReadCommand = defineCommand({
  type: "files.read",
  sensitive: false,
  minRole: "editor",
  body: z7.object({
    server_id: serverIdSchema,
    path: z7.string().min(1),
    encoding: fileEncodingSchema.optional()
  }).strict()
});
var filesWriteCommand = defineCommand({
  type: "files.write",
  sensitive: false,
  minRole: "editor",
  body: z7.object({
    server_id: serverIdSchema,
    path: z7.string().min(1),
    content: z7.string(),
    encoding: fileEncodingSchema.optional()
  }).strict()
});
var filesMkdirCommand = defineCommand({
  type: "files.mkdir",
  sensitive: false,
  minRole: "editor",
  body: z7.object({
    server_id: serverIdSchema,
    path: z7.string().min(1)
  }).strict()
});
var filesRenameCommand = defineCommand({
  type: "files.rename",
  sensitive: false,
  minRole: "editor",
  body: z7.object({
    server_id: serverIdSchema,
    path: z7.string().min(1),
    new_name: z7.string().min(1)
  }).strict()
});
var filesMoveCommand = defineCommand({
  type: "files.move",
  sensitive: false,
  minRole: "editor",
  body: z7.object({
    server_id: serverIdSchema,
    from_path: z7.string().min(1),
    to_path: z7.string().min(1)
  }).strict()
});
var filesCopyCommand = defineCommand({
  type: "files.copy",
  sensitive: false,
  minRole: "editor",
  body: z7.object({
    server_id: serverIdSchema,
    from_path: z7.string().min(1),
    to_path: z7.string().min(1)
  }).strict()
});
var filesDeleteCommand = defineCommand({
  type: "files.delete",
  sensitive: true,
  minRole: "editor",
  body: z7.object({
    server_id: serverIdSchema,
    path: z7.string().min(1),
    recursive: z7.boolean().optional()
  }).strict()
});
var filesUploadBeginCommand = defineCommand({
  type: "files.upload.begin",
  sensitive: false,
  minRole: "editor",
  body: z7.object({
    server_id: serverIdSchema,
    path: z7.string().min(1),
    total_size: z7.number().int().nonnegative(),
    sha256: sha256HexSchema,
    part_size: z7.number().int().positive().optional()
  }).strict()
});
var filesUploadPartCommand = defineCommand({
  type: "files.upload.part",
  sensitive: false,
  minRole: "editor",
  body: z7.object({
    server_id: serverIdSchema,
    upload_id: z7.string().min(1),
    part_index: z7.number().int().nonnegative(),
    data_base64: z7.string()
  }).strict()
});
var filesUploadCommitCommand = defineCommand({
  type: "files.upload.commit",
  sensitive: false,
  minRole: "editor",
  body: z7.object({
    server_id: serverIdSchema,
    upload_id: z7.string().min(1)
  }).strict()
});
var filesUploadAbortCommand = defineCommand({
  type: "files.upload.abort",
  sensitive: false,
  minRole: "editor",
  body: z7.object({
    server_id: serverIdSchema,
    upload_id: z7.string().min(1)
  }).strict()
});
var filesDownloadBeginCommand = defineCommand({
  type: "files.download.begin",
  sensitive: false,
  minRole: "editor",
  body: z7.object({
    server_id: serverIdSchema,
    path: z7.string().min(1),
    part_size: z7.number().int().positive().optional()
  }).strict()
});
var filesDownloadPartCommand = defineCommand({
  type: "files.download.part",
  sensitive: false,
  minRole: "editor",
  body: z7.object({
    server_id: serverIdSchema,
    download_id: z7.string().min(1),
    part_index: z7.number().int().nonnegative()
  }).strict()
});
var filesDownloadCloseCommand = defineCommand({
  type: "files.download.close",
  sensitive: false,
  minRole: "editor",
  body: z7.object({
    server_id: serverIdSchema,
    download_id: z7.string().min(1)
  }).strict()
});
var filesDownloadCommand = defineCommand({
  type: "files.download",
  sensitive: false,
  minRole: "editor",
  body: z7.object({
    server_id: serverIdSchema,
    path: z7.string().min(1),
    offset: z7.number().int().nonnegative(),
    length: z7.number().int().positive()
  }).strict()
});
var filesZipCommand = defineCommand({
  type: "files.zip",
  sensitive: false,
  minRole: "editor",
  body: z7.object({
    server_id: serverIdSchema,
    paths: z7.array(z7.string().min(1)).min(1),
    dest_path: z7.string().min(1)
  }).strict()
});
var filesUnzipCommand = defineCommand({
  type: "files.unzip",
  sensitive: false,
  minRole: "editor",
  body: z7.object({
    server_id: serverIdSchema,
    zip_path: z7.string().min(1),
    dest_path: z7.string().optional()
  }).strict()
});
var FILES_COMMANDS = [
  filesListCommand,
  filesStatCommand,
  filesReadCommand,
  filesWriteCommand,
  filesMkdirCommand,
  filesRenameCommand,
  filesMoveCommand,
  filesCopyCommand,
  filesDeleteCommand,
  filesUploadBeginCommand,
  filesUploadPartCommand,
  filesUploadCommitCommand,
  filesUploadAbortCommand,
  filesDownloadBeginCommand,
  filesDownloadPartCommand,
  filesDownloadCloseCommand,
  filesDownloadCommand,
  filesZipCommand,
  filesUnzipCommand
];
function registerFilesCommands(registry) {
  return registry.registerAll(FILES_COMMANDS);
}

// src/protocol/commands/pairing.ts
import { z as z8 } from "zod";
var agentRevocationsSetCommand = defineCommand({
  type: "agent.revocations.set",
  sensitive: false,
  minRole: "admin",
  body: z8.object({
    list: revocationListSchema
  })
});
var PAIRING_COMMANDS = [agentRevocationsSetCommand];
function registerPairingCommands(registry) {
  return registry.registerAll(PAIRING_COMMANDS);
}

// src/protocol/commands/state.ts
import { z as z9 } from "zod";
var SHA1_HEX_PATTERN = /^[0-9a-f]{40}$/i;
var SHA512_HEX_PATTERN = /^[0-9a-f]{128}$/i;
var sha1HexSchema = z9.string().regex(SHA1_HEX_PATTERN, "Expected 40 hex characters").transform((v) => v.toLowerCase());
var sha512HexSchema = z9.string().regex(SHA512_HEX_PATTERN, "Expected 128 hex characters").transform((v) => v.toLowerCase());
var modSourceSchema = z9.enum(["modrinth", "curseforge", "tegra", "local"]);
var modLayerSchema = z9.enum(["origin", "user"]);
var MOD_UNSAFE_UNICODE_REGEX = /(?:\p{Cc}|\p{Cf}|\u034F|\u180E|\u2028|\u2029|\u3164|\uFFA0)/u;
var MOD_ENCODED_TRAVERSAL_REGEX = /%(?:2f|5c|00)/i;
var MOD_RESERVED_WINDOWS_REGEX = /^(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³]|CONIN\$|CONOUT\$|CLOCK\$)\s*(?:\.|$)/i;
var MOD_FORBIDDEN_NAMES = new Set([".runtime", ".tegrad-uploads"]);
var modFileNameSchema = z9.string().min(1).max(255).refine((name) => {
  if (name.includes("/") || name.includes("\\") || name.includes("\x00") || name.includes(":") || name === "." || name === ".." || name.endsWith(".") || name.endsWith(" ")) {
    return false;
  }
  if (MOD_UNSAFE_UNICODE_REGEX.test(name) || name.normalize("NFC") !== name) {
    return false;
  }
  if (MOD_ENCODED_TRAVERSAL_REGEX.test(name) || MOD_RESERVED_WINDOWS_REGEX.test(name)) {
    return false;
  }
  const lower = name.toLowerCase();
  if (MOD_FORBIDDEN_NAMES.has(lower) || lower.startsWith(".tmp-upload-")) {
    return false;
  }
  return new TextEncoder().encode(name).byteLength <= 255;
}, { message: "Mod filename must be a single safe filename" });
var serverModEntrySchema = z9.object({
  file: modFileNameSchema,
  source: modSourceSchema,
  project_id: z9.string().min(1).max(128).optional(),
  version_id: z9.string().min(1).max(128).optional(),
  sha1: sha1HexSchema.optional(),
  sha256: sha256HexSchema.optional(),
  sha512: sha512HexSchema.optional(),
  layer: modLayerSchema
}).strict();
var serverOriginSchema = z9.discriminatedUnion("kind", [
  z9.object({
    kind: z9.literal("modpack"),
    source: modSourceSchema,
    modpack_id: z9.string().min(1).max(128),
    version_id: z9.string().min(1).max(128)
  }).strict(),
  z9.object({
    kind: z9.literal("local"),
    note: z9.string().max(512).optional()
  }).strict()
]).nullable();
var serverOriginSyncStateSchema = z9.object({
  excluded_mod_keys: z9.array(z9.string().min(1).max(256)).max(4000),
  synced_mod_keys: z9.array(z9.string().min(1).max(256)).max(4000),
  removed_origin_files: z9.array(z9.string().min(1).max(1024)).max(5000).optional(),
  synced_files: z9.array(z9.string().min(1).max(1024)).max(5000).optional(),
  last_synced_at: z9.string().nullable().optional(),
  last_synced_version_id: z9.string().min(1).max(128).nullable().optional()
}).strict();
var modEnvironmentInfoSchema = z9.object({
  client: z9.enum(["required", "optional", "unsupported", "unknown"]).optional(),
  server: z9.enum(["required", "optional", "unsupported", "unknown"]).optional()
}).strict();
var originPlanModInputSchema = z9.object({
  key: z9.string().min(1).max(256),
  file: modFileNameSchema,
  name: z9.string().min(1).max(256).optional(),
  enabled: z9.boolean().optional(),
  source: modSourceSchema.optional(),
  project_id: z9.string().min(1).max(128).optional(),
  version_id: z9.string().min(1).max(128).optional(),
  url: z9.string().url().max(2048).optional(),
  sha1: sha1HexSchema.optional(),
  sha256: sha256HexSchema.optional(),
  sha512: sha512HexSchema.optional(),
  environment: modEnvironmentInfoSchema.optional()
}).strict();
var originPlanFileInputSchema = z9.object({
  path: z9.string().min(1).max(1024),
  sha1: sha1HexSchema,
  sha256: sha256HexSchema.optional(),
  size_bytes: z9.number().int().nonnegative(),
  url: z9.string().url().max(2048).optional(),
  content_base64: z9.string().optional()
}).strict();
var serverModsListBodySchema = z9.object({
  server_id: serverIdSchema
}).strict();
var serverModsInstallBodySchema = z9.object({
  server_id: serverIdSchema,
  file: modFileNameSchema,
  url: z9.string().url().max(2048),
  source: modSourceSchema,
  project_id: z9.string().min(1).max(128).optional(),
  version_id: z9.string().min(1).max(128).optional(),
  sha1: sha1HexSchema.optional(),
  sha256: sha256HexSchema.optional(),
  sha512: sha512HexSchema.optional()
}).strict();
var serverModsRemoveBodySchema = z9.object({
  server_id: serverIdSchema,
  file: modFileNameSchema
}).strict();
var serverOriginPlanBodySchema = z9.object({
  server_id: serverIdSchema,
  to_version_id: z9.string().min(1).max(128),
  source: modSourceSchema.optional(),
  modpack_id: z9.string().min(1).max(128).optional(),
  minecraft_version: z9.string().min(1).max(64).optional(),
  loader: serverLoaderSchema.optional(),
  loader_version: z9.string().min(1).max(64).nullable().optional(),
  mods: z9.array(originPlanModInputSchema).max(2000),
  files: z9.array(originPlanFileInputSchema).max(5000).optional()
}).strict();
var serverOriginApplyBodySchema = z9.object({
  server_id: serverIdSchema,
  plan_id: z9.string().min(1).max(128),
  selected_mod_keys: z9.array(z9.string().min(1).max(256)).max(2000).optional(),
  selected_file_paths: z9.array(z9.string().min(1).max(1024)).max(5000).optional()
}).strict();
var serverOriginUnlinkBodySchema = z9.object({
  server_id: serverIdSchema
}).strict();
var blobKeySchema = z9.string().regex(/^[A-Za-z0-9_-]{43}$/, "Expected a 32-byte key in base64url");
var WORLD_NAME_REGEX = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
var RESERVED_WORLD_NAMES = new Set([
  "mods",
  "config",
  "defaultconfigs",
  "logs",
  "libraries",
  "plugins",
  "versions",
  "crash-reports",
  "resourcepacks",
  "datapacks",
  "kubejs",
  "scripts"
]);
var worldNameSchema = z9.string().regex(WORLD_NAME_REGEX, "Invalid world name").refine((name) => !name.includes("..") && !RESERVED_WORLD_NAMES.has(name.toLowerCase()), {
  message: "Reserved or unsafe world name"
});
var serverWorldImportBodySchema = z9.object({
  server_id: serverIdSchema,
  world_name: worldNameSchema,
  url: z9.string().url().max(2048),
  sha256: sha256HexSchema,
  key: blobKeySchema
}).strict();
var serverDeployServerpackBodySchema = z9.object({
  server_id: serverIdSchema,
  url: z9.string().url().max(2048),
  sha256: sha256HexSchema.optional(),
  sha512: sha512HexSchema.optional(),
  sha1: sha1HexSchema.optional(),
  origin: serverOriginSchema.optional(),
  key: blobKeySchema.optional()
}).strict();
var serverModsListCommand = defineCommand({
  type: "server.mods.list",
  sensitive: false,
  minRole: "viewer",
  body: serverModsListBodySchema
});
var serverModsInstallCommand = defineCommand({
  type: "server.mods.install",
  sensitive: false,
  minRole: "editor",
  body: serverModsInstallBodySchema
});
var serverModsRemoveCommand = defineCommand({
  type: "server.mods.remove",
  sensitive: false,
  minRole: "editor",
  body: serverModsRemoveBodySchema
});
var serverOriginPlanCommand = defineCommand({
  type: "server.origin.plan",
  sensitive: false,
  minRole: "editor",
  body: serverOriginPlanBodySchema
});
var serverOriginApplyCommand = defineCommand({
  type: "server.origin.apply",
  sensitive: true,
  minRole: "editor",
  body: serverOriginApplyBodySchema
});
var serverOriginUnlinkCommand = defineCommand({
  type: "server.origin.unlink",
  sensitive: false,
  minRole: "editor",
  body: serverOriginUnlinkBodySchema
});
var serverDeployServerpackCommand = defineCommand({
  type: "server.deploy.serverpack",
  sensitive: true,
  minRole: "editor",
  body: serverDeployServerpackBodySchema
});
var serverWorldImportCommand = defineCommand({
  type: "server.world.import",
  sensitive: false,
  minRole: "editor",
  body: serverWorldImportBodySchema
});
var STATE_COMMANDS = [
  serverModsListCommand,
  serverModsInstallCommand,
  serverModsRemoveCommand,
  serverOriginPlanCommand,
  serverOriginApplyCommand,
  serverOriginUnlinkCommand,
  serverDeployServerpackCommand,
  serverWorldImportCommand
];
function registerStateCommands(registry) {
  return registry.registerAll(STATE_COMMANDS);
}

// src/protocol/commands/tunnel.ts
import { z as z10 } from "zod";
var PLAYIT_SECRET_KEY_REGEX = /^[0-9a-fA-F]{16,256}$/;
var playitSecretKeySchema = z10.string().trim().regex(PLAYIT_SECRET_KEY_REGEX, "secret_key must be a 16-256 character hexadecimal string").refine((value) => value.length % 2 === 0, {
  message: "secret_key must have an even number of hexadecimal characters"
});
var tunnelPlayitSetKeyBodySchema = z10.object({
  secret_key: playitSecretKeySchema
}).strict();
var tunnelPlayitSetKeyCommand = defineCommand({
  type: "tunnel.playit.set_key",
  sensitive: true,
  minRole: "admin",
  body: tunnelPlayitSetKeyBodySchema
});
var tunnelPlayitStartCommand = defineCommand({
  type: "tunnel.playit.start",
  sensitive: false,
  minRole: "admin",
  body: z10.object({}).strict()
});
var tunnelPlayitStopCommand = defineCommand({
  type: "tunnel.playit.stop",
  sensitive: false,
  minRole: "admin",
  body: z10.object({}).strict()
});
var tunnelPlayitStatusCommand = defineCommand({
  type: "tunnel.playit.status",
  sensitive: false,
  minRole: "viewer",
  body: z10.object({}).strict()
});
var TUNNEL_COMMANDS = [
  tunnelPlayitSetKeyCommand,
  tunnelPlayitStartCommand,
  tunnelPlayitStopCommand,
  tunnelPlayitStatusCommand
];
function registerTunnelCommands(registry) {
  return registry.registerAll(TUNNEL_COMMANDS);
}

// src/protocol/commands/core.ts
var serverIdBodySchema = z11.object({
  server_id: z11.string().min(1)
});
var strictServerDeleteBodySchema = z11.object({
  server_id: serverIdSchema
}).strict();
var agentPingCommand = defineCommand({
  type: "agent.ping",
  sensitive: false,
  minRole: "viewer",
  body: z11.object({}).strict()
});
var serverStartCommand = defineCommand({
  type: "server.start",
  sensitive: false,
  minRole: "operator",
  body: serverIdBodySchema
});
var serverStopCommand = defineCommand({
  type: "server.stop",
  sensitive: false,
  minRole: "operator",
  body: serverIdBodySchema
});
var serverDeleteCommand = defineCommand({
  type: "server.delete",
  sensitive: true,
  minRole: "admin",
  body: strictServerDeleteBodySchema
});
var CORE_COMMANDS = [
  agentPingCommand,
  serverStartCommand,
  serverStopCommand,
  serverDeleteCommand
];
function registerCoreCommands(registry) {
  return registry.registerAll(CORE_COMMANDS);
}
function createCoreRegistry() {
  return registerAgentCommands(registerTunnelCommands(registerBackupCommands(registerStateCommands(registerServerCommands(registerFilesCommands(registerPairingCommands(registerCoreCommands(new CommandRegistry))))))));
}
// src/protocol/pairing.ts
import { z as z12 } from "zod";
var PAIRING_CODE_LENGTH = 10;
var PAIRING_SECRET_BYTES = 16;
var DEFAULT_TRUST_GRANT_TTL_MS = 10 * 60 * 1000;
var MAX_TRUST_GRANT_TTL_MS = 15 * 60 * 1000;
var CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
var PAIRING_CODE_REGEX = /^[0-9A-HJKMNP-TV-Z]{10}$/;
var pairingCodeSchema = z12.string().regex(PAIRING_CODE_REGEX, "Invalid pairing code");
var trustGrantSchema = z12.object({
  v: z12.literal(PROTOCOL_VERSION),
  kind: z12.literal("agent-pairing"),
  account_key: base64UrlSchema,
  agent: keyIdSchema,
  issued_at: z12.number().int().nonnegative(),
  expires_at: z12.number().int().nonnegative(),
  proof: base64UrlSchema.optional(),
  sig: base64UrlSchema
});
function bytesEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0;i < a.length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}
function decodeSecretBytes(secret) {
  let bytes;
  if (typeof secret === "string") {
    if (!base64UrlSchema.safeParse(secret).success) {
      return null;
    }
    try {
      bytes = fromBase64Url(secret);
    } catch {
      return null;
    }
  } else {
    bytes = secret;
  }
  if (bytes.length !== PAIRING_SECRET_BYTES) {
    return null;
  }
  return bytes;
}
function generatePairingCode() {
  const bytes = randomBytes(PAIRING_CODE_LENGTH);
  let out = "";
  for (let i = 0;i < PAIRING_CODE_LENGTH; i++) {
    const idx = (bytes[i] ?? 0) & 31;
    out += CROCKFORD_ALPHABET[idx] ?? "";
  }
  return out;
}
function generatePairingSecret() {
  return toBase64Url(randomBytes(PAIRING_SECRET_BYTES));
}
function buildPairingFragment(params) {
  if (!pairingCodeSchema.safeParse(params.code).success) {
    throw new ProtocolError("invalid_format", "Invalid pairing code");
  }
  if (decodeSecretBytes(params.secret) === null) {
    throw new ProtocolError("invalid_format", "Invalid pairing secret");
  }
  if (!keyIdSchema.safeParse(params.agentFingerprint).success) {
    throw new ProtocolError("invalid_format", "Invalid agent fingerprint");
  }
  return `${params.code}.${params.secret}.${params.agentFingerprint}`;
}
function parsePairingFragment(text) {
  const raw = text.startsWith("#") ? text.slice(1) : text;
  if (raw.length === 0) {
    throw new ProtocolError("invalid_format", "Empty pairing fragment");
  }
  const parts = raw.split(".");
  if (parts.length === 1) {
    const code = parts[0] ?? "";
    if (!pairingCodeSchema.safeParse(code).success) {
      throw new ProtocolError("invalid_format", "Invalid pairing code");
    }
    return { code };
  }
  if (parts.length === 3) {
    const code = parts[0] ?? "";
    const secret = parts[1] ?? "";
    const agentFingerprint = parts[2] ?? "";
    if (!pairingCodeSchema.safeParse(code).success) {
      throw new ProtocolError("invalid_format", "Invalid pairing code");
    }
    if (decodeSecretBytes(secret) === null) {
      throw new ProtocolError("invalid_format", "Invalid pairing secret");
    }
    const parsedFp = keyIdSchema.safeParse(agentFingerprint);
    if (!parsedFp.success) {
      throw new ProtocolError("invalid_format", "Invalid agent fingerprint");
    }
    return {
      code,
      secret,
      agentFingerprint: parsedFp.data
    };
  }
  throw new ProtocolError("invalid_format", "Malformed pairing fragment");
}
function computePairingProof(base, secretBytes) {
  const input = concatBytes(DOMAIN_PAIRING_PROOF, canonicalize(base));
  return hash(input, secretBytes);
}
function signTrustGrant(params) {
  if (!Number.isSafeInteger(params.issuedAt) || params.issuedAt < 0) {
    throw new RangeError("issuedAt must be a non-negative safe integer");
  }
  if (params.agentPublicKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new RangeError(`Agent public key must be ${SIGNING_PUBLIC_KEY_BYTES} bytes`);
  }
  const ttlMs = params.ttlMs ?? DEFAULT_TRUST_GRANT_TTL_MS;
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0 || ttlMs > MAX_TRUST_GRANT_TTL_MS) {
    throw new RangeError(`ttlMs must be a positive safe integer at most ${MAX_TRUST_GRANT_TTL_MS} ms`);
  }
  const base = {
    v: PROTOCOL_VERSION,
    kind: "agent-pairing",
    account_key: toBase64Url(params.accountKeyPair.publicKey),
    agent: fingerprint(params.agentPublicKey),
    issued_at: params.issuedAt,
    expires_at: params.issuedAt + ttlMs
  };
  let proof;
  if (params.secret !== undefined) {
    const secretBytes = decodeSecretBytes(params.secret);
    if (secretBytes === null) {
      throw new RangeError(`Pairing secret must be ${PAIRING_SECRET_BYTES} bytes`);
    }
    proof = toBase64Url(computePairingProof(base, secretBytes));
  }
  const unsigned = proof !== undefined ? { ...base, proof } : base;
  const signingInput = concatBytes(DOMAIN_TRUST_GRANT, canonicalize(unsigned));
  const signature = sign(signingInput, params.accountKeyPair.secretKey);
  return {
    ...unsigned,
    sig: toBase64Url(signature)
  };
}
function verifyTrustGrant(grant, options) {
  assertSupportedVersion(grant);
  const parsed = trustGrantSchema.safeParse(grant);
  if (!parsed.success) {
    throw new ProtocolError("grant_invalid", "Malformed trust grant");
  }
  const data = parsed.data;
  if (data.expires_at <= data.issued_at) {
    throw new ProtocolError("grant_invalid", "Trust grant expiration is not after issuance");
  }
  if (data.expires_at - data.issued_at > MAX_TRUST_GRANT_TTL_MS) {
    throw new ProtocolError("grant_invalid", "Trust grant lifetime exceeds maximum allowed window");
  }
  let accountPublicKey;
  try {
    accountPublicKey = fromBase64Url(data.account_key);
  } catch {
    throw new ProtocolError("grant_invalid", "Invalid account_key encoding in trust grant");
  }
  if (accountPublicKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new ProtocolError("grant_invalid", "Invalid account_key length in trust grant");
  }
  const expectedAgent = fingerprint(options.agentPublicKey);
  if (data.agent !== expectedAgent) {
    throw new ProtocolError("grant_wrong_agent", "Trust grant is addressed to a different agent");
  }
  if (data.issued_at > options.now + MAX_CLOCK_SKEW_MS) {
    throw new ProtocolError("not_yet_valid", "Trust grant issued_at is in the future");
  }
  if (options.now >= data.expires_at) {
    throw new ProtocolError("grant_expired", "Trust grant has expired");
  }
  let signatureBytes;
  try {
    signatureBytes = fromBase64Url(data.sig);
  } catch {
    throw new ProtocolError("grant_bad_signature", "Invalid trust grant signature encoding");
  }
  const base = {
    v: data.v,
    kind: data.kind,
    account_key: data.account_key,
    agent: data.agent,
    issued_at: data.issued_at,
    expires_at: data.expires_at
  };
  const unsigned = data.proof !== undefined ? { ...base, proof: data.proof } : base;
  const signingInput = concatBytes(DOMAIN_TRUST_GRANT, canonicalize(unsigned));
  if (!verify(signingInput, signatureBytes, accountPublicKey)) {
    throw new ProtocolError("grant_bad_signature", "Invalid trust grant signature");
  }
  let proven = false;
  if (data.proof === undefined) {
    if (options.requireProof) {
      throw new ProtocolError("grant_proof_required", "Trust grant is missing pairing proof");
    }
  } else {
    if (options.secret === undefined) {
      throw new ProtocolError("grant_bad_proof", "Pairing secret unavailable to verify proof");
    }
    const secretBytes = decodeSecretBytes(options.secret);
    if (secretBytes === null) {
      throw new ProtocolError("grant_bad_proof", "Invalid pairing secret");
    }
    let proofBytes;
    try {
      proofBytes = fromBase64Url(data.proof);
    } catch {
      throw new ProtocolError("grant_bad_proof", "Invalid proof encoding");
    }
    if (proofBytes.length !== HASH_BYTES) {
      throw new ProtocolError("grant_bad_proof", "Invalid proof length");
    }
    const expectedProof = computePairingProof(base, secretBytes);
    if (!bytesEqual(proofBytes, expectedProof)) {
      throw new ProtocolError("grant_bad_proof", "Pairing proof does not match secret");
    }
    proven = true;
  }
  return {
    accountPublicKey,
    accountId: fingerprint(accountPublicKey),
    proven
  };
}
// src/protocol/revocation.ts
function signRevocationList(params) {
  if (!Number.isSafeInteger(params.issuedAt) || params.issuedAt < 0) {
    throw new RangeError("issuedAt must be a non-negative safe integer");
  }
  const unsigned = {
    v: PROTOCOL_VERSION,
    account: fingerprint(params.accountKeyPair.publicKey),
    issued_at: params.issuedAt,
    revoked: [...params.revoked]
  };
  const signingInput = concatBytes(DOMAIN_REVOCATION, canonicalize(unsigned));
  const signature = sign(signingInput, params.accountKeyPair.secretKey);
  return {
    ...unsigned,
    sig: toBase64Url(signature)
  };
}
function verifyRevocationList(list, accountPublicKey) {
  assertSupportedVersion(list);
  const parsed = revocationListSchema.safeParse(list);
  if (!parsed.success) {
    throw new ProtocolError("invalid_format", "Malformed revocation list");
  }
  const data = parsed.data;
  if (data.account !== fingerprint(accountPublicKey)) {
    throw new ProtocolError("untrusted_signer", "Revocation list account mismatch");
  }
  let signatureBytes;
  try {
    signatureBytes = fromBase64Url(data.sig);
  } catch {
    throw new ProtocolError("bad_signature", "Invalid revocation list signature encoding");
  }
  const { sig: _sig, ...unsigned } = data;
  const signingInput = concatBytes(DOMAIN_REVOCATION, canonicalize(unsigned));
  if (!verify(signingInput, signatureBytes, accountPublicKey)) {
    throw new ProtocolError("bad_signature", "Invalid revocation list signature");
  }
  return data;
}
// src/protocol/trust.ts
function createInMemoryTrustContext(options) {
  const trusted = new Map;
  for (const key of options.trustedAccountKeys) {
    trusted.set(fingerprint(key), key);
  }
  const members = new RoleTable(options.members);
  const revoked = new Set(options.revokedSessionIds);
  const seenIds = new Set;
  const lastCounters = new Map;
  let clock = options.now ?? (() => Date.now());
  return {
    agentKeyPair: options.agentKeyPair,
    isTrustedAccountKey(id) {
      return trusted.get(id) ?? members.keyFor(id, clock());
    },
    roleFor(account, serverId) {
      if (trusted.has(account)) {
        return "owner";
      }
      return members.roleFor(account, serverId, clock());
    },
    listMembers() {
      return members.entries();
    },
    setMember(entry) {
      members.set(entry);
    },
    revokeMembers(account, servers) {
      return members.revoke(account, servers);
    },
    isSessionRevoked(certificateId) {
      return revoked.has(certificateId);
    },
    now() {
      return clock();
    },
    claimCommand(signer, id, counter) {
      if (seenIds.has(id)) {
        return false;
      }
      const prev = lastCounters.get(signer);
      if (prev !== undefined && counter <= prev) {
        return false;
      }
      seenIds.add(id);
      lastCounters.set(signer, counter);
      return true;
    },
    revokeSession(certificateId) {
      revoked.add(certificateId);
    },
    setNow(nextClock) {
      clock = nextClock;
    }
  };
}
export { ProtocolError, PROTOCOL_VERSION, DOMAIN_COMMAND, DOMAIN_SESSION, DOMAIN_AGENT_MESSAGE, DOMAIN_REVOCATION, DOMAIN_TRUST_GRANT, DOMAIN_PAIRING_PROOF, DOMAIN_AGENT_AUTH, DOMAIN_AGENT_HTTP, DOMAIN_ROLE_GRANT, keyIdSchema, base64UrlSchema, sessionCertificateSchema, commandHeaderSchema, signedCommandSchema, agentMessageHeaderSchema, agentMessageSchema, revocationListSchema, transportCommandFrameSchema, transportEventFrameSchema, transportAckFrameSchema, transportPingFrameSchema, AGENT_NONCE_BYTES, agentNonceSchema, transportHelloFrameSchema, transportAuthFrameSchema, transportFrameSchema, AGENT_AUTH_MAX_SKEW_MS, AGENT_HTTP_MAX_SKEW_MS, AGENT_HTTP_HEADER_AGENT, AGENT_HTTP_HEADER_TS, AGENT_HTTP_HEADER_SIG, generateAgentNonce, createHelloFrame, signAgentAuth, verifyAgentAuth, signAgentRequest, verifyAgentRequest, sealAgentMessage, openAgentMessage, agentEventBodySchema, wrapEventBody, openAgentEvent, ROLES, roleSchema, GRANTABLE_ROLES, grantableRoleSchema, ROLE_LEVEL, roleAtLeast, maxRole, ALL_SERVERS, MAX_GRANT_SERVERS, MAX_MEMBERS, roleGrantSchema, MAX_GRANT_CLOCK_SKEW_MS, signRoleGrant, verifyRoleGrant, memberEntrySchema, RoleTable, signSessionCertificate, verifySessionCertificate, COMMAND_ID_BYTES, DEFAULT_COMMAND_TTL_MS, MAX_COMMAND_TTL_MS, MAX_CLOCK_SKEW_MS, createSignedCommand, openCommand, defineCommand, CommandRegistry, SERVER_ID_REGEX, DEFAULT_SERVER_PORT, MAX_CONSOLE_LINE_LENGTH, MIN_SERVER_MEMORY_MB, MAX_SERVER_MEMORY_MB, MAX_JVM_ARGS, serverIdSchema, serverLoaderSchema, serverPortSchema, serverMemoryMbSchema, consoleLineSchema, serverCreateBodySchema, serverUpdateSettingsBodySchema, serverConsoleSendBodySchema, serverConsoleSubscribeBodySchema, serverCreateCommand, serverRestartCommand, serverStatusCommand, serverListCommand, serverUpdateSettingsCommand, serverConsoleSendCommand, serverConsoleSubscribeCommand, serverConsoleUnsubscribeCommand, SERVER_COMMANDS, registerServerCommands, SUBSCRIPTION_TOPICS, subscriptionTopicSchema, SERVER_STATES, serverStateSchema, serverStatusChangedSchema, agentSubscribeBodySchema, agentMembersSetBodySchema, agentMembersRevokeBodySchema, agentSubscribeCommand, agentUnsubscribeCommand, agentMembersSetCommand, agentMembersRevokeCommand, AGENT_COMMANDS, registerAgentCommands, BACKUP_ID_REGEX, MIN_BACKUP_INTERVAL_MINUTES, MAX_BACKUP_INTERVAL_MINUTES, MIN_BACKUP_RETENTION_COUNT, MAX_BACKUP_RETENTION_COUNT, backupIdSchema, backupDestinationKindSchema, backupScheduleConfigSchema, backupLocalConfigSchema, s3BucketSchema, s3RegionSchema, s3PrefixSchema, backupS3ConfigSchema, backupTegraCloudConfigSchema, serverBackupConfigSetBodySchema, serverBackupCreateBodySchema, serverBackupListBodySchema, serverBackupDeleteBodySchema, serverBackupRestoreBodySchema, serverBackupConfigSetCommand, serverBackupConfigGetCommand, serverBackupCreateCommand, serverBackupListCommand, serverBackupDeleteCommand, serverBackupRestoreCommand, BACKUP_COMMANDS, registerBackupCommands, SERVER_ID_PATTERN, SHA256_HEX_PATTERN, fileEncodingSchema, sha256HexSchema, filesListCommand, filesStatCommand, filesReadCommand, filesWriteCommand, filesMkdirCommand, filesRenameCommand, filesCopyCommand, filesDeleteCommand, filesUploadBeginCommand, filesUploadPartCommand, filesUploadCommitCommand, filesUploadAbortCommand, filesDownloadBeginCommand, filesDownloadPartCommand, filesDownloadCloseCommand, filesDownloadCommand, filesZipCommand, filesUnzipCommand, FILES_COMMANDS, registerFilesCommands, agentRevocationsSetCommand, PAIRING_COMMANDS, registerPairingCommands, SHA1_HEX_PATTERN, SHA512_HEX_PATTERN, sha1HexSchema, sha512HexSchema, modSourceSchema, modLayerSchema, modFileNameSchema, serverModEntrySchema, serverOriginSchema, serverOriginSyncStateSchema, modEnvironmentInfoSchema, originPlanModInputSchema, originPlanFileInputSchema, serverModsListBodySchema, serverModsInstallBodySchema, serverModsRemoveBodySchema, serverOriginPlanBodySchema, serverOriginApplyBodySchema, serverOriginUnlinkBodySchema, blobKeySchema, WORLD_NAME_REGEX, RESERVED_WORLD_NAMES, worldNameSchema, serverWorldImportBodySchema, serverDeployServerpackBodySchema, serverModsListCommand, serverModsInstallCommand, serverModsRemoveCommand, serverOriginPlanCommand, serverOriginApplyCommand, serverOriginUnlinkCommand, serverDeployServerpackCommand, serverWorldImportCommand, STATE_COMMANDS, registerStateCommands, PLAYIT_SECRET_KEY_REGEX, playitSecretKeySchema, tunnelPlayitSetKeyBodySchema, tunnelPlayitSetKeyCommand, tunnelPlayitStartCommand, tunnelPlayitStopCommand, tunnelPlayitStatusCommand, TUNNEL_COMMANDS, registerTunnelCommands, agentPingCommand, serverStartCommand, serverStopCommand, serverDeleteCommand, CORE_COMMANDS, registerCoreCommands, createCoreRegistry, PAIRING_CODE_LENGTH, PAIRING_SECRET_BYTES, DEFAULT_TRUST_GRANT_TTL_MS, MAX_TRUST_GRANT_TTL_MS, pairingCodeSchema, trustGrantSchema, generatePairingCode, generatePairingSecret, buildPairingFragment, parsePairingFragment, signTrustGrant, verifyTrustGrant, signRevocationList, verifyRevocationList, createInMemoryTrustContext };
