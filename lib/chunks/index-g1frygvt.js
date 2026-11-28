// src/crypto/sodium.ts
import sodium from "libsodium-wrappers-sumo";
var initialized = false;
async function ready() {
  if (initialized)
    return;
  await sodium.ready;
  initialized = true;
}
function getSodium() {
  if (!initialized) {
    throw new Error("Crypto module is not initialized. Call await ready() first.");
  }
  return sodium;
}
function randomBytes(length) {
  if (!Number.isInteger(length) || length < 0) {
    throw new RangeError("length must be a non-negative integer");
  }
  return getSodium().randombytes_buf(length);
}
function memzero(buffer) {
  getSodium().memzero(buffer);
}

// src/crypto/aead.ts
var SYMMETRIC_KEY_BYTES = 32;
var AEAD_NONCE_BYTES = 24;
var AEAD_TAG_BYTES = 16;
function generateSymmetricKey() {
  return getSodium().randombytes_buf(SYMMETRIC_KEY_BYTES);
}
function aeadEncrypt(plaintext, key, associatedData) {
  const s = getSodium();
  if (key.length !== SYMMETRIC_KEY_BYTES) {
    throw new RangeError(`Symmetric key must be ${SYMMETRIC_KEY_BYTES} bytes`);
  }
  const nonce = s.randombytes_buf(AEAD_NONCE_BYTES);
  const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, associatedData ?? null, null, nonce, key);
  const out = new Uint8Array(AEAD_NONCE_BYTES + ciphertext.length);
  out.set(nonce, 0);
  out.set(ciphertext, AEAD_NONCE_BYTES);
  return out;
}
function aeadDecrypt(ciphertext, key, associatedData) {
  const s = getSodium();
  if (key.length !== SYMMETRIC_KEY_BYTES) {
    throw new RangeError(`Symmetric key must be ${SYMMETRIC_KEY_BYTES} bytes`);
  }
  if (ciphertext.length < AEAD_NONCE_BYTES + AEAD_TAG_BYTES) {
    throw new Error("Ciphertext is too short");
  }
  const nonce = ciphertext.subarray(0, AEAD_NONCE_BYTES);
  const body = ciphertext.subarray(AEAD_NONCE_BYTES);
  return s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, body, associatedData ?? null, nonce, key);
}
// src/crypto/canonical.ts
var utf8Encoder = new TextEncoder;
function compareCodeUnits(a, b) {
  if (a < b)
    return -1;
  if (a > b)
    return 1;
  return 0;
}
function serializeCanonical(value, ancestors) {
  if (value === null)
    return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number": {
      if (!Number.isFinite(value)) {
        throw new TypeError("Cannot canonicalize non-finite number");
      }
      return Object.is(value, -0) ? "0" : JSON.stringify(value);
    }
    case "string":
      return JSON.stringify(value);
    case "undefined":
    case "function":
    case "symbol":
    case "bigint":
      throw new TypeError(`Cannot canonicalize value of type ${typeof value}`);
    case "object": {
      if (ancestors.has(value)) {
        throw new TypeError("Cannot canonicalize circular reference");
      }
      if (Array.isArray(value)) {
        ancestors.add(value);
        try {
          const items = [];
          for (let i = 0;i < value.length; i++) {
            items.push(serializeCanonical(value[i], ancestors));
          }
          return `[${items.join(",")}]`;
        } finally {
          ancestors.delete(value);
        }
      }
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) {
        throw new TypeError("Cannot canonicalize non-plain object");
      }
      ancestors.add(value);
      try {
        const record = value;
        const keys = Object.keys(record).filter((k) => record[k] !== undefined).sort(compareCodeUnits);
        const entries = [];
        for (const key of keys) {
          entries.push(`${JSON.stringify(key)}:${serializeCanonical(record[key], ancestors)}`);
        }
        return `{${entries.join(",")}}`;
      } finally {
        ancestors.delete(value);
      }
    }
    default:
      throw new TypeError(`Cannot canonicalize value of type ${typeof value}`);
  }
}
function canonicalize(value) {
  return utf8Encoder.encode(serializeCanonical(value, new Set));
}

// src/crypto/blob-stream.ts
var BLOB_MAGIC = new Uint8Array([84, 71, 66, 49]);
var BLOB_CHUNK_BYTES = 1024 * 1024;
var BLOB_MAX_FRAME_BYTES = BLOB_CHUNK_BYTES + AEAD_NONCE_BYTES + AEAD_TAG_BYTES;
function chunkAad(index, last) {
  return canonicalize({ v: 1, index, last });
}
async function* iterate(input) {
  if (input instanceof Uint8Array) {
    yield input;
    return;
  }
  for await (const part of input) {
    yield part;
  }
}
async function* slice(input, size) {
  let pending = new Uint8Array(0);
  for await (const part of iterate(input)) {
    if (part.length === 0) {
      continue;
    }
    let data = part;
    if (pending.length > 0) {
      const merged = new Uint8Array(pending.length + data.length);
      merged.set(pending, 0);
      merged.set(data, pending.length);
      data = merged;
      pending = new Uint8Array(0);
    }
    let offset = 0;
    while (data.length - offset >= size) {
      yield data.subarray(offset, offset + size);
      offset += size;
    }
    pending = data.subarray(offset);
  }
  if (pending.length > 0) {
    yield pending;
  }
}
function u32le(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, true);
  return out;
}
async function* encryptBlobChunks(plaintext, key) {
  yield BLOB_MAGIC;
  let index = 0;
  let previous = null;
  for await (const chunk of slice(plaintext, BLOB_CHUNK_BYTES)) {
    if (previous !== null) {
      const sealed2 = aeadEncrypt(previous, key, chunkAad(index, false));
      yield u32le(sealed2.length);
      yield sealed2;
      index++;
    }
    previous = chunk;
  }
  const sealed = aeadEncrypt(previous ?? new Uint8Array(0), key, chunkAad(index, true));
  yield u32le(sealed.length);
  yield sealed;
}

class ByteReader {
  #iterator;
  #buffer = new Uint8Array(0);
  #done = false;
  constructor(input) {
    this.#iterator = iterate(input)[Symbol.asyncIterator]();
  }
  async read(length) {
    while (this.#buffer.length < length && !this.#done) {
      const next = await this.#iterator.next();
      if (next.done === true) {
        this.#done = true;
        break;
      }
      if (next.value.length === 0) {
        continue;
      }
      if (this.#buffer.length === 0) {
        this.#buffer = next.value;
      } else {
        const merged = new Uint8Array(this.#buffer.length + next.value.length);
        merged.set(this.#buffer, 0);
        merged.set(next.value, this.#buffer.length);
        this.#buffer = merged;
      }
    }
    const take = Math.min(length, this.#buffer.length);
    const out = this.#buffer.subarray(0, take);
    this.#buffer = this.#buffer.subarray(take);
    return out;
  }
}

class BlobFormatError extends Error {
  constructor(message) {
    super(message);
    this.name = "BlobFormatError";
  }
}
async function* decryptBlobChunks(ciphertext, key, options = {}) {
  const reader = new ByteReader(ciphertext);
  const magic = await reader.read(BLOB_MAGIC.length);
  if (magic.length !== BLOB_MAGIC.length || !BLOB_MAGIC.every((byte, i) => magic[i] === byte)) {
    throw new BlobFormatError("Not a TGB1 blob");
  }
  let index = 0;
  let total = 0;
  while (true) {
    const prefix = await reader.read(4);
    if (prefix.length === 0) {
      throw new BlobFormatError("Blob is truncated");
    }
    if (prefix.length !== 4) {
      throw new BlobFormatError("Blob frame header is truncated");
    }
    const length = new DataView(prefix.buffer, prefix.byteOffset, 4).getUint32(0, true);
    if (length < AEAD_NONCE_BYTES + AEAD_TAG_BYTES || length > BLOB_MAX_FRAME_BYTES) {
      throw new BlobFormatError("Blob frame has an invalid length");
    }
    const frame = await reader.read(length);
    if (frame.length !== length) {
      throw new BlobFormatError("Blob frame is truncated");
    }
    let plain;
    let last;
    try {
      plain = aeadDecrypt(frame, key, chunkAad(index, false));
      last = false;
    } catch {
      try {
        plain = aeadDecrypt(frame, key, chunkAad(index, true));
        last = true;
      } catch {
        throw new BlobFormatError("Blob chunk failed authentication");
      }
    }
    total += plain.length;
    if (options.maxPlaintextBytes !== undefined && total > options.maxPlaintextBytes) {
      throw new BlobFormatError("Blob exceeds the maximum plaintext size");
    }
    if (last) {
      const rest = await reader.read(1);
      if (rest.length !== 0) {
        throw new BlobFormatError("Blob has data after the final chunk");
      }
      yield plain;
      return;
    }
    yield plain;
    index++;
  }
}
async function collectChunks(input) {
  const parts = [];
  let total = 0;
  for await (const part of iterate(input)) {
    parts.push(part);
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
// src/crypto/encoding.ts
var BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
var BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
var BASE64URL_LOOKUP = new Int8Array(128).fill(-1);
for (let i = 0;i < BASE64URL_ALPHABET.length; i++) {
  BASE64URL_LOOKUP[BASE64URL_ALPHABET.charCodeAt(i)] = i;
}
function toBase64Url(bytes) {
  let out = "";
  const len = bytes.length;
  let i = 0;
  for (;i + 2 < len; i += 3) {
    const b0 = bytes[i] ?? 0;
    const b1 = bytes[i + 1] ?? 0;
    const b2 = bytes[i + 2] ?? 0;
    const triple = b0 << 16 | b1 << 8 | b2;
    out += (BASE64URL_ALPHABET[triple >>> 18 & 63] ?? "") + (BASE64URL_ALPHABET[triple >>> 12 & 63] ?? "") + (BASE64URL_ALPHABET[triple >>> 6 & 63] ?? "") + (BASE64URL_ALPHABET[triple & 63] ?? "");
  }
  const remaining = len - i;
  if (remaining === 1) {
    const b0 = bytes[i] ?? 0;
    out += (BASE64URL_ALPHABET[b0 >>> 2 & 63] ?? "") + (BASE64URL_ALPHABET[b0 << 4 & 63] ?? "");
  } else if (remaining === 2) {
    const b0 = bytes[i] ?? 0;
    const b1 = bytes[i + 1] ?? 0;
    out += (BASE64URL_ALPHABET[b0 >>> 2 & 63] ?? "") + (BASE64URL_ALPHABET[(b0 << 4 | b1 >>> 4) & 63] ?? "") + (BASE64URL_ALPHABET[b1 << 2 & 63] ?? "");
  }
  return out;
}
function fromBase64Url(text) {
  const len = text.length;
  const rem = len % 4;
  if (rem === 1) {
    throw new Error("Invalid base64url length");
  }
  const byteLen = Math.floor(len * 3 / 4);
  const out = new Uint8Array(byteLen);
  let outIdx = 0;
  let i = 0;
  const decodeChar = (idx) => {
    const code = text.charCodeAt(idx);
    if (code >= 128)
      throw new Error("Invalid base64url character");
    const val = BASE64URL_LOOKUP[code] ?? -1;
    if (val < 0)
      throw new Error("Invalid base64url character");
    return val;
  };
  for (;i + 3 < len; i += 4) {
    const c0 = decodeChar(i);
    const c1 = decodeChar(i + 1);
    const c2 = decodeChar(i + 2);
    const c3 = decodeChar(i + 3);
    const triple = c0 << 18 | c1 << 12 | c2 << 6 | c3;
    out[outIdx++] = triple >>> 16 & 255;
    out[outIdx++] = triple >>> 8 & 255;
    out[outIdx++] = triple & 255;
  }
  if (rem === 2) {
    const c0 = decodeChar(i);
    const c1 = decodeChar(i + 1);
    if ((c1 & 15) !== 0) {
      throw new Error("Non-canonical base64url trailing bits");
    }
    out[outIdx++] = c0 << 2 | c1 >>> 4;
  } else if (rem === 3) {
    const c0 = decodeChar(i);
    const c1 = decodeChar(i + 1);
    const c2 = decodeChar(i + 2);
    if ((c2 & 3) !== 0) {
      throw new Error("Non-canonical base64url trailing bits");
    }
    out[outIdx++] = c0 << 2 | c1 >>> 4;
    out[outIdx++] = (c1 & 15) << 4 | c2 >>> 2;
  }
  return out;
}
function toBase32(bytes) {
  let out = "";
  let buffer = 0;
  let bitsLeft = 0;
  for (let i = 0;i < bytes.length; i++) {
    buffer = buffer << 8 | (bytes[i] ?? 0);
    bitsLeft += 8;
    while (bitsLeft >= 5) {
      bitsLeft -= 5;
      out += BASE32_ALPHABET[buffer >>> bitsLeft & 31] ?? "";
    }
  }
  if (bitsLeft > 0) {
    out += BASE32_ALPHABET[buffer << 5 - bitsLeft & 31] ?? "";
  }
  return out;
}

// src/crypto/signing.ts
var SIGNING_PUBLIC_KEY_BYTES = 32;
var SIGNING_SECRET_KEY_BYTES = 64;
var SIGNING_SEED_BYTES = 32;
var SIGNATURE_BYTES = 64;
var FINGERPRINT_HASH_BYTES = 32;
var FINGERPRINT_TRUNCATED_BYTES = 20;
function generateSigningKeyPair() {
  const s = getSodium();
  const kp = s.crypto_sign_keypair();
  return {
    publicKey: kp.publicKey,
    secretKey: kp.privateKey
  };
}
function signingKeyPairFromSeed(seed) {
  const s = getSodium();
  if (seed.length !== SIGNING_SEED_BYTES) {
    throw new RangeError(`Signing seed must be ${SIGNING_SEED_BYTES} bytes`);
  }
  const kp = s.crypto_sign_seed_keypair(seed);
  return {
    publicKey: kp.publicKey,
    secretKey: kp.privateKey
  };
}
function sign(message, secretKey) {
  const s = getSodium();
  if (secretKey.length !== SIGNING_SECRET_KEY_BYTES) {
    throw new RangeError(`Signing secret key must be ${SIGNING_SECRET_KEY_BYTES} bytes`);
  }
  return s.crypto_sign_detached(message, secretKey);
}
function verify(message, signature, publicKey) {
  const s = getSodium();
  if (signature.length !== SIGNATURE_BYTES || publicKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
    return false;
  }
  try {
    return s.crypto_sign_verify_detached(signature, message, publicKey);
  } catch {
    return false;
  }
}
function fingerprint(publicKey) {
  const s = getSodium();
  if (publicKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new RangeError(`Public key must be ${SIGNING_PUBLIC_KEY_BYTES} bytes`);
  }
  const digest = s.crypto_generichash(FINGERPRINT_HASH_BYTES, publicKey, null);
  return toBase32(digest.subarray(0, FINGERPRINT_TRUNCATED_BYTES));
}

// src/crypto/box.ts
function sealTo(plaintext, recipientSigningPublicKey) {
  const s = getSodium();
  if (recipientSigningPublicKey.length !== SIGNING_PUBLIC_KEY_BYTES) {
    throw new RangeError(`Recipient public key must be ${SIGNING_PUBLIC_KEY_BYTES} bytes`);
  }
  const curvePk = s.crypto_sign_ed25519_pk_to_curve25519(recipientSigningPublicKey);
  return s.crypto_box_seal(plaintext, curvePk);
}
function openSealed(ciphertext, recipientSigningKeyPair) {
  const s = getSodium();
  if (recipientSigningKeyPair.publicKey.length !== SIGNING_PUBLIC_KEY_BYTES || recipientSigningKeyPair.secretKey.length !== SIGNING_SECRET_KEY_BYTES) {
    throw new RangeError("Invalid recipient signing key pair length");
  }
  const curvePk = s.crypto_sign_ed25519_pk_to_curve25519(recipientSigningKeyPair.publicKey);
  const curveSk = s.crypto_sign_ed25519_sk_to_curve25519(recipientSigningKeyPair.secretKey);
  try {
    return s.crypto_box_seal_open(ciphertext, curvePk, curveSk);
  } finally {
    s.memzero(curveSk);
  }
}
// src/crypto/hash.ts
var HASH_BYTES = 32;
function hash(data, key) {
  const s = getSodium();
  if (key !== undefined) {
    if (key.length < s.crypto_generichash_KEYBYTES_MIN || key.length > s.crypto_generichash_KEYBYTES_MAX) {
      throw new RangeError(`Hash key must be between ${s.crypto_generichash_KEYBYTES_MIN} and ${s.crypto_generichash_KEYBYTES_MAX} bytes`);
    }
    return s.crypto_generichash(HASH_BYTES, data, key);
  }
  return s.crypto_generichash(HASH_BYTES, data, null);
}
var SHA256_BYTES = 32;
function sha256(data) {
  return getSodium().crypto_hash_sha256(data);
}
// src/crypto/kdf.ts
var KDF_ALG_ARGON2ID13 = "argon2id13";
var KDF_SALT_BYTES = 16;
var KDF_KEY_BYTES = 32;
var KDF_FLOOR = {
  alg: KDF_ALG_ARGON2ID13,
  opslimit: 3,
  memlimit: 128 * 1024 * 1024
};
var KDF_MODERATE = {
  alg: KDF_ALG_ARGON2ID13,
  opslimit: 3,
  memlimit: 256 * 1024 * 1024
};
var utf8Encoder2 = new TextEncoder;
function generateSalt() {
  return getSodium().randombytes_buf(KDF_SALT_BYTES);
}
function assertKdfParams(params) {
  if (typeof params !== "object" || params === null) {
    throw new Error("KDF parameters must be an object");
  }
  const record = params;
  if (record.alg !== KDF_ALG_ARGON2ID13) {
    throw new Error(`Unsupported KDF algorithm: expected ${KDF_ALG_ARGON2ID13}`);
  }
  if (typeof record.opslimit !== "number" || !Number.isSafeInteger(record.opslimit) || record.opslimit < KDF_FLOOR.opslimit) {
    throw new Error(`KDF opslimit must be an integer >= ${KDF_FLOOR.opslimit}`);
  }
  if (typeof record.memlimit !== "number" || !Number.isSafeInteger(record.memlimit) || record.memlimit < KDF_FLOOR.memlimit) {
    throw new Error(`KDF memlimit must be an integer >= ${KDF_FLOOR.memlimit}`);
  }
  if (!(record.salt instanceof Uint8Array) || record.salt.length !== KDF_SALT_BYTES) {
    throw new Error(`KDF salt must be a Uint8Array of ${KDF_SALT_BYTES} bytes`);
  }
}
function deriveKeyFromPassword(password, params, keyLength = KDF_KEY_BYTES) {
  const s = getSodium();
  assertKdfParams(params);
  if (!Number.isSafeInteger(keyLength) || keyLength < 16) {
    throw new RangeError("Derived key length must be an integer >= 16");
  }
  const isString = typeof password === "string";
  const pwBytes = isString ? utf8Encoder2.encode(password) : password;
  try {
    return s.crypto_pwhash(keyLength, pwBytes, params.salt, params.opslimit, params.memlimit, s.crypto_pwhash_ALG_ARGON2ID13);
  } finally {
    if (isString) {
      s.memzero(pwBytes);
    }
  }
}
export { ready, randomBytes, memzero, SYMMETRIC_KEY_BYTES, AEAD_NONCE_BYTES, AEAD_TAG_BYTES, generateSymmetricKey, aeadEncrypt, aeadDecrypt, canonicalize, BLOB_MAGIC, BLOB_CHUNK_BYTES, BLOB_MAX_FRAME_BYTES, encryptBlobChunks, BlobFormatError, decryptBlobChunks, collectChunks, toBase64Url, fromBase64Url, toBase32, SIGNING_PUBLIC_KEY_BYTES, SIGNING_SECRET_KEY_BYTES, SIGNING_SEED_BYTES, SIGNATURE_BYTES, FINGERPRINT_HASH_BYTES, FINGERPRINT_TRUNCATED_BYTES, generateSigningKeyPair, signingKeyPairFromSeed, sign, verify, fingerprint, sealTo, openSealed, HASH_BYTES, hash, SHA256_BYTES, sha256, KDF_ALG_ARGON2ID13, KDF_SALT_BYTES, KDF_KEY_BYTES, KDF_FLOOR, KDF_MODERATE, generateSalt, assertKdfParams, deriveKeyFromPassword };
