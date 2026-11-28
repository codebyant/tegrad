// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { AEAD_NONCE_BYTES, AEAD_TAG_BYTES, aeadDecrypt, aeadEncrypt } from "./aead";
import { canonicalize } from "./canonical";

/**
 * Chunked blob format ("TGB1"):
 *
 *   "TGB1" | frame*
 *   frame = u32le(length) | aeadEncrypt(chunk, key, aad)    // length = nonce + ciphertext + tag
 *   aad   = canonicalize({ v: 1, index, last })
 *
 * Chunks hold up to 1 MiB of plaintext. Binding the index and the `last` flag
 * into the AAD makes reordering, repeating and truncating a blob detectable.
 * The input is never required to fit in memory.
 */
export const BLOB_MAGIC = new Uint8Array([0x54, 0x47, 0x42, 0x31]); // "TGB1"
export const BLOB_CHUNK_BYTES = 1024 * 1024;
export const BLOB_MAX_FRAME_BYTES = BLOB_CHUNK_BYTES + AEAD_NONCE_BYTES + AEAD_TAG_BYTES;

export type BlobInput = Uint8Array | AsyncIterable<Uint8Array> | Iterable<Uint8Array>;

function chunkAad(index: number, last: boolean): Uint8Array {
  return canonicalize({ v: 1, index, last });
}

async function* iterate(input: BlobInput): AsyncGenerator<Uint8Array> {
  if (input instanceof Uint8Array) {
    yield input;
    return;
  }
  for await (const part of input as AsyncIterable<Uint8Array>) {
    yield part;
  }
}

/** Re-slices an arbitrary byte stream into fixed-size pieces (the last one may be shorter). */
async function* slice(input: BlobInput, size: number): AsyncGenerator<Uint8Array> {
  let pending: Uint8Array = new Uint8Array(0);
  for await (const part of iterate(input)) {
    if (part.length === 0) {
      continue;
    }
    let data: Uint8Array = part;
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

function u32le(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, true);
  return out;
}

/** Encrypts a byte stream into TGB1 pieces. Yields the header first, then one frame per chunk. */
export async function* encryptBlobChunks(
  plaintext: BlobInput,
  key: Uint8Array,
): AsyncGenerator<Uint8Array> {
  yield BLOB_MAGIC;

  let index = 0;
  let previous: Uint8Array | null = null;
  for await (const chunk of slice(plaintext, BLOB_CHUNK_BYTES)) {
    if (previous !== null) {
      const sealed = aeadEncrypt(previous, key, chunkAad(index, false));
      yield u32le(sealed.length);
      yield sealed;
      index++;
    }
    previous = chunk;
  }

  // The final chunk is always written, even for empty input, so a stream cannot end unmarked.
  const sealed = aeadEncrypt(previous ?? new Uint8Array(0), key, chunkAad(index, true));
  yield u32le(sealed.length);
  yield sealed;
}

class ByteReader {
  readonly #iterator: AsyncIterator<Uint8Array>;
  #buffer: Uint8Array = new Uint8Array(0);
  #done = false;

  constructor(input: BlobInput) {
    this.#iterator = iterate(input)[Symbol.asyncIterator]();
  }

  /** Reads exactly `length` bytes, or fewer only at end of input (returns what was left). */
  async read(length: number): Promise<Uint8Array> {
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

export class BlobFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BlobFormatError";
  }
}

/**
 * Decrypts a TGB1 stream, yielding plaintext chunks as they are verified.
 * Throws `BlobFormatError` on a bad header, oversized frame, truncation, trailing
 * data, reordering or tampering. Nothing is yielded for a chunk that fails.
 */
export async function* decryptBlobChunks(
  ciphertext: BlobInput,
  key: Uint8Array,
  options: { readonly maxPlaintextBytes?: number } = {},
): AsyncGenerator<Uint8Array> {
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

    // A frame is the last one only if nothing follows it; try both readings of the AAD.
    let plain: Uint8Array;
    let last: boolean;
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

/** Collects a stream of chunks into one buffer (for small blobs and tests). */
export async function collectChunks(input: BlobInput): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
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
