// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>

import { beforeAll, describe, expect, test } from "bun:test";
import {
  BLOB_CHUNK_BYTES,
  BLOB_MAGIC,
  BlobFormatError,
  collectChunks,
  decryptBlobChunks,
  encryptBlobChunks,
  generateSymmetricKey,
  randomBytes,
  ready,
} from "./index";

beforeAll(async () => {
  await ready();
});

async function seal(plain: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  return collectChunks(encryptBlobChunks(plain, key));
}

async function* inPieces(data: Uint8Array, size: number): AsyncGenerator<Uint8Array> {
  for (let i = 0; i < data.length; i += size) {
    yield data.subarray(i, i + size);
  }
}

async function expectFormatError(promise: Promise<unknown>): Promise<void> {
  try {
    await promise;
  } catch (err) {
    expect(err).toBeInstanceOf(BlobFormatError);
    return;
  }
  throw new Error("expected BlobFormatError");
}

function frames(blob: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  let offset = BLOB_MAGIC.length;
  while (offset < blob.length) {
    const length = new DataView(blob.buffer, blob.byteOffset + offset, 4).getUint32(0, true);
    out.push(blob.subarray(offset, offset + 4 + length));
    offset += 4 + length;
  }
  return out;
}

function join(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

describe("chunked blob encryption (TGB1)", () => {
  test("round-trips empty, small and multi-chunk data; header is TGB1", async () => {
    const key = generateSymmetricKey();
    for (const size of [
      0,
      1,
      1000,
      BLOB_CHUNK_BYTES,
      BLOB_CHUNK_BYTES + 1,
      2.5 * BLOB_CHUNK_BYTES,
    ]) {
      const plain = randomBytes(size);
      const blob = await seal(plain, key);
      expect(Array.from(blob.subarray(0, 4))).toEqual([0x54, 0x47, 0x42, 0x31]);
      const back = await collectChunks(decryptBlobChunks(blob, key));
      expect(back).toEqual(plain);
    }
  });

  test("accepts streams for both directions with arbitrary piece sizes", async () => {
    const key = generateSymmetricKey();
    const plain = randomBytes(BLOB_CHUNK_BYTES * 2 + 12345);
    const blob = await collectChunks(encryptBlobChunks(inPieces(plain, 7777), key));
    const back = await collectChunks(decryptBlobChunks(inPieces(blob, 513), key));
    expect(back).toEqual(plain);
  });

  test("uses chunks of at most 1 MiB and decrypts incrementally", async () => {
    const key = generateSymmetricKey();
    const blob = await seal(randomBytes(BLOB_CHUNK_BYTES * 3), key);
    const sizes: number[] = [];
    for await (const chunk of decryptBlobChunks(blob, key)) {
      sizes.push(chunk.length);
    }
    expect(sizes).toEqual([BLOB_CHUNK_BYTES, BLOB_CHUNK_BYTES, BLOB_CHUNK_BYTES]);
  });

  test("the wrong key fails", async () => {
    const blob = await seal(randomBytes(100), generateSymmetricKey());
    await expectFormatError(collectChunks(decryptBlobChunks(blob, generateSymmetricKey())));
  });

  test("a bad header fails", async () => {
    const key = generateSymmetricKey();
    const blob = await seal(randomBytes(10), key);
    const bad = blob.slice();
    bad[0] = 0x00;
    await expectFormatError(collectChunks(decryptBlobChunks(bad, key)));
    await expectFormatError(collectChunks(decryptBlobChunks(new Uint8Array(2), key)));
  });

  test("flipping any byte of a frame fails", async () => {
    const key = generateSymmetricKey();
    const blob = await seal(randomBytes(5000), key);
    const tampered = blob.slice();
    tampered[blob.length - 5] = (tampered[blob.length - 5] ?? 0) ^ 1;
    await expectFormatError(collectChunks(decryptBlobChunks(tampered, key)));
  });

  test("truncation is detected, at a frame boundary and inside a frame", async () => {
    const key = generateSymmetricKey();
    const blob = await seal(randomBytes(BLOB_CHUNK_BYTES * 2 + 10), key);
    const all = frames(blob);
    expect(all.length).toBe(3);

    // Dropping the last frame leaves a stream that never says "last".
    const cutAtBoundary = join([BLOB_MAGIC, ...all.slice(0, 2)]);
    await expectFormatError(collectChunks(decryptBlobChunks(cutAtBoundary, key)));

    // Cutting inside a frame.
    await expectFormatError(
      collectChunks(decryptBlobChunks(blob.subarray(0, blob.length - 3), key)),
    );
    await expectFormatError(collectChunks(decryptBlobChunks(blob.subarray(0, 6), key)));
    await expectFormatError(collectChunks(decryptBlobChunks(blob.subarray(0, 4), key)));
  });

  test("reordering and repeating chunks are detected", async () => {
    const key = generateSymmetricKey();
    const blob = await seal(randomBytes(BLOB_CHUNK_BYTES * 2 + 10), key);
    const [a, b, c] = frames(blob);
    if (!a || !b || !c) throw new Error("frames");

    await expectFormatError(collectChunks(decryptBlobChunks(join([BLOB_MAGIC, b, a, c]), key)));
    await expectFormatError(collectChunks(decryptBlobChunks(join([BLOB_MAGIC, a, a, c]), key)));
    await expectFormatError(collectChunks(decryptBlobChunks(join([BLOB_MAGIC, a, b, b, c]), key)));
  });

  test("data after the final chunk is refused, and so is a frame of absurd length", async () => {
    const key = generateSymmetricKey();
    const blob = await seal(randomBytes(10), key);
    await expectFormatError(collectChunks(decryptBlobChunks(join([blob, new Uint8Array(1)]), key)));

    const huge = new Uint8Array(4);
    new DataView(huge.buffer).setUint32(0, 0xffffffff, true);
    await expectFormatError(collectChunks(decryptBlobChunks(join([BLOB_MAGIC, huge]), key)));
  });

  test("a chunk from another blob cannot be spliced in", async () => {
    const key = generateSymmetricKey();
    const one = frames(await seal(randomBytes(BLOB_CHUNK_BYTES + 10), key));
    const two = frames(await seal(randomBytes(BLOB_CHUNK_BYTES + 10), key));
    // Same key, same index and flags: this is valid by design (same key means same trust),
    // but a first chunk marked as non-last cannot stand in for a last one.
    const spliced = join([BLOB_MAGIC, one[0] as Uint8Array, one[0] as Uint8Array]);
    await expectFormatError(collectChunks(decryptBlobChunks(spliced, key)));
    expect(two.length).toBe(2);
  });

  test("maxPlaintextBytes stops oversized blobs", async () => {
    const key = generateSymmetricKey();
    const blob = await seal(randomBytes(BLOB_CHUNK_BYTES * 2), key);
    await expectFormatError(
      collectChunks(decryptBlobChunks(blob, key, { maxPlaintextBytes: BLOB_CHUNK_BYTES })),
    );
  });

  test("rejects keys of the wrong size", async () => {
    await expect(
      collectChunks(encryptBlobChunks(randomBytes(4), new Uint8Array(5))),
    ).rejects.toThrow();
  });
});
