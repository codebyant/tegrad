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
export declare const BLOB_MAGIC: Uint8Array<ArrayBuffer>;
export declare const BLOB_CHUNK_BYTES: number;
export declare const BLOB_MAX_FRAME_BYTES: number;
export type BlobInput = Uint8Array | AsyncIterable<Uint8Array> | Iterable<Uint8Array>;
/** Encrypts a byte stream into TGB1 pieces. Yields the header first, then one frame per chunk. */
export declare function encryptBlobChunks(plaintext: BlobInput, key: Uint8Array): AsyncGenerator<Uint8Array>;
export declare class BlobFormatError extends Error {
    constructor(message: string);
}
/**
 * Decrypts a TGB1 stream, yielding plaintext chunks as they are verified.
 * Throws `BlobFormatError` on a bad header, oversized frame, truncation, trailing
 * data, reordering or tampering. Nothing is yielded for a chunk that fails.
 */
export declare function decryptBlobChunks(ciphertext: BlobInput, key: Uint8Array, options?: {
    readonly maxPlaintextBytes?: number;
}): AsyncGenerator<Uint8Array>;
/** Collects a stream of chunks into one buffer (for small blobs and tests). */
export declare function collectChunks(input: BlobInput): Promise<Uint8Array>;
