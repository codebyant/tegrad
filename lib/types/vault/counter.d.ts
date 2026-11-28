import type { KeyId } from "../protocol";
export interface CounterStore {
    next(signer: KeyId, now: number): Promise<number>;
}
export declare function createMemoryCounterStore(): CounterStore;
