import { createHasher, type Argon2Cost } from "../../src/methods/password/argon2.js"

/**
 * The smallest argon2id cost hash-wasm accepts: 8 KiB, one pass, one lane. Every test hashes at it through
 * `createAuth`'s test-mode `argon2Cost` or `testHasher`; test/budgets/argon2-parameters.test.ts alone runs the
 * ADR 0018 cost, so a loaded machine never turns a slow hash into a timeout.
 */
export const TEST_ARGON2_COST: Argon2Cost = { memoryKiB: 8, iterations: 1, parallelism: 1 }

/** A hasher at the test cost, behind the process's one hashing semaphore. */
export const testHasher = createHasher(TEST_ARGON2_COST)
