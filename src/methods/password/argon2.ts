/**
 * argon2id through `hash-wasm`, at a fixed cost (ADR 0018 §1) and behind one per-process semaphore (ADR 0018 §2).
 * Each stored hash is the PHC string `hash-wasm` encodes, which records the parameters it was made with, so a change
 * of constants never makes an old hash unverifiable; `needsRehash` tells the caller to move it at the next sign-in.
 */

import { argon2id, argon2Verify } from "hash-wasm"
import { randomBytes, type RandomSource } from "../../core/clock.js"
import type { NormalisedPassword } from "./rules.js"
import { createSemaphore } from "./semaphore.js"

/** The fixed argon2id cost: OWASP's minimum configuration (ADR 0018 Open 1). */
export const ARGON2_PARAMETERS = {
  memoryKiB: 19_456,
  iterations: 2,
  parallelism: 1,
  saltBytes: 16,
  hashBytes: 32,
} as const

/** How many argon2id computations run at once per process (ADR 0018 Open 2). */
export const HASH_CONCURRENCY = 4
/** How many more may wait; one beyond this is refused with the throttled reply. */
export const HASH_QUEUE_LIMIT = 32

/** The one semaphore every argon2id computation of this process goes through, the dummy one included. */
export const hashing = createSemaphore(HASH_CONCURRENCY, HASH_QUEUE_LIMIT)

/** An argon2id cost: memory in KiB, passes and lanes. ADR 0018 fixes it; only test mode may pass another (ADR 0026 §4). */
export interface Argon2Cost {
  /** Memory in KiB. */
  readonly memoryKiB: number
  /** Passes over the memory. */
  readonly iterations: number
  /** Lanes. */
  readonly parallelism: number
}

/**
 * The argon2id computation itself: hash-wasm in every deployment. A test that measures the semaphore injects one that
 * holds each computation open, so it needs no real hash.
 */
export interface Argon2Engine {
  /** Hashes `password` with `salt` at `cost`; resolves to the encoded PHC string. */
  readonly hash: (input: {
    readonly password: string
    readonly salt: Uint8Array
    readonly cost: Argon2Cost
  }) => Promise<string>
  /** True when `password` matches the encoded hash, at the cost the hash records. */
  readonly verify: (password: string, encoded: string) => Promise<boolean>
}

const HASH_WASM: Argon2Engine = {
  hash: ({ password, salt, cost }) =>
    argon2id({
      password,
      salt,
      memorySize: cost.memoryKiB,
      iterations: cost.iterations,
      parallelism: cost.parallelism,
      hashLength: ARGON2_PARAMETERS.hashBytes,
      outputType: "encoded",
    }),
  verify: (password, hash) => argon2Verify({ password, hash }),
}

/** Hashing and verifying at one cost, every computation behind the process's one semaphore. */
export interface PasswordHasher {
  /**
   * A hash at this cost, verified whenever no stored hash is (ADR 0009 §6), so the time spent hashing does not reveal
   * whether an account has a password. No password verifies against it.
   */
  readonly dummyHash: string
  /** Hashes `password` with a fresh salt from `random`; resolves to the encoded PHC string. */
  hash(password: NormalisedPassword, random: RandomSource): Promise<string>
  /** True when `password` matches the encoded hash. */
  verify(password: NormalisedPassword, encoded: string): Promise<boolean>
  /** Runs a verification against the dummy hash; always resolves to `false`. */
  dummyVerify(password: NormalisedPassword): Promise<false>
  /** True when the encoded hash was made with parameters other than this hasher's. */
  needsRehash(encoded: string): boolean
}

/** The salt and digest of the dummy hash: a digest no password is known to produce. */
const DUMMY_TAIL = "WlpaWlpaWlpaWlpaWlpaWg$lhxJyQ2352vbiodRTI+m5puq1xV3hswYXC3vhJ2nHqg"

const prefixOf = (cost: Argon2Cost): string =>
  `$argon2id$v=19$m=${cost.memoryKiB},t=${cost.iterations},p=${cost.parallelism}$`

/** The dummy hash at the ADR 0018 cost. */
export const DUMMY_HASH = `${prefixOf(ARGON2_PARAMETERS)}${DUMMY_TAIL}`

/** Why `cost` is one hash-wasm cannot compute, or `undefined` when it can. */
export function argon2CostProblem(cost: Argon2Cost): string | undefined {
  const whole = (value: number, min: number): boolean => Number.isSafeInteger(value) && value >= min
  return whole(cost.iterations, 1) &&
    whole(cost.parallelism, 1) &&
    whole(cost.memoryKiB, 8 * cost.parallelism)
    ? undefined
    : "argon2Cost must be whole numbers: iterations and parallelism at least 1, memoryKiB at least 8 times parallelism."
}

/** A hasher at `cost`, the ADR 0018 one unless a test passes another, computing through `engine`. */
export function createHasher(
  cost: Argon2Cost = ARGON2_PARAMETERS,
  engine: Argon2Engine = HASH_WASM,
): PasswordHasher {
  const prefix = prefixOf(cost)
  const dummyHash = `${prefix}${DUMMY_TAIL}`
  const verify = (password: NormalisedPassword, encoded: string): Promise<boolean> =>
    hashing.run(() => engine.verify(password, encoded))
  return {
    dummyHash,
    hash: (password, random) => {
      const salt = randomBytes(random, ARGON2_PARAMETERS.saltBytes)
      return hashing.run(() => engine.hash({ password, salt, cost }))
    },
    verify,
    async dummyVerify(password) {
      await verify(password, dummyHash)
      return false
    },
    needsRehash: (encoded) => !encoded.startsWith(prefix),
  }
}
