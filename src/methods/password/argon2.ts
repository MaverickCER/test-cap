/**
 * argon2id through `hash-wasm`, at a fixed cost (ADR 0018 §1) and behind one per-process semaphore (ADR 0018 §2).
 * Where the runtime refuses to compile WebAssembly (Cloudflare Workers), the same argon2id runs on `@noble/hashes`, and
 * an app may replace both with its own `Argon2Hasher` (ADR 0031). Each stored hash is the PHC string `hash-wasm`
 * encodes, which records the parameters it was made with, so a change of constants never makes an old hash
 * unverifiable; `needsRehash` tells the caller to move it at the next sign-in.
 */

import { argon2id, argon2Verify } from "hash-wasm"
import type { AuthDiagnostic } from "../../core/auth.js"
import { randomBytes, type RandomSource } from "../../core/clock.js"
import { constantTimeEqual, utf8Encode } from "../../core/encoding.js"
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
 * The argon2id computation itself, which `createAuth`'s `argon2Hasher` replaces: by default hash-wasm, or
 * `@noble/hashes` where WebAssembly cannot compile (ADR 0031). test-cap keeps around it the fixed cost, the salt,
 * the semaphore and the dummy hash, and refuses what it can check: a hash that is not the argon2id PHC string of the
 * salt and cost it asked for, a stored hash in any other format, and any answer from `verify` but `true` as a match.
 *
 * What the app takes on by replacing it: a correct argon2id (RFC 9106, version 19) that writes the PHC string with
 * standard base64 and no padding, as hash-wasm does, so hashes stay verifiable when the hasher changes back; a
 * constant-time comparison in `verify`; and the time and memory each hash costs where the app runs.
 */
export interface Argon2Hasher {
  /**
   * Hashes `password` with `salt` at `cost`, to a 32-byte digest; resolves to the PHC string, such as
   * `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<digest>`.
   */
  readonly hash: (input: {
    readonly password: string
    readonly salt: Uint8Array
    readonly cost: Argon2Cost
  }) => Promise<string>
  /** Resolves to `true` when `password` matches the PHC string `encoded`, at the cost `encoded` records. */
  readonly verify: (password: string, encoded: string) => Promise<boolean>
}

/** An argon2id PHC string as test-cap stores it: version 19, the cost, a 16-byte salt and a 32-byte digest. */
const PHC = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]{22})\$[A-Za-z0-9+/]{43}$/

/** Standard base64 without padding, as a PHC string writes bytes. */
const base64 = (bytes: Uint8Array): string =>
  btoa(String.fromCharCode(...bytes)).replaceAll("=", "")

/** argon2id on `@noble/hashes`, loaded only when used: the fallback where WebAssembly cannot compile. */
export const nobleArgon2: Argon2Hasher = {
  async hash({ password, salt, cost }) {
    const { argon2idAsync } = await import("@noble/hashes/argon2.js")
    const digest = await argon2idAsync(password, salt, {
      m: cost.memoryKiB,
      t: cost.iterations,
      p: cost.parallelism,
      dkLen: ARGON2_PARAMETERS.hashBytes,
    })
    return `${prefixOf(cost)}${base64(salt)}$${base64(digest)}`
  },
  async verify(password, encoded) {
    const match = PHC.exec(encoded)
    if (match === null) return false
    // PHC captures all four groups whenever it matches.
    const [, m, t, p, salt] = match as unknown as readonly [string, string, string, string, string]
    const again = await nobleArgon2.hash({
      password,
      salt: Uint8Array.from(atob(salt), (char) => char.charCodeAt(0)),
      cost: { memoryKiB: Number(m), iterations: Number(t), parallelism: Number(p) },
    })
    return constantTimeEqual(utf8Encode(again), utf8Encode(encoded))
  },
}

const HASH_WASM: Argon2Hasher = {
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

/**
 * hash-wasm until the runtime refuses to compile its WebAssembly, then `@noble/hashes` for the life of the hasher,
 * reported once through `diagnose`. Any other failure is passed on.
 */
function wasmOrNoble(diagnose?: (diagnostic: AuthDiagnostic) => void): Argon2Hasher {
  let engine = HASH_WASM
  const run = async <T>(work: (each: Argon2Hasher) => Promise<T>): Promise<T> => {
    try {
      return await work(engine)
    } catch (error) {
      if ((error as Error).name !== "CompileError") throw error
      engine = nobleArgon2
      diagnose?.({
        code: "argon2-fallback",
        message:
          "WebAssembly cannot compile here, so argon2id runs on @noble/hashes, slower: check your plan's CPU time limit (ADR 0031).",
      })
      return work(engine)
    }
  }
  return {
    hash: (input) => run((each) => each.hash(input)),
    verify: (password, encoded) => run((each) => each.verify(password, encoded)),
  }
}

/**
 * A hasher at `cost`, the ADR 0018 one unless a test passes another, computing through `engine`: the app's own, or
 * hash-wasm with its fallback, which reports through `diagnose`.
 */
export function createHasher(
  cost: Argon2Cost = ARGON2_PARAMETERS,
  engine?: Argon2Hasher,
  diagnose?: (diagnostic: AuthDiagnostic) => void,
): PasswordHasher {
  const prefix = prefixOf(cost)
  const dummyHash = `${prefix}${DUMMY_TAIL}`
  const computes = engine ?? wasmOrNoble(diagnose)
  const verify = async (password: NormalisedPassword, encoded: string): Promise<boolean> =>
    PHC.test(encoded) && (await hashing.run(() => computes.verify(password, encoded))) === true
  return {
    dummyHash,
    hash: async (password, random) => {
      const salt = randomBytes(random, ARGON2_PARAMETERS.saltBytes)
      const encoded = await hashing.run(() => computes.hash({ password, salt, cost }))
      if (PHC.test(encoded) && encoded.startsWith(`${prefix}${base64(salt)}$`)) return encoded
      throw new Error(
        "argon2Hasher.hash must return the argon2id PHC string of the salt and cost it was given.",
      )
    },
    verify,
    async dummyVerify(password) {
      await verify(password, dummyHash)
      return false
    },
    needsRehash: (encoded) => !encoded.startsWith(prefix),
  }
}
