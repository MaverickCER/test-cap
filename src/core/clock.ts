/**
 * The injected clock and random source (ADR 0003). Every expiry, window and time step reads a `Clock`; every token,
 * code and challenge draws from a `RandomSource`. The defaults read the system clock and Web Crypto.
 */

import { base64UrlEncode } from "./encoding.js"

/** The time source every flow reads. */
export interface Clock {
  /** Epoch milliseconds. */
  now(): number
}

/**
 * The random source every token, code and challenge draws from. It must be cryptographically secure in production;
 * a predictable source makes every token guessable.
 */
export interface RandomSource {
  /** Fills `bytes` with random values and returns the same array. */
  fill(bytes: Uint8Array): Uint8Array
}

/** The system clock. */
export const systemClock: Clock = { now: () => Date.now() }

/** Web Crypto's `getRandomValues`. */
export const systemRandom: RandomSource = { fill: (bytes) => crypto.getRandomValues(bytes) }

/** A clock a test sets and advances by hand. */
export interface FixedClock extends Clock {
  set(epochMilliseconds: number): void
  advance(milliseconds: number): void
}

function assertTime(value: number, what: string): void {
  if (!Number.isSafeInteger(value))
    throw new RangeError(`${what} must be a whole number of milliseconds.`)
}

/** A clock fixed at `start` until the test moves it. For tests only. */
export function fixedClock(start: number): FixedClock {
  assertTime(start, "The start time")
  let current = start
  return {
    now: () => current,
    set(epochMilliseconds) {
      assertTime(epochMilliseconds, "The time")
      current = epochMilliseconds
    },
    advance(milliseconds) {
      assertTime(milliseconds, "The step")
      current += milliseconds
    },
  }
}

/** A source that replays `bytes` in order, cycling. Predictable by design: for tests only. */
export function sequenceRandom(bytes: readonly number[]): RandomSource {
  if (bytes.length === 0) throw new RangeError("The sequence needs at least one byte.")
  for (const byte of bytes) {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new RangeError("Every value in the sequence must be a byte (0-255).")
    }
  }
  let position = 0
  return {
    fill(target) {
      for (const i of target.keys()) {
        target[i] = bytes[position % bytes.length] ?? 0
        position += 1
      }
      return target
    },
  }
}

function assertLength(length: number): void {
  if (!Number.isInteger(length) || length < 1)
    throw new RangeError("The length must be a positive integer.")
}

/** `length` bytes from `random`. */
export function randomBytes(random: RandomSource, length: number): Uint8Array {
  assertLength(length)
  return random.fill(new Uint8Array(length))
}

/** A base64url token of `bytes` random bytes; 32 bytes (256 bits) by default. */
export function randomToken(random: RandomSource, bytes = 32): string {
  return base64UrlEncode(randomBytes(random, bytes))
}

/** The highest multiple of 10 below 256; bytes at or above it would bias the digits towards 0-5. */
const DIGIT_CEILING = 250
/** Rounds of drawing before a source that keeps yielding rejected bytes is treated as broken. */
const MAX_ROUNDS = 64
const ROUNDS: readonly undefined[] = Array.from({ length: MAX_ROUNDS })

/** `length` uniformly distributed decimal digits, by rejection sampling. */
export function randomDigits(random: RandomSource, length: number): string {
  let digits = ""
  // Each round draws only the digits still missing; `randomBytes` refuses a `length` that is not a positive integer.
  const drawRound = (): boolean => {
    const missing = length - digits.length
    // Stryker disable all: unreachable progress bound -- `digits` never passes `length`, so at most `length` digits are missing; the bound turns a miscounted draw into an error instead of a draw that doubles every round.
    /* v8 ignore next -- unreachable: `digits` never grows past `length`, so this check is never true */
    if (missing > length) throw new Error("randomDigits miscounted the missing digits.")
    // Stryker restore all
    for (const byte of randomBytes(random, missing)) {
      if (byte < DIGIT_CEILING) digits += String(byte % 10)
    }
    return digits.length === length
  }
  // `some` runs at most MAX_ROUNDS rounds and stops at the first that completes the digits.
  if (ROUNDS.some(drawRound)) return digits
  throw new Error(
    "The random source kept yielding rejected bytes; it is not a usable random source.",
  )
}
