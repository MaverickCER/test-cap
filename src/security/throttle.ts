/**
 * Throttling of guessable secrets (ADR 0009 §1 to §4): failures slow further attempts, they never disable an account.
 * The counting and the blocks are rate-limiter-flexible's, over the app's store (`createStoreLimiter`, ADR 0030),
 * following the library's own pattern for login brute force: consecutive failures by user, by user and client, and by
 * client.
 *
 * - Three keys: the account, the account and the client, and the client alone. The two account keys are kept per kind
 *   of secret (a password, a TOTP code, a recovery code), so the flows that check one secret share its budget and a
 *   success on one secret never clears the failures of another. On the two account keys every attempt
 *   is counted before the secret is checked, and an attempt past the free ones must take the key's one slot for the
 *   coming block, so a burst of parallel guesses gets one attempt, not one each (ADR 0009 §2; the
 *   `otp-attempt-limit-race` attack). The client key counts failures only, after the check, so many people signing in
 *   behind one address are not slowed by each other's successes. The client key is the socket address, with an
 *   IPv4-mapped IPv6 address read as its IPv4 form and any other IPv6 address read as its /64 (`clientKey`), so the
 *   per-IP and per-/64 keys of ADR 0009 §2 are one key here.
 * - The first `freeFailures` on a key in `windowMs` cost nothing. After that each one blocks the key for a delay that
 *   doubles from `firstDelayMs` up to `maxDelayMs`, through the library's `block`; an attempt on a blocked key is
 *   refused before any secret is checked.
 * - A success deletes the account's keys for its own kind of secret, never the client's key, so one correct guess
 *   does not reset a spray, and a correct password does not reset the guessing of a TOTP code.
 * - The account key is the identifier the person typed (normalised when it is an address), not the account id, so an
 *   address no account holds is throttled exactly like one an account holds, and the throttle reveals nothing. A
 *   signed-in session's TOTP check or step-up uses its account's address, so sign-in and step-up share the password's
 *   keys, and TOTP verification and step-up share the TOTP code's.
 */

import { clientKey } from "../core/client-address.js"
import type { Clock } from "../core/clock.js"
import type { AuthStore, TenantId } from "../store/port.js"
import { createStoreLimiter } from "./store-limiter.js"

/** The throttle's values (ADR 0009 Open 1). */
export interface ThrottleConfig {
  /** Failures on one key in a window that cost nothing. */
  readonly freeFailures: number
  /** The window failures are counted in, in milliseconds. */
  readonly windowMs: number
  /** The block after the first failure past the free ones, in milliseconds; each further failure doubles it. */
  readonly firstDelayMs: number
  /** The longest block, in milliseconds. */
  readonly maxDelayMs: number
}

/** ADR 0009 Open 1: 5 free failures in 15 minutes, then a delay doubling from 1 second up to 15 minutes. */
export const DEFAULT_THROTTLE: ThrottleConfig = {
  freeFailures: 5,
  windowMs: 15 * 60_000,
  firstDelayMs: 1_000,
  maxDelayMs: 15 * 60_000,
}

/** The kinds of secret the throttle counts apart: each has its own account keys. */
export type ThrottleSecret = "password" | "totp" | "recovery-code"

/** What one attempt is throttled by. */
export interface ThrottleSubject {
  /**
   * The identifier as typed, normalised when it is an address. A signed-in session's TOTP check or step-up passes its
   * account's address, or the account id when the account has none.
   */
  readonly account: string
  /** The socket address, already resolved through any trusted proxy; `undefined` when the adapter had none. */
  readonly clientAddress: string | undefined
  /** The kind of secret checked; a success clears only this kind's account keys. */
  readonly secret: ThrottleSecret
}

/** The prefix of every throttle key in the store: its counters, and its blocks in `LIMIT_BLOCK_COLLECTION`. */
const THROTTLE_PREFIX = "throttle"

interface Keys {
  /** Cleared by a success. */
  readonly account: readonly string[]
  /** Kept through a success. */
  readonly client: readonly string[]
}

function keysOf(subject: ThrottleSubject): Keys {
  const client = clientKey(subject.clientAddress)
  const account = `account:${subject.secret}:${subject.account}`
  return client === null
    ? { account: [account], client: [] }
    : {
        account: [account, `account-client:${subject.secret}:${subject.account}|${client}`],
        client: [`client:${client}`],
      }
}

/** The block after the `count`th failure in a window, in milliseconds; 0 while failures are still free. */
export function delayAfter(config: ThrottleConfig, count: number): number {
  const past = count - config.freeFailures
  if (past <= 0) return 0
  // Past 2^30 the delay is long over the ceiling; capping the exponent keeps the arithmetic exact.
  return Math.min(config.firstDelayMs * 2 ** Math.min(past - 1, 30), config.maxDelayMs)
}

/** A throttle over one store and tenant. */
export interface Throttle {
  /**
   * Asks to make an attempt. Resolves to 0 when it may go ahead (the attempt is then counted on the account's keys),
   * or to how long to wait, in milliseconds, when a key is blocked or a parallel attempt took the slot. `strict` counts
   * nothing as free, for a client the stuffing detector flagged with no challenge hook to send it to.
   */
  attempt(subject: ThrottleSubject, strict?: boolean): Promise<number>
  /** Counts a failure on the client's key and blocks it past its free failures; resolves to that block's length. */
  failed(subject: ThrottleSubject, strict?: boolean): Promise<number>
  /** Clears the account's keys for the subject's kind of secret after a success. The client's key keeps counting. */
  succeeded(subject: ThrottleSubject): Promise<void>
}

/**
 * A throttle that lets every attempt through and counts nothing: what `throttle: false` gives in development and
 * test. Production and staging refuse it (ADR 0009 §8).
 */
export const NO_THROTTLE: Throttle = {
  attempt: () => Promise.resolve(0),
  failed: () => Promise.resolve(0),
  succeeded: () => Promise.resolve(),
}

/**
 * The wait in the library's answer to a refused `consume`. Anything else, an `Error` or any other rejection, is a
 * failure and is thrown, so a failing counter refuses the attempt instead of letting it through.
 */
function waitOf(refusal: unknown): number {
  const wait = (refusal as { readonly msBeforeNext?: unknown } | null)?.msBeforeNext
  if (typeof wait !== "number" || Number.isNaN(wait)) throw refusal
  return Math.max(1, wait)
}

/** Builds the throttle. */
export function createThrottle(deps: {
  readonly store: AuthStore
  readonly tenant: TenantId
  readonly clock: Clock
  readonly config: ThrottleConfig
}): Throttle {
  const { store, tenant, clock, config } = deps
  /** Every attempt and failure, counted per key in the window; its blocks are read with `get`. Never refuses itself. */
  const keys = createStoreLimiter({
    store,
    tenant,
    clock,
    points: Number.MAX_SAFE_INTEGER,
    duration: config.windowMs / 1000,
    keyPrefix: THROTTLE_PREFIX,
    blocks: false,
  })
  /** One point per key per block: the attempt that takes it goes ahead, a parallel one is refused. */
  const slots = createStoreLimiter({
    store,
    tenant,
    clock,
    points: 1,
    duration: 1,
    keyPrefix: `${THROTTLE_PREFIX}-slot`,
    blocks: false,
  })

  const configFor = (strict: boolean): ThrottleConfig =>
    strict ? { ...config, freeFailures: 0 } : config

  /** How long the key's block has left, in milliseconds; 0 when it has none. */
  const blockedFor = async (key: string): Promise<number> =>
    (await keys.get(key))?.msBeforeNext ?? 0

  return {
    async attempt(subject, strict = false) {
      const applied = configFor(strict)
      const { account, client } = keysOf(subject)
      const waits = await Promise.all([...account, ...client].map(blockedFor))
      const wait = Math.max(0, ...waits)
      if (wait > 0) return wait
      for (const key of account) {
        const { consumedPoints } = await keys.consume(key)
        const delay = delayAfter(applied, consumedPoints)
        if (delay === 0) continue
        // Past the free attempts, this one takes the key's slot for the coming block: of a parallel burst, one does.
        try {
          await slots.consume(key, 1, { customDuration: delay / 1000 })
        } catch (refusal) {
          return waitOf(refusal)
        }
        await keys.block(key, delay / 1000)
      }
      return 0
    },

    async failed(subject, strict = false) {
      const applied = configFor(strict)
      let longest = 0
      for (const key of keysOf(subject).client) {
        const { consumedPoints } = await keys.consume(key)
        const delay = delayAfter(applied, consumedPoints)
        if (delay === 0) continue
        // A block never shortens one in place, so parallel failures settle on the longest.
        await keys.block(key, delay / 1000)
        longest = Math.max(longest, delay)
      }
      return longest
    },

    async succeeded(subject) {
      // The slot goes too: the attempt that just succeeded took one as long as its block.
      for (const key of keysOf(subject).account) {
        await keys.delete(key)
        await slots.delete(key)
      }
    },
  }
}
