/**
 * The failure ceiling (ADR 0009 §3): an authenticator that reaches 100 consecutive failures stops accepting attempts.
 * An app may lower the number (`failureCeiling`), never raise it.
 * The account and its other authenticators are unaffected, and recovery stays open, so the ceiling never locks the
 * account. A success before the ceiling resets the count. `succeeded` would also clear a reached ceiling, but no flow
 * calls it for one: an authenticator at the ceiling is never checked, so it stays stopped, and recovery replaces it
 * with a new one (ADR 0009 Open 7).
 *
 * The count is rate-limiter-flexible's over the store's atomic `increment`, in a window that never ends, so parallel
 * failures lose none; reaching the ceiling writes a block with no end, which `reached` reads before any check.
 */

import type { Clock } from "../core/clock.js"
import type { AuthStore, TenantId } from "../store/port.js"
import { createStoreLimiter } from "./store-limiter.js"

/** Consecutive failures an authenticator accepts (NIST SP 800-63B-4 §3.2.2, as ADR 0009 §3 applies it). */
export const FAILURE_CEILING = 100

/** The prefix of the ceiling's keys in the store: its counters, and its reached marks in `LIMIT_BLOCK_COLLECTION`. */
const CEILING_PREFIX = "ceiling"

/** The ceiling over one store and tenant. */
export interface FailureCeiling {
  /** True when the authenticator has reached the ceiling and must not be checked. */
  reached(authenticatorId: string): Promise<boolean>
  /** Counts one failure; at the ceiling, records that it is reached. */
  failed(authenticatorId: string): Promise<void>
  /** Resets the count and clears a reached ceiling. */
  succeeded(authenticatorId: string): Promise<void>
}

/**
 * Builds the ceiling as a rate-limiter-flexible limiter over the store (ADR 0030): `limit` points that never expire,
 * a block with no end once they are spent, and both deleted by a success.
 */
export function createFailureCeiling(deps: {
  readonly store: AuthStore
  readonly tenant: TenantId
  readonly clock: Clock
  /** The ceiling, from 1 to `FAILURE_CEILING`; `FAILURE_CEILING` when absent. `createAuth` checks the range. */
  readonly limit?: number | undefined
}): FailureCeiling {
  const limit = deps.limit ?? FAILURE_CEILING
  const failures = createStoreLimiter({
    store: deps.store,
    tenant: deps.tenant,
    clock: deps.clock,
    points: limit,
    duration: 0,
    keyPrefix: CEILING_PREFIX,
    blocks: false,
  })
  return {
    async reached(authenticatorId) {
      return (await failures.get(authenticatorId)) !== null
    },

    async failed(authenticatorId) {
      const { consumedPoints } = await failures.penalty(authenticatorId)
      // A block of 0 seconds never ends: only `succeeded` lifts it.
      if (consumedPoints >= limit) await failures.block(authenticatorId, 0)
    },

    async succeeded(authenticatorId) {
      await failures.delete(authenticatorId)
    },
  }
}
