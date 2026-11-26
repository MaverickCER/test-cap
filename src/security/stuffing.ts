/**
 * The credential-stuffing detector (ADR 0009 §4 and Open 3). Stuffing uses pairs leaked elsewhere, so it fails on
 * many accounts once each and the per-account throttle never sees it. The detector counts, per client, how many
 * distinct accounts failed in the window; at the threshold the client is flagged until the window ends.
 *
 * A flagged client's next sign-in goes to the app's `challengeHook`, which decides with a challenge of its own choice
 * (test-cap ships none). Without a hook, every failure from the client blocks at once, as if no failure were free.
 */

import { clientKey } from "../core/client-address.js"
import type { Clock } from "../core/clock.js"
import type { PlainRequest } from "../transport/types.js"
import type { AuthStore, TenantId } from "../store/port.js"
import { createStoreLimiter } from "./store-limiter.js"

/** When the detector fires (ADR 0009 Open 3). */
export interface StuffingConfig {
  /** Distinct accounts failing from one client in the window that flag it. */
  readonly distinctAccounts: number
  /** The window, in milliseconds. */
  readonly windowMs: number
}

/** 20 distinct accounts from one client in 15 minutes. */
export const DEFAULT_STUFFING: StuffingConfig = { distinctAccounts: 20, windowMs: 15 * 60_000 }

/**
 * The app's challenge (ADR 0009 §4): called for each sign-in from a flagged client, before any password is checked.
 * It answers `true` when the request carries a challenge the app accepts, such as a token its own widget issued.
 */
export type ChallengeHook = (input: {
  /** The sign-in request, so the hook can read its own challenge answer from a header. */
  readonly request: PlainRequest
  /** The client key the detector flagged: an IPv4 address or an IPv6 /64. */
  readonly client: string
}) => boolean | Promise<boolean>

/** The prefix of the detector's keys in the store: its counters, and its flags in `LIMIT_BLOCK_COLLECTION`. */
const STUFFING_PREFIX = "stuffing"

/** The detector over one store and tenant; an app can pass its own in place of the default (ADR 0009 §8). */
export interface StuffingDetector {
  /** The flagged client key of an address, or `null` when it is not flagged (or the adapter supplied no address). */
  flagged(clientAddress: string | undefined): Promise<string | null>
  /** Counts a failure of `account` from the client; resolves to `true` when this failure flags the client. */
  failed(account: string, clientAddress: string | undefined): Promise<boolean>
}

/**
 * A detector that never flags anyone: what `stuffing: false` gives in development and test. Production and staging
 * refuse it (ADR 0009 §8).
 */
export const NO_STUFFING: StuffingDetector = {
  flagged: () => Promise.resolve(null),
  failed: () => Promise.resolve(false),
}

/**
 * Builds the detector. Its counting is rate-limiter-flexible's over the store (ADR 0030): one limiter counts each
 * account's failures from a client, so the first of them is one more distinct account; another counts those distinct
 * accounts per client, and at the threshold blocks the client for the rest of the window, which is the flag.
 */
export function createStuffingDetector(deps: {
  readonly store: AuthStore
  readonly tenant: TenantId
  readonly clock: Clock
  readonly config: StuffingConfig
}): StuffingDetector {
  const { store, tenant, clock, config } = deps
  const limiter = (keyPrefix: string, points: number) =>
    createStoreLimiter({
      store,
      tenant,
      clock,
      points,
      duration: config.windowMs / 1000,
      keyPrefix,
      blocks: false,
    })
  const pairs = limiter(`${STUFFING_PREFIX}-pair`, 1)
  const spread = limiter(STUFFING_PREFIX, config.distinctAccounts)
  return {
    async flagged(clientAddress) {
      const client = clientKey(clientAddress)
      if (client === null) return null
      return (await spread.get(client)) === null ? null : client
    },

    async failed(account, clientAddress) {
      const client = clientKey(clientAddress)
      if (client === null) return false
      // The first failure of this account from this client is one more distinct account; repeats are the throttle's.
      const pair = await pairs.penalty(`${client}|${account}`)
      if (!pair.isFirstInDuration) return false
      const accounts = await spread.penalty(client)
      if (accounts.consumedPoints !== config.distinctAccounts) return false
      await spread.block(client, accounts.msBeforeNext / 1000)
      return true
    },
  }
}
