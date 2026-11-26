/**
 * A rate-limiter-flexible limiter over the app's own `AuthStore` (ADR 0030), so every limit test-cap keeps needs no
 * infrastructure beyond the store the app already gave it, and every instance sharing that store shares the counts.
 *
 * - A count is the port's atomic `increment`, a fixed window per key; a duration of 0 counts in a window longer than
 *   any deployment, which is the library's "never expires".
 * - A block (`block`, `set`, and the library's own blocking past `points` when `blockDuration` is set) is a record in
 *   `LIMIT_BLOCK_COLLECTION`, and it never shortens a block already in place: of two blocks written at once, the later
 *   end wins, as parallel failures need.
 * - `get` answers a key's block, or `null`: the port reads a counter only by counting.
 * - Time is the injected `Clock`, never `Date.now`, so tests and the library agree on it.
 */

import RateLimiterRes from "rate-limiter-flexible/lib/RateLimiterRes.js"
import RateLimiterStoreAbstract from "rate-limiter-flexible/lib/RateLimiterStoreAbstract.js"
import type { RateLimiterStoreAbstract as StoreLimiter } from "rate-limiter-flexible"
import { systemClock, type Clock } from "../core/clock.js"
import type { AuthStore, StoredRecord, TenantId } from "../store/port.js"

/** The collection a limiter's blocks live in, one record per key. */
export const LIMIT_BLOCK_COLLECTION = "rate-limit-block"

/** A window longer than any deployment: how a duration of 0, "never expires", is counted. */
const FOREVER_MS = 100 * 365 * 24 * 60 * 60 * 1000

/** Lost races a block write retries before it settles for the block another write left. */
const BLOCK_TRIES = 8

/** What the store holds for a key, as the library's `_getRateLimiterRes` reads it: `expire` is `null` for never. */
interface Held {
  readonly points: number
  readonly expire: number | null
}

/** What `createStoreLimiter` takes. */
export interface StoreLimiterOptions {
  /** The store the counts and blocks live in. */
  readonly store: AuthStore
  /** The tenant they are kept under; `default` when absent. */
  readonly tenant?: TenantId | undefined
  /** The clock; the system clock when absent. */
  readonly clock?: Clock | undefined
  /** Requests allowed per key in each window. */
  readonly points: number
  /** The window, in seconds; 0 for one that never ends. */
  readonly duration: number
  /** Put before every key, so limiters sharing a store keep apart; `test-cap` when absent. */
  readonly keyPrefix?: string | undefined
  /** Seconds to block a key once it goes past `points`; 0 (the default) for no block. */
  readonly blockDuration?: number | undefined
  /**
   * Whether counting reads the key's block too, so a blocked key's `consume` is refused. `false` saves that read for a
   * limiter whose blocks are read with `get` instead, or that never blocks.
   */
  readonly blocks?: boolean | undefined
}

/** The block a record holds, or `null` when it holds none that is live at `now`. */
function liveBlock(record: StoredRecord | null, now: number): (Held & { version: number }) | null {
  const data = record?.data as Partial<Held> | null | undefined
  // A record with numeric points is a block; anything else, a missing record included, is none.
  if (typeof data?.points !== "number") return null
  const expire = data.expire ?? null
  return expire === null || expire > now
    ? { points: data.points, expire, version: (record as StoredRecord).version }
    : null
}

/** True when a block ending at `a` lasts at least as long as one ending at `b`; `null` is never. */
function lastsAsLong(a: number | null, b: number | null): boolean {
  return a === null || (b !== null && a >= b)
}

/**
 * The library's store limiter, built on the port. It implements the four methods the library asks a store for:
 *
 * - `_getRateLimiterRes`: the library's result for what the store holds;
 * - `_upsert`: counts one point on the key, or with `forceExpire` writes a block of `points` for `msDuration`;
 * - `_get`: the key's live block;
 * - `_delete`: forgets the key's count and its block.
 *
 * A block write makes the key's block end no earlier than `expire`: a block another write already moved later stays,
 * and a write that loses a race reads the newer block and tries again, at most `BLOCK_TRIES` times.
 */
class AuthStoreLimiter extends RateLimiterStoreAbstract {
  private readonly authStore: AuthStore
  private readonly tenantId: TenantId
  private readonly clockSource: Clock
  private readonly readsBlocks: boolean

  constructor(options: StoreLimiterOptions) {
    super({
      storeClient: options.store,
      points: options.points,
      duration: options.duration,
      keyPrefix: options.keyPrefix ?? "test-cap",
      // The library reads an absent block duration as 0, no block.
      blockDuration: options.blockDuration as number,
    })
    this.authStore = options.store
    this.tenantId = options.tenant ?? "default"
    this.clockSource = options.clock ?? systemClock
    this.readsBlocks = options.blocks ?? true
  }

  _getRateLimiterRes(_rlKey: string, changedPoints: number, held: Held): RateLimiterRes {
    const msBeforeNext =
      held.expire === null ? -1 : Math.max(held.expire - this.clockSource.now(), 0)
    return new RateLimiterRes(
      Math.max(this.points - held.points, 0),
      msBeforeNext,
      held.points,
      held.points === changedPoints,
    )
  }

  async _upsert(
    rlKey: string,
    points: number,
    msDuration: number,
    forceExpire: boolean,
  ): Promise<Held | undefined> {
    const now = this.clockSource.now()
    const expire = msDuration > 0 ? now + Math.round(msDuration) : null
    // The library reads nothing back from a block's write; it answers the block itself.
    if (forceExpire) return this.writeBlock(rlKey, points, expire, now)
    if (points !== 1)
      throw new RangeError("A limiter over the AuthStore counts one point per call.")
    const counter = await this.authStore.increment(
      this.tenantId,
      rlKey,
      expire === null ? FOREVER_MS : expire - now,
      now,
    )
    const counted: Held = {
      points: counter.count,
      expire: expire === null ? null : counter.resetAt,
    }
    if (!this.readsBlocks) return counted
    const block = await this.readBlock(rlKey, now)
    return block === null
      ? counted
      : { points: Math.max(counted.points, block.points), expire: block.expire }
  }

  async _get(rlKey: string): Promise<Held | null> {
    return this.readBlock(rlKey, this.clockSource.now())
  }

  async _delete(rlKey: string): Promise<boolean> {
    await this.authStore.resetCounter(this.tenantId, rlKey)
    return this.authStore.delete(this.tenantId, LIMIT_BLOCK_COLLECTION, rlKey)
  }

  private async readBlock(
    rlKey: string,
    now: number,
  ): Promise<(Held & { version: number }) | null> {
    return liveBlock(await this.authStore.get(this.tenantId, LIMIT_BLOCK_COLLECTION, rlKey), now)
  }

  private async writeBlock(
    rlKey: string,
    points: number,
    expire: number | null,
    now: number,
  ): Promise<undefined> {
    const change = { expiresAt: expire, data: { points, expire } }
    /** One try: true once the block lasts as long as wanted, by this write or another. */
    const once = async (): Promise<boolean> => {
      const record = await this.authStore.get(this.tenantId, LIMIT_BLOCK_COLLECTION, rlKey)
      const current = liveBlock(record, now)
      if (current !== null && lastsAsLong(current.expire, expire)) return true
      return record === null
        ? (await this.authStore.createUnique(this.tenantId, {
            collection: LIMIT_BLOCK_COLLECTION,
            key: rlKey,
            owner: null,
            ...change,
          })) === "created"
        : (await this.authStore.update(
            this.tenantId,
            LIMIT_BLOCK_COLLECTION,
            rlKey,
            record.version,
            change,
          )) === "updated"
    }
    // A fixed number of tries, each after the last lost; no loop condition, so nothing can make it run forever.
    await Array.from({ length: BLOCK_TRIES }).reduce<Promise<boolean>>(
      async (previous) => (await previous) || once(),
      Promise.resolve(false),
    )
    return undefined
  }
}

/**
 * A rate-limiter-flexible limiter over the app's `AuthStore`: the default behind every limit test-cap keeps, and a
 * piece an app can combine with the library's own, such as in a `RateLimiterUnion`.
 */
export function createStoreLimiter(options: StoreLimiterOptions): StoreLimiter {
  return new AuthStoreLimiter(options)
}
