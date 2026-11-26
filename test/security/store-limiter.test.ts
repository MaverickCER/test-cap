// The rate-limiter-flexible limiter over the AuthStore (ADR 0030): counts are the port's atomic increment in fixed
// windows, blocks are records that never shorten, and time is the injected clock.
import RateLimiterUnion from "rate-limiter-flexible/lib/RateLimiterUnion.js"
import RateLimiterMemory from "rate-limiter-flexible/lib/RateLimiterMemory.js"
import { afterEach, describe, expect, it, vi } from "vitest"
import { fixedClock } from "../../src/core/clock.js"
import { createStoreLimiter, LIMIT_BLOCK_COLLECTION } from "../../src/security/store-limiter.js"
import { memoryStore } from "../../src/store/memory.js"
import type { AuthStore } from "../../src/store/port.js"

const T0 = 1_700_000_000_000

function setup(
  options: { points?: number; duration?: number; blocks?: boolean; blockDuration?: number } = {},
) {
  const store = memoryStore()
  const clock = fixedClock(T0)
  const limiter = createStoreLimiter({
    store,
    tenant: "t",
    clock,
    points: options.points ?? 2,
    duration: options.duration ?? 10,
    keyPrefix: "p",
    blocks: options.blocks,
    blockDuration: options.blockDuration,
  })
  return { store, clock, limiter }
}

/** The answer of a consume, resolved or rejected, as plain values. */
async function consumed(limiter: ReturnType<typeof setup>["limiter"], key = "k") {
  try {
    const res = await limiter.consume(key)
    return { allowed: true, ...res.toJSON() }
  } catch (refusal) {
    return { allowed: false, ...(refusal as { toJSON(): object }).toJSON() }
  }
}

describe("createStoreLimiter", () => {
  it("allows points in a window, then refuses with the wait, counted on the injected clock", async () => {
    const { limiter, clock } = setup()
    const first = await consumed(limiter)
    clock.advance(4_000)
    const second = await consumed(limiter)
    const third = await consumed(limiter)
    expect([first, second, third]).toEqual([
      {
        allowed: true,
        remainingPoints: 1,
        msBeforeNext: 10_000,
        consumedPoints: 1,
        isFirstInDuration: true,
      },
      {
        allowed: true,
        remainingPoints: 0,
        msBeforeNext: 6_000,
        consumedPoints: 2,
        isFirstInDuration: false,
      },
      {
        allowed: false,
        remainingPoints: 0,
        msBeforeNext: 6_000,
        consumedPoints: 3,
        isFirstInDuration: false,
      },
    ])
    clock.advance(6_000)
    expect((await consumed(limiter)).allowed).toBe(true)
  })

  it("counts in the store under the prefix and the key, in the tenant, through the port's increment", async () => {
    const { limiter, store, clock } = setup()
    await limiter.consume("k")
    expect((await store.increment("t", "p:k", 10_000, clock.now())).count).toBe(2)
    expect((await store.increment("default", "p:k", 10_000, clock.now())).count).toBe(1)
  })

  it("counts in the default tenant, with the test-cap prefix, when given neither", async () => {
    const store = memoryStore()
    const clock = fixedClock(T0)
    await createStoreLimiter({ store, clock, points: 1, duration: 1 }).consume("k")
    expect((await store.increment("default", "test-cap:k", 1_000, T0)).count).toBe(2)
  })

  it("counts in a window that never ends for a duration of 0, and says so with -1", async () => {
    const { limiter, clock } = setup({ duration: 0 })
    await limiter.consume("k")
    clock.advance(10 * 365 * 24 * 60 * 60_000)
    expect(await consumed(limiter)).toMatchObject({ consumedPoints: 2, msBeforeNext: -1 })
  })

  it("loses no count to a parallel burst", async () => {
    const { limiter } = setup({ points: 10 })
    const answers = await Promise.allSettled(Array.from({ length: 30 }, () => limiter.consume("k")))
    expect(answers.filter((answer) => answer.status === "fulfilled")).toHaveLength(10)
  })

  it("counts one point per call, and refuses any other number", async () => {
    const { limiter } = setup()
    await expect(limiter.consume("k", 2)).rejects.toThrow(
      "A limiter over the AuthStore counts one point per call.",
    )
    await expect(limiter.reward("k")).rejects.toThrow(
      "A limiter over the AuthStore counts one point per call.",
    )
    expect((await limiter.penalty("k")).consumedPoints).toBe(1)
  })

  it("blocks a key, refusing it until the block ends, and get reports the block", async () => {
    const { limiter, clock, store } = setup()
    expect(await limiter.get("k")).toBeNull()
    await limiter.block("k", 30)
    expect(await consumed(limiter)).toMatchObject({
      allowed: false,
      msBeforeNext: 30_000,
      consumedPoints: 3,
    })
    expect((await limiter.get("k"))?.msBeforeNext).toBe(30_000)
    expect((await store.get("t", LIMIT_BLOCK_COLLECTION, "p:k"))?.data).toEqual({
      points: 3,
      expire: T0 + 30_000,
    })
    clock.advance(30_000)
    expect(await limiter.get("k")).toBeNull()
    expect((await consumed(limiter)).allowed).toBe(true)
  })

  it("blocks for good with a block of 0 seconds", async () => {
    const { limiter, clock } = setup()
    await limiter.block("k", 0)
    clock.advance(10 * 365 * 24 * 60 * 60_000)
    expect((await limiter.get("k"))?.msBeforeNext).toBe(-1)
  })

  it("never shortens a block in place, and lengthens one", async () => {
    const { limiter, store } = setup()
    await limiter.block("k", 30)
    await limiter.block("k", 5)
    expect((await store.get("t", LIMIT_BLOCK_COLLECTION, "p:k"))?.data).toEqual({
      points: 3,
      expire: T0 + 30_000,
    })
    await limiter.block("k", 0)
    await limiter.block("k", 60)
    expect((await store.get("t", LIMIT_BLOCK_COLLECTION, "p:k"))?.data).toEqual({
      points: 3,
      expire: null,
    })
  })

  it("replaces a block that has ended", async () => {
    const { limiter, store, clock } = setup()
    await limiter.block("k", 1)
    clock.advance(2_000)
    await limiter.block("k", 1)
    expect((await store.get("t", LIMIT_BLOCK_COLLECTION, "p:k"))?.data).toEqual({
      points: 3,
      expire: T0 + 3_000,
    })
  })

  it("blocks past points by itself with blockDuration, as the library does", async () => {
    const { limiter } = setup({ points: 1, blockDuration: 60 })
    await limiter.consume("k")
    expect(await consumed(limiter)).toMatchObject({ allowed: false, msBeforeNext: 60_000 })
    expect((await limiter.get("k"))?.msBeforeNext).toBe(60_000)
  })

  it("skips the block read with blocks: false, and still writes and reports blocks", async () => {
    const { limiter } = setup({ blocks: false })
    await limiter.block("k", 30)
    expect((await consumed(limiter)).allowed).toBe(true)
    expect((await limiter.get("k"))?.msBeforeNext).toBe(30_000)
  })

  it("forgets the count and the block on delete", async () => {
    const { limiter } = setup({ points: 1 })
    await limiter.consume("k")
    await limiter.block("k", 30)
    expect(await limiter.delete("k")).toBe(true)
    expect(await limiter.get("k")).toBeNull()
    expect((await consumed(limiter)).allowed).toBe(true)
    expect(await limiter.delete("other")).toBe(false)
  })

  it("settles for the block in place after eight lost races, instead of retrying forever", async () => {
    const base = memoryStore()
    const clock = fixedClock(T0)
    let updates = 0
    const losing = new Proxy(base, {
      get(target, property, receiver) {
        if (property === "update") {
          return () => {
            updates += 1
            return Promise.resolve("conflict")
          }
        }
        return Reflect.get(target, property, receiver) as unknown
      },
    }) as AuthStore
    const limiter = createStoreLimiter({
      store: losing,
      tenant: "t",
      clock,
      points: 1,
      duration: 1,
      keyPrefix: "p",
    })
    await limiter.block("k", 10)
    await limiter.block("k", 20)
    expect(updates).toBe(8)
    expect((await base.get("t", LIMIT_BLOCK_COLLECTION, "p:k"))?.data).toEqual({
      points: 2,
      expire: T0 + 10_000,
    })
  })

  it("reads a record that holds no block as no block", async () => {
    const { limiter, store } = setup()
    await store.createUnique("t", {
      collection: LIMIT_BLOCK_COLLECTION,
      key: "p:k",
      owner: null,
      data: { other: 1 },
    })
    expect(await limiter.get("k")).toBeNull()
  })

  it("works inside the library's own RateLimiterUnion, beside a stock limiter", async () => {
    const { limiter } = setup({ points: 1 })
    const union = new RateLimiterUnion(
      limiter,
      new RateLimiterMemory({ keyPrefix: "m", points: 5, duration: 10 }),
    )
    await union.consume("k")
    await expect(union.consume("k")).rejects.toBeDefined()
  })
})

describe("the clock a limiter uses when none is given", () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it("counts windows on the system clock", async () => {
    vi.useFakeTimers({ now: T0, toFake: ["Date"] })
    const limiter = createStoreLimiter({ store: memoryStore(), points: 1, duration: 10 })
    await limiter.consume("k")
    await expect(limiter.consume("k")).rejects.toMatchObject({ msBeforeNext: 10_000 })
    vi.setSystemTime(T0 + 4_000)
    await expect(limiter.consume("k")).rejects.toMatchObject({ msBeforeNext: 6_000 })
  })
})
