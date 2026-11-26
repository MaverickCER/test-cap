// Sentinels for the store limiter (ADR 0030): every limit counts through it, so each check here pins one of its
// answers exactly, on the injected clock, with plain loops and no flow.
import { describe, expect, it } from "vitest"
import { fixedClock } from "../../src/core/clock.js"
import { createStoreLimiter, LIMIT_BLOCK_COLLECTION } from "../../src/security/store-limiter.js"
import { memoryStore } from "../../src/store/memory.js"
import type { AuthStore } from "../../src/store/port.js"

const T0 = 1_700_000_000_000

/** A memory store that records each call by name, and answers `createUnique` and `update` as `answers` says. */
function storeAnswering(answers: { createUnique?: string; update?: string } = {}) {
  const base = memoryStore()
  const calls: string[] = []
  const store = new Proxy(base, {
    get(target, property, receiver) {
      const value: unknown = Reflect.get(target, property, receiver)
      if (typeof value !== "function") return value
      return (...args: unknown[]) => {
        calls.push(String(property))
        const answer = (answers as Record<string, string | undefined>)[String(property)]
        if (answer !== undefined) return Promise.resolve(answer)
        return (value as (...a: unknown[]) => unknown).apply(target, args)
      }
    },
  }) as AuthStore
  return { store, base, calls }
}

/** What a limiter call resolves or rejects with, as plain values. */
async function answerOf(pending: Promise<unknown>) {
  try {
    const res = (await pending) as { toJSON?: () => object } | boolean | null
    return typeof res === "object" && res !== null && res.toJSON !== undefined
      ? { resolved: res.toJSON() }
      : { resolved: res }
  } catch (refusal) {
    const res = refusal as { toJSON?: () => object; message?: string }
    return { rejected: res.toJSON === undefined ? String(res.message) : res.toJSON() }
  }
}

describe("the store limiter's answers", () => {
  it("resolve consume, penalty, block, get and delete exactly, on the injected clock", async () => {
    const clock = fixedClock(T0)
    const limiter = createStoreLimiter({
      store: memoryStore(),
      tenant: "t",
      clock,
      points: 1,
      duration: 10,
      keyPrefix: "p",
    })
    expect(await answerOf(limiter.consume("k"))).toEqual({
      resolved: {
        remainingPoints: 0,
        msBeforeNext: 10_000,
        consumedPoints: 1,
        isFirstInDuration: true,
      },
    })
    clock.advance(4_000)
    expect(await answerOf(limiter.penalty("k"))).toEqual({
      resolved: {
        remainingPoints: 0,
        msBeforeNext: 6_000,
        consumedPoints: 2,
        isFirstInDuration: false,
      },
    })
    expect(await answerOf(limiter.consume("k"))).toEqual({
      rejected: {
        remainingPoints: 0,
        msBeforeNext: 6_000,
        consumedPoints: 3,
        isFirstInDuration: false,
      },
    })
    expect(await answerOf(limiter.block("k", 30))).toEqual({
      resolved: {
        remainingPoints: 0,
        msBeforeNext: 30_000,
        consumedPoints: 2,
        isFirstInDuration: false,
      },
    })
    expect(await answerOf(limiter.get("k"))).toEqual({
      resolved: {
        remainingPoints: 0,
        msBeforeNext: 30_000,
        consumedPoints: 2,
        isFirstInDuration: false,
      },
    })
    expect(await answerOf(limiter.consume("k"))).toEqual({
      rejected: {
        remainingPoints: 0,
        msBeforeNext: 30_000,
        consumedPoints: 4,
        isFirstInDuration: false,
      },
    })
    expect(await answerOf(limiter.delete("k"))).toEqual({ resolved: true })
    expect(await answerOf(limiter.get("k"))).toEqual({ resolved: null })
    expect(await answerOf(limiter.consume("k", 2))).toEqual({
      rejected: "A limiter over the AuthStore counts one point per call.",
    })
  })

  it("answer -1 for a window or a block that never ends", async () => {
    const clock = fixedClock(T0)
    const limiter = createStoreLimiter({ store: memoryStore(), clock, points: 5, duration: 0 })
    expect(await answerOf(limiter.consume("k"))).toEqual({
      resolved: {
        remainingPoints: 4,
        msBeforeNext: -1,
        consumedPoints: 1,
        isFirstInDuration: true,
      },
    })
    await limiter.block("k", 0)
    expect(await answerOf(limiter.get("k"))).toEqual({
      resolved: {
        remainingPoints: 0,
        msBeforeNext: -1,
        consumedPoints: 6,
        isFirstInDuration: false,
      },
    })
  })
})

describe("the store limiter's defaults", () => {
  it("count in the default tenant under test-cap:, read blocks, and never block by themselves", async () => {
    const { store, base, calls } = storeAnswering()
    const limiter = createStoreLimiter({ store, clock: fixedClock(T0), points: 1, duration: 10 })
    await limiter.consume("k")
    expect(calls).toEqual(["increment", "get"])
    expect((await base.increment("default", "test-cap:k", 10_000, T0)).count).toBe(2)
    await expect(limiter.consume("k")).rejects.toMatchObject({ msBeforeNext: 10_000 })
    expect(await base.get("default", LIMIT_BLOCK_COLLECTION, "test-cap:k")).toBeNull()
    await limiter.block("k", 30)
    await expect(limiter.consume("k")).rejects.toMatchObject({ msBeforeNext: 30_000 })
  })

  it("block past points by themselves when given a block duration", async () => {
    const { base, store } = storeAnswering()
    const limiter = createStoreLimiter({
      store,
      clock: fixedClock(T0),
      points: 1,
      duration: 10,
      blockDuration: 60,
    })
    await limiter.consume("k")
    await expect(limiter.consume("k")).rejects.toMatchObject({ msBeforeNext: 60_000 })
    expect((await base.get("default", LIMIT_BLOCK_COLLECTION, "test-cap:k"))?.data).toEqual({
      points: 2,
      expire: T0 + 60_000,
    })
  })

  it("skip the block read with blocks: false", async () => {
    const { store, calls } = storeAnswering()
    const limiter = createStoreLimiter({
      store,
      clock: fixedClock(T0),
      points: 1,
      duration: 10,
      blocks: false,
    })
    await limiter.consume("k")
    expect(calls).toEqual(["increment"])
  })
})

describe("the store limiter's block writes", () => {
  it("write a new block with one read and one create", async () => {
    const { store, calls } = storeAnswering()
    const limiter = createStoreLimiter({ store, clock: fixedClock(T0), points: 1, duration: 10 })
    await limiter.block("k", 30)
    expect(calls).toEqual(["get", "createUnique"])
  })

  it("replace an ended block with one read and one update", async () => {
    const clock = fixedClock(T0)
    const { store, calls } = storeAnswering()
    const limiter = createStoreLimiter({ store, clock, points: 1, duration: 10 })
    await limiter.block("k", 1)
    clock.advance(2_000)
    calls.length = 0
    await limiter.block("k", 1)
    expect(calls).toEqual(["get", "update"])
  })

  it("leave a block that lasts as long with one read and no write", async () => {
    const { store, calls } = storeAnswering()
    const limiter = createStoreLimiter({ store, clock: fixedClock(T0), points: 1, duration: 10 })
    await limiter.block("k", 30)
    calls.length = 0
    await limiter.block("k", 30)
    await limiter.block("k", 10)
    expect(calls).toEqual(["get", "get"])
  })

  it("try eight times when another write always wins the create, and settle for the block in place", async () => {
    const { store, calls } = storeAnswering({ createUnique: "exists" })
    const limiter = createStoreLimiter({ store, clock: fixedClock(T0), points: 1, duration: 10 })
    await limiter.block("k", 30)
    expect(calls.filter((call) => call === "createUnique")).toHaveLength(8)
  })

  it("try eight times when the block is always gone before the update lands", async () => {
    const clock = fixedClock(T0)
    const { store, calls } = storeAnswering({ update: "missing" })
    const limiter = createStoreLimiter({ store, clock, points: 1, duration: 10 })
    await limiter.block("k", 1)
    clock.advance(2_000)
    calls.length = 0
    await limiter.block("k", 1)
    expect(calls.filter((call) => call === "update")).toHaveLength(8)
  })

  it("stop at the first write that wins after a lost one", async () => {
    const base = memoryStore()
    let lost = false
    const calls: string[] = []
    const store = new Proxy(base, {
      get(target, property, receiver) {
        const value: unknown = Reflect.get(target, property, receiver)
        if (typeof value !== "function") return value
        return (...args: unknown[]) => {
          calls.push(String(property))
          if (property === "createUnique" && !lost) {
            lost = true
            return Promise.resolve("exists")
          }
          return (value as (...a: unknown[]) => unknown).apply(target, args)
        }
      },
    }) as AuthStore
    const limiter = createStoreLimiter({ store, clock: fixedClock(T0), points: 1, duration: 10 })
    await limiter.block("k", 30)
    expect(calls).toEqual(["get", "createUnique", "get", "createUnique"])
  })

  it("read a record without a numeric points, or with no data, as no block", async () => {
    const { base, store } = storeAnswering()
    const limiter = createStoreLimiter({ store, clock: fixedClock(T0), points: 1, duration: 10 })
    for (const [key, data] of [
      ["a", { other: 1 }],
      ["b", null],
      ["c", { points: "2", expire: null }],
    ] as const) {
      await base.createUnique("default", {
        collection: LIMIT_BLOCK_COLLECTION,
        key: `test-cap:${key}`,
        owner: null,
        data,
      })
      expect(await limiter.get(key), key).toBeNull()
    }
  })
})
