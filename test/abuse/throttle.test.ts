// The throttle itself (ADR 0009 §1 to §3): the delay curve, the three keys, what a success clears, and atomic
// counting under parallel failures.
import { describe, expect, it } from "vitest"
import { fixedClock } from "../../src/core/clock.js"
import {
  createThrottle,
  DEFAULT_THROTTLE,
  delayAfter,
  type ThrottleConfig,
  type Throttle,
  type ThrottleSubject,
} from "../../src/security/throttle.js"
import { LIMIT_BLOCK_COLLECTION } from "../../src/security/store-limiter.js"
import { memoryStore } from "../../src/store/memory.js"

const T0 = 1_700_000_000_000

function setup(config: ThrottleConfig = DEFAULT_THROTTLE) {
  const store = memoryStore()
  const clock = fixedClock(T0)
  return { store, clock, throttle: createThrottle({ store, tenant: "t", clock, config }) }
}

const ada = { account: "ada@example.com", clientAddress: "192.0.2.7", secret: "password" } as const

describe("DEFAULT_THROTTLE", () => {
  it("is what the GUIDE states: 5 free failures in a 15-minute window, then 1 second doubling to 15 minutes", () => {
    expect(DEFAULT_THROTTLE).toEqual({
      freeFailures: 5,
      windowMs: 900_000,
      firstDelayMs: 1_000,
      maxDelayMs: 900_000,
    })
  })
})

describe("the default throttle over one window", () => {
  it("lets 15 guesses through and waits at most 512 seconds before the count restarts", async () => {
    const { clock, throttle } = setup()
    const start = clock.now()
    const waits: number[] = []
    let guesses = 0
    // One guesser waits out every block and fails every time, until the first window ends.
    while (clock.now() - start < DEFAULT_THROTTLE.windowMs) {
      const wait = await throttle.attempt(ada)
      if (wait > 0) {
        waits.push(wait)
        clock.advance(wait)
        continue
      }
      guesses += 1
      await throttle.failed(ada)
    }
    expect(guesses).toBe(15)
    expect(Math.max(...waits)).toBe(512_000)
  })
})

describe("a slot counter that fails", () => {
  // Some drivers reject with a string or a plain object; only the library's own refusal carries a wait.
  it("refuses the attempt whatever the rejection is, never letting the guess through", async () => {
    for (const rejection of [
      new Error("db down"),
      "db down",
      { code: "ECONNRESET" },
      null,
      { msBeforeNext: Number.NaN },
    ]) {
      const base = memoryStore()
      const store = new Proxy(base, {
        get(target, property, receiver) {
          if (property !== "increment") return Reflect.get(target, property, receiver) as unknown
          return (tenant: string, counter: string, ...rest: [number, number]) =>
            counter.startsWith("throttle-slot")
              ? Promise.reject(rejection)
              : target.increment(tenant, counter, ...rest)
        },
      })
      const throttle = createThrottle({
        store,
        tenant: "t",
        clock: fixedClock(T0),
        config: { ...DEFAULT_THROTTLE, freeFailures: 0 },
      })
      await expect(throttle.attempt(ada), JSON.stringify(rejection)).rejects.toBe(rejection)
    }
  })
})

describe("delayAfter", () => {
  it("is free for the first five failures, then doubles from one second up to fifteen minutes", () => {
    expect(
      [1, 5, 6, 7, 8, 15, 15 + 20].map((count) => delayAfter(DEFAULT_THROTTLE, count)),
    ).toEqual([0, 0, 1_000, 2_000, 4_000, 512_000, 900_000])
  })

  it("stays exact and at the ceiling for any count", () => {
    expect(delayAfter(DEFAULT_THROTTLE, 1_000_000)).toBe(900_000)
    expect(delayAfter({ ...DEFAULT_THROTTLE, maxDelayMs: Number.MAX_SAFE_INTEGER }, 50)).toBe(
      1_000 * 2 ** 30,
    )
  })
})

describe("createThrottle", () => {
  /** One full failed attempt: asks, and counts the failure; resolves to the attempt's answer. */
  async function failOnce(throttle: Throttle, subject: ThrottleSubject, strict = false) {
    const wait = await throttle.attempt(subject, strict)
    if (wait === 0) await throttle.failed(subject, strict)
    return wait
  }

  async function failTimes(throttle: Throttle, subject: ThrottleSubject, times: number) {
    for (let i = 0; i < times; i += 1) expect(await failOnce(throttle, subject)).toBe(0)
  }

  it("lets an untouched subject try now", async () => {
    expect(await setup().throttle.attempt(ada)).toBe(0)
  })

  it("lets six attempts through, then blocks for the delay and lets the subject try once it ends", async () => {
    const { throttle, clock } = setup()
    await failTimes(throttle, ada, 6)
    expect(await throttle.attempt(ada)).toBe(1_000)
    clock.advance(400)
    expect(await throttle.attempt(ada)).toBe(600)
    clock.advance(600)
    expect(await failOnce(throttle, ada)).toBe(0)
    expect(await throttle.attempt(ada)).toBe(2_000)
  })

  it("blocks the account from another client, and the client for another account", async () => {
    const { throttle } = setup()
    await failTimes(throttle, ada, 6)
    expect(await throttle.attempt({ ...ada, clientAddress: "198.51.100.1" })).toBe(1_000)
    expect(
      await throttle.attempt({
        account: "bob@example.com",
        clientAddress: "192.0.2.7",
        secret: "password" as const,
      }),
    ).toBe(1_000)
    expect(
      await throttle.attempt({
        account: "bob@example.com",
        clientAddress: "198.51.100.1",
        secret: "password" as const,
      }),
    ).toBe(0)
  })

  it("keeps a block in the store under each key, until it ends", async () => {
    const { throttle, store } = setup()
    await failTimes(throttle, ada, 6)
    for (const key of [
      "account:password:ada@example.com",
      "account-client:password:ada@example.com|192.0.2.7",
      "client:192.0.2.7",
    ]) {
      const record = await store.get("t", LIMIT_BLOCK_COLLECTION, `throttle:${key}`)
      expect([record?.data, record?.expiresAt], key).toMatchObject([
        { expire: T0 + 1_000 },
        T0 + 1_000,
      ])
    }
  })

  it("throttles by the account alone when the adapter supplied no client address", async () => {
    const { throttle } = setup()
    const anonymous = {
      account: "ada@example.com",
      clientAddress: undefined,
      secret: "password" as const,
    }
    await failTimes(throttle, anonymous, 6)
    expect(await throttle.attempt(anonymous)).toBe(1_000)
    expect(await throttle.failed(anonymous)).toBe(0)
    expect(
      await throttle.attempt({
        account: "bob@example.com",
        clientAddress: undefined,
        secret: "password" as const,
      }),
    ).toBe(0)
  })

  it("clears the account's keys after a success, but keeps counting the client's failures", async () => {
    const { throttle, clock } = setup()
    await failTimes(throttle, ada, 6)
    clock.advance(1_000)
    expect(await throttle.attempt(ada)).toBe(0)
    await throttle.succeeded(ada)
    expect(await throttle.attempt({ ...ada, clientAddress: "198.51.100.1" })).toBe(0)
    // The client's six failures still stand: its seventh blocks it for two seconds.
    expect(
      await throttle.failed({
        account: "bob@example.com",
        clientAddress: "192.0.2.7",
        secret: "password" as const,
      }),
    ).toBe(2_000)
  })

  it("clears the account's slot after a success too, so the next waits start from one second again", async () => {
    const { throttle, clock } = setup()
    // Drive the account's delay up: each attempt past the free ones takes a slot as long as its block.
    for (let n = 0; n < 15; n += 1) {
      const wait = await throttle.attempt(ada)
      clock.advance(wait > 0 ? wait : 1)
    }
    // Wait out each block until an attempt goes ahead: it took a long slot, and that attempt succeeds.
    for (let wait = await throttle.attempt(ada); wait > 0; wait = await throttle.attempt(ada)) {
      clock.advance(wait)
    }
    await throttle.succeeded(ada)
    const elsewhere = { ...ada, clientAddress: "198.51.100.9" }
    for (let n = 0; n < 6; n += 1) expect(await throttle.attempt(elsewhere)).toBe(0)
    expect(await throttle.attempt(elsewhere)).toBeLessThanOrEqual(DEFAULT_THROTTLE.firstDelayMs)
  })

  it("counts nothing as free when strict", async () => {
    const { throttle } = setup()
    expect(await failOnce(throttle, ada, true)).toBe(0)
    expect(await throttle.attempt(ada, true)).toBe(1_000)
  })

  it("never shortens a client block another failure already moved later", async () => {
    const { throttle, store, clock } = setup()
    await failTimes(throttle, ada, 6)
    // The client's block ends 1 s from now; a failure counted with a 1 ms delay leaves it as it is.
    await createThrottle({
      store,
      tenant: "t",
      clock,
      config: { ...DEFAULT_THROTTLE, firstDelayMs: 1, maxDelayMs: 1 },
    }).failed(ada)
    expect(
      (await store.get("t", LIMIT_BLOCK_COLLECTION, "throttle:client:192.0.2.7"))?.data,
    ).toMatchObject({ expire: T0 + 1_000 })
  })

  it("gives a parallel burst past the free attempts one attempt, not one each", async () => {
    const { throttle } = setup()
    await failTimes(throttle, ada, 5)
    const answers = await Promise.all(Array.from({ length: 10 }, () => throttle.attempt(ada)))
    expect(answers.filter((wait) => wait === 0)).toHaveLength(1)
    expect(answers.filter((wait) => wait > 0)).toHaveLength(9)
  })

  it("loses no client failure to a race", async () => {
    const { throttle, store, clock } = setup()
    await Promise.all(Array.from({ length: 20 }, () => throttle.failed(ada)))
    const counter = await store.increment(
      "t",
      "throttle:client:192.0.2.7",
      DEFAULT_THROTTLE.windowMs,
      clock.now(),
    )
    expect(counter.count).toBe(21)
  })

  it("gives the free attempts unless told to be strict", async () => {
    const { throttle } = setup()
    expect([await throttle.attempt(ada), await throttle.attempt(ada)]).toEqual([0, 0])
  })

  it("tells each loser of a parallel burst to wait for the winner's block", async () => {
    const { throttle } = setup()
    await failTimes(throttle, ada, 5)
    const answers = await Promise.all(Array.from({ length: 6 }, () => throttle.attempt(ada)))
    expect([...answers].sort((a, b) => a - b)).toEqual([0, 1_000, 1_000, 1_000, 1_000, 1_000])
  })

  it("writes no block for a failure that is still free", async () => {
    const { throttle, store } = setup()
    expect(await throttle.failed(ada)).toBe(0)
    expect(await store.get("t", LIMIT_BLOCK_COLLECTION, "throttle:client:192.0.2.7")).toBeNull()
  })

  it("leaves a block that already ends at the same time as it is, without writing", async () => {
    const { throttle, store, clock } = setup()
    await failTimes(throttle, ada, 6)
    const before = await store.get("t", LIMIT_BLOCK_COLLECTION, "throttle:client:192.0.2.7")
    // Another failure counted against the same block end: a throttle whose delay lands on the same moment.
    await createThrottle({
      store,
      tenant: "t",
      clock,
      config: { ...DEFAULT_THROTTLE, freeFailures: 0, firstDelayMs: 1_000, maxDelayMs: 1_000 },
    }).failed(ada)
    expect(
      (await store.get("t", LIMIT_BLOCK_COLLECTION, "throttle:client:192.0.2.7"))?.version,
    ).toBe(before?.version)
  })

  it("gives up after eight lost races instead of retrying forever, keeping the newest block", async () => {
    const base = memoryStore()
    const clock = fixedClock(T0)
    let updates = 0
    // Every write loses: another failure always changed the record first.
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
    })
    const throttle = createThrottle({ store: losing, tenant: "t", clock, config: DEFAULT_THROTTLE })
    // The first failure past the free ones creates the block; the second must replace it, and always loses.
    for (let i = 0; i < 6; i += 1) await throttle.failed(ada)
    expect(updates).toBe(0)
    expect(await throttle.failed(ada)).toBe(2_000)
    expect(updates).toBe(8)
    expect(
      (await base.get("t", LIMIT_BLOCK_COLLECTION, "throttle:client:192.0.2.7"))?.data,
    ).toMatchObject({ expire: T0 + 1_000 })
  })
})
