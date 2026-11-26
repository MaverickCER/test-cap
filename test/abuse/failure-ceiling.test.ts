// ADR 0009 §3: an authenticator stops accepting attempts after 100 consecutive failures; a success before the ceiling
// resets the count; the ceiling is per authenticator, never the account.
import { describe, expect, it } from "vitest"
import { fixedClock } from "../../src/core/clock.js"
import { createFailureCeiling, FAILURE_CEILING } from "../../src/security/ceiling.js"
import { LIMIT_BLOCK_COLLECTION } from "../../src/security/store-limiter.js"
import { memoryStore } from "../../src/store/memory.js"
import { account, Browser, inProcess, PASSWORD, testAuth } from "../support/auth.js"

describe("createFailureCeiling", () => {
  const setup = () => {
    const store = memoryStore()
    return {
      store,
      ceiling: createFailureCeiling({ store, tenant: "t", clock: fixedClock(1_000) }),
    }
  }

  it("is 100", () => {
    expect(FAILURE_CEILING).toBe(100)
  })

  it("is reached on the 100th consecutive failure, not before, and records when", async () => {
    const { store, ceiling } = setup()
    for (let i = 0; i < 99; i += 1) await ceiling.failed("a1")
    expect(await ceiling.reached("a1")).toBe(false)
    await ceiling.failed("a1")
    expect(await ceiling.reached("a1")).toBe(true)
    // A block with no end: only a success lifts it.
    expect((await store.get("t", LIMIT_BLOCK_COLLECTION, "ceiling:a1"))?.data).toEqual({
      points: 101,
      expire: null,
    })
    // More failures past the ceiling change nothing.
    await ceiling.failed("a1")
    expect(await ceiling.reached("a1")).toBe(true)
    expect(await ceiling.reached("a2")).toBe(false)
  })

  it("resets on success, so only consecutive failures count", async () => {
    const { ceiling } = setup()
    for (let i = 0; i < 99; i += 1) await ceiling.failed("a1")
    await ceiling.succeeded("a1")
    for (let i = 0; i < 99; i += 1) await ceiling.failed("a1")
    expect(await ceiling.reached("a1")).toBe(false)
  })

  it("clears a reached ceiling on success", async () => {
    const { ceiling } = setup()
    for (let i = 0; i < 100; i += 1) await ceiling.failed("a1")
    await ceiling.succeeded("a1")
    expect(await ceiling.reached("a1")).toBe(false)
  })

  it("loses no failure to a race", async () => {
    const { ceiling } = setup()
    await Promise.all(Array.from({ length: 100 }, () => ceiling.failed("a1")))
    expect(await ceiling.reached("a1")).toBe(true)
  })
})

describe("the ceiling at the sign-in route", () => {
  // Free failures far above the ceiling, so the throttle never answers first and the ceiling alone is tested.
  // The request limiter is off as well: at 10 sign-ins per 10 seconds it would answer long before the 100th failure.
  const unthrottled = () => testAuth({ throttle: { freeFailures: 1_000 }, rateLimit: false })

  async function signIn(setup: ReturnType<typeof testAuth>, password: string) {
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    return browser.post("/auth/sign-in", { identifier: "ada@example.com", password })
  }

  it("refuses even the right password after 100 consecutive failures, with the same reply as a wrong one", async () => {
    const setup = unthrottled()
    await account(setup)
    for (let i = 0; i < 100; i += 1)
      expect((await signIn(setup, "wrong password entirely")).status).toBe(401)
    const refused = await signIn(setup, PASSWORD)
    expect([refused.status, refused.text]).toEqual([401, '{"error":"invalid-credentials"}'])
    expect(JSON.stringify(setup.events.at(-1))).toContain('"ceiling"')
  }, 120_000)

  it("still lets the right password in after 99 failures, and that success resets the count", async () => {
    const setup = unthrottled()
    await account(setup)
    for (let i = 0; i < 99; i += 1) await signIn(setup, "wrong password entirely")
    expect((await signIn(setup, PASSWORD)).status).toBe(200)
    for (let i = 0; i < 99; i += 1) await signIn(setup, "wrong password entirely")
    expect((await signIn(setup, PASSWORD)).status).toBe(200)
  }, 120_000)
})
