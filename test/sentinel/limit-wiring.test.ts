// Sentinels for how the limits are wired (ADR 0009 §8, ADR 0030): how a limiter's refusal is told from its failure,
// which limiter each rule gets, how createAuth hands the store, keys and methods to each limit, and what each
// refusal reports. Each check sees one choice directly, so a mutant in these lines fails here first.
import RateLimiterMemory from "rate-limiter-flexible/lib/RateLimiterMemory.js"
import { describe, expect, it, vi } from "vitest"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import { createAuth } from "../../src/core/auth.js"
import { ConfigError } from "../../src/core/errors.js"
import { ownProxies } from "../../src/core/proxy-trust.js"
import type { SecurityEvent } from "../../src/ocsf/events.js"
import {
  createRequestLimits,
  decide,
  type LimiterOptions,
  limitersBy,
  type RateLimiterLike,
} from "../../src/security/rate-limit.js"
import { createStuffingDetector } from "../../src/security/stuffing.js"
import { createThrottle, DEFAULT_THROTTLE, type Throttle } from "../../src/security/throttle.js"
import { fixedClock } from "../../src/core/clock.js"
import { memoryStore } from "../../src/store/memory.js"
import {
  Browser,
  discardEmail,
  ENV,
  hibpClear,
  aal1,
  PASSWORD,
  plainRequest,
  seedAccount,
  seedSession,
  testAuth,
} from "../support/auth.js"
import { recordingStore, sendFrom } from "../support/requests.js"
import { codeAt } from "../support/totp.js"

vi.mock("../../src/security/limit-store.js", async (importOriginal) =>
  (await import("../support/limit-keys.js")).recordingKeyNames(await importOriginal()),
)

const T0 = 1_700_000_000_000

/** A limiter that rejects every consume with `refusal`. */
function rejecting(refusal: unknown): RateLimiterLike {
  return { consume: () => Promise.reject(refusal) } as unknown as RateLimiterLike
}

/** The problems createAuth names, or [] when it starts. */
function problems(config: object): readonly string[] {
  try {
    testAuth(config)
    return []
  } catch (error) {
    if (error instanceof ConfigError) return error.problems
    throw error
  }
}

describe("a limiter's refusal and its failure", () => {
  it("tell a RateLimiterRes from anything else a limiter rejects with", async () => {
    await expect(decide(rejecting(null), "k")).rejects.toBeNull()
    const fn = Object.assign(() => undefined, { msBeforeNext: 5 })
    await expect(decide(rejecting(fn), "k")).rejects.toBe(fn)
    expect(await decide(rejecting({ msBeforeNext: 5, remainingPoints: 0 }), "k")).toEqual({
      allowed: false,
      retryAfterMs: 5,
    })
  })
})

describe("each rule's limiter", () => {
  it("is built once per rule from the library's options, and an instance passes through", () => {
    const built: LimiterOptions[] = []
    const memory = new RateLimiterMemory({ points: 1, duration: 1 })
    const limiterOf = limitersBy((options) => {
      built.push(options)
      return memory
    }, "rate")
    for (let n = 0; n < 3; n += 1) limiterOf({ windowMs: 20_000, max: 4 })
    const own = new RateLimiterMemory({ points: 2, duration: 2 })
    expect(limiterOf(own)).toBe(own)
    expect(built).toEqual([{ points: 4, duration: 20, keyPrefix: "rate:20000:4" }])
  })

  it("is keyed under rate: for the request limits", async () => {
    const built: string[] = []
    const limits = createRequestLimits({}, (options) => {
      built.push(options.keyPrefix)
      return new RateLimiterMemory({ points: 100, duration: 10 })
    })
    await limits.check("session", plainRequest({ method: "GET", path: "/auth/session" }), "c")
    expect(built).toEqual(["rate:10000:100"])
  })
})

describe("createAuth's wiring of the limits", () => {
  it("counts a read with one increment, reading no block", async () => {
    const recorded = recordingStore()
    const { auth } = testAuth({ store: recorded.store })
    await sendFrom(auth)({ method: "GET", path: "/auth/session" })
    expect(recorded.calls).toEqual(["increment"])
  })

  it("counts a refused post and its refusal with two increments, reading no block", async () => {
    const recorded = recordingStore()
    const { auth } = testAuth({ store: recorded.store, rateLimit: { max: 1 } })
    const send = sendFrom(auth)
    await send({ method: "POST", path: "/auth/password" })
    recorded.calls.length = 0
    expect((await send({ method: "POST", path: "/auth/password" })).status).toBe(429)
    expect(recorded.calls).toEqual(["increment", "increment"])
  })

  it("runs a failed sign-in through the throttle, the stuffing detector and the ceiling", async () => {
    const recorded = recordingStore()
    const setup = testAuth({ store: recorded.store })
    await seedAccount(setup, { password: true, totp: true })
    const browser = new Browser(sendFrom(setup.auth))
    await browser.start()
    const reply = await browser.post("/auth/sign-in", {
      identifier: "ada@example.com",
      password: "wrong password entirely",
    })
    expect(reply.status).toBe(401)
    const counted = recorded.counters.map((name) => name.split(":")[0])
    for (const prefix of ["throttle", "stuffing-pair", "stuffing", "ceiling"]) {
      expect(counted, prefix).toContain(prefix)
    }
  })

  it("counts each kind of secret under its own account key: password, TOTP code and recovery code", async () => {
    const recorded = recordingStore()
    const setup = testAuth({ store: recorded.store })
    const { subject } = await seedAccount(setup, { password: true, totp: true })
    const accountKeys = () =>
      recorded.counters.filter((name) => name.startsWith("throttle:account:")).splice(0)
    const browser = new Browser(sendFrom(setup.auth))
    await browser.start()
    await browser.post("/auth/sign-in", {
      identifier: "ada@example.com",
      password: "wrong one here",
    })
    expect(accountKeys()).toEqual(["throttle:account:password:ada@example.com"])
    recorded.counters.length = 0
    const session = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    await session.browser.post("/auth/totp/verify", { code: "000000" })
    expect(accountKeys()).toEqual(["throttle:account:totp:ada@example.com"])
    recorded.counters.length = 0
    await browser.post("/auth/recovery", {
      identifier: "ada@example.com",
      code: "AAAAAA-AAAA-AAAA-AAAA-AAAA",
    })
    expect(accountKeys()).toEqual(["throttle:account:recovery-code:ada@example.com"])
  })

  it("seals and verifies with the configured keys, so a second Auth over the same store agrees", async () => {
    const store = memoryStore()
    const first = testAuth({ store })
    const { secret } = await seedAccount(first, { password: true, totp: true })
    const second = testAuth({ store })
    const browser = new Browser(sendFrom(second.auth))
    const token = await sendFrom(first.auth)({ method: "GET", path: "/auth/session" })
    browser.csrf = (token.json as { csrfToken: string }).csrfToken
    for (const line of token.headers.getSetCookie()) {
      const [pair = ""] = line.split(";")
      const [name = "", value = ""] = pair.split("=")
      browser.cookies.set(name, value)
    }
    const signIn = await browser.post("/auth/sign-in", {
      identifier: "ada@example.com",
      password: PASSWORD,
    })
    expect(signIn.status).toBe(200)
    second.clock.advance(30_000)
    const verify = await browser.post("/auth/totp/verify", {
      code: await codeAt(String(secret), second.clock.now()),
    })
    expect(verify.status).toBe(200)
  })

  it("uses the app's own throttle and refuses a value it does not have", async () => {
    const throttle: Throttle = {
      attempt: () => Promise.resolve(7_000),
      failed: () => Promise.resolve(0),
      succeeded: () => Promise.resolve(),
    }
    const { auth } = testAuth({ throttle })
    const browser = new Browser(sendFrom(auth))
    await browser.start()
    const reply = await browser.post("/auth/sign-in", {
      identifier: "a@example.com",
      password: "x",
    })
    expect([reply.status, reply.headers.get("retry-after")]).toEqual([429, "7"])
    expect(problems({ throttle: { freeFailurs: 3 } })).toEqual([
      'throttle has no value "freeFailurs": its values are freeFailures, windowMs, firstDelayMs and maxDelayMs.',
    ])
    expect(problems({ throttle: { firstDelayMs: 1_000, maxDelayMs: 1_000 } })).toEqual([])
  })

  it("raises the password minimum only with a default below AAL2", async () => {
    const minOf = async (policy?: ReturnType<typeof defineAuthPolicy>) => {
      const auth = createAuth({
        store: memoryStore(),
        env: ENV,
        hibpFetch: hibpClear,
        sendEmail: discardEmail,
        ...(policy === undefined ? {} : { policy }),
      })
      const page = await sendFrom(auth)({ method: "GET", path: "/auth/password" })
      return /data-min="(\d+)"/.exec(page.text)?.[1]
    }
    expect(await minOf()).toBe("8")
    expect(
      await minOf(
        defineAuthPolicy({
          version: "1",
          emailSignIn: true,
          defaultRequirement: { level: "AAL1" },
        }),
      ),
    ).toBe("15")
  })

  it("serves the step-up page to a signed-in session, with its challenge", async () => {
    const setup = testAuth()
    await seedAccount(setup, { password: true, totp: true })
    const browser = new Browser(sendFrom(setup.auth))
    await browser.start()
    await browser.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD })
    const page = await browser.get("/auth/step-up")
    expect(page.status).toBe(200)
    expect(page.text).toContain('data-form="step-up"')
    expect(page.text).toMatch(/name="challenge" value="[A-Za-z0-9_.-]+"/)
  })
})

describe("what each refusal reports", () => {
  /** The refused event and a failed one of the same flow. */
  const pair = (events: readonly unknown[]) => {
    const all = events as SecurityEvent[]
    return {
      refused: all.find((event) => event.status_detail === "rate-limited"),
      failed: all.find(
        (event) => event.status_detail !== "rate-limited" && event.status === "Failure",
      ),
    }
  }

  it("names the same factor, and step-up, as the failures before it", async () => {
    const flows: [string, (browser: Browser) => Promise<unknown>][] = [
      [
        "sign-in",
        (browser) =>
          browser.post("/auth/sign-in", { identifier: "ada@example.com", password: "wrong one" }),
      ],
      ["totp/verify", (browser) => browser.post("/auth/totp/verify", { code: "000000" })],
      [
        "step-up",
        async (browser) => {
          const start = await browser.post("/auth/step-up/start")
          const { challenge } = start.json as { challenge: string }
          return browser.post("/auth/step-up", { challenge, code: "000000" })
        },
      ],
      [
        "recovery",
        (browser) =>
          browser.post("/auth/recovery", { identifier: "ada@example.com", code: "AAAA" }),
      ],
    ]
    for (const [name, attempt] of flows) {
      const setup = testAuth({ rateLimit: false })
      await seedAccount(setup, { password: true, totp: true })
      const browser = new Browser(sendFrom(setup.auth))
      await browser.start()
      if (name !== "sign-in" && name !== "recovery") {
        await browser.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD })
      }
      for (let n = 0; n < 7; n += 1) await attempt(browser)
      const { refused, failed } = pair(setup.events)
      expect(refused, name).toBeDefined()
      expect(refused?.auth_factors, name).toEqual(failed?.auth_factors)
      expect(refused?.auth_factors, name).toBeDefined()
      expect(refused?.unmapped?.test_cap.step_up, name).toBe(failed?.unmapped?.test_cap.step_up)
    }
  })
})

describe("the smaller guards", () => {
  it("never reads the store to flag a request with no address", async () => {
    const recorded = recordingStore()
    const detector = createStuffingDetector({
      store: recorded.store,
      tenant: "t",
      clock: fixedClock(T0),
      config: { distinctAccounts: 1, windowMs: 60_000 },
    })
    expect(await detector.flagged(undefined)).toBeNull()
    expect(await detector.failed("a", undefined)).toBe(false)
    expect(recorded.calls).toEqual([])
  })

  it("gives no trust for an empty proxy list, and trust for a listed one", () => {
    expect(ownProxies([], "x-forwarded-for")).toBeNull()
    expect(ownProxies(["10.0.0.1"], "x-forwarded-for")).toMatchObject({ header: "x-forwarded-for" })
  })

  it("reads a past-free attempt's blocks, counts it, takes its slot without reading a block, and blocks", async () => {
    const recorded = recordingStore()
    const throttle = createThrottle({
      store: recorded.store,
      tenant: "t",
      clock: fixedClock(T0),
      config: { ...DEFAULT_THROTTLE, freeFailures: 0 },
    })
    await throttle.attempt({ account: "a", clientAddress: undefined, secret: "password" as const })
    expect(recorded.calls).toEqual(["get", "increment", "increment", "get", "createUnique"])
  })
})
