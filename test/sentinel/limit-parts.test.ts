// Sentinels for the parts every limit is built from (ADR 0009 §8, ADR 0030): the store limiter's options in each
// caller, the throttle's slot and block, the stuffing detector's counts, the ceiling, the mail limits, the address
// parsers, and the dispatcher's edges. Nearly every test passes through these lines, so each check here sees one
// choice directly and fails in milliseconds.
import { describe, expect, it, vi } from "vitest"
import { createAuth } from "../../src/core/auth.js"
import { canonicalAddress, clientKey, parseAddress } from "../../src/core/client-address.js"
import { fixedClock } from "../../src/core/clock.js"
import { sendConfirmation } from "../../src/core/email.js"
import { addressRanges, rangeProblems, resolveClient } from "../../src/core/proxy-trust.js"
import { pageAssets } from "../../src/pages/assets.js"
import { createFailureCeiling } from "../../src/security/ceiling.js"
import { isLimiter, isRule } from "../../src/security/rate-limit.js"
import { createStuffingDetector, NO_STUFFING } from "../../src/security/stuffing.js"
import { createThrottle, DEFAULT_THROTTLE, NO_THROTTLE } from "../../src/security/throttle.js"
import { memoryStore } from "../../src/store/memory.js"
import type { AuthStore } from "../../src/store/port.js"
import { Browser, discardEmail, ENV, hibpClear, testAuth } from "../support/auth.js"
import { recordingStore, sendFrom } from "../support/requests.js"

vi.mock("../../src/security/limit-store.js", async (importOriginal) =>
  (await import("../support/limit-keys.js")).recordingKeyNames(await importOriginal()),
)

const T0 = 1_700_000_000_000
const ada = { account: "ada@example.com", clientAddress: "192.0.2.7", secret: "password" } as const

/** A memory store whose `createUnique` into `collection` fails while `failing.on` is true. */
function failingWrites(collection: string) {
  const failing = { on: false }
  const base = memoryStore()
  const store = new Proxy(base, {
    get(target, property, receiver) {
      const value: unknown = Reflect.get(target, property, receiver)
      if (property !== "createUnique" || typeof value !== "function") return value
      return (tenant: string, record: { collection: string }) =>
        failing.on && record.collection === collection
          ? Promise.reject(new Error("write failed"))
          : (value as (...a: unknown[]) => unknown).call(target, tenant, record)
    },
  }) as AuthStore
  return { store, failing }
}

describe("isRule and isLimiter", () => {
  it("tell rules and limiters from everything else", () => {
    const fnWithConsume = Object.assign(() => undefined, { consume: () => undefined })
    for (const value of [null, undefined, true, "1/1", fnWithConsume, { windowMs: 1 }]) {
      expect(isRule(value), String(value)).toBe(false)
    }
    for (const value of [null, undefined, {}, { consume: 1 }, fnWithConsume]) {
      expect(isLimiter(value), String(value)).toBe(false)
    }
    expect([isRule({ windowMs: 1, max: 1 }), isLimiter({ consume: () => undefined })]).toEqual([
      true,
      true,
    ])
  })
})

describe("the stand-ins for a limit turned off", () => {
  it("let everything through and flag no one", async () => {
    expect(await NO_STUFFING.failed("a", "192.0.2.1")).toBe(false)
    expect(await NO_STUFFING.flagged("192.0.2.1")).toBeNull()
    expect(await NO_THROTTLE.attempt(ada)).toBe(0)
    expect(await NO_THROTTLE.failed(ada)).toBe(0)
  })
})

describe("the throttle's parts", () => {
  it("counts under throttle: keys, reads three blocks, and counts the two account keys", async () => {
    const recorded = recordingStore()
    const throttle = createThrottle({
      store: recorded.store,
      tenant: "t",
      clock: fixedClock(T0),
      config: DEFAULT_THROTTLE,
    })
    await throttle.attempt(ada)
    expect(recorded.calls).toEqual(["get", "get", "get", "increment", "increment"])
    expect(recorded.counters).toEqual([
      "throttle:account:password:ada@example.com",
      "throttle:account-client:password:ada@example.com|192.0.2.7",
    ])
  })

  it("takes the slot under throttle-slot: once past the free attempts", async () => {
    const recorded = recordingStore()
    const throttle = createThrottle({
      store: recorded.store,
      tenant: "t",
      clock: fixedClock(T0),
      config: { ...DEFAULT_THROTTLE, freeFailures: 0 },
    })
    await throttle.attempt(ada)
    expect(recorded.counters).toContain("throttle-slot:account:password:ada@example.com")
  })

  it("starts its counts afresh once the window ends", async () => {
    const clock = fixedClock(T0)
    const throttle = createThrottle({
      store: memoryStore(),
      tenant: "t",
      clock,
      config: DEFAULT_THROTTLE,
    })
    for (let n = 0; n < 5; n += 1) await throttle.failed(ada)
    clock.advance(DEFAULT_THROTTLE.windowMs)
    expect(await throttle.failed(ada)).toBe(0)
  })

  it("keeps the slot for the whole delay when the block's write is lost", async () => {
    const { store, failing } = failingWrites("rate-limit-block")
    const clock = fixedClock(T0)
    const config = { ...DEFAULT_THROTTLE, freeFailures: 0, firstDelayMs: 4_000, maxDelayMs: 4_000 }
    const throttle = createThrottle({ store, tenant: "t", clock, config })
    failing.on = true
    await expect(throttle.attempt(ada)).rejects.toThrow("write failed")
    failing.on = false
    clock.advance(2_000)
    expect(await throttle.attempt(ada)).toBe(2_000)
  })

  it("passes on a store error from the slot, never reading it as a refusal", async () => {
    const base = memoryStore()
    let increments = 0
    const store = new Proxy(base, {
      get(target, property, receiver) {
        const value: unknown = Reflect.get(target, property, receiver)
        if (property !== "increment" || typeof value !== "function") return value
        return (...args: unknown[]) => {
          increments += 1
          return increments === 2
            ? Promise.reject(new Error("slot failed"))
            : (value as (...a: unknown[]) => unknown).apply(target, args)
        }
      },
    }) as AuthStore
    const throttle = createThrottle({
      store,
      tenant: "t",
      clock: fixedClock(T0),
      config: { ...DEFAULT_THROTTLE, freeFailures: 0 },
    })
    await expect(
      throttle.attempt({ account: "a", clientAddress: undefined, secret: "password" as const }),
    ).rejects.toThrow("slot failed")
  })
})

describe("the stuffing detector's parts", () => {
  it("counts pairs and accounts under its prefixes, without reading blocks, and resets with the window", async () => {
    const recorded = recordingStore()
    const clock = fixedClock(T0)
    const detector = createStuffingDetector({
      store: recorded.store,
      tenant: "t",
      clock,
      config: { distinctAccounts: 2, windowMs: 60_000 },
    })
    await detector.failed("a", "192.0.2.1")
    expect(recorded.calls).toEqual(["increment", "increment"])
    expect(recorded.counters).toEqual(["stuffing-pair:192.0.2.1|a", "stuffing:192.0.2.1"])
    clock.advance(60_000)
    expect(await detector.failed("b", "192.0.2.1")).toBe(false)
    expect(await detector.failed("c", "192.0.2.1")).toBe(true)
  })

  it("never flags a request with no address, even when a client keyed null is flagged", async () => {
    const detector = createStuffingDetector({
      store: memoryStore(),
      tenant: "t",
      clock: fixedClock(T0),
      config: { distinctAccounts: 1, windowMs: 60_000 },
    })
    expect(await detector.failed("a", "null")).toBe(true)
    expect(await detector.flagged("null")).toBe("null")
    expect(await detector.flagged(undefined)).toBeNull()
  })
})

describe("the ceiling's parts", () => {
  it("counts each failure with one increment, and reads only the block", async () => {
    const recorded = recordingStore()
    const ceiling = createFailureCeiling({
      store: recorded.store,
      tenant: "t",
      clock: fixedClock(T0),
      limit: 2,
    })
    await ceiling.failed("a1")
    expect(recorded.calls).toEqual(["increment"])
    expect(await ceiling.reached("a1")).toBe(false)
  })
})

describe("the mail limits' parts", () => {
  it("count each default limit under its own prefix, without reading blocks", async () => {
    const recorded = recordingStore()
    await sendConfirmation(
      {
        store: recorded.store,
        tenant: "t",
        clock: fixedClock(T0),
        random: { fill: (bytes: Uint8Array) => bytes.fill(1) },
        linkBase: "https://app.example/auth",
        sendEmail: discardEmail,
        keyRing: [{ id: "k1", bytes: new Uint8Array(32).fill(7) }],
      },
      { accountId: "a1", address: "ada@example.com", clientAddress: "192.0.2.1" },
    )
    expect(recorded.counters.slice(0, 3)).toEqual([
      "email-send:60000:1:address:ada@example.com",
      "email-send:3600000:5:address:ada@example.com",
      "email-send:3600000:20:client:192.0.2.1",
    ])
    expect(recorded.calls.slice(0, 4)).toEqual([
      "increment",
      "increment",
      "increment",
      "revokeByOwner",
    ])
  })

  it("count no client with perClient: false", async () => {
    const recorded = recordingStore()
    const setup = testAuth({ store: recorded.store, emailLimit: { perClient: false } })
    const browser = new Browser(sendFrom(setup.auth))
    await browser.start()
    await browser.post("/auth/sign-up", { identifier: "ada@example.com" })
    expect(recorded.counters.filter((name) => name.includes(":client:"))).toEqual([])
    expect(setup.outbox[0]?.text).toContain("https://app.example/auth/email/confirm")
  })
})

describe("the address parsers", () => {
  it("read IPv4 as IPv4, and name each list entry that is no address or range", () => {
    expect([canonicalAddress("192.0.2.1"), clientKey("192.0.2.1")]).toEqual([
      "192.0.2.1",
      "192.0.2.1",
    ])
    expect(parseAddress("192.0.2.1")?.kind()).toBe("ipv4")
    expect(rangeProblems("trustedProxies", ["10.0.0.0/8", "nope", "1.2.3.4/33"])).toEqual([
      'trustedProxies: "nope" is not an IP address or CIDR range.',
      'trustedProxies: "1.2.3.4/33" is not an IP address or CIDR range.',
    ])
  })

  it("keep a quoted name with colons whole, and remove only one port", () => {
    const trust = {
      header: "forwarded",
      format: "forwarded" as const,
      peers: addressRanges(["10.0.0.1"]),
      hops: addressRanges(["10.0.0.1"]),
    }
    const read = (value: string) =>
      resolveClient("10.0.0.1", new Headers([["forwarded", value]]), trust)
    expect(read('for="_a:b:c"')).toBe("_a:b:c")
    expect(read('for="_a:1"')).toBe("_a")
  })
})

describe("the dispatcher's edges", () => {
  it("answers nothing outside /auth, serves the hashed assets, and redirects a page that needs a session", async () => {
    const send = sendFrom(testAuth().auth)
    expect((await send({ method: "GET", path: "/elsewhere" })).status).toBe(0)
    const { script } = await pageAssets()
    const asset = await send({ method: "GET", path: script.path })
    expect([asset.status, asset.headers.get("cache-control")]).toEqual([
      200,
      "public, max-age=31536000, immutable",
    ])
    const enrol = await send({ method: "GET", path: "/auth/totp/enrol" })
    expect([enrol.status, enrol.headers.get("location")]).toEqual([303, "/auth/sign-in"])
  })

  it("counts refusals under refusal-event: for the whole wait, so one event per wait", async () => {
    const recorded = recordingStore()
    const setup = testAuth({ store: recorded.store })
    const send = sendFrom(setup.auth)
    for (let n = 0; n < 21; n += 1) await send({ method: "POST", path: "/auth/sign-up" })
    expect(recorded.counters.at(-1)).toBe("refusal-event:request|sign-up|203.0.113.7")
    setup.clock.advance(2_000)
    await send({ method: "POST", path: "/auth/sign-up" })
    const refusals = (setup.events as { status_detail?: string }[]).filter(
      (event) => event.status_detail === "request-limit",
    )
    expect(refusals).toHaveLength(1)
  })

  it("runs a whole sign-up with the default clock, keys and methods wired", async () => {
    const auth = createAuth({
      store: memoryStore(),
      env: { ...ENV, APP_ENV: "development" },
      hibpFetch: hibpClear,
      sendEmail: discardEmail,
    })
    const browser = new Browser(sendFrom(auth))
    await browser.start()
    expect((await browser.post("/auth/sign-up", { identifier: "ada@example.com" })).status).toBe(
      200,
    )
  })
})
