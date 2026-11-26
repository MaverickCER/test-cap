// ADR 0009 §4: failures spread over many accounts from one client flag it; a flagged client's sign-in goes to the
// app's challenge hook first, and without a hook every failure from it blocks at once. The detector reports itself.
import { describe, expect, it } from "vitest"
import { fixedClock } from "../../src/core/clock.js"
import { createStuffingDetector, DEFAULT_STUFFING } from "../../src/security/stuffing.js"
import { LIMIT_BLOCK_COLLECTION } from "../../src/security/store-limiter.js"
import { memoryStore } from "../../src/store/memory.js"
import type { PlainRequest } from "../../src/transport/types.js"
import { account, Browser, inProcess, PASSWORD, testAuth } from "../support/auth.js"

describe("createStuffingDetector", () => {
  const setup = (distinctAccounts = 3) => {
    const store = memoryStore()
    const clock = fixedClock(1_000)
    const detector = createStuffingDetector({
      store,
      tenant: "t",
      clock,
      config: { ...DEFAULT_STUFFING, distinctAccounts },
    })
    return { store, clock, detector }
  }

  it("defaults to 20 accounts in 15 minutes", () => {
    expect(DEFAULT_STUFFING).toEqual({ distinctAccounts: 20, windowMs: 900_000 })
  })

  it("flags a client on its third distinct account, not on repeats of one account", async () => {
    const { detector } = setup()
    expect(await detector.failed("a", "192.0.2.1")).toBe(false)
    expect(await detector.failed("a", "192.0.2.1")).toBe(false)
    expect(await detector.failed("b", "192.0.2.1")).toBe(false)
    expect(await detector.flagged("192.0.2.1")).toBeNull()
    expect(await detector.failed("c", "192.0.2.1")).toBe(true)
    expect(await detector.flagged("192.0.2.1")).toBe("192.0.2.1")
    // Further accounts do not report the flag again.
    expect(await detector.failed("d", "192.0.2.1")).toBe(false)
    expect(await detector.flagged("192.0.2.2")).toBeNull()
  })

  it("keeps the flag until the window ends, keyed on the /64 for IPv6", async () => {
    const { detector, clock, store } = setup()
    for (const name of ["a", "b", "c"]) await detector.failed(name, `2001:db8::${name}`)
    expect(await detector.flagged("2001:db8::ffff")).toBe("2001:db8:0:0::/64")
    expect(
      (await store.get("t", LIMIT_BLOCK_COLLECTION, "stuffing:2001:db8:0:0::/64"))?.data,
    ).toEqual({
      points: 4,
      expire: 901_000,
    })
    clock.advance(899_999)
    expect(await detector.flagged("2001:db8::1")).not.toBeNull()
    clock.advance(1)
    expect(await detector.flagged("2001:db8::1")).toBeNull()
  })

  it("never flags a request without a client address", async () => {
    const { detector } = setup(1)
    expect(await detector.failed("a", undefined)).toBe(false)
    expect(await detector.flagged(undefined)).toBeNull()
  })
})

describe("the detector at the sign-in route", () => {
  async function attempt(
    setup: ReturnType<typeof testAuth>,
    identifier: string,
    password = "wrong password entirely",
  ) {
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    return browser.post("/auth/sign-in", { identifier, password }, { clientAddress: "192.0.2.50" })
  }

  async function spray(setup: ReturnType<typeof testAuth>) {
    for (const name of ["a", "b", "c"]) await attempt(setup, `${name}@example.com`)
  }

  it("reports the failure that flags the client as credential stuffing", async () => {
    const setup = testAuth({ stuffing: { distinctAccounts: 3 } })
    await spray(setup)
    const details = setup.events.map((event) => JSON.stringify(event))
    expect(details.filter((text) => text.includes('"credential-stuffing"'))).toHaveLength(1)
  })

  it("sends a flagged client to the app's challenge before any password is checked", async () => {
    const seen: { client: string; challenge: string | null }[] = []
    const challengeHook = ({ request, client }: { request: PlainRequest; client: string }) => {
      seen.push({ client, challenge: request.headers.get("x-challenge") })
      return false
    }
    const setup = testAuth({ stuffing: { distinctAccounts: 3 }, challengeHook })
    await account(setup)
    await spray(setup)
    const refused = await attempt(setup, "ada@example.com", PASSWORD)
    expect([refused.status, refused.text]).toEqual([403, '{"error":"challenge-required"}'])
    expect(seen).toEqual([{ client: "192.0.2.50", challenge: null }])
  })

  it("lets a flagged client through when the app's challenge passes", async () => {
    const setup = testAuth({
      stuffing: { distinctAccounts: 3 },
      challengeHook: () => Promise.resolve(true),
    })
    await account(setup)
    await spray(setup)
    expect((await attempt(setup, "ada@example.com", PASSWORD)).status).toBe(200)
  })

  it("without a hook, blocks a flagged client at its next failure", async () => {
    const setup = testAuth({ stuffing: { distinctAccounts: 3 } })
    await spray(setup)
    // Three failures so far, all free; the fourth, from a flagged client, blocks at once.
    expect((await attempt(setup, "d@example.com")).status).toBe(401)
    expect((await attempt(setup, "e@example.com")).status).toBe(429)
  })

  it("leaves a client that is not flagged alone", async () => {
    const setup = testAuth({ stuffing: { distinctAccounts: 3 }, challengeHook: () => false })
    await attempt(setup, "a@example.com")
    expect((await attempt(setup, "b@example.com")).status).toBe(401)
  })

  it("refuses a stuffing setting out of range", () => {
    expect(() => testAuth({ stuffing: { distinctAccounts: 0, windowMs: 1.5 } })).toThrow(
      /stuffing.distinctAccounts must be a whole number, 1 or more.[\s\S]*stuffing.windowMs must be a whole number of milliseconds, from 1 to 31536000000 \(a year\)./,
    )
  })
})
