// Refusal events (ADR 0009 §8): a flood of refused requests is one event per key per window by default, not one per
// request, so an attacker's flood does not become a flood in the app's logs. `refusalEvents: "every"` emits each.
import { describe, expect, it } from "vitest"
import type { SecurityEvent } from "../../src/ocsf/events.js"
import { Browser, expectOk, PASSWORD, seedAccount, testAuth } from "../support/auth.js"
import { faultyStore } from "../support/faulty-store.js"
import { sendFrom } from "../support/requests.js"

const SIGN_UP = { method: "POST", path: "/auth/sign-up" }

/** The events whose detail is `detail`. */
function withDetail(events: readonly unknown[], detail: string): readonly SecurityEvent[] {
  return (events as SecurityEvent[]).filter((event) => event.status_detail === detail)
}

/** Sends `request` `times` times. */
async function repeat(send: ReturnType<typeof sendFrom>, request: typeof SIGN_UP, times: number) {
  for (let n = 0; n < times; n += 1) await send(request)
}

/** Fails `times` sign-ins on one account from one browser, with the request limit off. */
async function failSignIns(setup: ReturnType<typeof testAuth>, times: number) {
  const browser = new Browser(sendFrom(setup.auth))
  await browser.start()
  const statuses: number[] = []
  for (let n = 0; n < times; n += 1) {
    const reply = await browser.post("/auth/sign-in", {
      identifier: "ada@example.com",
      password: "wrong password entirely",
    })
    statuses.push(reply.status)
  }
  return statuses
}

describe("refusal events", () => {
  it("are one per client and route per window for the request limit by default", async () => {
    const setup = testAuth()
    const send = sendFrom(setup.auth)
    await repeat(send, SIGN_UP, 30)
    expect(withDetail(setup.events, "request-limit")).toHaveLength(1)
    await repeat(sendFrom(setup.auth, "198.51.100.77"), SIGN_UP, 25)
    expect(withDetail(setup.events, "request-limit")).toHaveLength(2)
  })

  it("start again with the next window", async () => {
    const setup = testAuth()
    const send = sendFrom(setup.auth)
    await repeat(send, SIGN_UP, 22)
    setup.clock.advance(60 * 60_000)
    await repeat(send, SIGN_UP, 22)
    expect(withDetail(setup.events, "request-limit")).toHaveLength(2)
  })

  it("are one per request with refusalEvents: every", async () => {
    const setup = testAuth({ refusalEvents: "every" })
    await repeat(sendFrom(setup.auth), SIGN_UP, 30)
    expect(withDetail(setup.events, "request-limit")).toHaveLength(10)
  })

  it("are one per blocked key for the guessing throttle by default, and each with every", async () => {
    for (const [mode, expected] of [
      ["first", 1],
      ["every", 4],
    ] as const) {
      const setup = testAuth({ refusalEvents: mode, rateLimit: { rules: { "sign-in": false } } })
      await seedAccount(setup, { password: true, totp: true })
      const statuses = await failSignIns(setup, 10)
      expect(statuses, mode).toEqual([401, 401, 401, 401, 401, 401, 429, 429, 429, 429])
      expect(withDetail(setup.events, "rate-limited"), mode).toHaveLength(expected)
      expect(withDetail(setup.events, "invalid"), mode).toHaveLength(6)
    }
  })

  it("are one per code for an email code past its attempts by default, and each with every", async () => {
    for (const [mode, expected] of [
      ["first", 1],
      ["every", 3],
    ] as const) {
      const setup = testAuth({ refusalEvents: mode })
      const browser = new Browser(sendFrom(setup.auth))
      await browser.start()
      await expectOk(browser.post("/auth/sign-up", { identifier: "ada@example.com" }))
      for (let n = 0; n < 8; n += 1) await browser.post("/auth/email/confirm", { code: "000000" })
      expect(withDetail(setup.events, "rate-limited"), mode).toHaveLength(expected)
      expect(withDetail(setup.events, "invalid-code"), mode).toHaveLength(5)
    }
  })

  it("are one per identifier for the throttle, so a second account refused from the same client is reported too", async () => {
    const setup = testAuth({ rateLimit: { rules: { "sign-in": false } } })
    const browser = new Browser(sendFrom(setup.auth))
    await browser.start()
    for (const identifier of ["ada@example.com", "bob@example.com"]) {
      for (let n = 0; n < 8; n += 1) {
        await browser.post("/auth/sign-in", { identifier, password: "wrong password entirely" })
      }
    }
    expect(withDetail(setup.events, "rate-limited")).toHaveLength(2)
  })

  it("are one per account for email codes past their attempts", async () => {
    const setup = testAuth()
    for (const [index, identifier] of ["ada@example.com", "bob@example.com"].entries()) {
      const browser = new Browser(sendFrom(setup.auth, `198.51.100.${index + 1}`))
      await browser.start()
      await expectOk(browser.post("/auth/sign-up", { identifier }))
      for (let n = 0; n < 7; n += 1) await browser.post("/auth/email/confirm", { code: "000000" })
    }
    expect(withDetail(setup.events, "rate-limited")).toHaveLength(2)
  })

  it("are one per block for TOTP, step-up and recovery guesses too", async () => {
    /** A signed-in browser of a fresh Auth, and its events. */
    const signedIn = async () => {
      const setup = testAuth()
      await seedAccount(setup, { password: true, totp: true })
      const browser = new Browser(sendFrom(setup.auth))
      await browser.start()
      await expectOk(
        browser.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD }),
      )
      return { setup, browser }
    }
    const totp = await signedIn()
    for (let n = 0; n < 9; n += 1) await totp.browser.post("/auth/totp/verify", { code: "000000" })
    const stepUp = await signedIn()
    for (let n = 0; n < 9; n += 1) {
      const start = await stepUp.browser.post("/auth/step-up/start")
      const { challenge } = start.json as { challenge: string }
      await stepUp.browser.post("/auth/step-up", { challenge, code: "000000" })
    }
    const recovery = await signedIn()
    for (let n = 0; n < 9; n += 1) {
      await recovery.browser.post("/auth/recovery", {
        identifier: "ada@example.com",
        code: "AAAA-AAAA",
      })
    }
    for (const { setup } of [totp, stepUp, recovery]) {
      expect(withDetail(setup.events, "rate-limited")).toHaveLength(1)
    }
  })

  it("still emit, and the refusal still stands, when the store cannot record that one was sent", async () => {
    const faulty = faultyStore()
    const setup = testAuth({ store: faulty.store })
    const send = sendFrom(setup.auth)
    await repeat(send, SIGN_UP, 20)
    faulty.arm({ op: "increment", call: 2, mode: "reject" })
    const reply = await send(SIGN_UP)
    expect(reply.status).toBe(429)
    expect(faulty.calls()).toEqual(["increment", "increment"])
    expect(withDetail(setup.events, "request-limit")).toHaveLength(1)
  })

  it("refuse to start with any other value", () => {
    expect(() => testAuth({ refusalEvents: "some" as never })).toThrow(
      'refusalEvents must be "first" or "every".',
    )
  })
})
