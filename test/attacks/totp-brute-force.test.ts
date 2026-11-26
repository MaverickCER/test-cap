// Attack: guessing a session's TOTP codes online. Stopped by: the throttle on the account and on the account and
// client, and the ceiling of 100 consecutive failures per authenticator (ADR 0009, 0027).
import { describe, expect, it } from "vitest"
import { aal1, seedAccount, seedSession, testAuth } from "../support/auth.js"
import { codeAt } from "../support/totp.js"

describe("totp-brute-force", () => {
  it("throttles guesses past the free ones", async () => {
    const setup = testAuth()
    const { subject } = await seedAccount(setup, { totp: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    const statuses: number[] = []
    for (let i = 0; i < 7; i += 1)
      statuses.push((await browser.post("/auth/totp/verify", { code: "000000" })).status)
    expect(statuses).toEqual([401, 401, 401, 401, 401, 401, 429])
  })

  it("stops an authenticator after 100 consecutive wrong codes, even for the right code", async () => {
    // Neither the throttle nor the request limiter may answer first: the ceiling is what this checks.
    const setup = testAuth({ throttle: { freeFailures: 1_000 }, rateLimit: false })
    const { subject, secret } = await seedAccount(setup, { totp: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    for (let i = 0; i < 100; i += 1) await browser.post("/auth/totp/verify", { code: "000000" })
    setup.clock.advance(30_000)
    const right = await browser.post("/auth/totp/verify", {
      code: await codeAt(secret ?? "", setup.clock.now()),
    })
    expect([right.status, right.text]).toEqual([401, '{"error":"invalid-code"}'])
  }, 120_000)
})
