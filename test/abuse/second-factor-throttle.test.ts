// ADR 0009 §1: the second factor is a guessable secret too. TOTP verification and step-up go through the same throttle,
// keyed on the account the session names and the client.
import { describe, expect, it } from "vitest"
import { aal1, aal2, seedAccount, seedSession, testAuth } from "../support/auth.js"
import { codeAt } from "../support/totp.js"

describe("throttling the second factor", () => {
  it("throttles wrong TOTP codes on /auth/totp/verify, then lets a right one in once the wait ends", async () => {
    const setup = testAuth()
    const { subject, secret } = await seedAccount(setup, { totp: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    for (let i = 0; i < 6; i += 1) {
      expect((await browser.post("/auth/totp/verify", { code: "000000" })).status).toBe(401)
    }
    const right = { code: await codeAt(secret ?? "", setup.clock.now()) }
    const blocked = await browser.post("/auth/totp/verify", right)
    expect([blocked.status, blocked.text, blocked.headers.get("retry-after")]).toEqual([
      429,
      '{"error":"rate-limited"}',
      "1",
    ])
    setup.clock.advance(1_000)
    expect((await browser.post("/auth/totp/verify", right)).status).toBe(200)
  })

  it("throttles wrong secrets on /auth/step-up the same way", async () => {
    const setup = testAuth()
    const { subject } = await seedAccount(setup, { totp: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal2(setup.clock) })
    const attempt = async () => {
      const started = await browser.post("/auth/step-up/start")
      const { challenge } = started.json as { challenge: string }
      return browser.post("/auth/step-up", { challenge, password: "wrong password entirely" })
    }
    for (let i = 0; i < 6; i += 1) expect((await attempt()).status).toBe(401)
    const blocked = await attempt()
    expect([blocked.status, blocked.text]).toEqual([429, '{"error":"rate-limited"}'])
  })
})
