// Attack: a burst of parallel OTP guesses, each checked before any failure is recorded, gets past the attempt limit.
// Stopped by: every attempt is counted with the atomic `increment` before the code is checked, and past the free
// attempts one compare-and-set wins the next slot (ADR 0002, 0009).
import { describe, expect, it } from "vitest"
import { aal1, seedAccount, seedSession, testAuth } from "../support/auth.js"

describe("otp-attempt-limit-race", () => {
  it("lets a parallel burst past the free attempts check one guess, not one each", async () => {
    const setup = testAuth()
    const { subject } = await seedAccount(setup, { totp: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    for (let i = 0; i < 5; i += 1) await browser.post("/auth/totp/verify", { code: "000000" })
    const burst = await Promise.all(
      Array.from({ length: 12 }, (_, i) =>
        browser.post("/auth/totp/verify", { code: String(100000 + i) }),
      ),
    )
    expect(burst.filter((reply) => reply.status === 401)).toHaveLength(1)
    expect(burst.filter((reply) => reply.status === 429)).toHaveLength(11)
  })
})
