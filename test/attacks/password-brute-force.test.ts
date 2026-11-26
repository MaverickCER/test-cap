// Attack: guessing one account's password online. Stopped by: the per-account throttle, whose delay doubles past the
// free failures, and the ceiling of 100 consecutive failures on the password (ADR 0009).
import { describe, expect, it } from "vitest"
import { account, Browser, inProcess, testAuth } from "../support/auth.js"

describe("password-brute-force", () => {
  it("doubles the wait for each guess past the free ones, whatever address the guesses come from", async () => {
    const setup = testAuth()
    await account(setup)
    const waits: (string | null)[] = []
    for (let i = 0; i < 11; i += 1) {
      const browser = new Browser(inProcess(setup.auth))
      await browser.start()
      const reply = await browser.post(
        "/auth/sign-in",
        { identifier: "ada@example.com", password: `guess number ${String(i)}` },
        { clientAddress: `198.51.100.${String(i)}` },
      )
      if (reply.status === 429) {
        waits.push(reply.headers.get("retry-after"))
        setup.clock.advance(Number(reply.headers.get("retry-after")) * 1000)
      }
    }
    expect(waits).toEqual(["1", "2", "4"])
  }, 60_000)
})
