// Attack: guessing saved recovery codes online. Stopped by: 80-bit codes, and attempts counted per account and per
// account and client with the atomic `increment` (ADR 0007, 0009).
import { describe, expect, it } from "vitest"
import { account, Browser, inProcess, testAuth } from "../support/auth.js"

describe("recovery-code-brute-force", () => {
  it("throttles recovery guesses on the account, from any address", async () => {
    const setup = testAuth()
    await account(setup)
    const statuses: number[] = []
    for (let i = 0; i < 7; i += 1) {
      const browser = new Browser(inProcess(setup.auth))
      await browser.start()
      const reply = await browser.post(
        "/auth/recovery",
        {
          identifier: "ada@example.com",
          code: `AAAAAA-AAAA-AAAA-AAAA-AAA${"ABCDEFG"[i] as string}`,
        },
        { clientAddress: `198.51.100.${String(i)}` },
      )
      statuses.push(reply.status)
    }
    expect(statuses).toEqual([401, 401, 401, 401, 401, 401, 429])
  })
})
