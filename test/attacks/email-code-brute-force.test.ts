// Attack: guessing a 6-digit email code within its lifetime, in sequence or in parallel.
// Stopped by: every attempt is counted per account with the atomic `increment` before the code is checked; at the
// limit the code dies, and the count refuses further attempts for the rest of the code's life (ADR 0009, ADR 0021).
// Email confirmation codes are the only email codes so far; recovery codes (phase 4) join this test when they land.
import { describe, expect, it } from "vitest"
import { type RandomSource, systemRandom } from "../../src/core/clock.js"
import { CONFIRMATION_FAILURE_LIMIT } from "../../src/core/email.js"
import { Browser, expectOk, inProcess, testAuth } from "../support/auth.js"

/** Every draw of at most 6 bytes yields the code 123456. */
const fixedCode: RandomSource = {
  fill(bytes) {
    if (bytes.length > 6) return systemRandom.fill(bytes)
    bytes.set([1, 2, 3, 4, 5, 6].slice(0, bytes.length))
    return bytes
  },
}

async function signedUp() {
  const setup = testAuth({ random: fixedCode })
  const browser = new Browser(inProcess(setup.auth))
  await browser.start()
  await expectOk(browser.post("/auth/sign-up", { identifier: "ada@example.com" }))
  return { setup, browser }
}

describe("email-code-brute-force", () => {
  it(`stops a sequential guesser at ${CONFIRMATION_FAILURE_LIMIT} attempts, with the right code among the later ones`, async () => {
    const { browser } = await signedUp()
    const statuses: number[] = []
    for (let guess = 0; guess < 20; guess += 1) {
      const code = guess === 10 ? "123456" : String(guess).padStart(6, "0")
      statuses.push((await browser.post("/auth/email/confirm", { code })).status)
    }
    expect(statuses).toEqual([
      ...Array<number>(CONFIRMATION_FAILURE_LIMIT).fill(400),
      ...Array<number>(20 - CONFIRMATION_FAILURE_LIMIT).fill(429),
    ])
  })

  it("counts parallel guesses one by one, so a burst checks no more codes than the limit", async () => {
    const { browser } = await signedUp()
    const replies = await Promise.all(
      Array.from({ length: 30 }, (_, guess) =>
        browser.post("/auth/email/confirm", { code: `9${String(guess).padStart(5, "0")}` }),
      ),
    )
    const statuses = replies.map((reply) => reply.status)
    expect(statuses.filter((status) => status === 400)).toHaveLength(CONFIRMATION_FAILURE_LIMIT)
    expect(statuses.filter((status) => status === 429)).toHaveLength(
      30 - CONFIRMATION_FAILURE_LIMIT,
    )
    // The burst used up the attempts, and the code died with them.
    expect((await browser.post("/auth/email/confirm", { code: "123456" })).status).toBe(429)
  })
})
