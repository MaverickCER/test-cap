// Attack: two concurrent sign-ups or enrolments claim one identifier or credential. Stopped by: confirmed identifiers
// and authenticators are written with createUnique, unique per tenant (ADR 0002).
import { describe, expect, it } from "vitest"
import { IDENTIFIER_COLLECTION } from "../../src/core/accounts.js"
import { Browser, confirmationCode, inProcess, testAuth } from "../support/auth.js"

describe("concurrent-enrolment-collision", () => {
  it("lets exactly one of many accounts confirming one address in parallel claim it", async () => {
    const setup = testAuth()
    const browsers = Array.from({ length: 5 }, () => new Browser(inProcess(setup.auth)))
    const codes: string[] = []
    for (const browser of browsers) {
      await browser.start()
      await browser.post("/auth/sign-up", { identifier: "ada@example.com" })
      codes.push(confirmationCode(setup.outbox, "ada@example.com"))
      // One confirmation email per address per minute, five an hour.
      setup.clock.advance(60_000)
    }
    const replies = await Promise.all(
      browsers.map((browser, i) => browser.post("/auth/email/confirm", { code: codes[i] })),
    )
    // Every reply is the same, so none says the address was taken.
    expect(new Set(replies.map((reply) => reply.text))).toEqual(new Set(['{"outcome":"enroll"}']))
    const owners = new Set(
      (setup.events as { status_id?: number; message?: string }[])
        .map((event) => JSON.stringify(event))
        .filter((text) => text.includes("email-confirmed")),
    )
    expect(owners.size).toBe(1)
    const claimed = await setup.store.get("default", IDENTIFIER_COLLECTION, "ada@example.com")
    expect(claimed?.owner).toBeTypeOf("string")
  })
})
