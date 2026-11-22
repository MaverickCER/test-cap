// Attack: an emailed confirmation link carries an attacker-chosen redirect, or the code itself, in its URL.
// Stopped by: the email's one link is the confirmation page on APP_ORIGIN, with no query, no fragment and no redirect
// target; the code is typed in, never carried in a URL (ADR 0026 §5, ADR 0021). Recovery and email sign-in links
// join this test when they land.
import { describe, expect, it } from "vitest"
import {
  Browser,
  confirmationCode,
  expectOk,
  inProcess,
  ORIGIN,
  testAuth,
} from "../support/auth.js"

const URLS = /[a-z][a-z0-9+.-]*:\/\/\S+/gi

describe("email-link-redirect", () => {
  it("links only to the confirmation page, whatever returnTo the sign-up asked for", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    await expectOk(
      browser.post("/auth/sign-up", {
        identifier: "ada@example.com",
        returnTo: "/billing?next=%2F%2Fevil",
      }),
    )
    const [message] = setup.outbox
    const code = confirmationCode(setup.outbox, "ada@example.com")
    expect(message?.text.match(URLS)).toEqual([`${ORIGIN}/auth/email/confirm`])
    for (const url of message?.text.match(URLS) ?? []) expect(url).not.toContain(code)
    expect(message?.text).not.toContain("billing")
    expect(message?.subject).not.toContain(code)
  })

  it("sends the same link on a resend", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    await expectOk(
      browser.post("/auth/sign-up", { identifier: "ada@example.com", returnTo: "/billing" }),
    )
    setup.clock.advance(60_000)
    await expectOk(browser.post("/auth/email/resend"))
    expect(setup.outbox.map((message) => message.text.match(URLS))).toEqual([
      [`${ORIGIN}/auth/email/confirm`],
      [`${ORIGIN}/auth/email/confirm`],
    ])
  })
})
