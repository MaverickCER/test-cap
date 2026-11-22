// Dependency: the app's mail sender, `sendEmail` (specs/dependency-failures.md, "Email delivery"; ADR 0021, ADR 0029).
// Policy: degraded, never open. test-cap hands the message over without waiting, so a sender that throws, rejects or
// hangs changes no reply and no timing; the person gets no code, so nothing is confirmed and no assurance moves.
import { describe, expect, it } from "vitest"
import type { EmailMessage, SendEmail } from "../../src/core/auth.js"
import { IDENTIFIER_COLLECTION } from "../../src/core/accounts.js"
import {
  Browser,
  confirmationCode,
  expectOk,
  inProcess,
  plainRequest,
  TENANT,
  testAuth,
} from "../support/auth.js"
import { within } from "../support/within.js"

const SENDERS: readonly (readonly [string, SendEmail])[] = [
  [
    "throws",
    () => {
      throw new Error("mail is down")
    },
  ],
  ["rejects", () => Promise.reject(new Error("mail is down"))],
  ["never answers", () => new Promise<void>(() => undefined)],
]

/** A sender that fails as `failing` does until `recover` is called, then keeps every message. */
function flakySender(failing: SendEmail) {
  const sent: EmailMessage[] = []
  let down = true
  const send: SendEmail = (message) => {
    if (down) return failing(message)
    sent.push(message)
    return Promise.resolve()
  }
  return {
    send,
    sent,
    recover: () => {
      down = false
    },
  }
}

describe("a mail sender that fails", () => {
  it.each(SENDERS)(
    "that %s: sign-up still answers at once and the session stays enrolling",
    async (_how, failing) => {
      const setup = testAuth({ sendEmail: failing })
      const browser = new Browser(inProcess(setup.auth))
      await browser.start()
      const reply = await within(browser.post("/auth/sign-up", { identifier: "ada@example.com" }))
      expect([reply.status, reply.text]).toEqual([200, '{"outcome":"enroll","returnTo":"/"}'])
      const cookie = `__Host-test-cap=${String(browser.cookies.get("__Host-test-cap"))}`
      const request = plainRequest({ method: "GET", path: "/", headers: [["Cookie", cookie]] })
      expect(await setup.auth.require(request, "default")).toEqual({ outcome: "enroll" })
      expect(await setup.store.get(TENANT, IDENTIFIER_COLLECTION, "ada@example.com")).toBeNull()
    },
  )

  it.each(SENDERS)(
    "that %s: a resend still answers at once with the wait, and confirms nothing",
    async (_how, failing) => {
      const sender = flakySender(failing)
      const setup = testAuth({ sendEmail: sender.send })
      const browser = new Browser(inProcess(setup.auth))
      await browser.start()
      await expectOk(browser.post("/auth/sign-up", { identifier: "ada@example.com" }))
      setup.clock.advance(60_000)
      const reply = await within(browser.post("/auth/email/resend"))
      expect([reply.status, reply.text]).toEqual([200, '{"outcome":"enroll","retryAfterMs":60000}'])
      expect(sender.sent).toEqual([])
      expect(await setup.store.get(TENANT, IDENTIFIER_COLLECTION, "ada@example.com")).toBeNull()
    },
  )

  it("recovers by a resend once the sender works again, and the new code confirms the address", async () => {
    const sender = flakySender(() => Promise.reject(new Error("mail is down")))
    const setup = testAuth({ sendEmail: sender.send })
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    await expectOk(browser.post("/auth/sign-up", { identifier: "ada@example.com" }))
    sender.recover()
    setup.clock.advance(60_000)
    await expectOk(browser.post("/auth/email/resend"))
    const code = confirmationCode(sender.sent, "ada@example.com")
    const confirmed = await browser.post("/auth/email/confirm", { code })
    expect([confirmed.status, confirmed.text]).toEqual([200, '{"outcome":"enroll"}'])
    expect(
      (await setup.store.get(TENANT, IDENTIFIER_COLLECTION, "ada@example.com"))?.owner,
    ).toBeTypeOf("string")
  })

  it("counts a send the sender lost against the send limits, so an outage cannot be used to flood later", async () => {
    const sender = flakySender(() => Promise.reject(new Error("mail is down")))
    const setup = testAuth({ sendEmail: sender.send })
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    await expectOk(browser.post("/auth/sign-up", { identifier: "ada@example.com" }))
    sender.recover()
    const reply = await browser.post("/auth/email/resend")
    expect([reply.status, reply.text]).toEqual([200, '{"outcome":"enroll","retryAfterMs":60000}'])
    expect(sender.sent).toEqual([])
  })
})
