// Attack: a request's Host header, or the host in its absolute URL, sets the base path the routes answer on or the
// origin of an emailed link, so a poisoned request mails the victim a link to the attacker's site.
// Stopped by: every origin and link comes from APP_ORIGIN, and routes match the raw path alone; the Host header is
// never read for either (ADR 0026, ADR 0003). Recovery links join this test when they land.
import { describe, expect, it } from "vitest"
import { Browser, expectOk, inProcess, ORIGIN, testAuth, type Transport } from "../support/auth.js"

const EVIL = "https://evil.example"

describe("host-header-poisoning", () => {
  it("builds the confirmation email's link on APP_ORIGIN, whatever Host and URL the sign-up came with", async () => {
    const setup = testAuth()
    const poisoned: Transport = (request) =>
      inProcess(setup.auth)({
        ...request,
        path: `${EVIL}${request.path}`,
        headers: [
          ...(request.headers ?? []),
          ["Host", "evil.example"],
          ["X-Forwarded-Host", "evil.example"],
        ],
      })
    const browser = new Browser(poisoned)
    await browser.start()
    await expectOk(browser.post("/auth/sign-up", { identifier: "ada@example.com" }))
    expect(setup.outbox).toHaveLength(1)
    expect(setup.outbox[0]?.text).toContain(`${ORIGIN}/auth/email/confirm`)
    expect(setup.outbox[0]?.text).not.toContain("evil")
  })

  it("answers on the raw path's base path only, whatever host the URL names", async () => {
    const setup = testAuth()
    for (const url of [`${EVIL}/auth/session`, "/auth/session"]) {
      const reply = await setup.auth.handle({
        method: "GET",
        url,
        headers: new Headers({ Host: "evil.example" }),
        body: null,
      })
      expect(reply?.status).toBe(200)
    }
    const outside = await setup.auth.handle({
      method: "GET",
      url: `${EVIL}/evil/auth/session`,
      headers: new Headers({ Host: "evil.example" }),
      body: null,
    })
    expect(outside).toBeNull()
  })
})
