// Attack: a sibling subdomain sets a same-name cookie with a parent Domain that shadows the session or a CSRF cookie.
// Stopped by: the __Host- prefix on every cookie (Secure, Path=/, no Domain), and a request carrying two values of one
// cookie is read as carrying none (ADR 0006).
import { describe, expect, it } from "vitest"
import { aal2, body, Browser, inProcess, seedSession, testAuth } from "../support/auth.js"

describe("cookie-tossing", () => {
  it("sets every cookie with the __Host- prefix, Secure, Path=/ and no Domain", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    const reply = await browser.post("/auth/sign-up", { identifier: "ada@example.com" })
    const lines = reply.headers.getSetCookie()
    expect(lines.length).toBeGreaterThan(0)
    for (const line of lines) {
      expect(line).toMatch(/^__Host-/)
      expect(line).toMatch(/; Secure/i)
      expect(line).toMatch(/; Path=\/(;|$)/i)
      expect(line).not.toMatch(/domain=/i)
    }
  })

  it("treats a tossed second session cookie as no session, rather than picking one", async () => {
    const setup = testAuth()
    const victim = await seedSession(setup, { subject: "victim", evidence: aal2(setup.clock) })
    const attacker = await seedSession(setup, { subject: "attacker", evidence: aal2(setup.clock) })
    for (const order of [
      [attacker.token, victim.token],
      [victim.token, attacker.token],
    ]) {
      const reply = await new Browser(inProcess(setup.auth)).send({
        method: "GET",
        path: "/auth/session",
        headers: [["Cookie", order.map((token) => `__Host-test-cap=${token}`).join("; ")]],
      })
      expect(body(reply)["session"]).toBeNull()
    }
  })

  it("ignores a cookie named without the prefix", async () => {
    const setup = testAuth()
    const { token } = await seedSession(setup, { subject: "acct-1", evidence: aal2(setup.clock) })
    const reply = await new Browser(inProcess(setup.auth)).send({
      method: "GET",
      path: "/auth/session",
      headers: [["Cookie", `test-cap=${token}`]],
    })
    expect(body(reply)["session"]).toBeNull()
  })
})
