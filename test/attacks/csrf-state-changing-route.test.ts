// Attack: a cross-site request performs a state change (sign-out, revoke, enrolment).
// Stopped by: Origin / `Sec-Fetch-Site` check plus a synchronizer token under `AUTH_CSRF_KEY`; SameSite=Lax (ADR 0011).
import { describe, expect, it } from "vitest"
import { aal2, body, Browser, inProcess, ORIGIN, seedSession, testAuth } from "../support/auth.js"

const ROUTES = [
  "/auth/sign-up",
  "/auth/email/confirm",
  "/auth/email/resend",
  "/auth/sign-in",
  "/auth/password",
  "/auth/totp/enrol",
  "/auth/totp/confirm",
  "/auth/totp/verify",
  "/auth/step-up/start",
  "/auth/step-up",
  "/auth/sign-out",
  "/auth/sessions/revoke",
]

describe("csrf-state-changing-route", () => {
  it.each(ROUTES)(
    "refuses a cross-site POST to %s even with the victim's own session cookie",
    async (path) => {
      const setup = testAuth()
      const { token } = await seedSession(setup, { evidence: aal2(setup.clock) })
      const forged = new Browser(inProcess(setup.auth), "https://evil.example")
      forged.cookies.set("__Host-test-cap", token)
      const reply = await forged.postForm(path, {})
      expect([reply.status, reply.text]).toEqual([403, '{"error":"csrf"}'])
    },
  )

  it("leaves the victim signed in after a forged sign-out", async () => {
    const setup = testAuth()
    const { browser, token } = await seedSession(setup, { evidence: aal2(setup.clock) })
    const forged = new Browser(inProcess(setup.auth))
    forged.cookies.set("__Host-test-cap", token)
    const noToken = await forged.send({
      method: "POST",
      path: "/auth/sign-out",
      headers: [["Origin", ORIGIN]],
    })
    expect(noToken.status).toBe(403)
    const crossSite = await forged.send({
      method: "POST",
      path: "/auth/sign-out",
      headers: [
        ["Sec-Fetch-Site", "cross-site"],
        ["X-CSRF-Token", browser.csrf ?? ""],
      ],
    })
    expect(crossSite.status).toBe(403)
    expect(body(await browser.get("/auth/session"))["session"]).not.toBeNull()
  })

  it("accepts Origin: null only with Sec-Fetch-Site: same-origin, as a no-referrer page's own form post sends it", async () => {
    // The default pages set Referrer-Policy: no-referrer, so a browser posts their forms with `Origin: null`
    // (ADR 0011 §2). That null counts as no Origin: the request still needs the synchronizer token, and
    // Sec-Fetch-Site decides where it came from.
    const setup = testAuth()
    const { browser, token } = await seedSession(setup, { evidence: aal2(setup.clock) })
    const post = (site: string | null) => {
      const forged = new Browser(inProcess(setup.auth))
      forged.cookies.set("__Host-test-cap", token)
      return forged.send({
        method: "POST",
        path: "/auth/step-up/start",
        headers: [
          ["Origin", "null"],
          ...(site === null ? [] : [["Sec-Fetch-Site", site] as [string, string]]),
          ["X-CSRF-Token", browser.csrf ?? ""],
        ],
      })
    }
    for (const site of ["cross-site", "same-site", "none", null]) {
      const reply = await post(site)
      expect([reply.status, reply.text], String(site)).toEqual([403, '{"error":"csrf"}'])
    }
    // A same-origin post passes the origin check and reaches the route, which opens a step-up.
    const accepted = await post("same-origin")
    expect(accepted.status).toBe(200)
    expect(body(accepted)).toHaveProperty("challenge")
    expect(body(await browser.get("/auth/session"))["session"]).not.toBeNull()
  })

  it("refuses a token bound to another session of the same account", async () => {
    const setup = testAuth()
    const mine = await seedSession(setup, { subject: "acct-1", evidence: aal2(setup.clock) })
    const other = await seedSession(setup, { subject: "acct-1", evidence: aal2(setup.clock) })
    mine.browser.csrf = other.browser.csrf
    expect((await mine.browser.post("/auth/sessions/revoke", { sessionId: other.id })).status).toBe(
      403,
    )
  })
})
