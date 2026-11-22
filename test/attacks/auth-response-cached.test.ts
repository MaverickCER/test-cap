// Attack: a shared cache stores a response that carries `Set-Cookie` or account data.
// Stopped by: `Cache-Control: no-store` on every auth response; immutable only on hashed assets (ADR 0026). Hashed
// assets arrive with the default pages.
import { describe, expect, it } from "vitest"
import { aal2, Browser, inProcess, seedSession, testAuth } from "../support/auth.js"

describe("auth-response-cached", () => {
  it("marks every reply no-store: successes, refusals, errors and deny by default", async () => {
    const setup = testAuth()
    const { browser, id } = await seedSession(setup, { evidence: aal2(setup.clock) })
    const replies = [
      await browser.get("/auth/session"),
      await browser.get("/auth/sessions"),
      await browser.get("/auth/nope"),
      await browser.get("/auth//x"),
      await browser.send({ method: "PUT", path: "/auth/session" }),
      await browser.post("/auth/sign-up", { identifier: "bad" }),
      await browser.post("/auth/sessions/revoke", { sessionId: id }),
      await new Browser(inProcess(setup.auth)).send({ method: "POST", path: "/auth/sign-out" }),
      await browser.post("/auth/sign-up", { identifier: "ada@example.com" }),
    ]
    for (const reply of replies)
      expect([reply.status, reply.headers.get("cache-control")]).toEqual([reply.status, "no-store"])
    expect(replies.some((reply) => reply.headers.getSetCookie().length > 0)).toBe(true)
  })
})
