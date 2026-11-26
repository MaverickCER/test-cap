// Attack: one account revokes, or lists, another account's session by naming its id. Stopped by: session operations
// are scoped to the tenant and the subject in the store call itself (ADR 0002, 0006).
import { describe, expect, it } from "vitest"
import { aal2, body, seedSession, testAuth } from "../support/auth.js"

describe("idor-session-revoke", () => {
  it("refuses to revoke another account's session, which stays signed in", async () => {
    const setup = testAuth()
    const victim = await seedSession(setup, { subject: "victim", evidence: aal2(setup.clock) })
    const attacker = await seedSession(setup, { subject: "attacker", evidence: aal2(setup.clock) })
    const reply = await attacker.browser.post("/auth/sessions/revoke", { sessionId: victim.id })
    expect([reply.status, reply.text]).toEqual([404, '{"error":"not-found"}'])
    expect(body(await victim.browser.get("/auth/session"))["session"]).toMatchObject({
      subject: "victim",
    })
    const listed = body(await attacker.browser.get("/auth/sessions"))["sessions"] as {
      id: string
    }[]
    expect(listed.map((session) => session.id)).toEqual([attacker.id])
  })
})
