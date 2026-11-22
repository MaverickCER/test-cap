// Attack: a signed-out session token still works.
// Stopped by: sign-out revokes in the store; the cookie is cleared (ADR 0006).
import { describe, expect, it } from "vitest"
import { password, totp } from "../support/evidence.js"
import { setup, TENANT } from "../support/sessions.js"

describe("sign-out-leaves-session-valid", () => {
  it("revokes the session in the store and clears the cookie", async () => {
    const { sessions, store } = setup()
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password(), totp()],
    })
    expect(await sessions.signOut(TENANT, issued.token)).toBe(
      "__Host-test-cap=-; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
    )
    expect(await sessions.require(TENANT, issued.token, "default")).toEqual({
      outcome: "unauthenticated",
    })
    const [record] = await store.listByOwner(TENANT, "session", "acct-1")
    expect(record?.revokedAt).not.toBeNull()
  })

  it("clears the cookie even without a session", async () => {
    const { sessions } = setup()
    expect(await sessions.signOut(TENANT, null)).toContain("Max-Age=0")
  })
})
