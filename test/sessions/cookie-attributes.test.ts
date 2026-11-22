// ADR 0006 §2: `__Host-test-cap` with Secure, HttpOnly, SameSite=Lax, Path=/ and no Domain.
import { describe, expect, it } from "vitest"
import { clearSessionCookie, readSessionToken, sessionCookie } from "../../src/sessions/sessions.js"
import { HOUR, password, totp } from "../support/evidence.js"
import { setup, TENANT } from "../support/sessions.js"

describe("session cookie", () => {
  it("sets the token under __Host-test-cap with the fixed attributes, never outliving the absolute limit", async () => {
    const { sessions, clock } = setup()
    clock.advance(500)
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password(), totp()],
    })
    expect(issued.cookie).toBe(
      `__Host-test-cap=${issued.token}; Path=/; Max-Age=86400; Secure; HttpOnly; SameSite=Lax`,
    )
    expect(issued.cookie).not.toContain("Domain")
  })

  it("rounds the remaining lifetime down to whole seconds", () => {
    expect(sessionCookie("abc", 1999)).toBe(
      "__Host-test-cap=abc; Path=/; Max-Age=1; Secure; HttpOnly; SameSite=Lax",
    )
    expect(sessionCookie("abc", 24 * HOUR)).toContain("Max-Age=86400;")
  })

  it("clears the cookie with the same attributes", () => {
    expect(clearSessionCookie()).toBe(
      "__Host-test-cap=-; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
    )
  })

  it("reads the token by its exact name, and reads nothing when the name arrives twice", () => {
    expect(readSessionToken(new Headers({ cookie: "__Host-test-cap=abc" }))).toBe("abc")
    expect(readSessionToken(new Headers({ cookie: "test-cap=abc" }))).toBeNull()
    expect(readSessionToken(new Headers())).toBeNull()
    expect(
      readSessionToken(new Headers({ cookie: "__Host-test-cap=abc; __Host-test-cap=def" })),
    ).toBeNull()
  })
})
