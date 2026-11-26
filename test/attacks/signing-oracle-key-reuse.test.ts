// Attack: an endpoint signs a value the caller chose with a key that also authenticates sessions, links or state.
// Stopped by: one key per purpose, and sessions and one-time secrets are random references looked up by hash, never
// signed values a caller could have minted (ADR 0022, 0006).
import { describe, expect, it } from "vitest"
import { createCsrfTokens } from "../../src/security/csrf.js"
import { aal2, body, Browser, inProcess, seedSession, testAuth } from "../support/auth.js"

const KEY = { id: "c1", bytes: Uint8Array.from({ length: 32 }, (_, i) => i) }

describe("signing-oracle-key-reuse", () => {
  it("issues a session token that is a random reference, which no CSRF token can stand in for", async () => {
    const setup = testAuth()
    const { browser, token } = await seedSession(setup, {
      subject: "acct-1",
      evidence: aal2(setup.clock),
    })
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/)
    const forged = new Browser(inProcess(setup.auth))
    forged.cookies.set("__Host-test-cap", browser.csrf ?? "")
    expect(body(await forged.get("/auth/session"))["session"]).toBeNull()
  })

  it("binds a CSRF token to its purpose and browser state, so it signs nothing else", async () => {
    const tokens = createCsrfTokens([KEY])
    const issued = await tokens.issue("session-hash-a", 0)
    expect(await tokens.verify(issued, "session-hash-a", 1)).toBe(true)
    expect(await tokens.verify(issued, "session-hash-b", 1)).toBe(false)
    // A tag from another key that shares the id never verifies.
    const other = createCsrfTokens([{ id: "c1", bytes: new Uint8Array(32) }])
    expect(await other.verify(issued, "session-hash-a", 1)).toBe(false)
  })

  it("echoes no caller-supplied value back signed", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    const chosen = "attacker-chosen-value-0123456789abcdefghijk"
    const reply = await browser.post("/auth/sign-up", { identifier: `${chosen}@example.com` })
    const headers = [...reply.headers].map(([name, value]) => `${name}: ${value}`).join("\n")
    expect(`${headers}\n${reply.text}`).not.toContain(chosen)
  })
})
