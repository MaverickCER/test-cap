// Attack: revoke-all reads the session list, then revokes it, missing a session created in between. Stopped by:
// revoke-all is one store operation over the account's sessions, not a read-modify-write list (ADR 0002, 0006).
import { describe, expect, it } from "vitest"
import { SESSION_COLLECTION } from "../../src/sessions/sessions.js"
import { memoryStore } from "../../src/store/memory.js"
import { aal2, body, hookedStore, seedSession, testAuth } from "../support/auth.js"

describe("bulk-revoke-race-misses-session", () => {
  it("revokes every session the account holds, in one operation", async () => {
    const setup = testAuth()
    const seeded = await Promise.all(
      Array.from({ length: 25 }, () =>
        seedSession(setup, { subject: "acct-bulk", evidence: aal2(setup.clock) }),
      ),
    )
    expect(await setup.auth.admin.revoke("acct-bulk")).toBe(25)
    for (const { browser } of seeded)
      expect(body(await browser.get("/auth/session"))["session"]).toBeNull()
  })

  it("revokes a session written while the revocation is already running", async () => {
    const operations: string[] = []
    const state: { armed: boolean; write: (() => Promise<unknown>) | null } = {
      armed: false,
      write: null,
    }
    const store = hookedStore(memoryStore(), async (operation, args) => {
      if (state.armed) operations.push(operation)
      if (!state.armed || operation !== "revokeByOwner" || args[1] !== SESSION_COLLECTION) return
      state.armed = false
      await state.write?.()
    })
    const setup = testAuth({ store })
    const before = await seedSession(setup, { subject: "acct-race", evidence: aal2(setup.clock) })
    let during: Awaited<ReturnType<typeof seedSession>> | null = null
    state.write = async () => {
      during = await seedSession(setup, { subject: "acct-race", evidence: aal2(setup.clock) })
    }
    state.armed = true
    expect(await setup.auth.admin.revoke("acct-race")).toBe(2)
    // The session list is never read and then revoked: the one store operation is the whole revocation.
    expect(operations.filter((each) => each === "listByOwner")).toEqual([])
    expect(during).not.toBeNull()
    for (const { browser } of [before, during as unknown as typeof before])
      expect(body(await browser.get("/auth/session"))["session"]).toBeNull()
  })
})
