// Attack: a deprovisioned account's sessions keep working. Stopped by: deprovision revokes every session, and every
// session read checks the account's status (ADR 0012, 0006).
import { describe, expect, it } from "vitest"
import { aal2, body, seedSession, testAuth } from "../support/auth.js"

describe("deleted-account-sessions-survive", () => {
  it("ends every session at deprovision", async () => {
    const setup = testAuth()
    const { browser } = await seedSession(setup, {
      subject: "acct-gone",
      evidence: aal2(setup.clock),
    })
    await seedSession(setup, { subject: "acct-gone", evidence: aal2(setup.clock) })
    expect(await setup.auth.admin.deprovision("acct-gone")).toBe(true)
    // Each stored session is revoked, not only refused because the account is disabled.
    const stored = await setup.store.listByOwner("default", "session", "acct-gone")
    expect(stored.map((record) => record.revokedAt !== null)).toEqual([true, true])
    expect(body(await browser.get("/auth/session"))["session"]).toBeNull()
    expect(await setup.auth.admin.deprovision("no-such-account")).toBe(false)
  })

  it("refuses a session of a disabled account even before it is revoked", async () => {
    const setup = testAuth()
    const { browser } = await seedSession(setup, {
      subject: "acct-off",
      evidence: aal2(setup.clock),
    })
    const record = await setup.store.get("default", "account", "acct-off")
    await setup.store.update("default", "account", "acct-off", record?.version ?? 0, {
      data: { status: "disabled" },
    })
    expect(body(await browser.get("/auth/session"))["session"]).toBeNull()
    expect((await browser.get("/auth/sessions")).status).toBe(401)
  })
})
