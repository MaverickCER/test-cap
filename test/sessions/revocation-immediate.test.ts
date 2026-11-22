// ADR 0006 §6: sign-out and remote revoke take effect on the next request.
import { describe, expect, it } from "vitest"
import { password, T0, totp } from "../support/evidence.js"
import { setup, TENANT } from "../support/sessions.js"

describe("revocation is immediate", () => {
  it("answers unauthenticated on the request after sign-out, remote revoke or a store revoke", async () => {
    const { sessions, store } = setup()
    const evidence = [password(), totp()]
    const a = await sessions.signIn(TENANT, null, { subject: "acct-1", evidence })
    const b = await sessions.signIn(TENANT, null, { subject: "acct-1", evidence })
    const c = await sessions.signIn(TENANT, null, { subject: "acct-1", evidence })
    for (const issued of [a, b, c])
      expect((await sessions.require(TENANT, issued.token, "default")).outcome).toBe("allow")
    await sessions.signOut(TENANT, a.token)
    await sessions.revoke(TENANT, c.token, b.id)
    await store.revokeByOwner(TENANT, "session", "acct-1", T0, { except: "none" })
    for (const issued of [a, b, c]) {
      expect(await sessions.require(TENANT, issued.token, "default")).toEqual({
        outcome: "unauthenticated",
      })
    }
  })

  it("records activity on each read, so the idle limit counts from the last request", async () => {
    const { sessions, clock } = setup()
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password(), totp()],
    })
    clock.advance(1000)
    expect((await sessions.read(TENANT, issued.token))?.state.lastSeenAt).toBe(T0)
    expect((await sessions.read(TENANT, issued.token))?.state.lastSeenAt).toBe(T0 + 1000)
    expect((await sessions.read(TENANT, issued.token))?.id).toBe(issued.id)
  })

  it("returns the assurance the evidence supports at the time of the read", async () => {
    const { sessions } = setup()
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password(), totp()],
    })
    expect((await sessions.read(TENANT, issued.token))?.assurance).toMatchObject({
      level: "AAL2",
      lastMultiFactorAt: T0,
      idleExpiresAt: T0 + 3_600_000,
    })
  })
})
