// Attack: a revoked session keeps working from a cache, or mints a passkey or a new session before expiry.
// Stopped by: every request reads revocation from the store; revoke has immediate visibility (ADR 0006, 0002).
import { describe, expect, it } from "vitest"
import { hardwareKey, password, T0, totp } from "../support/evidence.js"
import { setup, TENANT } from "../support/sessions.js"

describe("cached-session-survives-revocation", () => {
  it("refuses a revoked session on the very next request, after it had just been allowed", async () => {
    const { sessions, store } = setup()
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password(), totp()],
    })
    expect((await sessions.require(TENANT, issued.token, "default")).outcome).toBe("allow")
    await store.revokeByOwner(TENANT, "session", "acct-1", T0)
    expect(await sessions.require(TENANT, issued.token, "default")).toEqual({
      outcome: "unauthenticated",
    })
  })

  it("lets a revoked token mint nothing: no rotation, step-up, credential change, list or revoke", async () => {
    const { sessions } = setup()
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password(), totp()],
    })
    const other = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password(), totp()],
    })
    const challenge = await sessions.beginStepUp(TENANT, issued.token)
    await sessions.signOut(TENANT, issued.token)
    expect(await sessions.beginStepUp(TENANT, issued.token)).toBeNull()
    expect(await sessions.rotate(TENANT, issued.token)).toBeNull()
    expect(await sessions.stepUp(TENANT, issued.token, challenge ?? "", hardwareKey())).toBeNull()
    expect(await sessions.credentialChanged(TENANT, issued.token)).toBeNull()
    expect(await sessions.list(TENANT, issued.token)).toBeNull()
    expect(await sessions.revoke(TENANT, issued.token, other.id)).toBe(false)
    expect(await sessions.read(TENANT, other.token)).not.toBeNull()
  })
})
