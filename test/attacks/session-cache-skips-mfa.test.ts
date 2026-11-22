// Attack: a cached session state counts as signed in before the second factor completes (BA GHSA-xg6x-h9c9-2m83).
// Stopped by: no cached session skips the assurance check; a step-up-pending session gets `step-up` (ADR 0006, 0005).
import { describe, expect, it } from "vitest"
import { password, T0, totp } from "../support/evidence.js"
import { setup, stepUp, TENANT } from "../support/sessions.js"

describe("session-cache-skips-mfa", () => {
  it("keeps answering step-up for a password-only session however often it is read", async () => {
    const { sessions } = setup()
    const pending = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password()],
    })
    for (let request = 0; request < 5; request += 1) {
      expect(await sessions.require(TENANT, pending.token, "default")).toMatchObject({
        outcome: "step-up",
        missing: [{ kind: "level", level: "AAL2" }],
      })
    }
  })

  it("allows only the rotated token after the second factor, and the pre-MFA token never", async () => {
    const { sessions } = setup()
    const pending = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password()],
    })
    const done = await stepUp(sessions, pending.token, totp({ at: T0 }))
    expect(await sessions.require(TENANT, done?.token ?? null, "default")).toMatchObject({
      outcome: "allow",
    })
    expect(await sessions.require(TENANT, pending.token, "default")).toEqual({
      outcome: "unauthenticated",
    })
  })

  it("answers enroll, not allow, for a session that has not finished enrolling MFA", async () => {
    const { sessions } = setup()
    const enrolling = await sessions.begin(TENANT, null, {
      subject: "acct-1",
      state: "pre-auth",
      evidence: [password(), totp()],
    })
    expect(await sessions.require(TENANT, enrolling.token, "profile.read")).toEqual({
      outcome: "enroll",
    })
  })
})
