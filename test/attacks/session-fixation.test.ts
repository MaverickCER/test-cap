// Attack: a token planted before sign-in, or a pre-auth token, stays valid after authentication.
// Stopped by: the token rotates on every change of trust, including the end of enrolment and of the recovery-only
// state; unknown tokens are never adopted (ADR 0006).
import { describe, expect, it } from "vitest"
import { randomToken, sequenceRandom } from "../../src/core/clock.js"
import { password, totp } from "../support/evidence.js"
import { setup, TENANT } from "../support/sessions.js"

describe("session-fixation", () => {
  it("never adopts a token the client chose", async () => {
    const { sessions } = setup()
    const planted = randomToken(sequenceRandom([42]))
    const issued = await sessions.signIn(TENANT, planted, {
      subject: "acct-1",
      evidence: [password(), totp()],
    })
    expect(issued.token).not.toBe(planted)
    expect(await sessions.require(TENANT, planted, "profile.read")).toEqual({
      outcome: "unauthenticated",
    })
  })

  it("revokes a real session planted in the victim's browser when the victim signs in", async () => {
    const { sessions } = setup()
    const attacker = await sessions.signIn(TENANT, null, {
      subject: "acct-2",
      evidence: [password()],
    })
    const victim = await sessions.signIn(TENANT, attacker.token, {
      subject: "acct-1",
      evidence: [password(), totp()],
    })
    expect(await sessions.read(TENANT, attacker.token)).toBeNull()
    expect((await sessions.read(TENANT, victim.token))?.state.subject).toBe("acct-1")
    const planted = await sessions.begin(TENANT, null, { subject: "acct-2", state: "pre-auth" })
    await sessions.begin(TENANT, planted.token, { subject: "acct-1", state: "recovery-only" })
    expect(await sessions.read(TENANT, planted.token)).toBeNull()
  })

  it("stops a pre-auth token working once enrolment ends", async () => {
    const { sessions } = setup()
    const preAuth = await sessions.begin(TENANT, null, {
      subject: "acct-1",
      state: "pre-auth",
      evidence: [password()],
    })
    const done = await sessions.completeEnrolment(TENANT, preAuth.token, [totp()])
    expect(done?.token).not.toBe(preAuth.token)
    expect(await sessions.require(TENANT, preAuth.token, "default")).toEqual({
      outcome: "unauthenticated",
    })
  })

  it("stops a recovery-only token working once recovery ends", async () => {
    const { sessions } = setup()
    const recovering = await sessions.begin(TENANT, null, {
      subject: "acct-1",
      state: "recovery-only",
    })
    await sessions.endRecovery(TENANT, recovering.token)
    expect(await sessions.require(TENANT, recovering.token, "profile.read")).toEqual({
      outcome: "unauthenticated",
    })
  })
})
