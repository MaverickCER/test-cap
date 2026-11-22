// Attack: evidence from a step-up ceremony is applied to a different session.
// Stopped by: the step-up challenge is bound to the session that asked for it; the token rotates on success
// (ADR 0005, 0006).
import { describe, expect, it } from "vitest"
import { hardwareKey, MINUTE, password, totp } from "../support/evidence.js"
import { sequenceRandom, setup, TENANT } from "../support/sessions.js"

describe("step-up-bound-to-other-session", () => {
  it("refuses a challenge another session asked for, and leaves it usable by its own session", async () => {
    const { sessions } = setup()
    const victim = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password()],
    })
    const attacker = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password()],
    })
    const challenge = (await sessions.beginStepUp(TENANT, victim.token)) ?? ""
    expect(await sessions.stepUp(TENANT, attacker.token, challenge, totp())).toBeNull()
    expect((await sessions.require(TENANT, attacker.token, "default")).outcome).toBe("step-up")
    const next = await sessions.stepUp(TENANT, victim.token, challenge, totp())
    expect(next?.token).not.toBe(victim.token)
    expect((await sessions.require(TENANT, next?.token ?? null, "default")).outcome).toBe("allow")
  })

  it("uses each challenge once, and never after 10 minutes", async () => {
    const { sessions, clock } = setup()
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password(), totp()],
    })
    const once = (await sessions.beginStepUp(TENANT, issued.token)) ?? ""
    const next = await sessions.stepUp(TENANT, issued.token, once, hardwareKey())
    expect(await sessions.stepUp(TENANT, next?.token ?? "", once, hardwareKey())).toBeNull()
    const late = (await sessions.beginStepUp(TENANT, next?.token ?? "")) ?? ""
    clock.advance(10 * MINUTE - 1)
    const early = (await sessions.beginStepUp(TENANT, next?.token ?? "")) ?? ""
    clock.advance(1)
    expect(await sessions.stepUp(TENANT, next?.token ?? "", late, hardwareKey())).toBeNull()
    expect(await sessions.stepUp(TENANT, next?.token ?? "", early, hardwareKey())).not.toBeNull()
  })

  it("refuses a challenge id the store never issued", async () => {
    const { sessions } = setup()
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password()],
    })
    expect(await sessions.stepUp(TENANT, issued.token, "made-up", totp())).toBeNull()
    expect(await sessions.stepUp(TENANT, issued.token, "", totp())).toBeNull()
    expect(await sessions.stepUp(TENANT, issued.token, "A".repeat(22), totp())).toBeNull()
  })

  it("refuses to open a challenge that collides with a stored one, which only a broken random source causes", async () => {
    const { sessions } = setup({ random: sequenceRandom([7]) })
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password()],
    })
    await sessions.beginStepUp(TENANT, issued.token)
    await expect(sessions.beginStepUp(TENANT, issued.token)).rejects.toThrow(
      "A new step-up challenge collided with a stored one; the random source is broken.",
    )
  })
})
