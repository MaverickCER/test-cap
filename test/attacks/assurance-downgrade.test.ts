// Attack: forcing a weaker method still satisfies a requirement.
// Stopped by: the level comes from the evidence produced, so a weaker method yields `step-up` (ADR 0005).
import { describe, expect, it } from "vitest"
import { passkey, password, totp } from "../support/evidence.js"
import { setup, stepUp, TENANT } from "../support/sessions.js"

describe("assurance-downgrade", () => {
  it("asks a password plus TOTP session for phishing resistance on a phishing-resistant requirement", async () => {
    const { sessions } = setup()
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password(), totp()],
    })
    expect(await sessions.require(TENANT, issued.token, "keys.rotate")).toMatchObject({
      outcome: "step-up",
      missing: [{ kind: "phishing-resistance" }],
    })
  })

  it("asks for AAL3 when a synced passkey or an unverified key is offered in place of a hardware key", async () => {
    const { sessions } = setup()
    for (const weaker of [
      passkey({ attestationVerified: true }),
      passkey({ userVerified: false }),
    ]) {
      const issued = await sessions.signIn(TENANT, null, { subject: "acct-1", evidence: [weaker] })
      expect((await sessions.require(TENANT, issued.token, "admin.root")).outcome).toBe("step-up")
    }
  })

  it("keeps step-up when the step-up itself uses a weaker method", async () => {
    const { sessions } = setup()
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password(), totp()],
    })
    const next = await stepUp(sessions, issued.token, totp({ authenticatorId: "totp-2" }))
    expect((await sessions.require(TENANT, next?.token ?? null, "keys.rotate")).outcome).toBe(
      "step-up",
    )
  })
})
