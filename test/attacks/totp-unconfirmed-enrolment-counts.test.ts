// Attack: a TOTP secret counts as an authenticator before one valid code confirms it.
// Stopped by: unconfirmed secrets produce no evidence and are not shown again (ADR 0027, 0005).
import { describe, expect, it } from "vitest"
import { beginTotpEnrolment, verifyTotp } from "../../src/methods/totp/method.js"
import { codeAt, totpDeps } from "../support/totp.js"

describe("totp-unconfirmed-enrolment-counts", () => {
  it("produces no evidence from an unconfirmed secret, even with a correct code", async () => {
    const d = totpDeps()
    const { secret } = await beginTotpEnrolment(d, { tenant: "t", accountId: "a" })
    expect(
      await verifyTotp(d, {
        tenant: "t",
        accountId: "a",
        code: await codeAt(secret, d.clock.now()),
      }),
    ).toEqual({
      ok: false,
      reason: "invalid",
    })
  })

  it("returns the secret once: a second enrolment draws a new one and nothing reads the first back", async () => {
    const d = totpDeps()
    const first = await beginTotpEnrolment(d, { tenant: "t", accountId: "a" })
    const second = await beginTotpEnrolment(d, { tenant: "t", accountId: "a" })
    expect(second.authenticatorId).not.toBe(first.authenticatorId)
    expect(second.secret).not.toBe(first.secret)
  })
})
