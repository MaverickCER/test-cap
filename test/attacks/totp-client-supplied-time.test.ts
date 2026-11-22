// Attack: the client supplies the time a TOTP code is checked against.
// Stopped by: only the injected server clock is read (ADR 0027, 0003).
import { describe, expect, it } from "vitest"
import { verifyTotp } from "../../src/methods/totp/method.js"
import { TOTP_STEP_MS } from "../../src/methods/totp/totp.js"
import { codeAt, enrol, totpDeps } from "../support/totp.js"

describe("totp-client-supplied-time", () => {
  it("ignores any time field in the input and checks against the server clock", async () => {
    const d = totpDeps()
    const { secret } = await enrol(d)
    const past = d.clock.now() - 10 * TOTP_STEP_MS
    d.clock.advance(5 * TOTP_STEP_MS)
    const stale = await codeAt(secret, past)
    const input = {
      tenant: "t",
      accountId: "a",
      code: stale,
      time: past,
      now: past,
      timestamp: past,
    }
    expect(await verifyTotp(d, input)).toEqual({ ok: false, reason: "invalid" })
  })

  it("accepts a code only within one step of the server clock", async () => {
    const d = totpDeps()
    const { secret } = await enrol(d)
    d.clock.advance(10 * TOTP_STEP_MS)
    const twoAhead = await codeAt(secret, d.clock.now() + 2 * TOTP_STEP_MS)
    expect(await verifyTotp(d, { tenant: "t", accountId: "a", code: twoAhead })).toEqual({
      ok: false,
      reason: "invalid",
    })
    const oneAhead = await codeAt(secret, d.clock.now() + TOTP_STEP_MS)
    expect(await verifyTotp(d, { tenant: "t", accountId: "a", code: oneAhead })).toMatchObject({
      ok: true,
    })
  })
})
