// Attack: a TOTP code is used twice in its time step.
// Stopped by: the last accepted step is stored with a compare-and-set; an equal or earlier step is refused (ADR 0027).
import { describe, expect, it } from "vitest"
import { verifyTotp } from "../../src/methods/totp/method.js"
import { TOTP_STEP_MS } from "../../src/methods/totp/totp.js"
import { codeAt, enrol, totpDeps } from "../support/totp.js"

describe("totp-code-replay", () => {
  it("refuses the same code a second time within its step", async () => {
    const d = totpDeps()
    const { secret } = await enrol(d)
    d.clock.advance(TOTP_STEP_MS)
    const code = await codeAt(secret, d.clock.now())
    expect(await verifyTotp(d, { tenant: "t", accountId: "a", code })).toMatchObject({ ok: true })
    d.clock.advance(1_000)
    expect(await verifyTotp(d, { tenant: "t", accountId: "a", code })).toEqual({
      ok: false,
      reason: "replayed",
    })
  })

  it("refuses the confirming code at sign-in in the same step", async () => {
    const d = totpDeps()
    const { secret } = await enrol(d)
    expect(
      await verifyTotp(d, {
        tenant: "t",
        accountId: "a",
        code: await codeAt(secret, d.clock.now()),
      }),
    ).toEqual({
      ok: false,
      reason: "replayed",
    })
  })

  it("refuses an earlier step's code after a later one was accepted", async () => {
    const d = totpDeps()
    const { secret } = await enrol(d)
    d.clock.advance(2 * TOTP_STEP_MS)
    const earlier = await codeAt(secret, d.clock.now() - TOTP_STEP_MS)
    const later = await codeAt(secret, d.clock.now() + TOTP_STEP_MS)
    expect(await verifyTotp(d, { tenant: "t", accountId: "a", code: later })).toMatchObject({
      ok: true,
    })
    expect(await verifyTotp(d, { tenant: "t", accountId: "a", code: earlier })).toEqual({
      ok: false,
      reason: "replayed",
    })
  })

  it("lets exactly one of many concurrent requests with the same code succeed", async () => {
    const d = totpDeps()
    const { secret } = await enrol(d)
    d.clock.advance(TOTP_STEP_MS)
    const code = await codeAt(secret, d.clock.now())
    const results = await Promise.all(
      Array.from({ length: 12 }, () => verifyTotp(d, { tenant: "t", accountId: "a", code })),
    )
    expect(results.filter((result) => result.ok)).toHaveLength(1)
    expect(results.filter((result) => !result.ok)).toEqual(
      Array.from({ length: 11 }, () => ({ ok: false, reason: "replayed" })),
    )
  })
})
