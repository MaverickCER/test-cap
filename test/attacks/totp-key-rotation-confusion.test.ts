// Attack: a seed encrypted under a retired or mismatched key id is accepted after rotation.
// Stopped by: each ciphertext carries its key id; retired ids are refused after re-encryption (ADR 0027, 0022).
import { describe, expect, it } from "vitest"
import { TOTP_COLLECTION, verifyTotp } from "../../src/methods/totp/method.js"
import { TOTP_STEP_MS } from "../../src/methods/totp/totp.js"
import { codeAt, enrol, ringKey, totpDeps } from "../support/totp.js"

describe("totp-key-rotation-confusion", () => {
  it("refuses a seed whose key id has been retired from the ring", async () => {
    const old = ringKey("old", 2)
    const d = totpDeps({ keyRing: [old] })
    const { secret } = await enrol(d)
    d.clock.advance(TOTP_STEP_MS)
    const retired = { ...d, keyRing: [ringKey("new", 3)] }
    expect(
      await verifyTotp(retired, {
        tenant: "t",
        accountId: "a",
        code: await codeAt(secret, d.clock.now()),
      }),
    ).toEqual({
      ok: false,
      reason: "invalid",
    })
  })

  it("refuses a ciphertext relabelled with the current key id", async () => {
    const d = totpDeps({ keyRing: [ringKey("old", 2)] })
    const { authenticatorId, secret } = await enrol(d)
    const record = await d.store.get("t", TOTP_COLLECTION, authenticatorId)
    const data = record?.data as {
      confirmed: boolean
      lastStep: number
      secret: Record<string, string>
    }
    await d.store.update("t", TOTP_COLLECTION, authenticatorId, record?.version ?? 0, {
      data: { ...data, secret: { ...data.secret, keyId: "new" } },
    })
    d.clock.advance(TOTP_STEP_MS)
    const rotated = { ...d, keyRing: [ringKey("new", 3), ringKey("old", 2)] }
    expect(
      await verifyTotp(rotated, {
        tenant: "t",
        accountId: "a",
        code: await codeAt(secret, d.clock.now()),
      }),
    ).toEqual({
      ok: false,
      reason: "invalid",
    })
  })

  it("refuses a ciphertext swapped in from another account's row", async () => {
    const d = totpDeps()
    const victim = await enrol(d)
    const attacker = await (async () => {
      const { beginTotpEnrolment, confirmTotpEnrolment } =
        await import("../../src/methods/totp/method.js")
      const begun = await beginTotpEnrolment(d, { tenant: "t", accountId: "b" })
      await confirmTotpEnrolment(d, {
        tenant: "t",
        accountId: "b",
        authenticatorId: begun.authenticatorId,
        code: await codeAt(begun.secret, d.clock.now()),
      })
      return begun
    })()
    const attackerRecord = await d.store.get("t", TOTP_COLLECTION, attacker.authenticatorId)
    const victimRecord = await d.store.get("t", TOTP_COLLECTION, victim.authenticatorId)
    await d.store.update("t", TOTP_COLLECTION, victim.authenticatorId, victimRecord?.version ?? 0, {
      data: attackerRecord?.data ?? null,
    })
    d.clock.advance(TOTP_STEP_MS)
    expect(
      await verifyTotp(d, {
        tenant: "t",
        accountId: "a",
        code: await codeAt(attacker.secret, d.clock.now()),
      }),
    ).toEqual({ ok: false, reason: "invalid" })
  })
})
