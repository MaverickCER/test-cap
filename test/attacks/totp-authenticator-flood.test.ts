// Attack: a signed-in attacker enrols TOTP authenticators without end, or starts enrolments without end, so the
// account's authenticator list (which every TOTP verification reads) and the store grow until requests slow down.
// Stopped by: at most 5 confirmed TOTP authenticators per account, a sixth enrolment answering
// 409 too-many-authenticators; and a new enrolment replaces any unconfirmed one, so at most one waits (ADR 0027).
import { describe, expect, it } from "vitest"
import {
  beginTotpEnrolment,
  confirmTotpEnrolment,
  TOTP_COLLECTION,
  TOTP_MAX_AUTHENTICATORS,
  totpEnrolmentAllowed,
} from "../../src/methods/totp/method.js"
import { aal2, body, seedAccount, seedSession, TENANT, testAuth } from "../support/auth.js"
import { codeAt, totpDeps } from "../support/totp.js"

const account = { tenant: "t", accountId: "a" }

async function confirmed(d: ReturnType<typeof totpDeps>): Promise<void> {
  const begun = await beginTotpEnrolment(d, account)
  const result = await confirmTotpEnrolment(d, {
    ...account,
    authenticatorId: begun.authenticatorId,
    code: await codeAt(begun.secret, d.clock.now()),
  })
  if (!result.ok) throw new Error("enrolment did not confirm")
}

describe("totp-authenticator-flood", () => {
  it(`allows ${TOTP_MAX_AUTHENTICATORS} confirmed authenticators and no more`, async () => {
    const d = totpDeps()
    expect(TOTP_MAX_AUTHENTICATORS).toBe(5)
    for (let enrolled = 0; enrolled < TOTP_MAX_AUTHENTICATORS; enrolled += 1) {
      expect(await totpEnrolmentAllowed(d, account)).toBe(true)
      await confirmed(d)
    }
    expect(await totpEnrolmentAllowed(d, account)).toBe(false)
    // Another account is not affected.
    expect(await totpEnrolmentAllowed(d, { tenant: "t", accountId: "b" })).toBe(true)
  })

  it("counts a revoked authenticator no longer", async () => {
    const d = totpDeps()
    for (let enrolled = 0; enrolled < TOTP_MAX_AUTHENTICATORS; enrolled += 1) await confirmed(d)
    const [first] = await d.store.listByOwner("t", TOTP_COLLECTION, "a")
    await d.store.revoke("t", TOTP_COLLECTION, first?.key ?? "", d.clock.now())
    expect(await totpEnrolmentAllowed(d, account)).toBe(true)
  })

  it("keeps at most one unconfirmed enrolment, however many are begun", async () => {
    const d = totpDeps()
    await confirmed(d)
    for (let begun = 0; begun < 100; begun += 1) await beginTotpEnrolment(d, account)
    const records = await d.store.listByOwner("t", TOTP_COLLECTION, "a")
    const pending = records.filter(
      (record) => (record.data as { confirmed: boolean }).confirmed === false,
    )
    expect([records.length, pending.length]).toEqual([2, 1])
    // Unconfirmed enrolments never count towards the limit.
    expect(await totpEnrolmentAllowed(d, account)).toBe(true)
  })

  it("counts only confirmed authenticators: four and an enrolment waiting still leave room for a fifth", async () => {
    const d = totpDeps()
    for (let enrolled = 0; enrolled < TOTP_MAX_AUTHENTICATORS - 1; enrolled += 1) await confirmed(d)
    await beginTotpEnrolment(d, account)
    expect(await totpEnrolmentAllowed(d, account)).toBe(true)
  })

  it("passes over a record that is not a TOTP authenticator, neither counting nor removing it", async () => {
    const d = totpDeps()
    await d.store.createUnique("t", {
      collection: TOTP_COLLECTION,
      key: "odd",
      owner: "a",
      data: { x: 1 },
    })
    expect(await totpEnrolmentAllowed(d, account)).toBe(true)
    await beginTotpEnrolment(d, account)
    expect((await d.store.get("t", TOTP_COLLECTION, "odd"))?.data).toEqual({ x: 1 })
  })

  it("answers a sixth enrolment, by the API or the page, with 409 too-many-authenticators", async () => {
    const setup = testAuth()
    const { subject } = await seedAccount(setup, { password: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal2(setup.clock) })
    for (let enrolled = 0; enrolled < TOTP_MAX_AUTHENTICATORS; enrolled += 1) {
      const begun = body(await browser.post("/auth/totp/enrol")) as {
        authenticatorId: string
        secret: string
      }
      const reply = await browser.post("/auth/totp/confirm", {
        authenticatorId: begun.authenticatorId,
        code: await codeAt(begun.secret, setup.clock.now()),
      })
      expect(reply.status).toBe(200)
      setup.clock.advance(30_000)
    }
    const api = await browser.post("/auth/totp/enrol")
    expect([api.status, api.text]).toEqual([409, '{"error":"too-many-authenticators"}'])
    const page = await browser.send({
      method: "GET",
      path: "/auth/totp/enrol",
      headers: [["Accept", "text/html"]],
    })
    expect([page.status, page.text]).toEqual([409, '{"error":"too-many-authenticators"}'])
    expect(await setup.store.listByOwner(TENANT, TOTP_COLLECTION, subject)).toHaveLength(
      TOTP_MAX_AUTHENTICATORS,
    )
  })
})
