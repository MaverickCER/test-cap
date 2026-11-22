// Dependency: the clock (specs/dependency-failures.md, "The clock"; ADR 0003, ADR 0026 §4, ADR 0029). Outside test
// mode it is the system clock, so its failure is a jump. Policy: fail closed. A forward jump ends sessions and
// refuses codes, tokens and challenges early; a backward jump makes evidence dated in the future count for nothing
// and refuses every TOTP step at or before the last one accepted. A read that finds a session past a limit revokes it,
// so a later backward jump cannot give it back the rest of its window (L-1, fixed).
import { describe, expect, it } from "vitest"
import { parseKeyRing } from "../../src/core/mode.js"
import { verifyTotp } from "../../src/methods/totp/method.js"
import { systemRandom } from "../../src/core/clock.js"
import { SESSION_COLLECTION } from "../../src/sessions/sessions.js"
import {
  aal1,
  aal2,
  ENV,
  plainRequest,
  seedAccount,
  seedSession,
  TENANT,
  testAuth,
} from "../support/auth.js"
import { HOUR, MINUTE } from "../support/evidence.js"
import { faultyStore } from "../support/faulty-store.js"
import { codeAt } from "../support/totp.js"

/** When the one session of the seeded account was revoked; `null` while it stands. */
async function revokedAt(setup: ReturnType<typeof testAuth>): Promise<number | null> {
  const records = await setup.store.listByOwner(TENANT, SESSION_COLLECTION, "acct-1")
  expect(records).toHaveLength(1)
  return records[0]?.revokedAt ?? null
}

/** The `require` outcome and the level of the session `token` names, at the clock's current time. */
async function standing(setup: ReturnType<typeof testAuth>, token: string) {
  const request = () =>
    plainRequest({ method: "GET", path: "/", headers: [["Cookie", `__Host-test-cap=${token}`]] })
  const session = await setup.auth.session(request())
  const { outcome } = await setup.auth.require(request(), "default")
  return { outcome, level: session?.level ?? null }
}

describe("a clock that jumps backwards", () => {
  it("counts evidence dated after the new time for nothing, so an AAL2 session answers unauthenticated", async () => {
    const setup = testAuth()
    const { token } = await seedSession(setup, { evidence: aal2(setup.clock) })
    expect(await standing(setup, token)).toEqual({ outcome: "allow", level: "AAL2" })
    setup.clock.advance(-MINUTE)
    expect(await standing(setup, token)).toEqual({ outcome: "unauthenticated", level: null })
  })

  it("refuses the code of every TOTP step at or before the last one accepted", async () => {
    const setup = testAuth()
    const { subject, secret } = await seedAccount(setup, { totp: true })
    const deps = {
      clock: setup.clock,
      random: systemRandom,
      store: setup.store,
      keyRing: parseKeyRing("AUTH_ENCRYPTION_KEY", ENV.AUTH_ENCRYPTION_KEY).keys,
    }
    const verify = async () =>
      verifyTotp(deps, {
        tenant: TENANT,
        accountId: subject,
        code: await codeAt(String(secret), setup.clock.now()),
      })
    expect((await verify()).ok).toBe(true)
    setup.clock.advance(-5 * MINUTE)
    expect(await verify()).toEqual({ ok: false, reason: "replayed" })
  })

  it.each([
    { limit: "idle", keepAlive: [], jump: 2 * HOUR },
    // Read every 50 minutes, the session never idles out, and ends 24 hours after sign-in.
    { limit: "absolute", keepAlive: Array<number>(28).fill(50 * MINUTE), jump: 50 * MINUTE },
  ])(
    "revokes a session a read finds past its $limit limit, so a jump back cannot revive it (L-1, fixed)",
    async ({ keepAlive, jump }) => {
      const setup = testAuth()
      const { token } = await seedSession(setup, { evidence: aal2(setup.clock) })
      for (const step of keepAlive) {
        setup.clock.advance(step)
        expect(await standing(setup, token)).toEqual({ outcome: "allow", level: "AAL2" })
      }
      setup.clock.advance(jump)
      expect(await standing(setup, token)).toEqual({ outcome: "unauthenticated", level: null })
      expect(await revokedAt(setup)).toBe(setup.clock.now())
      setup.clock.advance(-90 * MINUTE)
      expect(await standing(setup, token)).toEqual({ outcome: "unauthenticated", level: null })
    },
  )

  it.each(["throw", "reject", "timeout"] as const)(
    "answers unauthenticated when the revoke of a session found expired fails by %s, and the next read revokes it",
    async (mode) => {
      const faulty = faultyStore()
      const setup = testAuth({ store: faulty.store })
      const { token } = await seedSession(setup, { evidence: aal2(setup.clock) })
      setup.clock.advance(2 * HOUR)
      faulty.arm({ op: "revoke", call: 1, mode })
      const request = plainRequest({
        method: "GET",
        path: "/",
        headers: [["Cookie", `__Host-test-cap=${token}`]],
      })
      expect(await setup.auth.session(request)).toBeNull()
      faulty.heal()
      expect(faulty.fired()).toBe(true)
      expect(await revokedAt(setup)).toBeNull()
      expect(await standing(setup, token)).toEqual({ outcome: "unauthenticated", level: null })
      expect(await revokedAt(setup)).toBe(setup.clock.now())
    },
  )
})

describe("a clock that jumps forwards", () => {
  it("ends the session at once when the jump passes its idle limit", async () => {
    const setup = testAuth()
    const { token } = await seedSession(setup, { evidence: aal2(setup.clock) })
    setup.clock.advance(HOUR)
    expect(await standing(setup, token)).toEqual({ outcome: "unauthenticated", level: null })
  })

  it("refuses the code the person's app shows for the real time", async () => {
    const setup = testAuth()
    const { subject, secret } = await seedAccount(setup, { password: true, totp: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    const code = await codeAt(String(secret), setup.clock.now())
    setup.clock.advance(5 * MINUTE)
    const reply = await browser.post("/auth/totp/verify", { code })
    expect([reply.status, reply.text]).toEqual([401, '{"error":"invalid-code"}'])
  })

  it("expires the synchronizer token, so a state-changing request is refused", async () => {
    const setup = testAuth()
    const { browser } = await seedSession(setup, { evidence: aal2(setup.clock) })
    setup.clock.advance(HOUR)
    const reply = await browser.post("/auth/sign-out")
    expect([reply.status, reply.text]).toEqual([403, '{"error":"csrf"}'])
  })

  it("expires a step-up challenge past its 10 minutes, adding no evidence", async () => {
    const setup = testAuth()
    const { subject, secret } = await seedAccount(setup, { password: true, totp: true })
    const { browser, token } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    const started = await browser.post("/auth/step-up/start")
    const { challenge } = started.json as { challenge: string }
    setup.clock.advance(10 * MINUTE)
    await browser.start()
    const code = await codeAt(String(secret), setup.clock.now())
    const reply = await browser.post("/auth/step-up", { challenge, code })
    expect([reply.status, reply.text]).toEqual([403, '{"error":"invalid-challenge"}'])
    expect(await standing(setup, token)).toEqual({ outcome: "step-up", level: "AAL1" })
  })
})
