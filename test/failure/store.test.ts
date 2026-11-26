// Dependency: the app's store (specs/dependency-failures.md, "The store"; ADR 0002, ADR 0029).
// Policy: fail closed. A store call that throws, rejects, times out or hangs, at any point of any phase 3 flow, ends
// the request with the fixed 500 (or no reply at all) and never with a session, a higher level or a success reply.
import { describe, expect, it } from "vitest"
import { systemRandom } from "../../src/core/clock.js"
import {
  CONFIRMATION_COLLECTION,
  CONFIRMATION_LIFETIME_MS,
  redeemConfirmation,
} from "../../src/core/email.js"
import { parseKeyRing } from "../../src/core/mode.js"
import { SESSION_COLLECTION } from "../../src/sessions/sessions.js"
import { TOTP_COLLECTION } from "../../src/methods/totp/method.js"
import {
  aal2,
  Browser,
  confirmationCode,
  ENV,
  expectOk,
  inProcess,
  internalsOfAuth,
  ORIGIN,
  plainRequest,
  type Reply,
  seedAccount,
  seedSession,
  T0,
  TENANT,
  testAuth,
} from "../support/auth.js"
import { MINUTE } from "../support/evidence.js"
import { FLOWS, type Flow, type Standing } from "../support/failure-flows.js"
import {
  type Fault,
  type FaultMode,
  faultyStore,
  STORE_DOWN,
  type StoreOperation,
} from "../support/faulty-store.js"
import { codeAt } from "../support/totp.js"
import { within } from "../support/within.js"

/** The flows whose session change takes several store steps, so a store without transactions matters. */
const MULTI_STEP = new Set([
  "TOTP verification",
  "step-up",
  "TOTP enrolment by a signed-in account",
])

/** Each call of a profile as (operation, n-th call of that operation). */
function positions(profile: readonly StoreOperation[]): { op: StoreOperation; call: number }[] {
  return profile.map((op, index) => ({
    op,
    call: profile.slice(0, index + 1).filter((each) => each === op).length,
  }))
}

/** The first call of each operation a profile makes. */
function firstCalls(profile: readonly StoreOperation[]): { op: StoreOperation; call: number }[] {
  return [...new Set(profile)].map((op) => ({ op, call: 1 }))
}

const flowNamed = (name: string): Flow => FLOWS.find((flow) => flow.name === name) as Flow

/** How far a standing lets the browser in: no session, a session short of the default requirement, or allow. */
function reach(standing: Standing): number {
  if (standing.outcome === "allow") return 2
  return standing.outcome === "step-up" ? 1 : 0
}

const LEVELS = [null, "AAL1", "AAL2", "AAL3"]

/** The `Set-Cookie` lines of a reply that set a session token (a clearing line sets none). */
function sessionCookies(reply: Reply): string[] {
  return reply.headers
    .getSetCookie()
    .filter((line) => line.startsWith("__Host-test-cap=") && !line.includes("Max-Age=0"))
}

/** Runs `flow` with `fault` injected and checks the browser gained nothing. */
async function expectFailsClosed(name: string, fault: Fault, transactional = true): Promise<void> {
  const faulty = faultyStore({ transactional })
  const prepared = await flowNamed(name).prepare(faulty)
  faulty.arm(fault)
  const reply = await within(prepared.run())
  faulty.heal()
  expect(faulty.fired(), "the fault was injected").toBe(true)
  expect([reply.status, reply.text]).toEqual([500, '{"error":"internal"}'])
  expect(sessionCookies(reply)).toEqual([])
  const after = await prepared.standing()
  expect(reach(after)).toBeLessThanOrEqual(reach(prepared.before))
  expect(LEVELS.indexOf(after.session?.level ?? null)).toBeLessThanOrEqual(
    LEVELS.indexOf(prepared.before.session?.level ?? null),
  )
  // The session is the same one or none: a failure never moves the browser to another state.
  expect([prepared.before.session?.state, undefined]).toContain(after.session?.state)
}

const cases = (
  pick: (profile: readonly StoreOperation[]) => { op: StoreOperation; call: number }[],
  names: readonly string[] = FLOWS.map((flow) => flow.name),
) =>
  names.flatMap((name) => pick(flowNamed(name).profile).map(({ op, call }) => ({ name, op, call })))

describe("store failures in every phase 3 flow", () => {
  it.each(FLOWS.map((flow) => flow.name))(
    "%s calls exactly the documented store operations",
    async (name) => {
      for (const transactional of [true, false]) {
        const faulty = faultyStore({ transactional })
        const prepared = await flowNamed(name).prepare(faulty)
        faulty.arm()
        const reply = await prepared.run()
        faulty.heal()
        expect(reply.status).toBe(prepared.success.status)
        expect((reply.json as { outcome?: unknown }).outcome).toBe(prepared.success.outcome)
        expect(faulty.calls()).toEqual(flowNamed(name).profile)
      }
    },
  )

  it.each(cases(positions))(
    "$name: a rejected $op (call $call) answers 500 and grants nothing",
    async ({ name, op, call }) => {
      await expectFailsClosed(name, { op, call, mode: "reject" })
    },
  )

  it.each(cases(positions, [...MULTI_STEP]))(
    "$name without store transactions: a rejected $op (call $call) answers 500 and grants nothing",
    async ({ name, op, call }) => {
      await expectFailsClosed(name, { op, call, mode: "reject" }, false)
    },
  )

  it.each(
    cases(firstCalls).flatMap((each) =>
      (["throw", "timeout"] as const).map((mode) => ({ ...each, mode })),
    ),
  )(
    "$name: a $op that fails by $mode answers 500 and grants nothing",
    async ({ name, op, call, mode }) => {
      await expectFailsClosed(name, { op, call, mode })
    },
  )

  it.each(cases(firstCalls))(
    "$name: a $op that never answers leaves the request pending, with nothing issued",
    async ({ name, op, call }) => {
      const faulty = faultyStore()
      const prepared = await flowNamed(name).prepare(faulty)
      faulty.arm({ op, call, mode: "hang" satisfies FaultMode })
      let settled = false
      void prepared.run().finally(() => {
        settled = true
      })
      // Waits by real time, bounded, until the request reaches the hung call; then gives it time to answer anyway. A
      // request that answers before reaching the call stops the wait at once, so a mutant that ends the flow early
      // fails this test fast instead of spending the whole bound.
      for (const turn of Array.from({ length: 2_000 }, (_, index) => index)) {
        if (faulty.fired() || settled) break
        await new Promise((resolve) => setTimeout(resolve, 1, turn))
      }
      expect(faulty.fired()).toBe(true)
      await new Promise((resolve) => setTimeout(resolve, 20))
      expect(settled).toBe(false)
    },
  )
})

describe("reading a session while the store fails", () => {
  const READS = ["get", "update"] as const

  it.each(READS)(
    "rejects auth.require and auth.session, never answering, when %s fails",
    async (op) => {
      const faulty = faultyStore()
      const setup = testAuth({ store: faulty.store })
      const { token } = await seedSession(setup, { evidence: aal2(setup.clock) })
      const request = () =>
        plainRequest({
          method: "GET",
          path: "/",
          headers: [["Cookie", `__Host-test-cap=${token}`]],
        })
      faulty.arm({ op, call: 1, mode: "reject" })
      await expect(setup.auth.require(request(), "default")).rejects.toThrow(STORE_DOWN)
      faulty.arm({ op, call: 1, mode: "reject" })
      await expect(setup.auth.session(request())).rejects.toThrow(STORE_DOWN)
    },
  )

  it.each(READS)(
    "answers deny by default with the fixed 500, never letting the request through, when %s fails",
    async (op) => {
      const faulty = faultyStore()
      const setup = testAuth({ store: faulty.store })
      const { token } = await seedSession(setup, { evidence: aal2(setup.clock) })
      const head = plainRequest({
        method: "GET",
        path: "/billing",
        headers: [["Cookie", `__Host-test-cap=${token}`]],
      })
      faulty.arm({ op, call: 1, mode: "reject" })
      const decision = await internalsOfAuth(setup.auth).gate(head, () => false)
      expect(decision.kind).toBe("respond")
      const response = (decision as { response: { status: number; body: Uint8Array } }).response
      expect([response.status, new TextDecoder().decode(response.body)]).toEqual([
        500,
        '{"error":"internal"}',
      ])
    },
  )
})

describe("a store that answers no", () => {
  it("refuses the step-up when the challenge's single use reports it already taken", async () => {
    const faulty = faultyStore()
    const prepared = await flowNamed("step-up").prepare(faulty)
    faulty.arm({ op: "consumeOnce", call: 1, mode: "answer", answer: null })
    const reply = await prepared.run()
    expect([reply.status, reply.text]).toEqual([403, '{"error":"invalid-challenge"}'])
    faulty.heal()
    expect((await prepared.standing()).outcome).toBe("step-up")
  })

  it("refuses the code when the TOTP step's compare-and-set reports a conflict", async () => {
    const faulty = faultyStore()
    const prepared = await flowNamed("TOTP verification").prepare(faulty)
    faulty.arm({ op: "update", call: 2, mode: "answer", answer: "conflict" })
    const reply = await prepared.run()
    expect([reply.status, reply.text]).toEqual([401, '{"error":"invalid-code"}'])
    faulty.heal()
    expect((await prepared.standing()).outcome).toBe("step-up")
  })

  it("issues nothing when the rotation's claim reports a conflict", async () => {
    const faulty = faultyStore()
    const prepared = await flowNamed("TOTP verification").prepare(faulty)
    faulty.arm({ op: "update", call: 3, mode: "answer", answer: "conflict" })
    const reply = await prepared.run()
    expect([reply.status, reply.text]).toEqual([401, '{"error":"unauthenticated"}'])
    expect(sessionCookies(reply)).toEqual([])
  })

  it("refuses the email code when its single use reports it already taken", async () => {
    const faulty = faultyStore()
    const prepared = await flowNamed("email confirmation").prepare(faulty)
    faulty.arm({ op: "consumeOnce", call: 1, mode: "answer", answer: null })
    const reply = await prepared.run()
    expect([reply.status, reply.text]).toEqual([400, '{"error":"invalid-code"}'])
    faulty.heal()
    expect(await prepared.standing()).toEqual(prepared.before)
  })

  it("answers 500 when a new session's key reports as taken, adopting nothing", async () => {
    const faulty = faultyStore()
    const prepared = await flowNamed("password sign-in").prepare(faulty)
    faulty.arm({ op: "createUnique", call: 1, mode: "answer", answer: "exists" })
    const reply = await prepared.run()
    expect([reply.status, reply.text]).toEqual([500, '{"error":"internal"}'])
    expect(sessionCookies(reply)).toEqual([])
  })
})

describe("revocation while the store fails", () => {
  it("never answers a sign-out whose revoke failed as signed out, and a retry revokes", async () => {
    const faulty = faultyStore()
    const setup = testAuth({ store: faulty.store })
    const { browser, token } = await seedSession(setup, { evidence: aal2(setup.clock) })
    faulty.arm({ op: "revoke", call: 1, mode: "reject" })
    const failed = await browser.post("/auth/sign-out")
    faulty.heal()
    expect([failed.status, failed.text]).toEqual([500, '{"error":"internal"}'])
    expect(browser.cookies.get("__Host-test-cap")).toBe(token)
    const retried = await browser.post("/auth/sign-out")
    expect(retried.status).toBe(200)
    const request = plainRequest({
      method: "GET",
      path: "/",
      headers: [["Cookie", `__Host-test-cap=${token}`]],
    })
    expect(await setup.auth.require(request, "default")).toEqual({ outcome: "unauthenticated" })
  })

  it("never answers a remote revoke whose revoke failed as revoked", async () => {
    const faulty = faultyStore()
    const setup = testAuth({ store: faulty.store })
    const mine = await seedSession(setup, { evidence: aal2(setup.clock) })
    const other = await seedSession(setup, { evidence: aal2(setup.clock) })
    faulty.arm({ op: "revoke", call: 1, mode: "reject" })
    const failed = await mine.browser.post("/auth/sessions/revoke", { sessionId: other.id })
    faulty.heal()
    expect([failed.status, failed.text]).toEqual([500, '{"error":"internal"}'])
    const retried = await mine.browser.post("/auth/sessions/revoke", { sessionId: other.id })
    expect(retried.text).toBe('{"revoked":true}')
  })

  it("rejects auth.admin.revoke when the store fails, and revokes on a retry", async () => {
    const faulty = faultyStore()
    const setup = testAuth({ store: faulty.store })
    const { token } = await seedSession(setup, { subject: "acct-1", evidence: aal2(setup.clock) })
    faulty.arm({ op: "revokeByOwner", call: 1, mode: "reject" })
    await expect(setup.auth.admin.revoke("acct-1")).rejects.toThrow(STORE_DOWN)
    faulty.heal()
    expect(await setup.auth.admin.revoke("acct-1")).toBe(1)
    const stored = await faulty.base.listByOwner(TENANT, SESSION_COLLECTION, "acct-1")
    expect(stored.map((record) => record.revokedAt === null)).toEqual([false])
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/)
  })
})

describe("a credential change interrupted by the store (finding F-1, ADR 0029)", () => {
  /** A signed-in account with a second session, about to confirm a second TOTP authenticator. */
  async function changing(transactional: boolean) {
    const faulty = faultyStore({ transactional })
    const setup = testAuth({ store: faulty.store })
    const { subject } = await seedAccount(setup, { password: true, totp: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal2(setup.clock) })
    const other = await seedSession(setup, { subject, evidence: aal2(setup.clock) })
    const begun = await expectOk(browser.post("/auth/totp/enrol"))
    const { authenticatorId, secret } = begun.json as { authenticatorId: string; secret: string }
    const code = await codeAt(secret, setup.clock.now())
    const outcomeOf = async (token: string) =>
      (
        await setup.auth.require(
          plainRequest({
            method: "GET",
            path: "/",
            headers: [["Cookie", `__Host-test-cap=${token}`]],
          }),
          "default",
        )
      ).outcome
    const confirmed = async () =>
      (await faulty.base.listByOwner(TENANT, TOTP_COLLECTION, subject)).filter(
        (record) => (record.data as { confirmed?: unknown }).confirmed === true,
      ).length
    const confirm = () => browser.post("/auth/totp/confirm", { authenticatorId, code })
    return { faulty, browser, other, outcomeOf, confirmed, confirm }
  }

  /** The calls of the flow after its compare-and-set confirmed the new authenticator. */
  // Since phase 4 each session lookup also reads the account's status, so the rotation reads twice.
  const AFTER_CONFIRMATION = [
    { op: "get", call: 5 },
    { op: "get", call: 6 },
    { op: "update", call: 3 },
    { op: "createUnique", call: 1 },
    { op: "revoke", call: 1 },
    { op: "revokeByOwner", call: 1 },
  ] as const

  it.each(
    AFTER_CONFIRMATION.flatMap((each) =>
      [true, false].map((transactional) => ({ ...each, transactional })),
    ),
  )(
    "leaves no session of the account standing once the authenticator is confirmed and $op (call $call) fails, transactions: $transactional",
    async ({ op, call, transactional }) => {
      const change = await changing(transactional)
      change.faulty.arm({ op, call, mode: "reject" })
      const reply = await change.confirm()
      change.faulty.heal()
      expect([reply.status, reply.text]).toEqual([500, '{"error":"internal"}'])
      expect(await change.confirmed()).toBe(2)
      expect(await change.outcomeOf(change.other.token)).toBe("unauthenticated")
      expect(await change.outcomeOf(String(change.browser.cookies.get("__Host-test-cap")))).toBe(
        "unauthenticated",
      )
    },
  )

  it("leaves no session of the account standing when the rotation finds its session already claimed", async () => {
    const change = await changing(true)
    change.faulty.arm({ op: "update", call: 3, mode: "answer", answer: "conflict" })
    const reply = await change.confirm()
    change.faulty.heal()
    expect([reply.status, reply.text]).toEqual([401, '{"error":"unauthenticated"}'])
    expect(await change.confirmed()).toBe(2)
    expect(await change.outcomeOf(change.other.token)).toBe("unauthenticated")
  })

  it("changes nothing when the store fails before the authenticator is confirmed", async () => {
    const change = await changing(true)
    change.faulty.arm({ op: "update", call: 2, mode: "reject" })
    const reply = await change.confirm()
    change.faulty.heal()
    expect([reply.status, reply.text]).toEqual([500, '{"error":"internal"}'])
    expect(await change.confirmed()).toBe(1)
    expect(await change.outcomeOf(change.other.token)).toBe("allow")
  })
})

describe("the email code's kill at its attempt limit, when the store fails (finding F-2, fixed)", () => {
  /** A signed-up browser whose fifth wrong code was answered 500 because the store failed the write that kills the code. */
  async function killWriteFailed() {
    const faulty = faultyStore()
    const setup = testAuth({ store: faulty.store })
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    await expectOk(browser.post("/auth/sign-up", { identifier: "ada@example.com" }))
    const code = confirmationCode(setup.outbox, "ada@example.com")
    const wrong = code === "000000" ? "111111" : "000000"
    for (const attempt of [1, 2, 3, 4]) {
      const reply = await browser.post("/auth/email/confirm", { code: wrong })
      expect([attempt, reply.text]).toEqual([attempt, '{"error":"invalid-code"}'])
    }
    faulty.arm({ op: "revoke", call: 1, mode: "reject" })
    const fifth = await browser.post("/auth/email/confirm", { code: wrong })
    faulty.heal()
    expect([fifth.status, fifth.text]).toEqual([500, '{"error":"internal"}'])
    const session = await browser.get("/auth/session")
    const subject = (session.json as { session: { subject: string } }).session.subject
    const [record] = await setup.store.listByOwner(TENANT, CONFIRMATION_COLLECTION, subject)
    // The kill write failed: the code's record is still live.
    expect(record?.revokedAt).toBeNull()
    return { faulty, setup, browser, code, subject }
  }

  it("refuses the right code for the rest of the code's life, even though the kill write failed", async () => {
    const { setup, browser, code, subject } = await killWriteFailed()
    // The pre-auth session ends after 15 minutes idle, so a guesser keeps it alive past every 15-minute mark.
    for (const minutes of [14, 28, 42, 56]) {
      setup.clock.set(T0 + minutes * MINUTE)
      const reply = await browser.post("/auth/email/confirm", { code })
      expect([minutes, reply.status, reply.text]).toEqual([
        minutes,
        429,
        '{"error":"rate-limited"}',
      ])
    }
    // To its last millisecond, the code takes no further attempt.
    setup.clock.set(T0 + CONFIRMATION_LIFETIME_MS - 1)
    const deps = {
      store: setup.store,
      tenant: TENANT,
      clock: setup.clock,
      random: systemRandom,
      linkBase: `${ORIGIN}/auth`,
      sendEmail: () => Promise.resolve(),
      keyRing: parseKeyRing("AUTH_ENCRYPTION_KEY", ENV.AUTH_ENCRYPTION_KEY).keys,
    }
    expect(
      await redeemConfirmation(deps, { accountId: subject, address: "ada@example.com", code }),
    ).toEqual({ ok: false, reason: "rate-limited", retryAfterMs: 1 })
  })

  it("gives the old code no fresh guesses when a resend fails to revoke it, and a resend that works starts a new count", async () => {
    const { faulty, setup, browser, code } = await killWriteFailed()
    setup.clock.advance(MINUTE)
    faulty.arm({ op: "revokeByOwner", call: 1, mode: "reject" })
    const failed = await browser.post("/auth/email/resend")
    faulty.heal()
    expect([failed.status, failed.text]).toEqual([500, '{"error":"internal"}'])
    const old = await browser.post("/auth/email/confirm", { code })
    expect([old.status, old.text]).toEqual([429, '{"error":"rate-limited"}'])
    setup.clock.advance(MINUTE)
    await expectOk(browser.post("/auth/email/resend"))
    const fresh = confirmationCode(setup.outbox, "ada@example.com")
    // The new code's count starts at nothing: a wrong code is refused as wrong, not as one too many.
    const other = ["000000", "111111", "222222"].find((each) => ![code, fresh].includes(each))
    const guess = await browser.post("/auth/email/confirm", { code: other })
    expect([guess.status, guess.text]).toEqual([400, '{"error":"invalid-code"}'])
    const confirmed = await browser.post("/auth/email/confirm", { code: fresh })
    expect([confirmed.status, confirmed.text]).toEqual([200, '{"outcome":"enroll"}'])
  })
})
