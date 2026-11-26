// ADR 0007 §1 and §4, ADR 0002: what partial failure and parallel requests leave behind in recovery. A redeemed code
// and the recovery-only session it starts commit together, and so do a recovery's new password and the session's
// rotation; without store transactions the order of the writes keeps every failure closed. An account holds one live
// set of codes, so of two parallel requests for a new set exactly one gets codes.
import { describe, expect, it } from "vitest"
import { PASSWORD_COLLECTION } from "../../src/methods/password/method.js"
import { SESSION_COLLECTION } from "../../src/sessions/sessions.js"
import { memoryStore } from "../../src/store/memory.js"
import {
  aal2,
  brief,
  Browser,
  ENABLE_MFA,
  expectOk,
  hookedStore,
  inProcess,
  plainRequest,
  type Reply,
  seedAccount,
  seedSession,
  TENANT,
  testAuth,
} from "../support/auth.js"
import { faultyStore, type StoreOperation } from "../support/faulty-store.js"
import { within } from "../support/within.js"

const NEW_PASSWORD = "a new passphrase for ada"

/** The `Set-Cookie` lines of a reply that set a session token (a clearing line sets none). */
function sessionCookies(reply: Reply): string[] {
  return reply.headers
    .getSetCookie()
    .filter((line) => line.startsWith("__Host-test-cap=") && !line.includes("Max-Age=0"))
}

/**
 * An enrolled account over a faulty store: a signed-in browser that made a set of codes, a second signed-in session,
 * and a fresh browser to recover from.
 */
async function recoverable(transactional: boolean) {
  const faulty = faultyStore({ transactional })
  const setup = testAuth({ store: faulty.store })
  const { subject } = await seedAccount(setup, { password: true, totp: true })
  const { browser } = await seedSession(setup, { subject, evidence: aal2(setup.clock) })
  const codes = ((await expectOk(browser.post("/auth/recovery-codes"))).json as { codes: string[] })
    .codes
  const other = await seedSession(setup, { subject, evidence: aal2(setup.clock) })
  const recoverer = new Browser(inProcess(setup.auth))
  await recoverer.start()
  const redeem = (code: string) =>
    recoverer.post("/auth/recovery", { identifier: "ada@example.com", code })
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
  /** The account's sessions no revocation reached. */
  const standing = async () =>
    (await faulty.base.listByOwner(TENANT, SESSION_COLLECTION, subject)).filter(
      (record) => record.revokedAt === null && !("rotatedAt" in (record.data as object)),
    )
  const password = async () => (await faulty.base.get(TENANT, PASSWORD_COLLECTION, subject))?.data
  return { faulty, setup, subject, codes, other, recoverer, redeem, outcomeOf, standing, password }
}

type Position = { readonly op: StoreOperation; readonly call: number }

/**
 * The calls of a successful run from the first call `from` matches to the first later call `to` matches, each as
 * (operation, n-th call of that operation since `arm`).
 */
function between(
  trace: readonly { readonly op: StoreOperation; readonly target: string }[],
  from: (call: { op: StoreOperation; target: string }) => boolean,
  to: (call: { op: StoreOperation; target: string }) => boolean,
): Position[] {
  const start = trace.findIndex(from)
  const end = trace.findIndex((call, index) => index > start && to(call))
  expect([start >= 0, end > start]).toEqual([true, true])
  return trace.slice(start, end + 1).map(({ op }, offset) => ({
    op,
    call: trace.slice(0, start + offset + 1).filter((each) => each.op === op).length,
  }))
}

/** The calls of a redemption from spending the code through writing the new session. */
async function redemptionSteps(transactional: boolean): Promise<Position[]> {
  const r = await recoverable(transactional)
  r.faulty.arm()
  await expectOk(r.redeem(r.codes[0] as string))
  r.faulty.heal()
  return between(
    r.faulty.trace(),
    (call) => call.op === "consumeOnce" && call.target === "recovery-code",
    (call) => call.op === "createUnique" && call.target === SESSION_COLLECTION,
  )
}

describe("redeeming a code when the store fails part way", () => {
  it("leaves the code unspent and every session as it was, at each step, with transactions", async () => {
    const steps = await redemptionSteps(true)
    expect(steps.length).toBeGreaterThanOrEqual(4)
    for (const step of steps) {
      const r = await recoverable(true)
      r.faulty.arm({ ...step, mode: "reject" })
      const reply = await within(r.redeem(r.codes[0] as string))
      r.faulty.heal()
      expect([step, reply.status, sessionCookies(reply)]).toEqual([step, 500, []])
      expect([step, await r.outcomeOf(r.other.token)]).toEqual([step, "allow"])
      const again = await r.redeem(r.codes[0] as string)
      expect([step, again.status]).toEqual([step, 200])
    }
  })

  it("starts no recovery-only session at any step without transactions, and a spent code stays spent", async () => {
    const steps = await redemptionSteps(false)
    for (const [index, step] of steps.entries()) {
      const r = await recoverable(false)
      r.faulty.arm({ ...step, mode: "reject" })
      const reply = await within(r.redeem(r.codes[0] as string))
      r.faulty.heal()
      expect([step, reply.status, sessionCookies(reply)]).toEqual([step, 500, []])
      const recovering = (await r.standing()).filter(
        (record) => (record.data as { state: string }).state === "recovery-only",
      )
      expect([step, recovering]).toEqual([step, []])
      // The first step is the spend itself: a refused spend leaves the code for a later try.
      const again = await r.redeem(r.codes[0] as string)
      expect([step, again.status]).toEqual([step, index === 0 ? 200 : 401])
    }
  })
})

/** The calls of a recovery's password change from claiming the session through revoking the account's others. */
async function passwordSteps(transactional: boolean): Promise<Position[]> {
  const r = await recoverable(transactional)
  await expectOk(r.redeem(r.codes[0] as string))
  r.faulty.arm()
  await expectOk(r.recoverer.post("/auth/password", { password: NEW_PASSWORD }))
  r.faulty.heal()
  return between(
    r.faulty.trace(),
    (call) => call.op === "update" && call.target === PASSWORD_COLLECTION,
    (call) => call.op === "revokeByOwner" && call.target === SESSION_COLLECTION,
  )
}

describe("a recovery's new password when the store fails part way", () => {
  it("keeps the old password at each step after the password is written, with transactions", async () => {
    const steps = await passwordSteps(true)
    expect(steps.length).toBeGreaterThanOrEqual(4)
    for (const step of steps) {
      const r = await recoverable(true)
      await expectOk(r.redeem(r.codes[0] as string))
      const before = await r.password()
      r.faulty.arm({ ...step, mode: "reject" })
      const reply = await within(r.recoverer.post("/auth/password", { password: NEW_PASSWORD }))
      r.faulty.heal()
      expect([step, reply.status, sessionCookies(reply)]).toEqual([step, 500, []])
      expect([step, await r.password()]).toEqual([step, before])
      expect([step, await r.standing()]).toEqual([step, []])
    }
  })

  it("leaves no session of the account standing at any step without transactions", async () => {
    const steps = await passwordSteps(false)
    for (const step of steps) {
      const r = await recoverable(false)
      await expectOk(r.redeem(r.codes[0] as string))
      r.faulty.arm({ ...step, mode: "reject" })
      const reply = await within(r.recoverer.post("/auth/password", { password: NEW_PASSWORD }))
      r.faulty.heal()
      expect([step, reply.status, sessionCookies(reply)]).toEqual([step, 500, []])
      expect([step, await r.standing()]).toEqual([step, []])
    }
  })

  it("writes no password when the session is signed out while the password is hashed", async () => {
    const base = memoryStore()
    const armed: { subject: string | null } = { subject: null }
    // The first transaction after the hash is the change itself; before it, another request signs the account out.
    const store = new Proxy(base, {
      get(target, property, receiver) {
        const value = Reflect.get(target, property, receiver) as unknown
        if (property !== "transaction") return value
        return async (run: (ops: unknown) => Promise<unknown>) => {
          if (armed.subject !== null) {
            await base.revokeByOwner(TENANT, SESSION_COLLECTION, armed.subject, 0)
            armed.subject = null
          }
          return (value as (r: typeof run) => Promise<unknown>).call(target, run)
        }
      },
    })
    const setup = testAuth({ store })
    const { subject } = await seedAccount(setup, { password: true, totp: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal2(setup.clock) })
    const [code] = (
      (await expectOk(browser.post("/auth/recovery-codes"))).json as { codes: string[] }
    ).codes as [string]
    const recoverer = new Browser(inProcess(setup.auth))
    await recoverer.start()
    await expectOk(recoverer.post("/auth/recovery", { identifier: "ada@example.com", code }))
    const before = (await base.get(TENANT, PASSWORD_COLLECTION, subject))?.data
    armed.subject = subject
    const reply = await recoverer.post("/auth/password", { password: NEW_PASSWORD })
    expect([reply.status, reply.text]).toEqual([401, '{"error":"unauthenticated"}'])
    expect((await base.get(TENANT, PASSWORD_COLLECTION, subject))?.data).toEqual(before)
  })
})

describe("two requests for a new set at once", () => {
  it("gives codes to exactly one; the other is refused and signs the account out, and only the winner's codes work", async () => {
    let reached = (): void => undefined
    const arrived = new Promise<void>((resolve) => {
      reached = resolve
    })
    let release = (): void => undefined
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    let holds = 1
    // The first request waits while it stores its codes, before its switch commits, until the second has finished.
    // (Holding inside the switch would hold the store's one transaction, which the second request needs.)
    const store = hookedStore(memoryStore(), async (operation, args) => {
      const collection =
        operation === "createUnique" ? (args[1] as { collection: string }).collection : args[1]
      if (operation !== "createUnique" || collection !== "recovery-code") return
      if (holds === 0) return
      holds -= 1
      reached()
      await gate
    })
    const setup = testAuth({ store })
    const { subject } = await seedAccount(setup, { password: true, totp: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal2(setup.clock) })
    const first = browser.post("/auth/recovery-codes")
    await within(arrived)
    const from = setup.events.length
    const second = await within(browser.post("/auth/recovery-codes"))
    release()
    const loser = await within(first)
    expect(second.status).toBe(200)
    // The winner rotated the session first, so the loser's change failed closed: every session was revoked.
    expect([loser.status, loser.text]).toEqual([401, '{"error":"unauthenticated"}'])
    const live = (await setup.store.listByOwner(TENANT, SESSION_COLLECTION, subject)).filter(
      (record) => record.revokedAt === null,
    )
    expect(live).toEqual([])
    expect(setup.events.slice(from).map(brief)).toEqual([
      { type: ENABLE_MFA, status: "Success", user: subject, factors: ["Recovery Code"] },
      {
        type: ENABLE_MFA,
        status: "Failure",
        user: subject,
        detail: "conflict",
        factors: ["Recovery Code"],
      },
    ])
    const [code] = (second.json as { codes: string[] }).codes as [string]
    const recoverer = new Browser(inProcess(setup.auth))
    await recoverer.start()
    await expectOk(recoverer.post("/auth/recovery", { identifier: "ada@example.com", code }))
  })
})
