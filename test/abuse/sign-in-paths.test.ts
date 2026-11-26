// The throttle and the stuffing detector at the routes (ADR 0009 §2 to §4), on their less travelled paths: a busy
// hashing queue counts nothing, a refused attempt is no evidence of stuffing, an app challenge keeps the free attempts,
// and the second factor is throttled per account.
import { describe, expect, it } from "vitest"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import { fixedClock } from "../../src/core/clock.js"
import { CREDENTIAL_CHANGE_WITHIN_MS } from "../../src/core/dispatcher.js"
import { HASH_CONCURRENCY, HASH_QUEUE_LIMIT, hashing } from "../../src/methods/password/argon2.js"
import {
  aal1,
  aal2,
  account,
  body,
  brief,
  Browser,
  ENABLE_MFA,
  inProcess,
  LOGON,
  PASSWORD,
  seedSession,
  testAuth,
} from "../support/auth.js"
import { codeAt } from "../support/totp.js"
import { within } from "../support/within.js"

/** Runs `work` while every argon2 slot and queue place is held, so each hash answers busy. */
async function whileBusy<T>(work: () => Promise<T>): Promise<T> {
  let release = (): void => undefined
  const gate = new Promise<void>((resolve) => {
    release = resolve
  })
  const held = Array.from({ length: HASH_CONCURRENCY + HASH_QUEUE_LIMIT }, () =>
    hashing.run(() => gate),
  )
  try {
    return await work()
  } finally {
    release()
    await Promise.all(held)
  }
}

async function signIn(
  setup: ReturnType<typeof testAuth>,
  identifier: string,
  password = "wrong password entirely",
  clientAddress = "192.0.2.10",
) {
  const browser = new Browser(inProcess(setup.auth))
  await browser.start()
  return browser.post("/auth/sign-in", { identifier, password }, { clientAddress })
}

const refuseEveryone = () => false

describe("what the sign-in throttle counts", () => {
  it("counts no attempt the busy hashing queue turned away", async () => {
    const setup = testAuth({ stuffing: { distinctAccounts: 3 }, challengeHook: refuseEveryone })
    await whileBusy(async () => {
      for (let i = 0; i < 8; i += 1) {
        expect((await signIn(setup, `user${String(i)}@example.com`)).status).toBe(503)
      }
    })
    // Neither throttled nor flagged: a wrong password is just a wrong password.
    expect((await signIn(setup, "user0@example.com")).status).toBe(401)
  })

  it("answers a new set of recovery codes the busy hashing queue turned away with 503, writing nothing", async () => {
    const setup = testAuth()
    const { subject } = await account(setup)
    const { browser } = await seedSession(setup, { subject, evidence: aal2(setup.clock) })
    const other = await seedSession(setup, { subject, evidence: aal2(setup.clock) })
    setup.events.length = 0
    const reply = await whileBusy(() => browser.post("/auth/recovery-codes"))
    expect([reply.status, reply.text]).toEqual([503, '{"error":"busy"}'])
    expect(setup.events.map(brief)).toEqual([
      {
        type: ENABLE_MFA,
        status: "Failure",
        user: subject,
        factors: ["Recovery Code"],
        detail: "busy",
      },
    ])
    // Nothing was switched or revoked: the other session lives, and a set can be made once the queue has room.
    expect(body(await other.browser.get("/auth/session"))["session"]).toMatchObject({ subject })
    expect((await browser.post("/auth/recovery-codes")).status).toBe(200)
  })

  it("passes on a hasher failure that is not a full queue while making recovery codes", async () => {
    const setup = testAuth({
      argon2Hasher: {
        hash: () => Promise.reject(new Error("hasher down")),
        verify: () => Promise.resolve(false),
      },
    })
    // No account is set up, since setting a password would hash too; the route needs only the session.
    const { browser } = await seedSession(setup, { subject: "acct-1", evidence: aal2(setup.clock) })
    const reply = await browser.post("/auth/recovery-codes")
    expect([reply.status, reply.text]).toEqual([500, '{"error":"internal"}'])
  })

  it("answers a recovery the busy hashing queue turned away with 503, and counts nothing", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    const recover = (identifier: string) =>
      browser.post("/auth/recovery", { identifier, code: "AAAAAA-AAAA-AAAA-AAAA-AAAA" })
    await whileBusy(async () => {
      for (let i = 0; i < 6; i += 1) {
        const reply = await recover(`user${String(i)}@example.com`)
        expect([reply.status, reply.text]).toEqual([503, '{"error":"busy"}'])
      }
    })
    // No failure counted against the client: the next wrong code is an ordinary refusal, not a throttled one.
    expect((await recover("user0@example.com")).status).toBe(401)
  })

  it("counts a refused attempt on another account too, so a spray the throttle slows is still flagged", async () => {
    // Sign-in's request limit (10 per 10 seconds) is off, so every refusal here is the throttle's.
    const setup = testAuth({
      stuffing: { distinctAccounts: 8 },
      challengeHook: refuseEveryone,
      rateLimit: { rules: { "sign-in": false } },
    })
    const statuses: number[] = []
    for (let i = 0; i < 9; i += 1) {
      statuses.push((await signIn(setup, `user${String(i)}@example.com`)).status)
    }
    // Six checked failures, then two attempts the client's block refused: eight accounts, so the next is challenged.
    expect(statuses).toEqual([401, 401, 401, 401, 401, 401, 429, 429, 403])
  })

  it("records a refused challenge as a failed sign-in", async () => {
    const setup = testAuth({ stuffing: { distinctAccounts: 2 }, challengeHook: refuseEveryone })
    await signIn(setup, "a@example.com")
    await signIn(setup, "b@example.com")
    const from = setup.events.length
    expect((await signIn(setup, "c@example.com")).text).toBe('{"error":"challenge-required"}')
    expect(setup.events.slice(from).map(brief)).toEqual([
      {
        type: LOGON,
        status: "Failure",
        user: "unknown",
        detail: "challenge-required",
        factors: ["Password"],
      },
    ])
  })

  it("keeps the free attempts for a flagged client the app's challenge passed", async () => {
    const setup = testAuth({ stuffing: { distinctAccounts: 3 }, challengeHook: () => true })
    for (const name of ["a", "b", "c"]) await signIn(setup, `${name}@example.com`)
    expect((await signIn(setup, "d@example.com")).status).toBe(401)
    expect((await signIn(setup, "d@example.com")).status).toBe(401)
  })
})

describe("the sign-in throttle's account key", () => {
  it("is the identifier as normalised, so case cannot spread one account's failures over several keys", async () => {
    const setup = testAuth()
    for (const [i, typed] of ["ADA@example.com", "Ada@Example.com", "ada@EXAMPLE.com"].entries()) {
      for (let j = 0; j < 2; j += 1)
        await signIn(setup, typed, undefined, `198.51.100.${String(i * 2 + j)}`)
    }
    expect((await signIn(setup, "ada@example.com", undefined, "203.0.113.9")).status).toBe(429)
  })

  it("is not the one recovery uses: recovery codes keep a budget of their own", async () => {
    const setup = testAuth()
    await account(setup)
    for (let i = 0; i < 6; i += 1) {
      expect(
        (await signIn(setup, "ada@example.com", undefined, `198.51.100.${String(i)}`)).status,
      ).toBe(401)
    }
    const recover = async (clientAddress: string) => {
      const browser = new Browser(inProcess(setup.auth))
      await browser.start()
      return browser.post(
        "/auth/recovery",
        { identifier: "ada@example.com", code: "AAAAAA-AAAA-AAAA-AAAA-AAAA" },
        { clientAddress },
      )
    }
    // The six failed passwords leave recovery its own free attempts; six wrong codes then use them up.
    const statuses: number[] = []
    for (let i = 0; i < 7; i += 1) statuses.push((await recover(`203.0.113.${String(i)}`)).status)
    expect(statuses).toEqual([401, 401, 401, 401, 401, 401, 429])
  })

  it("is the one a session's password step-up uses, so the two flows share one budget", async () => {
    const setup = testAuth()
    const { subject } = await account(setup)
    const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    for (let i = 0; i < 6; i += 1) {
      await within(signIn(setup, "ada@example.com", undefined, `198.51.100.${String(i)}`))
    }
    const started = await within(browser.post("/auth/step-up/start"))
    const { challenge } = started.json as { challenge: string }
    const reply = await within(
      browser.post(
        "/auth/step-up",
        { challenge, password: PASSWORD },
        { clientAddress: "203.0.113.9" },
      ),
    )
    expect(reply.status).toBe(429)
  })
})

describe("the second-factor throttle", () => {
  it("throttles each account's TOTP failures on their own", async () => {
    const setup = testAuth()
    const ada = await account(setup)
    const bob = await account(setup, "bob@example.com")
    const adaSession = await seedSession(setup, {
      subject: ada.subject,
      evidence: aal1(setup.clock),
    })
    for (let i = 0; i < 6; i += 1) {
      const failed = await adaSession.browser.post(
        "/auth/totp/verify",
        { code: "000000" },
        { clientAddress: `198.51.100.${String(i)}` },
      )
      expect(failed.status).toBe(401)
    }
    // Ada's account is now throttled, even from a client it has not seen.
    const adaAgain = await adaSession.browser.post(
      "/auth/totp/verify",
      { code: "000000" },
      { clientAddress: "198.51.100.99" },
    )
    expect(adaAgain.status).toBe(429)
    const bobSession = await seedSession(setup, {
      subject: bob.subject,
      evidence: aal1(setup.clock),
    })
    const reply = await bobSession.browser.post(
      "/auth/totp/verify",
      { code: "000000" },
      { clientAddress: "203.0.113.1" },
    )
    expect(reply.status).toBe(401)
  })

  it("keeps counting TOTP failures through a correct password sign-in", async () => {
    const setup = testAuth()
    const { subject } = await account(setup)
    const verifier = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    const guess = (i: number) =>
      verifier.browser.post(
        "/auth/totp/verify",
        { code: "000000" },
        { clientAddress: `198.51.100.${String(i)}` },
      )
    for (let i = 0; i < 5; i += 1) expect((await guess(i)).status).toBe(401)
    // Whoever holds the password signs in again; that success is the password's, not the TOTP code's.
    expect((await signIn(setup, "ada@example.com", PASSWORD, "198.51.100.50")).status).toBe(200)
    expect((await guess(5)).status).toBe(401)
    expect((await guess(6)).status).toBe(429)
  })

  it("counts no step-up the busy hashing queue turned away against the client", async () => {
    const setup = testAuth()
    const stepUp = async (subject: string) => {
      const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
      const { challenge } = (await browser.post("/auth/step-up/start")).json as {
        challenge: string
      }
      return browser.post("/auth/step-up", { challenge, password: "wrong password entirely" })
    }
    // Eight accounts from one client: only the client's key could add them up.
    await whileBusy(async () => {
      for (let i = 0; i < 8; i += 1) expect((await stepUp(`acct-${String(i)}`)).status).toBe(503)
    })
    expect((await stepUp("acct-8")).status).toBe(401)
  })

  it("does not count a pending authenticator's failures toward its ceiling", async () => {
    // The request limits are raised, so every one of the 100 codes reaches the TOTP check.
    const setup = testAuth({
      throttle: { freeFailures: 1_000 },
      rateLimit: { max: 10_000, rules: { "totp/verify": false } },
    })
    const { subject } = await account(setup)
    const fresh = await seedSession(setup, { subject, evidence: aal2(setup.clock) })
    const pending = (await fresh.browser.post("/auth/totp/enrol")).json as {
      authenticatorId: string
      secret: string
    }
    const verifier = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    for (let i = 0; i < 100; i += 1) {
      expect((await verifier.browser.post("/auth/totp/verify", { code: "000000" })).status).toBe(
        401,
      )
    }
    setup.clock.advance(30_000)
    const confirmed = await fresh.browser.post("/auth/totp/confirm", {
      authenticatorId: pending.authenticatorId,
      code: await codeAt(pending.secret, setup.clock.now()),
    })
    expect(confirmed.status).toBe(200)
    setup.clock.advance(30_000)
    const later = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    const reply = await later.browser.post("/auth/totp/verify", {
      code: await codeAt(pending.secret, setup.clock.now()),
    })
    expect(reply.status).toBe(200)
  }, 120_000)
})

describe("fresh proof for credential changes", () => {
  it("is the 15 minutes the GUIDE states", () => {
    expect(CREDENTIAL_CHANGE_WITHIN_MS).toBe(900_000)
  })

  it("refuses to confirm an enrolment once the multi-factor ceremony is stale", async () => {
    const setup = testAuth()
    const { subject } = await account(setup)
    const { browser } = await seedSession(setup, { subject, evidence: aal2(setup.clock) })
    const { authenticatorId, secret } = (await browser.post("/auth/totp/enrol")).json as {
      authenticatorId: string
      secret: string
    }
    setup.clock.advance(CREDENTIAL_CHANGE_WITHIN_MS + 1)
    const reply = await browser.post("/auth/totp/confirm", {
      authenticatorId,
      code: await codeAt(secret, setup.clock.now()),
    })
    expect([reply.status, reply.json]).toEqual([
      403,
      {
        error: "step-up",
        missing: [{ kind: "fresh-multi-factor", withinMs: CREDENTIAL_CHANGE_WITHIN_MS }],
      },
    ])
  })

  it("still allows a change exactly at the limit", async () => {
    const setup = testAuth()
    const { browser } = await seedSession(setup, { subject: "acct-1", evidence: aal2(setup.clock) })
    setup.clock.advance(CREDENTIAL_CHANGE_WITHIN_MS)
    expect((await browser.post("/auth/recovery-codes")).status).toBe(200)
  })

  it("treats a session with no multi-factor ceremony as stale, whatever the clock reads", async () => {
    // A default lowered to AAL1 lets a password-only session through the gate, to the freshness check itself.
    const clock = fixedClock(1_000)
    const policy = defineAuthPolicy({ version: "aal1", defaultRequirement: { level: "AAL1" } })
    const setup = { ...testAuth({ clock, policy }), clock }
    const { browser } = await seedSession(setup, { subject: "acct-1", evidence: aal1(clock) })
    const reply = await browser.post("/auth/totp/enrol")
    expect([reply.status, reply.json]).toEqual([
      403,
      {
        error: "step-up",
        missing: [{ kind: "fresh-multi-factor", withinMs: CREDENTIAL_CHANGE_WITHIN_MS }],
      },
    ])
  })
})
