// F08 email address confirmation through the dispatcher (ADR 0021 §2, §6; ADR 0008 §4; ADR 0009 §7; ADR 0015 §2).
// Sign-up sends a 6-digit code from the RandomSource, valid for 24 hours and stored only as a hash. Redeeming it with
// `POST /auth/email/confirm` claims the normalised address with createUnique; the pre-auth flow is sign-up, confirm,
// password, TOTP, and the session stays at `enroll` until every step is done.
import { describe, expect, it } from "vitest"
import { IDENTIFIER_COLLECTION } from "../../src/core/accounts.js"
import { type RandomSource, systemRandom } from "../../src/core/clock.js"
import {
  CONFIRMATION_COLLECTION,
  CONFIRMATION_DIGITS,
  CONFIRMATION_FAILURE_LIMIT,
  CONFIRMATION_LIFETIME_MS,
} from "../../src/core/email.js"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import {
  aal2,
  body,
  brief,
  Browser,
  confirmationCode,
  confirmEmail,
  CREATE,
  enrol,
  expectOk,
  inProcess,
  ORIGIN,
  PASSWORD,
  seedSession,
  T0,
  TENANT,
  testAuth,
  UPDATE,
} from "../support/auth.js"

type Setup = ReturnType<typeof testAuth>

async function signedUp(setup: Setup, identifier = "ada@example.com") {
  const browser = new Browser(inProcess(setup.auth))
  await browser.start()
  await expectOk(browser.post("/auth/sign-up", { identifier }))
  const session = await browser.get("/auth/session")
  const subject = (body(session)["session"] as { subject: string }).subject
  return { browser, subject }
}

/**
 * A random source that answers each draw of at most 6 bytes (a confirmation code's) with the next of `draws`, cycling,
 * and anything longer (tokens, ids, secrets) at random.
 */
function codeSource(...draws: readonly (readonly number[])[]): RandomSource {
  let next = 0
  return {
    fill(bytes) {
      if (bytes.length > CONFIRMATION_DIGITS) return systemRandom.fill(bytes)
      bytes.set((draws[next % draws.length] ?? []).slice(0, bytes.length))
      next += 1
      return bytes
    },
  }
}

const level = async (browser: Browser) =>
  (body(await browser.get("/auth/session"))["session"] as { level: string | null }).level

describe("the confirmation email sign-up sends", () => {
  it("goes to the normalised address with a 6-digit code from the random source and a link on APP_ORIGIN", async () => {
    const setup = testAuth({ random: codeSource([3, 1, 4, 1, 5, 9]) })
    await signedUp(setup, "Ada@Example.COM")
    expect(setup.outbox).toEqual([
      {
        to: "ada@example.com",
        subject: "Confirm your email address",
        text: [
          "Your confirmation code is 314159. It expires in 24 hours.",
          "",
          `Enter it on the confirmation page: ${ORIGIN}/auth/email/confirm`,
          "",
          "If you did not create an account, ignore this email.",
        ].join("\n"),
      },
    ])
  })

  it("draws digits without bias, skipping bytes of 250 and above", async () => {
    const setup = testAuth({ random: codeSource([250, 255, 7, 17, 27, 37], [8, 249]) })
    const { browser } = await signedUp(setup)
    // The two rejected bytes leave two digits missing, which the next draw supplies.
    expect(confirmationCode(setup.outbox, "ada@example.com")).toBe("777789")
    await expectOk(browser.post("/auth/email/confirm", { code: "777789" }))
  })

  it("stores only a keyed hash of the code, for 24 hours (email-code-storage.test.ts checks the key)", async () => {
    const setup = testAuth({ random: codeSource([1, 2, 3, 4, 5, 6]) })
    const { subject } = await signedUp(setup)
    const [record, ...rest] = await setup.store.listByOwner(
      TENANT,
      CONFIRMATION_COLLECTION,
      subject,
    )
    expect(rest).toEqual([])
    expect(record?.key).toMatch(/^[0-9a-f]{64}$/)
    expect(record).toMatchObject({
      owner: subject,
      expiresAt: T0 + 24 * 60 * 60_000,
      revokedAt: null,
      consumedAt: null,
      data: { address: "ada@example.com", keyId: "e1" },
    })
    expect(JSON.stringify(record)).not.toContain("123456")
    expect([CONFIRMATION_LIFETIME_MS, CONFIRMATION_DIGITS, CONFIRMATION_FAILURE_LIMIT]).toEqual([
      24 * 60 * 60_000,
      6,
      5,
    ])
  })

  it("sends nothing for an identifier that is not an email address", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    expect((await browser.post("/auth/sign-up", { identifier: "ada" })).status).toBe(400)
    expect(setup.outbox).toEqual([])
  })

  it("answers sign-up the same when the mail sender throws or rejects", async () => {
    for (const sendEmail of [
      () => {
        throw new Error("mail is down")
      },
      () => Promise.reject(new Error("mail is down")),
    ]) {
      const setup = testAuth({ sendEmail })
      const browser = new Browser(inProcess(setup.auth))
      await browser.start()
      const reply = await browser.post("/auth/sign-up", { identifier: "ada@example.com" })
      expect([reply.status, reply.text]).toEqual([200, '{"outcome":"enroll","returnTo":"/"}'])
    }
  })
})

describe("POST /auth/email/confirm", () => {
  it("confirms the address: the account now resolves by it, an Update event says so, and nothing else changes", async () => {
    const setup = testAuth()
    const { browser, subject } = await signedUp(setup)
    setup.events.length = 0
    const reply = await browser.post("/auth/email/confirm", {
      code: confirmationCode(setup.outbox, "ada@example.com"),
    })
    expect([reply.status, reply.text]).toEqual([200, '{"outcome":"enroll"}'])
    expect(reply.headers.getSetCookie()).toEqual([])
    expect((await setup.store.get(TENANT, IDENTIFIER_COLLECTION, "ada@example.com"))?.data).toEqual(
      { account: subject, kind: "email", confirmedAt: T0 },
    )
    expect(setup.events.map(brief)).toEqual([
      { type: UPDATE, status: "Success", user: subject, detail: "email-confirmed" },
    ])
    // Email never raises the level (ADR 0021 §3): the session is still pre-auth and holds no evidence.
    expect(body(await browser.get("/auth/session"))["session"]).toMatchObject({
      state: "pre-auth",
      level: null,
      methods: [],
    })
  })

  it("is single use", async () => {
    const setup = testAuth()
    const { browser } = await signedUp(setup)
    const code = confirmationCode(setup.outbox, "ada@example.com")
    await expectOk(browser.post("/auth/email/confirm", { code }))
    const again = await browser.post("/auth/email/confirm", { code })
    expect([again.status, again.text]).toEqual([400, '{"error":"invalid-code"}'])
  })

  it("refuses a code at the end of its 24 hours, and takes it a moment before", async () => {
    // A pre-auth session lasts an hour by default; this policy keeps it alive past the code's lifetime.
    const policy = defineAuthPolicy({
      version: "long pre-auth",
      timeouts: {
        restrictedIdleMs: 2 * CONFIRMATION_LIFETIME_MS,
        restrictedAbsoluteMs: 2 * CONFIRMATION_LIFETIME_MS,
      },
    })
    for (const [elapsed, status] of [
      [CONFIRMATION_LIFETIME_MS, 400],
      [CONFIRMATION_LIFETIME_MS - 1, 200],
    ] as const) {
      const setup = testAuth({ policy })
      const { browser } = await signedUp(setup)
      setup.clock.advance(elapsed)
      await browser.start()
      const reply = await browser.post("/auth/email/confirm", {
        code: confirmationCode(setup.outbox, "ada@example.com"),
      })
      expect(reply.status).toBe(status)
    }
  })

  it("refuses a code issued to another account, even for the same address", async () => {
    const setup = testAuth()
    const first = await signedUp(setup)
    const firstCode = confirmationCode(setup.outbox, "ada@example.com")
    // One send a minute per address (ADR 0009 §7).
    setup.clock.advance(60_000)
    const second = await signedUp(setup)
    const reply = await second.browser.post("/auth/email/confirm", { code: firstCode })
    expect([reply.status, reply.text]).toEqual([400, '{"error":"invalid-code"}'])
    // The first account's code is untouched by the second account's attempt.
    await expectOk(first.browser.post("/auth/email/confirm", { code: firstCode }))
  })

  it("reports a wrong code as a failed Update", async () => {
    const setup = testAuth({ random: codeSource([1, 2, 3, 4, 5, 6]) })
    const { browser, subject } = await signedUp(setup)
    setup.events.length = 0
    const reply = await browser.post("/auth/email/confirm", { code: "654321" })
    expect([reply.status, reply.text]).toEqual([400, '{"error":"invalid-code"}'])
    expect(setup.events.map(brief)).toEqual([
      { type: UPDATE, status: "Failure", user: subject, detail: "invalid-code" },
    ])
  })

  it(`counts each wrong code over the code's whole life: after ${CONFIRMATION_FAILURE_LIMIT} the code dies, and further tries wait`, async () => {
    const setup = testAuth({ random: codeSource([1, 2, 3, 4, 5, 6]) })
    const { browser, subject } = await signedUp(setup)
    for (let attempt = 1; attempt <= CONFIRMATION_FAILURE_LIMIT; attempt += 1) {
      const reply = await browser.post("/auth/email/confirm", { code: "000000" })
      expect([attempt, reply.status]).toEqual([attempt, 400])
      const [record] = await setup.store.listByOwner(TENANT, CONFIRMATION_COLLECTION, subject)
      expect([attempt, record?.revokedAt]).toEqual([
        attempt,
        attempt === CONFIRMATION_FAILURE_LIMIT ? T0 : null,
      ])
    }
    setup.clock.advance(1_000)
    const waiting = await browser.post("/auth/email/confirm", { code: "123456" })
    // The wait runs to the end of the code's 24 hours, counted from the first wrong code.
    expect([waiting.status, waiting.text, waiting.headers.get("retry-after")]).toEqual([
      429,
      '{"error":"rate-limited"}',
      "86399",
    ])
    expect(setup.events.map(brief).at(-1)).toEqual({
      type: UPDATE,
      status: "Failure",
      user: subject,
      detail: "rate-limited",
    })
    // No quarter-hour window restarts the count. The session stays alive meanwhile.
    setup.clock.set(T0 + 10 * 60_000)
    await browser.start()
    setup.clock.set(T0 + 15 * 60_000)
    expect((await browser.post("/auth/email/confirm", { code: "000000" })).status).toBe(429)
    // A new code starts a new count.
    await expectOk(browser.post("/auth/email/resend"))
    const wrong = await browser.post("/auth/email/confirm", { code: "000000" })
    expect([wrong.status, wrong.text]).toEqual([400, '{"error":"invalid-code"}'])
    await expectOk(
      browser.post("/auth/email/confirm", {
        code: confirmationCode(setup.outbox, "ada@example.com"),
      }),
    )
  })

  it("rounds the wait up to whole seconds", async () => {
    const setup = testAuth({ random: codeSource([1, 2, 3, 4, 5, 6]) })
    const { browser } = await signedUp(setup)
    for (let attempt = 0; attempt < CONFIRMATION_FAILURE_LIMIT; attempt += 1) {
      await browser.post("/auth/email/confirm", { code: "000000" })
    }
    setup.clock.advance(1_500)
    const reply = await browser.post("/auth/email/confirm", { code: "000000" })
    expect(reply.headers.get("retry-after")).toBe("86399")
  })

  it("forgets earlier wrong codes once the right one is redeemed", async () => {
    const setup = testAuth({ random: codeSource([1, 2, 3, 4, 5, 6]) })
    const { browser, subject } = await signedUp(setup)
    for (let attempt = 1; attempt < CONFIRMATION_FAILURE_LIMIT; attempt += 1) {
      await browser.post("/auth/email/confirm", { code: "000000" })
    }
    await expectOk(browser.post("/auth/email/confirm", { code: "123456" }))
    const counter = await setup.store.increment(
      TENANT,
      `email-confirm-failures:${subject}`,
      CONFIRMATION_LIFETIME_MS,
      setup.clock.now(),
    )
    expect(counter.count).toBe(1)
  })

  it("claims nothing when another account already confirmed the address, and answers the same", async () => {
    const setup = testAuth()
    const owner = await signedUp(setup)
    const ownerCode = confirmationCode(setup.outbox, "ada@example.com")
    setup.clock.advance(60_000)
    const late = await signedUp(setup)
    const lateCode = confirmationCode(setup.outbox, "ada@example.com")
    await expectOk(owner.browser.post("/auth/email/confirm", { code: ownerCode }))
    setup.events.length = 0
    const reply = await late.browser.post("/auth/email/confirm", { code: lateCode })
    expect([reply.status, reply.text]).toEqual([200, '{"outcome":"enroll"}'])
    expect((await setup.store.get(TENANT, IDENTIFIER_COLLECTION, "ada@example.com"))?.data).toEqual(
      { account: owner.subject, kind: "email", confirmedAt: T0 + 60_000 },
    )
    expect(setup.events.map(brief)).toEqual([
      { type: UPDATE, status: "Failure", user: late.subject, detail: "identifier-taken" },
    ])
    // Holding no address, the late account cannot go on to choose a password.
    const password = await late.browser.post("/auth/password", { password: PASSWORD })
    expect([password.status, password.text]).toEqual([409, '{"error":"confirm-email-first"}'])
  })

  it("needs a session that is enrolling", async () => {
    const setup = testAuth()
    const signedOut = new Browser(inProcess(setup.auth))
    await signedOut.start()
    const none = await signedOut.post("/auth/email/confirm", { code: "123456" })
    expect([none.status, none.text]).toEqual([401, '{"error":"unauthenticated"}'])
    const { browser } = await seedSession(setup, { evidence: aal2(setup.clock) })
    const done = await browser.post("/auth/email/confirm", { code: "123456" })
    expect([done.status, done.text]).toEqual([403, '{"error":"not-enrolling"}'])
  })

  it("refuses an enrolling session whose account typed no address", async () => {
    const setup = testAuth()
    const { browser } = await seedSession(setup, {
      subject: "acct-without-address",
      state: "pre-auth",
    })
    const confirm = await browser.post("/auth/email/confirm", { code: "123456" })
    expect([confirm.status, confirm.text]).toEqual([409, '{"error":"no-identifier"}'])
    const resend = await browser.post("/auth/email/resend")
    expect([resend.status, resend.text]).toEqual([409, '{"error":"no-identifier"}'])
    expect(setup.outbox).toEqual([])
  })

  it("declares exactly one required field, the code", async () => {
    const setup = testAuth()
    const { browser } = await signedUp(setup)
    expect((await browser.post("/auth/email/confirm", {})).text).toBe('{"error":"missing-field"}')
    const extra = await browser.post("/auth/email/confirm", { code: "123456", verified: "true" })
    expect(extra.text).toBe('{"error":"undeclared-field"}')
  })
})

describe("POST /auth/email/resend", () => {
  it("sends a new code, and the old one stops working", async () => {
    const setup = testAuth({ random: codeSource([1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1]) })
    const { browser } = await signedUp(setup)
    setup.clock.advance(60_000)
    const reply = await browser.post("/auth/email/resend")
    expect([reply.status, reply.text]).toEqual([200, '{"outcome":"enroll","retryAfterMs":60000}'])
    expect(setup.outbox.map((message) => confirmationCode([message], message.to))).toEqual([
      "123456",
      "654321",
    ])
    expect((await browser.post("/auth/email/confirm", { code: "123456" })).status).toBe(400)
    await expectOk(browser.post("/auth/email/confirm", { code: "654321" }))
  })

  it("can draw the same code again for the same account", async () => {
    const setup = testAuth({ random: codeSource([1, 2, 3, 4, 5, 6]) })
    const { browser } = await signedUp(setup)
    setup.clock.advance(60_000)
    await expectOk(browser.post("/auth/email/resend"))
    expect(setup.outbox).toHaveLength(2)
    await expectOk(browser.post("/auth/email/confirm", { code: "123456" }))
  })

  it("refuses once the address is confirmed", async () => {
    const setup = testAuth()
    const { browser } = await signedUp(setup)
    await confirmEmail(browser, setup.outbox)
    const reply = await browser.post("/auth/email/resend")
    expect([reply.status, reply.text]).toEqual([409, '{"error":"already-confirmed"}'])
    expect(setup.outbox).toHaveLength(1)
  })

  it("needs a session that is enrolling", async () => {
    const setup = testAuth()
    const signedOut = new Browser(inProcess(setup.auth))
    await signedOut.start()
    expect((await signedOut.post("/auth/email/resend")).status).toBe(401)
    const { browser } = await seedSession(setup, { evidence: aal2(setup.clock) })
    expect((await browser.post("/auth/email/resend")).text).toBe('{"error":"not-enrolling"}')
  })
})

describe("the pre-auth flow: sign-up, confirm, password, TOTP", () => {
  it("refuses a password before the address is confirmed", async () => {
    const setup = testAuth()
    const { browser } = await signedUp(setup)
    const reply = await browser.post("/auth/password", { password: PASSWORD })
    expect([reply.status, reply.text]).toEqual([409, '{"error":"confirm-email-first"}'])
  })

  it("answers enroll to every requirement after sign-up, after the confirmation and after the password", async () => {
    const setup = testAuth()
    const { browser } = await signedUp(setup)
    const outcome = async () =>
      (
        await setup.auth.require(
          {
            method: "GET",
            url: "/",
            headers: new Headers({
              Cookie: `__Host-test-cap=${browser.cookies.get("__Host-test-cap") ?? ""}`,
            }),
            body: null,
          },
          "default",
        )
      ).outcome
    expect(await outcome()).toBe("enroll")
    await confirmEmail(browser, setup.outbox)
    expect(await outcome()).toBe("enroll")
    await expectOk(browser.post("/auth/password", { password: PASSWORD }))
    expect(await outcome()).toBe("enroll")
  })

  it("stays at enroll until every step is done, then signs in again later by the confirmed address", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    const { subject, secret } = await enrol(browser, setup.clock, setup.outbox)
    expect(await level(browser)).toBe("AAL2")
    expect(setup.events.map(brief).map((event) => event["type"])).toEqual([
      CREATE,
      UPDATE,
      expect.any(Number),
      expect.any(Number),
    ])
    expect(secret).not.toBe("")
    await expectOk(browser.post("/auth/sign-out"))
    const later = new Browser(inProcess(setup.auth))
    await later.start()
    const signedIn = await later.post("/auth/sign-in", {
      identifier: "ada@example.com",
      password: PASSWORD,
    })
    expect([signedIn.status, signedIn.json]).toEqual([200, { outcome: "step-up", returnTo: "/" }])
    expect((body(await later.get("/auth/session"))["session"] as { subject: string }).subject).toBe(
      subject,
    )
  })
})
