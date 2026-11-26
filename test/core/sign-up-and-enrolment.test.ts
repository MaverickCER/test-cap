// F01 sign-up and F03 TOTP enrolment through the dispatcher: the account starts in the pre-auth state and must enrol a
// password plus TOTP before any requirement allows it (ADR 0005, ADR 0026 §1).
import { describe, expect, it } from "vitest"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import {
  ACCOUNT_COLLECTION,
  IDENTIFIER_COLLECTION,
  UNCONFIRMED_IDENTIFIER_COLLECTION,
} from "../../src/core/accounts.js"
import { hexEncode, sha256, utf8Encode } from "../../src/core/encoding.js"
import type { HibpFetch } from "../../src/methods/password/hibp.js"
import { memoryStore } from "../../src/store/memory.js"
import {
  aal1,
  aal2,
  body,
  Browser,
  ENV,
  expectOk,
  hookedStore,
  inProcess,
  PASSWORD,
  seedAccount,
  seedSession,
  TENANT,
  testAuth,
  brief,
  confirmEmail,
  CREATE,
  ENABLE_MFA,
  LOGON,
} from "../support/auth.js"
import { codeAt } from "../support/totp.js"

/** Signs up and, unless `confirm` is false, confirms the address with the emailed code: the step before a password. */
async function signedUp(
  setup: ReturnType<typeof testAuth>,
  identifier = "ada@example.com",
  confirm = true,
) {
  const browser = new Browser(inProcess(setup.auth))
  await browser.start()
  const reply = await browser.post("/auth/sign-up", { identifier })
  const session = await browser.get("/auth/session")
  const subject = (body(session)["session"] as { subject: string }).subject
  if (confirm) await confirmEmail(browser, setup.outbox, identifier)
  return { browser, reply, subject }
}

describe("sign-up", () => {
  it("creates an account in the pre-auth state and a session for it", async () => {
    const setup = testAuth()
    const { reply, subject, browser } = await signedUp(setup, " Ada@Example.com ".trim(), false)
    expect(reply.status).toBe(200)
    expect(reply.text).toBe('{"outcome":"enroll","returnTo":"/"}')
    expect(reply.headers.getSetCookie()).toEqual([
      expect.stringMatching(
        /^__Host-test-cap=[A-Za-z0-9_-]{43}; Path=\/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax$/,
      ),
    ])
    expect(reply.headers.get("x-csrf-token")).toMatch(/^c1\./)
    const session = body(await browser.get("/auth/session"))["session"]
    expect(session).toMatchObject({ subject, state: "pre-auth", level: null, methods: [] })
    expect((await setup.store.get(TENANT, ACCOUNT_COLLECTION, subject))?.data).toMatchObject({
      status: "active",
    })
    const [identifier] = await setup.store.listByOwner(
      TENANT,
      UNCONFIRMED_IDENTIFIER_COLLECTION,
      subject,
    )
    expect(identifier?.data).toEqual({ kind: "email", value: "ada@example.com" })
    expect(await setup.store.get(TENANT, IDENTIFIER_COLLECTION, "ada@example.com")).toBeNull()
    expect(setup.events.map(brief)).toEqual([{ type: CREATE, status: "Success", user: subject }])
    expect(
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
      ),
    ).toEqual({ outcome: "enroll" })
  })

  it("refuses an identifier that is not an email address, creating nothing", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    const reply = await browser.post("/auth/sign-up", { identifier: " ada@example.com" })
    expect([reply.status, reply.text]).toEqual([400, '{"error":"invalid-identifier"}'])
    expect(reply.headers.getSetCookie()).toEqual([])
    expect(setup.events.map(brief)).toEqual([])
  })

  it("refuses a returnTo that is not a same-origin path, before creating anything", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    const reply = await browser.post("/auth/sign-up", {
      identifier: "ada@example.com",
      returnTo: "//evil.example",
    })
    expect([reply.status, reply.text]).toEqual([400, '{"error":"invalid-return-to"}'])
    expect(setup.events.map(brief)).toEqual([])
  })

  it("revokes a session the browser already held", async () => {
    const setup = testAuth()
    const { browser, token } = await seedSession(setup, { evidence: aal2(setup.clock) })
    await expectOk(browser.post("/auth/sign-up", { identifier: "ada@example.com" }))
    const old = new Browser(inProcess(setup.auth))
    old.cookies.set("__Host-test-cap", token)
    expect(body(await old.get("/auth/session"))["session"]).toBeNull()
  })

  it("answers a form sign-up with JSON, since the session cannot be used yet", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    const reply = await browser.postForm("/auth/sign-up", { identifier: "ada@example.com" })
    expect([reply.status, reply.text]).toEqual([200, '{"outcome":"enroll","returnTo":"/"}'])
  })
})

describe("password enrolment", () => {
  it("sets the password of the enrolling account", async () => {
    const setup = testAuth()
    const { browser, subject } = await signedUp(setup)
    setup.events.length = 0
    const reply = await browser.post("/auth/password", { password: PASSWORD })
    expect([reply.status, reply.text]).toEqual([
      200,
      '{"outcome":"enroll","enrolled":["password"]}',
    ])
    expect(setup.events.map(brief)).toEqual([
      {
        type: ENABLE_MFA,
        status: "Success",
        user: subject,
        factors: ["Password"],
      },
    ])
  })

  it.each([
    ["too-short", "short1!", 400],
    ["too-common", "password1234", 400],
    ["too-common", "my billing-web pass", 400],
    ["too-common", "ada@example.com is me", 400],
  ])("refuses %s (%s) and reports it", async (reason, password, status) => {
    const setup = testAuth()
    const { browser, subject } = await signedUp(setup)
    setup.events.length = 0
    const reply = await browser.post("/auth/password", { password })
    expect([reply.status, reply.text]).toEqual([status, `{"error":"${reason}"}`])
    expect(setup.events.map(brief)).toEqual([
      {
        type: ENABLE_MFA,
        status: "Failure",
        user: subject,
        factors: ["Password"],
        detail: reason,
      },
    ])
  })

  it("refuses a breached password, asking HIBP through the fetch the app gave", async () => {
    const hashed = hexEncode(
      new Uint8Array(await crypto.subtle.digest("SHA-1", utf8Encode(PASSWORD))),
    ).toUpperCase()
    const breached: HibpFetch = () =>
      Promise.resolve({
        ok: true,
        status: 200,
        text: () => Promise.resolve(`${hashed.slice(5)}:12`),
      })
    const setup = testAuth({ hibpFetch: breached })
    const { browser } = await signedUp(setup)
    const reply = await browser.post("/auth/password", { password: PASSWORD })
    expect([reply.status, reply.text]).toEqual([400, '{"error":"breached"}'])
  })

  it("takes the context word from APP_SYSTEM_ID", async () => {
    const setup = testAuth({ env: { ...ENV, APP_SYSTEM_ID: "ledger-app" } })
    const { browser } = await signedUp(setup)
    expect(body(await browser.post("/auth/password", { password: "my ledger-app pass" }))).toEqual({
      error: "too-common",
    })
    expect((await browser.post("/auth/password", { password: "my billing-web pass" })).status).toBe(
      200,
    )
  })

  it("asks for 15 characters when a deviation lets a password alone pass the default requirement", async () => {
    const setup = testAuth({
      policy: defineAuthPolicy({ version: "v", defaultRequirement: { level: "AAL1" } }),
    })
    const { browser } = await signedUp(setup)
    expect(body(await browser.post("/auth/password", { password: "fourteen chars" }))).toEqual({
      error: "too-short",
    })
    expect((await browser.post("/auth/password", { password: "fifteen chars!!" })).status).toBe(200)
  })

  it("keeps the 8-character minimum under a deviation that leaves the default requirement at AAL2", async () => {
    const setup = testAuth({ policy: defineAuthPolicy({ version: "v", emailSignIn: true }) })
    const { browser } = await signedUp(setup)
    expect((await browser.post("/auth/password", { password: "fourteen chars" })).status).toBe(200)
  })

  it("is only for an enrolling session", async () => {
    const setup = testAuth()
    const signedOut = new Browser(inProcess(setup.auth))
    await signedOut.start()
    const none = await signedOut.post("/auth/password", { password: PASSWORD })
    expect([none.status, none.text]).toEqual([401, '{"error":"unauthenticated"}'])
    const { browser } = await seedSession(setup, { evidence: aal2(setup.clock) })
    const done = await browser.post("/auth/password", { password: PASSWORD })
    expect([done.status, done.text]).toEqual([403, '{"error":"not-enrolling"}'])
  })
})

describe("TOTP enrolment", () => {
  it.each(["", "x", "A".repeat(42), "A".repeat(44), `!${"A".repeat(43)}`])(
    "refuses the authenticator id %j as a malformed body, before the store sees it",
    async (authenticatorId) => {
      const store = memoryStore()
      const reads: string[] = []
      const setup = testAuth({
        store: hookedStore(store, async (operation, args) => {
          if (args[1] === "totp") reads.push(operation)
        }),
      })
      const { browser } = await signedUp(setup)
      await expectOk(browser.post("/auth/password", { password: PASSWORD }))
      await expectOk(browser.post("/auth/totp/enrol"))
      reads.length = 0
      const reply = await browser.post("/auth/totp/confirm", { authenticatorId, code: "123456" })
      expect([reply.status, reply.text]).toEqual([400, '{"error":"malformed-body"}'])
      expect(reads).toEqual([])
    },
  )

  it("needs the password first while enrolling", async () => {
    const setup = testAuth()
    const { browser } = await signedUp(setup)
    const enrol = await browser.post("/auth/totp/enrol")
    expect([enrol.status, enrol.text]).toEqual([409, '{"error":"password-first"}'])
    const confirm = await browser.post("/auth/totp/confirm", {
      authenticatorId: "A".repeat(43),
      code: "123456",
    })
    expect([confirm.status, confirm.text]).toEqual([409, '{"error":"password-first"}'])
  })

  it("shows the secret once, then ends enrolment with an AAL2 session under a new token", async () => {
    const setup = testAuth()
    const { browser, subject } = await signedUp(setup)
    await expectOk(browser.post("/auth/password", { password: PASSWORD }))
    const enrol = await browser.post("/auth/totp/enrol")
    expect(enrol.status).toBe(200)
    const { authenticatorId, secret } = body(enrol) as { authenticatorId: string; secret: string }
    expect(Object.keys(body(enrol))).toEqual(["authenticatorId", "secret"])
    expect(authenticatorId).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(secret).toMatch(/^[A-Z2-7]{32}$/)
    const before = browser.cookies.get("__Host-test-cap")
    setup.events.length = 0
    const wrong = await browser.post("/auth/totp/confirm", { authenticatorId, code: "000000" })
    expect([wrong.status, wrong.text]).toEqual([400, '{"error":"invalid-code"}'])
    expect(setup.events.map(brief)).toEqual([
      {
        type: ENABLE_MFA,
        status: "Failure",
        user: subject,
        factors: ["OTP"],
        detail: "invalid",
      },
    ])
    setup.events.length = 0
    const confirm = await browser.post("/auth/totp/confirm", {
      authenticatorId,
      code: await codeAt(secret, setup.clock.now()),
      returnTo: "/welcome",
    })
    expect([confirm.status, confirm.text]).toEqual([
      200,
      '{"outcome":"allow","returnTo":"/welcome"}',
    ])
    expect(setup.events.map(brief)).toEqual([
      {
        type: ENABLE_MFA,
        status: "Success",
        user: subject,
        factors: ["OTP"],
      },
    ])
    const after = browser.cookies.get("__Host-test-cap")
    expect(after).not.toBe(before)
    const session = body(await browser.get("/auth/session"))["session"]
    expect(session).toMatchObject({
      subject,
      state: "authenticated",
      level: "AAL2",
      methods: ["password", "totp"],
    })
    const stale = new Browser(inProcess(setup.auth))
    stale.cookies.set("__Host-test-cap", before ?? "")
    expect(body(await stale.get("/auth/session"))["session"]).toBeNull()
  })

  it("redirects a form that finishes enrolment to returnTo", async () => {
    const setup = testAuth()
    const { browser } = await signedUp(setup)
    await expectOk(browser.post("/auth/password", { password: PASSWORD }))
    const { authenticatorId, secret } = body(await browser.post("/auth/totp/enrol")) as Record<
      string,
      string
    >
    const reply = await browser.postForm("/auth/totp/confirm", {
      authenticatorId: authenticatorId ?? "",
      code: await codeAt(secret ?? "", setup.clock.now()),
      returnTo: "/home",
    })
    expect([reply.status, reply.headers.get("location"), reply.text]).toEqual([303, "/home", ""])
    expect(reply.headers.getSetCookie()).toHaveLength(1)
    expect(reply.headers.get("x-csrf-token")).toMatch(/^c1\./)
  })

  it("refuses a bad returnTo before confirming anything", async () => {
    const setup = testAuth()
    const { browser } = await signedUp(setup)
    const reply = await browser.post("/auth/totp/confirm", {
      authenticatorId: "A".repeat(43),
      code: "1",
      returnTo: "https://evil.example",
    })
    expect([reply.status, reply.text]).toEqual([400, '{"error":"invalid-return-to"}'])
  })

  it("lets an AAL2 session add a TOTP authenticator, which rotates it and revokes the account's other sessions", async () => {
    const setup = testAuth()
    const { subject } = await seedAccount(setup)
    const other = await seedSession(setup, { subject, evidence: aal2(setup.clock) })
    const { browser, token } = await seedSession(setup, { subject, evidence: aal2(setup.clock) })
    const { authenticatorId, secret } = body(
      await expectOk(browser.post("/auth/totp/enrol")),
    ) as Record<string, string>
    const reply = await browser.post("/auth/totp/confirm", {
      authenticatorId: authenticatorId ?? "",
      code: await codeAt(secret ?? "", setup.clock.now()),
    })
    expect(reply.text).toBe('{"outcome":"allow","returnTo":"/"}')
    expect(browser.cookies.get("__Host-test-cap")).not.toBe(token)
    expect(body(await other.browser.get("/auth/session"))["session"]).toBeNull()
    expect(body(await browser.get("/auth/session"))["session"]).toMatchObject({
      subject,
      level: "AAL2",
    })
  })

  it.each([
    ["no session", undefined, 401, "unauthenticated"],
    ["a session below the default requirement", "aal1", 403, "step-up"],
  ] as const)("refuses %s", async (_name, kind, status, code) => {
    const setup = testAuth()
    let browser: Browser
    if (kind === undefined) {
      browser = new Browser(inProcess(setup.auth))
      await browser.start()
    } else {
      browser = (
        await seedSession(setup, {
          state: "authenticated",
          evidence: aal1(setup.clock),
        })
      ).browser
    }
    for (const path of ["/auth/totp/enrol", "/auth/totp/confirm"]) {
      const reply = await browser.post(
        path,
        path.endsWith("confirm") ? { authenticatorId: "A".repeat(43), code: "1" } : {},
      )
      expect([reply.status, reply.text]).toEqual([status, `{"error":"${code}"}`])
    }
  })

  it("answers unauthenticated when the session is revoked while enrolment completes", async () => {
    const base = memoryStore()
    let armed = false
    const store = hookedStore(base, async (operation, args) => {
      if (armed && operation === "update" && args[1] === "totp") {
        armed = false
        await base.revokeByOwner(TENANT, "session", String(subject), 0)
      }
    })
    let subject = ""
    const setup = testAuth({ store })
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    await expectOk(browser.post("/auth/sign-up", { identifier: "ada@example.com" }))
    subject = (body(await browser.get("/auth/session"))["session"] as { subject: string }).subject
    await confirmEmail(browser, setup.outbox)
    await expectOk(browser.post("/auth/password", { password: PASSWORD }))
    const { authenticatorId, secret } = body(await browser.post("/auth/totp/enrol")) as Record<
      string,
      string
    >
    armed = true
    const reply = await browser.post("/auth/totp/confirm", {
      authenticatorId: authenticatorId ?? "",
      code: await codeAt(secret ?? "", setup.clock.now()),
    })
    expect([reply.status, reply.text]).toEqual([401, '{"error":"unauthenticated"}'])
  })

  it("dates the password evidence at the end of enrolment, with the stored authenticator id", async () => {
    const setup = testAuth()
    const { browser, subject } = await signedUp(setup)
    await expectOk(browser.post("/auth/password", { password: PASSWORD }))
    setup.clock.advance(5_000)
    const { authenticatorId, secret } = body(await browser.post("/auth/totp/enrol")) as Record<
      string,
      string
    >
    await expectOk(
      browser.post("/auth/totp/confirm", {
        authenticatorId: authenticatorId ?? "",
        code: await codeAt(secret ?? "", setup.clock.now()),
      }),
    )
    const stored = await setup.store.get(TENANT, "password", subject)
    const passwordId = (stored?.data as { authenticatorId: string }).authenticatorId
    const token = browser.cookies.get("__Host-test-cap") ?? ""
    const record = await setup.store.get(
      TENANT,
      "session",
      hexEncode(await sha256(utf8Encode(token))),
    )
    const evidence = (
      record?.data as { evidence: { method: string; authenticatorId: string; at: number }[] }
    ).evidence
    expect(evidence[0]).toEqual({
      method: "password",
      authenticatorId: passwordId,
      factors: ["knowledge"],
      phishingResistant: false,
      replayResistant: false,
      keyProtection: "unknown",
      userVerified: false,
      attestationVerified: false,
      at: setup.clock.now(),
    })
    expect(evidence[1]?.method).toBe("totp")
  })
})

describe("an account that stopped before its second factor", () => {
  /** Signs up, confirms the address and sets the password, then leaves; the next browser signs in with it. */
  async function stopped(setup: ReturnType<typeof testAuth>) {
    const { browser, subject } = await signedUp(setup)
    await expectOk(browser.post("/auth/password", { password: PASSWORD }))
    const later = new Browser(inProcess(setup.auth))
    await later.start()
    setup.events.length = 0
    const reply = await later.post("/auth/sign-in", {
      identifier: "ada@example.com",
      password: PASSWORD,
    })
    return { later, reply, subject }
  }

  it("goes back to enrolment on a password sign-in, and finishes it with TOTP", async () => {
    const setup = testAuth()
    const { later, reply, subject } = await stopped(setup)
    expect([reply.status, body(reply)["outcome"]]).toEqual([200, "enroll"])
    expect(body(await later.get("/auth/session"))["session"]).toMatchObject({
      subject,
      state: "pre-auth",
      level: null,
    })
    expect(setup.events.map(brief)).toEqual([
      { type: LOGON, status: "Success", user: subject, factors: ["Password"], detail: "enroll" },
    ])
    const begun = (await later.post("/auth/totp/enrol")).json as {
      authenticatorId: string
      secret: string
    }
    setup.clock.advance(30_000)
    const confirmed = await later.post("/auth/totp/confirm", {
      authenticatorId: begun.authenticatorId,
      code: await codeAt(begun.secret, setup.clock.now()),
    })
    expect(confirmed.status).toBe(200)
    expect(body(await later.get("/auth/session"))["session"]).toMatchObject({
      subject,
      state: "authenticated",
      level: "AAL2",
    })
  })

  it("may not replace the password from that session: a password changes only through recovery", async () => {
    const setup = testAuth()
    const { later } = await stopped(setup)
    const reply = await later.post("/auth/password", { password: "an entirely new passphrase" })
    expect([reply.status, reply.text]).toEqual([409, '{"error":"password-set"}'])
    const again = new Browser(inProcess(setup.auth))
    await again.start()
    const signIn = await again.post("/auth/sign-in", {
      identifier: "ada@example.com",
      password: PASSWORD,
    })
    expect(signIn.status).toBe(200)
  })

  it("signs in as usual when a deviation lets a password alone meet the default requirement", async () => {
    const setup = testAuth({
      policy: defineAuthPolicy({ version: "v", defaultRequirement: { level: "AAL1" } }),
    })
    const { browser, subject } = await signedUp(setup)
    await expectOk(browser.post("/auth/password", { password: "fifteen chars!!" }))
    const later = new Browser(inProcess(setup.auth))
    await later.start()
    const reply = await later.post("/auth/sign-in", {
      identifier: "ada@example.com",
      password: "fifteen chars!!",
    })
    expect([reply.status, body(reply)["outcome"]]).toEqual([200, "allow"])
    expect(body(await later.get("/auth/session"))["session"]).toMatchObject({
      subject,
      state: "authenticated",
      level: "AAL1",
    })
  })

  it("signs out a pre-auth session of someone who knew only the password, once the owner confirms TOTP", async () => {
    const setup = testAuth()
    const { browser: owner } = await signedUp(setup)
    await expectOk(owner.post("/auth/password", { password: PASSWORD }))
    const intruder = new Browser(inProcess(setup.auth))
    await intruder.start()
    const signIn = await intruder.post("/auth/sign-in", {
      identifier: "ada@example.com",
      password: PASSWORD,
    })
    expect(body(signIn)["outcome"]).toBe("enroll")
    const begun = (await owner.post("/auth/totp/enrol")).json as {
      authenticatorId: string
      secret: string
    }
    setup.clock.advance(30_000)
    await expectOk(
      owner.post("/auth/totp/confirm", {
        authenticatorId: begun.authenticatorId,
        code: await codeAt(begun.secret, setup.clock.now()),
      }),
    )
    // Finishing enrolment is a credential change: every other session of the account is gone.
    expect(body(await intruder.get("/auth/session"))["session"]).toBeNull()
    expect((await intruder.post("/auth/totp/enrol")).status).toBe(401)
  })

  it("refuses TOTP enrolment to a pre-auth session whose account already has a second factor, and signs it out", async () => {
    for (const path of ["/auth/totp/enrol", "/auth/totp/confirm"] as const) {
      const setup = testAuth()
      const { subject } = await seedAccount(setup, { password: true, totp: true })
      // A pre-auth session that outlived the account's enrolment, however it did.
      const { browser } = await seedSession(setup, { subject, state: "pre-auth" })
      const fields =
        path === "/auth/totp/confirm" ? { authenticatorId: "A".repeat(43), code: "000000" } : {}
      const reply = await browser.post(path, fields)
      expect([reply.status, reply.text], path).toEqual([401, '{"error":"unauthenticated"}'])
      expect(body(await browser.get("/auth/session"))["session"], path).toBeNull()
    }
  })

  it("counts a revoked TOTP authenticator as none", async () => {
    const setup = testAuth()
    const { subject, secret } = await seedAccount(setup, { password: true, totp: true })
    for (const record of await setup.store.listByOwner(TENANT, "totp", subject)) {
      expect(await setup.store.revoke(TENANT, "totp", record.key, setup.clock.now())).toBe(true)
    }
    expect(secret).toBeTypeOf("string")
    const later = new Browser(inProcess(setup.auth))
    await later.start()
    const reply = await later.post("/auth/sign-in", {
      identifier: "ada@example.com",
      password: PASSWORD,
    })
    expect(body(reply)["outcome"]).toBe("enroll")
  })
})
