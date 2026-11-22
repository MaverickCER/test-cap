// F02 password sign-in, F04 TOTP verification and F13 step-up through the dispatcher.
import { describe, expect, it } from "vitest"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import { ACCOUNT_COLLECTION } from "../../src/core/accounts.js"
import { hexEncode, sha256, utf8Encode } from "../../src/core/encoding.js"
import { HASH_CONCURRENCY, HASH_QUEUE_LIMIT, hashing } from "../../src/methods/password/argon2.js"
import { memoryStore } from "../../src/store/memory.js"
import {
  aal1,
  aal2,
  body,
  Browser,
  expectOk,
  hookedStore,
  inProcess,
  ORIGIN,
  PASSWORD,
  plainRequest,
  replyOf,
  seedAccount,
  seedSession,
  TENANT,
  testAuth,
  brief,
  LOGON,
} from "../support/auth.js"
import { codeAt } from "../support/totp.js"

/** Fills every argon2 slot and the whole queue, runs `work`, then frees them. */
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

const uid = async (token: string) => hexEncode(await sha256(utf8Encode(token))).slice(0, 16)

async function signedOut(setup: ReturnType<typeof testAuth>) {
  const browser = new Browser(inProcess(setup.auth))
  await browser.start()
  return browser
}

async function disable(setup: ReturnType<typeof testAuth>, subject: string) {
  const record = await setup.store.get(TENANT, ACCOUNT_COLLECTION, subject)
  await setup.store.update(TENANT, ACCOUNT_COLLECTION, subject, record?.version ?? 0, {
    data: { status: "disabled" },
  })
}

describe("password sign-in", () => {
  it("issues an AAL1 session that the default requirement still steps up", async () => {
    const setup = testAuth()
    const { subject } = await seedAccount(setup, { password: true })
    const browser = await signedOut(setup)
    const reply = await browser.post("/auth/sign-in", {
      identifier: "ADA@example.com",
      password: PASSWORD,
    })
    expect([reply.status, reply.text]).toEqual([200, '{"outcome":"step-up","returnTo":"/"}'])
    const token = browser.cookies.get("__Host-test-cap") ?? ""
    expect(setup.events.map(brief)).toEqual([
      {
        type: LOGON,
        status: "Success",
        user: subject,
        factors: ["Password"],
        session: await uid(token),
      },
    ])
    expect(body(await browser.get("/auth/session"))["session"]).toMatchObject({
      subject,
      state: "authenticated",
      level: "AAL1",
      methods: ["password"],
    })
  })

  it("revokes the session the browser presented, never adopting it", async () => {
    const setup = testAuth()
    const { subject } = await seedAccount(setup, { password: true })
    const { browser, token } = await seedSession(setup, {
      subject: "someone-else",
      evidence: aal2(setup.clock),
    })
    await expectOk(
      browser.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD }),
    )
    expect(browser.cookies.get("__Host-test-cap")).not.toBe(token)
    const old = new Browser(inProcess(setup.auth))
    old.cookies.set("__Host-test-cap", token)
    expect(body(await old.get("/auth/session"))["session"]).toBeNull()
    expect(body(await browser.get("/auth/session"))["session"]).toMatchObject({ subject })
  })

  it("answers a form whose sign-in meets the requirement with a redirect, and JSON when it does not", async () => {
    const lenient = testAuth({
      policy: defineAuthPolicy({ version: "v", defaultRequirement: { level: "AAL1" } }),
    })
    await seedAccount(lenient, { password: true })
    const form = await (
      await signedOut(lenient)
    ).postForm("/auth/sign-in", {
      identifier: "ada@example.com",
      password: PASSWORD,
      returnTo: "/inbox?x=1",
    })
    expect([form.status, form.headers.get("location"), form.text]).toEqual([303, "/inbox?x=1", ""])
    const json = await (
      await signedOut(lenient)
    ).post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD })
    expect(json.text).toBe('{"outcome":"allow","returnTo":"/"}')
    const strict = testAuth()
    await seedAccount(strict, { password: true })
    const stepUp = await (
      await signedOut(strict)
    ).postForm("/auth/sign-in", {
      identifier: "ada@example.com",
      password: PASSWORD,
    })
    expect([stepUp.status, stepUp.text]).toEqual([200, '{"outcome":"step-up","returnTo":"/"}'])
  })

  it("gives one reply for a wrong password, an unknown, unconfirmed or malformed identifier and a disabled account", async () => {
    const setup = testAuth()
    const { subject } = await seedAccount(setup, { password: true })
    await seedAccount(setup, { password: true, identifier: "off@example.com" }).then(
      ({ subject: off }) => disable(setup, off),
    )
    // A sign-up that set a password but never redeemed its confirmation code.
    await seedAccount(setup, { password: true, identifier: "new@example.com", confirmed: false })
    setup.events.length = 0
    const attempts = [
      ["ada@example.com", "wrong password here"],
      ["nobody@example.com", PASSWORD],
      ["new@example.com", PASSWORD],
      ["not an address", PASSWORD],
      ["off@example.com", PASSWORD],
      ["ada@example.com", "x".repeat(300)],
    ] as const
    for (const [identifier, password] of attempts) {
      const reply = await (await signedOut(setup)).post("/auth/sign-in", { identifier, password })
      expect([reply.status, reply.text, reply.headers.getSetCookie()]).toEqual([
        401,
        '{"error":"invalid-credentials"}',
        [],
      ])
    }
    expect(setup.events.map((event) => brief(event)["user"])).toEqual([
      subject,
      "unknown",
      "unknown",
      "unknown",
      "unknown",
      subject,
    ])
    expect(brief(setup.events[0])).toEqual({
      type: LOGON,
      status: "Failure",
      user: subject,
      factors: ["Password"],
      detail: "invalid",
    })
    expect(brief(setup.events[5])).toMatchObject({ detail: "too-long" })
  })

  it("refuses a bad returnTo before any password work", async () => {
    const setup = testAuth()
    const reply = await (
      await signedOut(setup)
    ).post("/auth/sign-in", {
      identifier: "ada@example.com",
      password: PASSWORD,
      returnTo: "javascript:alert(1)",
    })
    expect([reply.status, reply.text]).toEqual([400, '{"error":"invalid-return-to"}'])
    expect(setup.events.map(brief)).toEqual([])
  })

  it("answers busy when the argon2 queue is full", async () => {
    const setup = testAuth()
    const browser = await signedOut(setup)
    const reply = await whileBusy(() =>
      browser.post("/auth/sign-in", { identifier: "nobody@example.com", password: PASSWORD }),
    )
    expect([reply.status, reply.text]).toEqual([503, '{"error":"busy"}'])
    expect(setup.events.map(brief)).toEqual([
      { type: LOGON, status: "Failure", user: "unknown", factors: ["Password"], detail: "busy" },
    ])
  })

  it("stops before writing a session once the client has gone away", async () => {
    const setup = testAuth()
    await seedAccount(setup, { password: true })
    const browser = await signedOut(setup)
    const controller = new AbortController()
    const request = plainRequest(
      {
        method: "POST",
        path: "/auth/sign-in",
        headers: [
          ["Origin", ORIGIN],
          ["Content-Type", "application/json"],
          ["X-CSRF-Token", browser.csrf ?? ""],
          ["Cookie", [...browser.cookies].map(([name, value]) => `${name}=${value}`).join("; ")],
        ],
        body: JSON.stringify({ identifier: "ada@example.com", password: PASSWORD }),
      },
      controller.signal,
    )
    const pending = setup.auth.handle(request)
    controller.abort()
    const reply = replyOf((await pending) ?? (null as never))
    expect([reply.status, reply.text]).toEqual([400, '{"error":"aborted"}'])
    expect(
      await setup.store.listByOwner(
        TENANT,
        "session",
        (await setup.store.get(TENANT, "identifier", "ada@example.com"))?.owner ?? "",
      ),
    ).toEqual([])
  })
})

describe("TOTP verification", () => {
  it("raises a password session to AAL2 and rotates its token", async () => {
    const setup = testAuth()
    const { subject, secret } = await seedAccount(setup, { totp: true })
    const { browser, token } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    const reply = await browser.post("/auth/totp/verify", {
      code: await codeAt(secret ?? "", setup.clock.now()),
      returnTo: "/after",
    })
    expect([reply.status, reply.text]).toEqual([200, '{"outcome":"allow","returnTo":"/after"}'])
    const next = browser.cookies.get("__Host-test-cap") ?? ""
    expect(next).not.toBe(token)
    expect(setup.events.map(brief)).toEqual([
      {
        type: LOGON,
        status: "Success",
        user: subject,
        factors: ["OTP"],
        session: await uid(next),
      },
    ])
    expect(body(await browser.get("/auth/session"))["session"]).toMatchObject({ level: "AAL2" })
  })

  it("refuses a wrong code, and a right one for a disabled account", async () => {
    const setup = testAuth()
    const { subject, secret } = await seedAccount(setup, { totp: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    const wrong = await browser.post("/auth/totp/verify", { code: "000000" })
    expect([wrong.status, wrong.text]).toEqual([401, '{"error":"invalid-code"}'])
    expect(setup.events.map(brief)).toEqual([
      {
        type: LOGON,
        status: "Failure",
        user: subject,
        factors: ["OTP"],
        detail: "invalid",
      },
    ])
    await disable(setup, subject)
    const right = await browser.post("/auth/totp/verify", {
      code: await codeAt(secret ?? "", setup.clock.now()),
    })
    expect([right.status, right.text]).toEqual([401, '{"error":"invalid-code"}'])
  })

  it("needs a signed-in session", async () => {
    const setup = testAuth()
    const none = await (await signedOut(setup)).post("/auth/totp/verify", { code: "123456" })
    expect([none.status, none.text]).toEqual([401, '{"error":"unauthenticated"}'])
    const { browser } = await seedSession(setup, { state: "pre-auth" })
    const enrolling = await browser.post("/auth/totp/verify", { code: "123456" })
    expect([enrolling.status, enrolling.text]).toEqual([403, '{"error":"enroll"}'])
  })

  it("refuses a bad returnTo", async () => {
    const setup = testAuth()
    const { browser } = await seedSession(setup, { evidence: aal1(setup.clock) })
    const reply = await browser.post("/auth/totp/verify", {
      code: "123456",
      returnTo: "//evil.example",
    })
    expect([reply.status, reply.text]).toEqual([400, '{"error":"invalid-return-to"}'])
  })

  it("answers unauthenticated when the session is revoked between the code check and the rotation", async () => {
    const base = memoryStore()
    let armed = false
    let subject = ""
    const setup = testAuth({
      store: hookedStore(base, async (operation, args) => {
        if (armed && operation === "update" && args[1] === "totp") {
          armed = false
          await base.revokeByOwner(TENANT, "session", subject, 0)
        }
      }),
    })
    const seeded = await seedAccount(setup, { totp: true })
    subject = seeded.subject
    const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    armed = true
    const reply = await browser.post("/auth/totp/verify", {
      code: await codeAt(seeded.secret ?? "", setup.clock.now()),
    })
    expect([reply.status, reply.text]).toEqual([401, '{"error":"unauthenticated"}'])
  })
})

describe("step-up", () => {
  it("opens a challenge for a signed-in session only", async () => {
    const setup = testAuth()
    const none = await (await signedOut(setup)).post("/auth/step-up/start")
    expect([none.status, none.text]).toEqual([401, '{"error":"unauthenticated"}'])
    const { browser } = await seedSession(setup, { evidence: aal1(setup.clock) })
    const reply = await browser.post("/auth/step-up/start")
    expect(reply.status).toBe(200)
    expect(Object.keys(body(reply))).toEqual(["challenge"])
    expect(body(reply)["challenge"]).toMatch(/^[A-Za-z0-9_-]{22}$/)
  })

  it("adds TOTP evidence under the session's own challenge and rotates the token", async () => {
    const setup = testAuth()
    const { subject, secret } = await seedAccount(setup, { totp: true })
    const { browser, token } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    const { challenge } = body(await browser.post("/auth/step-up/start")) as { challenge: string }
    setup.events.length = 0
    const reply = await browser.post("/auth/step-up", {
      challenge,
      code: await codeAt(secret ?? "", setup.clock.now()),
    })
    expect([reply.status, reply.text]).toEqual([200, '{"outcome":"allow","returnTo":"/"}'])
    const next = browser.cookies.get("__Host-test-cap") ?? ""
    expect(next).not.toBe(token)
    expect(setup.events.map(brief)).toEqual([
      {
        type: LOGON,
        status: "Success",
        user: subject,
        factors: ["OTP"],
        stepUp: true,
        session: await uid(next),
      },
    ])
  })

  it("adds password evidence the same way", async () => {
    const setup = testAuth()
    const { subject } = await seedAccount(setup, { password: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal2(setup.clock) })
    setup.clock.advance(60_000)
    const { challenge } = body(await browser.post("/auth/step-up/start")) as { challenge: string }
    const reply = await browser.post("/auth/step-up", {
      challenge,
      password: PASSWORD,
      returnTo: "/x",
    })
    expect(reply.text).toBe('{"outcome":"allow","returnTo":"/x"}')
    expect(brief(setup.events.at(-1))).toMatchObject({
      factors: ["Password"],
      stepUp: true,
      status: "Success",
    })
    expect(body(await browser.get("/auth/session"))["session"]).toMatchObject({
      methods: ["password", "totp", "password"],
    })
  })

  it("refuses a wrong secret, and a right one for a disabled account", async () => {
    const setup = testAuth()
    const { subject } = await seedAccount(setup, { password: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    const { challenge } = body(await browser.post("/auth/step-up/start")) as { challenge: string }
    const wrong = await browser.post("/auth/step-up", { challenge, password: "not the password" })
    expect([wrong.status, wrong.text]).toEqual([401, '{"error":"invalid-credentials"}'])
    expect(brief(setup.events.at(-1))).toEqual({
      type: LOGON,
      status: "Failure",
      user: subject,
      factors: ["Password"],
      stepUp: true,
      detail: "invalid",
    })
    const code = await browser.post("/auth/step-up", { challenge, code: "000000" })
    expect([code.status, code.text]).toEqual([401, '{"error":"invalid-credentials"}'])
    expect(brief(setup.events.at(-1))).toMatchObject({ factors: ["OTP"] })
    await disable(setup, subject)
    const right = await browser.post("/auth/step-up", { challenge, password: PASSWORD })
    expect([right.status, right.text]).toEqual([401, '{"error":"invalid-credentials"}'])
  })

  it("refuses a challenge this session did not open", async () => {
    const setup = testAuth()
    const { subject } = await seedAccount(setup, { password: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    const reply = await browser.post("/auth/step-up", {
      challenge: "A".repeat(22),
      password: PASSWORD,
    })
    expect([reply.status, reply.text]).toEqual([403, '{"error":"invalid-challenge"}'])
    expect(brief(setup.events.at(-1))).toEqual({
      type: LOGON,
      status: "Failure",
      user: subject,
      factors: ["Password"],
      stepUp: true,
      detail: "invalid-challenge",
    })
  })

  it("takes exactly one secret", async () => {
    const setup = testAuth()
    const { browser } = await seedSession(setup, { evidence: aal1(setup.clock) })
    const both = await browser.post("/auth/step-up", {
      challenge: "c",
      password: PASSWORD,
      code: "123456",
    })
    expect([both.status, both.text]).toEqual([400, '{"error":"one-secret"}'])
    const neither = await browser.post("/auth/step-up", { challenge: "c" })
    expect([neither.status, neither.text]).toEqual([400, '{"error":"one-secret"}'])
  })

  it("needs a signed-in session, and a good returnTo", async () => {
    const setup = testAuth()
    const none = await (
      await signedOut(setup)
    ).post("/auth/step-up", { challenge: "c", code: "123456" })
    expect([none.status, none.text]).toEqual([401, '{"error":"unauthenticated"}'])
    const { browser } = await seedSession(setup, { state: "recovery-only" })
    const recovering = await browser.post("/auth/step-up", { challenge: "c", code: "123456" })
    expect([recovering.status, recovering.text]).toEqual([403, '{"error":"recovery-only"}'])
    const bad = await browser.post("/auth/step-up", { challenge: "c", code: "1", returnTo: "x" })
    expect([bad.status, bad.text]).toEqual([400, '{"error":"invalid-return-to"}'])
  })

  it("answers busy when the argon2 queue is full", async () => {
    const setup = testAuth()
    const { subject } = await seedAccount(setup, { password: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    const reply = await whileBusy(() =>
      browser.post("/auth/step-up", { challenge: "A".repeat(22), password: PASSWORD }),
    )
    expect([reply.status, reply.text]).toEqual([503, '{"error":"busy"}'])
  })

  it("stops before rotating once the client has gone away", async () => {
    const setup = testAuth()
    const { subject } = await seedAccount(setup, { password: true })
    const { browser, token } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    const { challenge } = body(await browser.post("/auth/step-up/start")) as { challenge: string }
    const controller = new AbortController()
    const pending = setup.auth.handle(
      plainRequest(
        {
          method: "POST",
          path: "/auth/step-up",
          headers: [
            ["Origin", ORIGIN],
            ["Content-Type", "application/json"],
            ["X-CSRF-Token", browser.csrf ?? ""],
            ["Cookie", `__Host-test-cap=${token}`],
          ],
          body: JSON.stringify({ challenge, password: PASSWORD }),
        },
        controller.signal,
      ),
    )
    controller.abort()
    expect(replyOf((await pending) ?? (null as never)).text).toBe('{"error":"aborted"}')
    expect(body(await browser.get("/auth/session"))["session"]).toMatchObject({ level: "AAL1" })
  })

  it("stops TOTP verification before rotating once the client has gone away", async () => {
    const setup = testAuth()
    const { subject, secret } = await seedAccount(setup, { totp: true })
    const { browser, token } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    const controller = new AbortController()
    const pending = setup.auth.handle(
      plainRequest(
        {
          method: "POST",
          path: "/auth/totp/verify",
          headers: [
            ["Origin", ORIGIN],
            ["Content-Type", "application/json"],
            ["X-CSRF-Token", browser.csrf ?? ""],
            ["Cookie", `__Host-test-cap=${token}`],
          ],
          body: JSON.stringify({ code: await codeAt(secret ?? "", setup.clock.now()) }),
        },
        controller.signal,
      ),
    )
    controller.abort()
    expect(replyOf((await pending) ?? (null as never)).text).toBe('{"error":"aborted"}')
    expect(body(await browser.get("/auth/session"))["session"]).toMatchObject({ level: "AAL1" })
  })
})
