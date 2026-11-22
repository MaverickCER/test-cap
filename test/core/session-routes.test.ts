// F14 through the dispatcher: the session endpoint, sign-out, the session list and remote revoke (ADR 0006).
import { describe, expect, it } from "vitest"
import { CSRF_COOKIE } from "../../src/security/csrf.js"
import { hexEncode, sha256, utf8Encode } from "../../src/core/encoding.js"
import {
  aal1,
  aal2,
  body,
  Browser,
  inProcess,
  seedSession,
  testAuth,
  brief,
  LOGOFF,
} from "../support/auth.js"

const uid = async (token: string) => hexEncode(await sha256(utf8Encode(token))).slice(0, 16)

describe("GET /auth/session", () => {
  it("gives a fresh browser a pre-session cookie and a token bound to it", async () => {
    const { auth, clock } = testAuth()
    const browser = new Browser(inProcess(auth))
    const reply = await browser.get("/auth/session")
    expect(reply.status).toBe(200)
    expect(body(reply)["session"]).toBeNull()
    expect(Object.keys(body(reply))).toEqual(["session", "csrfToken"])
    expect(body(reply)["csrfToken"]).toMatch(new RegExp(`^c1\\.${clock.now() + 3_600_000}\\.`))
    expect(reply.headers.getSetCookie()).toEqual([
      expect.stringMatching(
        new RegExp(`^${CSRF_COOKIE}=[A-Za-z0-9_-]{43}; Path=/; Secure; HttpOnly; SameSite=Lax$`),
      ),
    ])
    expect(reply.headers.get("cache-control")).toBe("no-store")
  })

  it("keeps the pre-session cookie a browser already holds, and its token keeps working", async () => {
    const { auth } = testAuth()
    const browser = new Browser(inProcess(auth))
    await browser.start()
    const cookie = browser.cookies.get(CSRF_COOKIE)
    const again = await browser.start()
    expect(again.headers.getSetCookie()).toEqual([])
    expect(browser.cookies.get(CSRF_COOKIE)).toBe(cookie)
    expect((await browser.post("/auth/sign-up", { identifier: "ada@example.com" })).status).toBe(
      200,
    )
  })

  it("describes the session without its token, and binds the token to the session", async () => {
    const setup = testAuth()
    const { browser, id, token } = await seedSession(setup, {
      subject: "acct-9",
      evidence: aal2(setup.clock),
    })
    const reply = await browser.get("/auth/session")
    expect(reply.headers.getSetCookie()).toEqual([])
    expect(body(reply)["session"]).toEqual({
      id,
      subject: "acct-9",
      state: "authenticated",
      level: "AAL2",
      methods: ["password", "totp"],
      idleExpiresAt: setup.clock.now() + 3_600_000,
      absoluteExpiresAt: setup.clock.now() + 86_400_000,
    })
    expect(reply.text).not.toContain(token)
    browser.cookies.delete("__Host-test-cap")
    expect((await browser.post("/auth/sign-out")).status).toBe(403)
  })

  it("reports no session for a revoked or expired one", async () => {
    const setup = testAuth()
    const { browser } = await seedSession(setup, { evidence: aal2(setup.clock) })
    setup.clock.advance(3_600_000)
    expect(body(await browser.get("/auth/session"))["session"]).toBeNull()
  })
})

describe("sign-out", () => {
  it("revokes the session, clears the cookie and reports the logoff", async () => {
    const setup = testAuth()
    const { browser, token } = await seedSession(setup, {
      subject: "acct-9",
      evidence: aal2(setup.clock),
    })
    const reply = await browser.post("/auth/sign-out")
    expect([reply.status, reply.text]).toEqual([200, '{"outcome":"unauthenticated"}'])
    expect(reply.headers.getSetCookie()).toEqual([
      "__Host-test-cap=-; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
    ])
    expect(setup.events.map(brief)).toEqual([
      {
        type: LOGOFF,
        status: "Success",
        user: "acct-9",
        session: await uid(token),
        detail: "sign-out",
      },
    ])
    const old = new Browser(inProcess(setup.auth))
    old.cookies.set("__Host-test-cap", token)
    expect(body(await old.get("/auth/session"))["session"]).toBeNull()
  })

  it("answers the same without a session, and reports nothing", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    const reply = await browser.post("/auth/sign-out")
    expect([reply.status, reply.text]).toEqual([200, '{"outcome":"unauthenticated"}'])
    expect(setup.events.map(brief)).toEqual([])
  })
})

describe("the session list and remote revoke", () => {
  it("lists the account's own sessions for a session meeting the default requirement", async () => {
    const setup = testAuth()
    const mine = await seedSession(setup, { subject: "acct-1", evidence: aal2(setup.clock) })
    const other = await seedSession(setup, { subject: "acct-1", evidence: aal2(setup.clock) })
    await seedSession(setup, { subject: "acct-2", evidence: aal2(setup.clock) })
    const reply = await mine.browser.get("/auth/sessions")
    expect(reply.status).toBe(200)
    const sessions = body(reply)["sessions"] as { id: string; current: boolean }[]
    expect(sessions.map(({ id, current }) => [id, current])).toEqual([
      [mine.id, true],
      [other.id, false],
    ])
  })

  it.each([
    ["no session", undefined, 401, "unauthenticated"],
    ["an AAL1 session", "aal1", 403, "step-up"],
    ["an enrolling session", "pre-auth", 403, "enroll"],
  ] as const)("refuses %s", async (_name, kind, status, code) => {
    const setup = testAuth()
    let browser: Browser
    if (kind === undefined) {
      browser = new Browser(inProcess(setup.auth))
      await browser.start()
    } else {
      browser = (
        await seedSession(
          setup,
          kind === "aal1" ? { evidence: aal1(setup.clock) } : { state: "pre-auth" },
        )
      ).browser
    }
    const list = await browser.get("/auth/sessions")
    expect([list.status, list.text]).toEqual([status, `{"error":"${code}"}`])
    const revoke = await browser.post("/auth/sessions/revoke", { sessionId: "x" })
    expect([revoke.status, revoke.text]).toEqual([status, `{"error":"${code}"}`])
  })

  it("revokes another of the account's sessions, keeping this one's cookie", async () => {
    const setup = testAuth()
    const mine = await seedSession(setup, { subject: "acct-1", evidence: aal2(setup.clock) })
    const other = await seedSession(setup, { subject: "acct-1", evidence: aal2(setup.clock) })
    const reply = await mine.browser.post("/auth/sessions/revoke", { sessionId: other.id })
    expect([reply.status, reply.text, reply.headers.getSetCookie()]).toEqual([
      200,
      '{"revoked":true}',
      [],
    ])
    expect(setup.events.map(brief)).toEqual([
      {
        type: LOGOFF,
        status: "Success",
        user: "acct-1",
        detail: "remote-revoke",
      },
    ])
    expect(body(await other.browser.get("/auth/session"))["session"]).toBeNull()
    expect(body(await mine.browser.get("/auth/session"))["session"]).not.toBeNull()
  })

  it("clears the cookie when the revoked session is this one", async () => {
    const setup = testAuth()
    const mine = await seedSession(setup, { subject: "acct-1", evidence: aal2(setup.clock) })
    const reply = await mine.browser.post("/auth/sessions/revoke", { sessionId: mine.id })
    expect(reply.headers.getSetCookie()).toEqual([
      "__Host-test-cap=-; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
    ])
  })

  it("answers 404 for a session id that is not the account's", async () => {
    const setup = testAuth()
    const mine = await seedSession(setup, { subject: "acct-1", evidence: aal2(setup.clock) })
    const theirs = await seedSession(setup, { subject: "acct-2", evidence: aal2(setup.clock) })
    const reply = await mine.browser.post("/auth/sessions/revoke", { sessionId: theirs.id })
    expect([reply.status, reply.text]).toEqual([404, '{"error":"not-found"}'])
    expect(setup.events.map(brief)).toEqual([])
    expect(body(await theirs.browser.get("/auth/session"))["session"]).not.toBeNull()
  })
})
