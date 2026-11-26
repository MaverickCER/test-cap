// The recovery routes' less travelled paths (ADR 0007): the events each one emits, the cookie finishing clears, a weak
// replacement password, a client that leaves mid-request, a session another request changed first, and CSRF refusals.
import { describe, expect, it } from "vitest"
import { SESSION_COLLECTION } from "../../src/sessions/sessions.js"
import { memoryStore } from "../../src/store/memory.js"
import {
  account,
  brief,
  Browser,
  ENABLE_MFA,
  hookedStore,
  inProcess,
  LOGON,
  PASSWORD,
  plainRequest,
  replyOf,
  testAuth,
  UPDATE,
} from "../support/auth.js"
import { codeAt } from "../support/totp.js"

async function withCodes(setup: ReturnType<typeof testAuth>) {
  const enrolled = await account(setup)
  await enrolled.browser.post("/auth/sign-in", {
    identifier: "ada@example.com",
    password: PASSWORD,
  })
  setup.clock.advance(30_000)
  await enrolled.browser.post("/auth/totp/verify", {
    code: await codeAt(enrolled.secret, setup.clock.now()),
  })
  const made = await enrolled.browser.post("/auth/recovery-codes")
  return { ...enrolled, codes: (made.json as { codes: string[] }).codes }
}

async function recovering(
  setup: ReturnType<typeof testAuth>,
  code: string,
  identifier = "ada@example.com",
) {
  const browser = new Browser(inProcess(setup.auth))
  await browser.start()
  const reply = await browser.post("/auth/recovery", { identifier, code })
  return { browser, reply }
}

/**
 * A store where, once `armed.subject` is set, the next transaction (a session rotation) first sees every session of
 * that account signed out by another request.
 */
function racingStore() {
  const base = memoryStore()
  const armed: { subject: string | null } = { subject: null }
  const store = new Proxy(base, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver) as unknown
      if (property !== "transaction") return value
      return async (run: (ops: unknown) => Promise<unknown>) => {
        if (armed.subject !== null) {
          await base.revokeByOwner("default", SESSION_COLLECTION, armed.subject, 0)
          armed.subject = null
        }
        return (value as (r: typeof run) => Promise<unknown>).call(target, run)
      }
    },
  })
  return { store, armed }
}

describe("recovery events", () => {
  it("records making codes, a refused code, a redeemed one and the finish", async () => {
    const setup = testAuth()
    const { subject, codes } = await withCodes(setup)
    const from = setup.events.length
    await recovering(setup, "AAAAAA-AAAA-AAAA-AAAA-AAAA")
    const { browser } = await recovering(setup, codes[0] as string)
    await browser.post("/auth/recovery/finish")
    expect(setup.events.slice(from).map(brief)).toEqual([
      {
        type: LOGON,
        status: "Failure",
        user: subject,
        detail: "invalid",
        factors: ["Recovery Code"],
      },
      {
        type: LOGON,
        status: "Success",
        user: subject,
        detail: "recovery",
        factors: ["Recovery Code"],
      },
      { type: UPDATE, status: "Success", user: subject, detail: "recovery-complete" },
    ])
    expect(setup.events.slice(0, from).map(brief).at(-1)).toEqual({
      type: ENABLE_MFA,
      status: "Success",
      user: subject,
      factors: ["Recovery Code"],
    })
  })

  it("clears the session cookie when the recovery finishes", async () => {
    const setup = testAuth()
    const { codes } = await withCodes(setup)
    const { browser } = await recovering(setup, codes[0] as string)
    const finished = await browser.post("/auth/recovery/finish")
    expect(finished.headers.getSetCookie()).toEqual([
      expect.stringMatching(/^__Host-test-cap=-; Path=\/; Max-Age=0;/),
    ])
  })
})

describe("recovery's replacement password", () => {
  it("refuses a weak or context-word password, with the reason and a failure event", async () => {
    const setup = testAuth()
    const { subject, codes } = await withCodes(setup)
    const { browser } = await recovering(setup, codes[0] as string)
    const from = setup.events.length
    const short = await browser.post("/auth/password", { password: "short" })
    expect([short.status, short.text]).toEqual([400, '{"error":"too-short"}'])
    const context = await browser.post("/auth/password", { password: "my billing-web pass phrase" })
    expect([context.status, context.text]).toEqual([400, '{"error":"too-common"}'])
    expect(setup.events.slice(from).map(brief)).toEqual([
      {
        type: UPDATE,
        status: "Failure",
        user: subject,
        detail: "too-short",
        factors: ["Password"],
      },
      {
        type: UPDATE,
        status: "Failure",
        user: subject,
        detail: "too-common",
        factors: ["Password"],
      },
    ])
    const good = await browser.post("/auth/password", { password: "a new passphrase for ada" })
    expect(good.status).toBe(200)
    expect(brief(setup.events.at(-1))).toEqual({
      type: UPDATE,
      status: "Success",
      user: subject,
      detail: "recovery",
      factors: ["Password"],
    })
  })

  it("answers unauthenticated when another request changed the session first", async () => {
    const { store, armed } = racingStore()
    const setup = testAuth({ store })
    const { subject, codes } = await withCodes(setup)
    const { browser } = await recovering(setup, codes[0] as string)
    armed.subject = subject
    const reply = await browser.post("/auth/password", { password: "a new passphrase for ada" })
    expect([reply.status, reply.text]).toEqual([401, '{"error":"unauthenticated"}'])
  })
})

describe("redeeming a code", () => {
  it("starts its session in the transaction that spends the code, so a sign-out just before changes nothing", async () => {
    const { store, armed } = racingStore()
    const setup = testAuth({ store })
    const { subject, codes } = await withCodes(setup)
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    armed.subject = subject
    const reply = await browser.post("/auth/recovery", {
      identifier: "ada@example.com",
      code: codes[0],
    })
    expect([reply.status, reply.json]).toEqual([200, { outcome: "recovery-only", returnTo: "/" }])
    expect(armed.subject).toBeNull()
  })

  it("starts no session once the client has gone away during the redemption", async () => {
    const controller = new AbortController()
    const armed = { on: false }
    const store = hookedStore(memoryStore(), (operation, args) => {
      // The client leaves while its code's row is read, before the code is checked and spent.
      if (armed.on && operation === "get" && args[1] === "recovery-code") controller.abort()
      return Promise.resolve()
    })
    const setup = testAuth({ store })
    const { subject, codes } = await withCodes(setup)
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    const liveSessions = async () =>
      (await setup.store.listByOwner("default", SESSION_COLLECTION, subject)).filter(
        (record) => record.revokedAt === null,
      ).length
    const before = await liveSessions()
    armed.on = true
    const reply = replyOf(
      (await setup.auth.handle(
        plainRequest(
          {
            method: "POST",
            path: "/auth/recovery",
            headers: [
              ["Origin", browser.origin],
              ["Content-Type", "application/json"],
              ["X-CSRF-Token", browser.csrf ?? ""],
              [
                "Cookie",
                [...browser.cookies].map(([name, value]) => `${name}=${value}`).join("; "),
              ],
            ],
            body: JSON.stringify({ identifier: "ada@example.com", code: codes[0] }),
          },
          controller.signal,
        ),
      )) ?? (null as never),
    )
    expect([reply.status, reply.text]).toEqual([400, '{"error":"aborted"}'])
    // No recovery-only session was started, and the account's sessions were not signed out.
    expect(await liveSessions()).toBe(before)
    // The transaction that spent the code rolled back, so the code still works.
    armed.on = false
    const again = await browser.post("/auth/recovery", {
      identifier: "ada@example.com",
      code: codes[0],
    })
    expect(again.status).toBe(200)
  })

  it("throttles by the identifier as normalised, whatever case it was typed in", async () => {
    const setup = testAuth()
    await withCodes(setup)
    for (const [i, typed] of ["ADA@example.com", "Ada@Example.com", "ada@EXAMPLE.com"].entries()) {
      for (let j = 0; j < 2; j += 1) {
        const browser = new Browser(inProcess(setup.auth))
        await browser.start()
        await browser.post(
          "/auth/recovery",
          { identifier: typed, code: "AAAAAA-AAAA-AAAA-AAAA-AAAA" },
          { clientAddress: `198.51.100.${String(i * 2 + j)}` },
        )
      }
    }
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    const reply = await browser.post(
      "/auth/recovery",
      { identifier: "ada@example.com", code: "AAAAAA-AAAA-AAAA-AAAA-AAAA" },
      { clientAddress: "203.0.113.9" },
    )
    expect(reply.status).toBe(429)
  })

  it("throttles text that is no address by the text itself", async () => {
    const setup = testAuth()
    for (let i = 0; i < 6; i += 1) {
      const browser = new Browser(inProcess(setup.auth))
      await browser.start()
      await browser.post(
        "/auth/recovery",
        { identifier: "not an address", code: "x" },
        { clientAddress: `198.51.100.${String(i)}` },
      )
    }
    const send = async (identifier: string) => {
      const browser = new Browser(inProcess(setup.auth))
      await browser.start()
      return browser.post(
        "/auth/recovery",
        { identifier, code: "x" },
        { clientAddress: "203.0.113.9" },
      )
    }
    expect((await send("not an address")).status).toBe(429)
    expect((await send("another non-address")).status).toBe(401)
  })
})

describe("CSRF refusals on the recovery routes", () => {
  it("names each route's activity in the refusal event", async () => {
    const setup = testAuth()
    for (const path of ["/auth/recovery-codes", "/auth/recovery", "/auth/recovery/finish"]) {
      await new Browser(inProcess(setup.auth)).send({
        method: "POST",
        path,
        headers: [
          ["Origin", "https://evil.example"],
          ["Content-Type", "application/json"],
        ],
        body: "{}",
      })
    }
    expect(setup.events.map(brief)).toEqual([
      { type: ENABLE_MFA, status: "Failure", user: "unknown", detail: "csrf" },
      { type: LOGON, status: "Failure", user: "unknown", detail: "csrf" },
      { type: UPDATE, status: "Failure", user: "unknown", detail: "csrf" },
    ])
  })
})
