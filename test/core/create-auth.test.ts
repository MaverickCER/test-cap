// createAuth (ADR 0003 §6, ADR 0026 §3–§4): the readiness check, the defaults, and the members of Auth.
import { describe, expect, it } from "vitest"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import { createAuth, internalsOf } from "../../src/core/auth.js"
import { fixedClock, sequenceRandom } from "../../src/core/clock.js"
import { ConfigError } from "../../src/core/errors.js"
import { PASSWORD_COLLECTION } from "../../src/methods/password/method.js"
import { memoryStore } from "../../src/store/memory.js"
import { TEST_ARGON2_COST } from "../support/argon2.js"
import {
  aal1,
  aal2,
  body,
  Browser,
  ENV,
  confirmEmail,
  discardEmail,
  hibpClear,
  inProcess,
  keyRing,
  PASSWORD,
  seedSession,
  T0,
  testAuth,
} from "../support/auth.js"

const durable = () => ({ ...memoryStore(), kind: "sql", durable: true })

function problems(run: () => unknown): readonly string[] {
  try {
    run()
  } catch (error) {
    if (error instanceof ConfigError) return error.problems
    throw error
  }
  throw new Error("expected a ConfigError")
}

const production = {
  APP_ENV: "production",
  APP_SYSTEM_ID: "billing-web",
  APP_ORIGIN: "https://app.example",
  AUTH_ENCRYPTION_KEY: keyRing("e1", 3),
  AUTH_CSRF_KEY: keyRing("c1", 5),
}

describe("the readiness check (ADR 0026 §4)", () => {
  it("starts in production with an https origin, a durable store and both keys", () => {
    expect(() =>
      createAuth({
        store: durable(),
        env: production,
        hibpFetch: hibpClear,
        sendEmail: discardEmail,
      }),
    ).not.toThrow()
  })

  it("names every production problem at once", () => {
    expect(
      problems(() =>
        createAuth({
          store: memoryStore(),
          env: { APP_ENV: "production", APP_ORIGIN: "http://app.example", APP_SYSTEM_ID: "-bad" },
          clock: fixedClock(T0),
          random: sequenceRandom([1]),
          hibpFetch: hibpClear,
          sendEmail: discardEmail,
        }),
      ),
    ).toEqual([
      "APP_ORIGIN must use https in production.",
      'The "memory" store keeps nothing across restarts or processes; production needs a durable store.',
      "AUTH_ENCRYPTION_KEY is missing.",
      "AUTH_CSRF_KEY is missing.",
      "A custom Clock is for tests only; production must use the system clock.",
      "A custom RandomSource is for tests only; production must use Web Crypto.",
      "APP_SYSTEM_ID must be 1-64 letters, digits, dots, dashes or underscores, starting with a letter or digit.",
    ])
  })

  it("runs as production when APP_ENV is missing, and refuses a missing origin", () => {
    expect(
      problems(() =>
        createAuth({ store: durable(), env: {}, hibpFetch: hibpClear, sendEmail: discardEmail }),
      ),
    ).toEqual([
      "APP_ORIGIN must be a bare origin exactly as browsers send it: scheme, lowercase host, and a port only if not the default.",
      "AUTH_ENCRYPTION_KEY is missing.",
      "AUTH_CSRF_KEY is missing.",
      "APP_SYSTEM_ID is missing.",
    ])
  })

  it("refuses a malformed key in every mode", () => {
    expect(
      problems(() =>
        createAuth({
          store: memoryStore(),
          env: { ...ENV, AUTH_CSRF_KEY: "k1:c2hvcnQ" },
          hibpFetch: hibpClear,
          sendEmail: discardEmail,
        }),
      ),
    ).toEqual(["AUTH_CSRF_KEY entry 1 is shorter than 32 bytes."])
  })

  it("accepts the memory store, an http localhost origin and generated keys in development", () => {
    const auth = createAuth({
      store: memoryStore(),
      env: { APP_ENV: "development", APP_ORIGIN: "http://localhost:3000", APP_SYSTEM_ID: "dev" },
      hibpFetch: hibpClear,
      sendEmail: discardEmail,
    })
    expect(auth.handle).toBeTypeOf("function")
  })

  it("accepts a custom clock and random source only in test mode", () => {
    expect(() =>
      createAuth({
        store: memoryStore(),
        env: ENV,
        clock: fixedClock(T0),
        random: sequenceRandom([1]),
        hibpFetch: hibpClear,
        sendEmail: discardEmail,
      }),
    ).not.toThrow()
    expect(
      problems(() =>
        createAuth({
          store: memoryStore(),
          env: { ...ENV, APP_ENV: "development" },
          clock: fixedClock(T0),
          hibpFetch: hibpClear,
          sendEmail: discardEmail,
        }),
      ),
    ).toEqual(["A custom Clock is for tests only; development must use the system clock."])
  })

  it("accepts an argon2id cost only in test mode, and hashes at it there (ADR 0018 §1, ADR 0026 §4)", async () => {
    for (const mode of ["development", "staging", "production"]) {
      expect(
        problems(() =>
          createAuth({
            store: durable(),
            env: { ...production, APP_ENV: mode },
            hibpFetch: hibpClear,
            sendEmail: discardEmail,
            argon2Cost: TEST_ARGON2_COST,
          }),
        ),
        mode,
      ).toEqual([`A custom argon2id cost is for tests only; ${mode} must use the ADR 0018 cost.`])
    }
    const { auth, store, outbox } = testAuth({ argon2Cost: TEST_ARGON2_COST })
    const browser = new Browser(inProcess(auth))
    await browser.start()
    await browser.post("/auth/sign-up", { identifier: "ada@example.com" })
    const subject = (body(await browser.get("/auth/session"))["session"] as { subject: string })
      .subject
    await confirmEmail(browser, outbox)
    expect((await browser.post("/auth/password", { password: PASSWORD })).status).toBe(200)
    const record = await store.get("default", PASSWORD_COLLECTION, subject)
    expect((record?.data as { hash: string }).hash).toMatch(/^\$argon2id\$v=19\$m=8,t=1,p=1\$/)
  })

  it("refuses an argon2id cost hash-wasm cannot compute, even in test mode", () => {
    expect(
      problems(() =>
        createAuth({
          store: memoryStore(),
          env: ENV,
          hibpFetch: hibpClear,
          sendEmail: discardEmail,
          argon2Cost: { memoryKiB: 4, iterations: 1, parallelism: 1 },
        }),
      ),
    ).toEqual([
      "argon2Cost must be whole numbers: iterations and parallelism at least 1, memoryKiB at least 8 times parallelism.",
    ])
  })
})

describe("the defaults", () => {
  it("generates the keys a test or development deployment leaves out, from the random source", async () => {
    const env = { ...ENV, AUTH_CSRF_KEY: undefined, AUTH_ENCRYPTION_KEY: undefined }
    const { auth } = testAuth({ env })
    const reply = await new Browser(inProcess(auth)).get("/auth/session")
    expect(body(reply)["csrfToken"]).toMatch(/^generated\./)
  })

  it("uses the default policy, AAL2 everywhere, when none is given", async () => {
    const setup = testAuth()
    const { token } = await seedSession(setup, { evidence: aal2(setup.clock) })
    const result = await setup.auth.require(
      {
        method: "GET",
        url: "/",
        headers: new Headers({ Cookie: `__Host-test-cap=${token}` }),
        body: null,
      },
      "default",
    )
    expect(result).toMatchObject({
      outcome: "allow",
      subject: "acct-1",
      assurance: { policyVersion: "test-cap default" },
    })
  })

  it("scopes everything to the tenant `default` unless told otherwise", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    await browser.post("/auth/sign-up", { identifier: "ada@example.com" })
    const subject = (body(await browser.get("/auth/session"))["session"] as { subject: string })
      .subject
    expect(await setup.store.get("default", "account", subject)).not.toBeNull()
    const other = testAuth({ tenant: "t9" })
    const second = new Browser(inProcess(other.auth))
    await second.start()
    await second.post("/auth/sign-up", { identifier: "ada@example.com" })
    const id = (body(await second.get("/auth/session"))["session"] as { subject: string }).subject
    expect(await other.store.get("t9", "account", id)).not.toBeNull()
    expect(await other.store.get("default", "account", id)).toBeNull()
  })

  it("runs without an event sink", async () => {
    const auth = createAuth({
      store: memoryStore(),
      env: ENV,
      hibpFetch: hibpClear,
      sendEmail: discardEmail,
    })
    const browser = new Browser(inProcess(auth))
    await browser.start()
    expect((await browser.post("/auth/sign-up", { identifier: "ada@example.com" })).status).toBe(
      200,
    )
  })

  it("keeps the outcome when the event sink throws", async () => {
    const setup = testAuth({
      onEvent: () => {
        throw new Error("sink down")
      },
    })
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    expect((await browser.post("/auth/sign-up", { identifier: "ada@example.com" })).status).toBe(
      200,
    )
  })
})

describe("auth.session and auth.require", () => {
  it("read the session from the store on every call", async () => {
    const setup = testAuth({
      policy: defineAuthPolicy({
        version: "p",
        requirements: { "profile.read": { level: "AAL1" } },
      }),
    })
    const { token, id } = await seedSession(setup, { evidence: aal1(setup.clock) })
    const req = {
      method: "GET",
      url: "/x",
      headers: new Headers({ Cookie: `__Host-test-cap=${token}` }),
      body: null,
    }
    expect(await setup.auth.session(req)).toMatchObject({ id, subject: "acct-1", level: "AAL1" })
    expect(await setup.auth.require(req, "profile.read")).toMatchObject({ outcome: "allow" })
    expect(await setup.auth.require(req, "default")).toMatchObject({ outcome: "step-up" })
    expect(await setup.auth.admin.revoke("acct-1")).toBe(1)
    expect(await setup.auth.session(req)).toBeNull()
    expect(await setup.auth.require(req, "profile.read")).toEqual({ outcome: "unauthenticated" })
  })

  it("answers null and unauthenticated without a session", async () => {
    const { auth } = testAuth()
    const req = { method: "GET", url: "/x", headers: new Headers(), body: null }
    expect(await auth.session(req)).toBeNull()
    expect(await auth.require(req, "default")).toEqual({ outcome: "unauthenticated" })
  })
})

describe("admin.revoke", () => {
  it("revokes every session of the account at once, and no other account's", async () => {
    const setup = testAuth()
    const first = await seedSession(setup, { subject: "acct-1", evidence: aal2(setup.clock) })
    const second = await seedSession(setup, { subject: "acct-1", evidence: aal2(setup.clock) })
    const other = await seedSession(setup, { subject: "acct-2", evidence: aal2(setup.clock) })
    expect(await setup.auth.admin.revoke("acct-1")).toBe(2)
    expect(body(await first.browser.get("/auth/session"))["session"]).toBeNull()
    expect(body(await second.browser.get("/auth/session"))["session"]).toBeNull()
    expect(body(await other.browser.get("/auth/session"))["session"]).not.toBeNull()
    expect(await setup.auth.admin.revoke("acct-1")).toBe(0)
  })
})

describe("the deny-by-default gate", () => {
  const head = (url: string, cookie?: string) => ({
    method: "GET",
    url,
    headers: new Headers(cookie === undefined ? {} : { Cookie: `__Host-test-cap=${cookie}` }),
    body: null,
  })

  it("decides each kind of request before its body is read", async () => {
    const setup = testAuth()
    const { gate } = internalsOf(setup.auth)
    const isPublic = (path: string) => path === "/open"
    expect(await gate(head("/auth/session"), isPublic)).toEqual({ kind: "dispatch" })
    expect(await gate(head("/open"), isPublic)).toEqual({ kind: "next", subject: null })
    const allowed = await seedSession(setup, { evidence: aal2(setup.clock) })
    expect(await gate(head("/x", allowed.token), isPublic)).toEqual({
      kind: "next",
      subject: "acct-1",
    })
    const signedOut = await gate(head("/x"), isPublic)
    expect(
      signedOut.kind === "respond" && [
        signedOut.response.status,
        signedOut.response.headers.get("cache-control"),
      ],
    ).toEqual([401, "no-store"])
    const low = await seedSession(setup, { evidence: aal1(setup.clock) })
    const stepUp = await gate(head("/x", low.token), isPublic)
    expect(stepUp.kind === "respond" && stepUp.response.status).toBe(403)
    const ambiguous = await gate(head("/x//y"), isPublic)
    expect(ambiguous.kind === "respond" && ambiguous.response.status).toBe(400)
  })
})

describe("internalsOf", () => {
  it("refuses an object createAuth did not build", () => {
    expect(() => internalsOf({ handle: () => null })).toThrow(
      new TypeError("Pass the Auth that createAuth returned."),
    )
  })

  it("keeps the internals off the enumerable surface", () => {
    const { auth } = testAuth()
    expect(Object.keys(auth).sort()).toEqual(["admin", "handle", "require", "session"])
    expect(internalsOf(auth).gate).toBeTypeOf("function")
  })
})
