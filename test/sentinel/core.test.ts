// Sentinels: small, direct checks of hot-path behaviour that nearly every test runs through but only a few test
// directly. The custom sequencer in vitest.config.ts runs this directory first, under Vitest and under Stryker's
// Vitest runner, so a mutant in one of these lines fails here in milliseconds instead of after the whole suite. Each
// check asserts behaviour, with the exact message, and runs no flow.
import { describe, expect, it } from "vitest"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import { serveAuth, headOf } from "../../src/adapters/fetch/convert.js"
import { internalsOf } from "../../src/core/auth.js"
import { fixedClock } from "../../src/core/clock.js"
import { base64UrlDecode, base64UrlEncode } from "../../src/core/encoding.js"
import { ConfigError } from "../../src/core/errors.js"
import { normaliseEmail } from "../../src/core/identifier.js"
import { exampleKeyProblems, parseKeyRing } from "../../src/core/mode.js"
import { sameOrigin } from "../../src/security/csrf.js"
import { SESSION_COLLECTION } from "../../src/sessions/sessions.js"
import { memoryStore } from "../../src/store/memory.js"
import { assertName } from "../../src/store/port.js"
import { DEFAULT_BODY_LIMIT, readBody } from "../../src/transport/body.js"
import { readCookie, serializeCookie } from "../../src/transport/cookies.js"
import { testAuth } from "../support/auth.js"
import { HOUR, password, T0, totp } from "../support/evidence.js"
import { setup, TENANT } from "../support/sessions.js"

const ORIGIN = "https://app.example"
const COOKIE = { httpOnly: true, sameSite: "Lax" } as const
/** A key the examples commit (src/core/mode.ts): refused in production and staging. */
const EXAMPLE_KEY = "HyZsmcRz3x-z7EXAIM0O952M67EBY26XZCevK6-p1q0"

describe("the test clock", () => {
  it("refuses a time that is not a whole number of milliseconds", () => {
    for (const time of [Number.NaN, 1.5, Number.POSITIVE_INFINITY]) {
      expect(() => fixedClock(time), String(time)).toThrow(
        new RangeError("The start time must be a whole number of milliseconds."),
      )
    }
  })
})

describe("the memory store", () => {
  it("declares itself the memory store, not durable", () => {
    const store = memoryStore()
    expect([store.kind, store.durable]).toEqual(["memory", false])
  })

  it("names the empty argument it refuses", async () => {
    const store = memoryStore()
    const refused = (what: string) => new TypeError(`${what} must be a non-empty string.`)
    await expect(store.get("", "c", "k")).rejects.toThrow(refused("The tenant"))
    await expect(store.get("t", "", "k")).rejects.toThrow(refused("The collection"))
    await expect(store.get("t", "c", "")).rejects.toThrow(refused("The key"))
    await expect(store.listByOwner("", "c", "o")).rejects.toThrow(refused("The tenant"))
    await expect(store.listByOwner("t", "", "o")).rejects.toThrow(refused("The collection"))
    await expect(store.listByOwner("t", "c", "")).rejects.toThrow(refused("The owner"))
    await expect(
      store.createUnique("", { collection: "c", key: "k", owner: null, data: 1 }),
    ).rejects.toThrow(refused("The tenant"))
  })

  it("refuses a name that is not a string", () => {
    expect(() => {
      assertName(7 as unknown as string, "The tenant")
    }).toThrow(new TypeError("The tenant must be a non-empty string."))
  })
})

describe("cookies", () => {
  it("sets only __Host- cookies", () => {
    expect(() => serializeCookie("test-cap", "v", COOKIE)).toThrow(
      new TypeError("test-cap only sets __Host- cookies."),
    )
    expect(serializeCookie("__Host-test-cap", "v", COOKIE)).toBe(
      "__Host-test-cap=v; Path=/; Secure; HttpOnly; SameSite=Lax",
    )
  })

  it("reads a cookie only from a pair with an equals sign", () => {
    expect(readCookie(new Headers(), "a")).toEqual({ kind: "absent" })
    expect(readCookie(new Headers({ Cookie: "ab" }), "a")).toEqual({ kind: "absent" })
    expect(readCookie(new Headers({ Cookie: "a=1" }), "a")).toEqual({ kind: "value", value: "1" })
  })
})

describe("base64url and the body limit", () => {
  it("refuses an impossible length and a character outside the alphabet", () => {
    expect(() => base64UrlDecode("A")).toThrow(
      new TypeError("Invalid base64url: impossible length."),
    )
    expect(() => base64UrlDecode("AA*A")).toThrow(
      new TypeError("Invalid base64url: character outside the alphabet."),
    )
  })

  it("refuses a body limit that is not a positive integer", () => {
    const request = { method: "POST", url: `${ORIGIN}/auth/x`, headers: new Headers(), body: null }
    for (const limit of [0, 1.5]) {
      expect(() => readBody(request, { limit }), String(limit)).toThrow(
        new RangeError("The body limit must be a positive integer."),
      )
    }
  })

  it("stops reading a fetch body once it passes the limit", async () => {
    const chunk = new Uint8Array(1024)
    let pulled = 0
    let cancelled = false
    const body = new ReadableStream<Uint8Array>(
      {
        pull(controller) {
          pulled += 1
          if (pulled > 200) controller.close()
          else controller.enqueue(chunk)
        },
        cancel() {
          cancelled = true
        },
      },
      { highWaterMark: 0 },
    )
    const req = new Request(`${ORIGIN}/auth/sign-in`, { method: "POST", body, duplex: "half" })
    await serveAuth(testAuth().auth, req, headOf(req, "192.0.2.1"))
    expect([cancelled, pulled]).toEqual([true, DEFAULT_BODY_LIMIT / 1024 + 1])
  })
})

describe("keys and modes", () => {
  it("refuses a key that repeats with a period of 8 bytes", () => {
    const bytes = new Uint8Array(32).map((_, index) => [1, 7, 3, 9, 2, 8, 4, 6][index % 8] ?? 0)
    expect(parseKeyRing("KEY", `k:${base64UrlEncode(bytes)}`).problems).toEqual([
      "KEY entry 1 looks like an example or default key, not a random one.",
    ])
  })

  it("refuses an example key only in production and staging", () => {
    const value = `e1:${EXAMPLE_KEY}`
    const problem = ["AUTH_ENCRYPTION_KEY entry 1 is a published example key; generate a new one."]
    expect(exampleKeyProblems("AUTH_ENCRYPTION_KEY", value, "production")).toEqual(problem)
    expect(exampleKeyProblems("AUTH_ENCRYPTION_KEY", value, "staging")).toEqual(problem)
    expect(exampleKeyProblems("AUTH_ENCRYPTION_KEY", value, "development")).toEqual([])
  })
})

describe("createAuth, the policy and CSRF", () => {
  it("lists the dispatcher's routes, each with the body fields it declares (ADR 0025)", () => {
    const routes = internalsOf(testAuth().auth).routes()
    const required = (...names: string[]) => Object.fromEntries(names.map((name) => [name, true]))
    expect(routes).toEqual([
      { method: "GET", path: "/auth/session", fields: {} },
      {
        method: "POST",
        path: "/auth/sign-up",
        fields: { ...required("identifier"), returnTo: false },
      },
      { method: "POST", path: "/auth/email/confirm", fields: required("code") },
      { method: "POST", path: "/auth/email/resend", fields: {} },
      { method: "POST", path: "/auth/password", fields: required("password") },
      { method: "POST", path: "/auth/totp/enrol", fields: {} },
      {
        method: "POST",
        path: "/auth/totp/confirm",
        fields: { ...required("authenticatorId", "code"), returnTo: false },
      },
      {
        method: "POST",
        path: "/auth/sign-in",
        fields: { ...required("identifier", "password"), returnTo: false },
      },
      { method: "POST", path: "/auth/totp/verify", fields: { code: true, returnTo: false } },
      { method: "POST", path: "/auth/step-up/start", fields: {} },
      {
        method: "POST",
        path: "/auth/step-up",
        fields: { challenge: true, password: false, code: false, returnTo: false },
      },
      { method: "POST", path: "/auth/sign-out", fields: {} },
      { method: "GET", path: "/auth/sessions", fields: {} },
      { method: "POST", path: "/auth/sessions/revoke", fields: required("sessionId") },
    ])
  })

  it("answers session, require and admin revoke for a request with no session", async () => {
    const { auth } = testAuth()
    const request = { method: "GET", url: `${ORIGIN}/`, headers: new Headers(), body: null }
    expect(await auth.session(request)).toBeNull()
    expect(await auth.require(request, "default")).toEqual({ outcome: "unauthenticated" })
    expect(await auth.admin.revoke("nobody")).toBe(0)
  })

  it("reports the trust config's problems", () => {
    let caught: unknown
    try {
      defineAuthPolicy({ version: "1", trust: [{ issuer: "", maxAuthAgeMs: HOUR }] })
    } catch (error) {
      caught = error
    }
    expect(caught).toBeInstanceOf(ConfigError)
    expect((caught as ConfigError).problems).toEqual(["A trusted issuer needs a non-empty issuer."])
  })

  it("ends a session at its absolute limit, not a millisecond later, and refuses an unknown requirement", () => {
    const policy = defineAuthPolicy({ version: "1" })
    const session = {
      subject: "acct-1",
      state: "authenticated" as const,
      evidence: [password(), totp()],
      stepUps: [],
      startedAt: T0,
      lastSeenAt: T0 + 24 * HOUR - 1,
    }
    expect(policy.assurance(session, T0 + 24 * HOUR - 1)).not.toBeNull()
    expect(policy.assurance(session, T0 + 24 * HOUR)).toBeNull()
    expect(() => policy.requirement("nope" as never)).toThrow(
      new Error('Unknown requirement id "nope".'),
    )
  })

  it("treats Origin: null as no Origin, so only Sec-Fetch-Site: same-origin passes", () => {
    const check = (site: string) =>
      sameOrigin(new Headers({ Origin: "null", "Sec-Fetch-Site": site }), ORIGIN)
    expect([check("same-origin"), check("same-site"), check("cross-site")]).toEqual([
      true,
      false,
      false,
    ])
  })
})

describe("email identifiers", () => {
  it("refuses an empty local part and one over 64 characters", () => {
    expect(normaliseEmail("@example.com")).toBeNull()
    expect(normaliseEmail(`${"a".repeat(65)}@example.com`)).toBeNull()
    expect(normaliseEmail(`${"a".repeat(64)}@example.com`)).toBe(`${"a".repeat(64)}@example.com`)
  })
})

describe("sessions", () => {
  it("gives an authenticated session 24 hours and a pre-auth one an hour", async () => {
    const { sessions } = setup()
    const signedIn = await sessions.signIn(TENANT, null, { subject: "a", evidence: [password()] })
    const enrolling = await sessions.begin(TENANT, null, { subject: "b", state: "pre-auth" })
    expect(signedIn.cookie).toContain("Max-Age=86400;")
    expect(enrolling.cookie).toContain("Max-Age=3600;")
  })

  it("never reads the store for a missing or malformed token", async () => {
    const store = memoryStore()
    let reads = 0
    const counted = {
      ...store,
      get: (...args: Parameters<typeof store.get>) => {
        reads += 1
        return store.get(...args)
      },
    }
    const { sessions } = setup({ store: counted })
    expect(await sessions.read(TENANT, null)).toBeNull()
    expect(await sessions.read(TENANT, "not-a-token")).toBeNull()
    expect(reads).toBe(0)
  })

  it("answers null for a token with no record, a revoked one and one a rotation claimed", async () => {
    const { store, sessions } = setup()
    expect(await sessions.read(TENANT, "A".repeat(43))).toBeNull()
    const revoked = await sessions.signIn(TENANT, null, { subject: "a", evidence: [password()] })
    await sessions.signOut(TENANT, revoked.token)
    expect(await sessions.read(TENANT, revoked.token)).toBeNull()
    const claimed = await sessions.signIn(TENANT, null, { subject: "b", evidence: [password()] })
    const [record] = await store.listByOwner(TENANT, SESSION_COLLECTION, "b")
    await store.update(TENANT, SESSION_COLLECTION, String(record?.key), Number(record?.version), {
      data: { ...(record?.data as object), rotatedAt: T0 },
    })
    expect(await sessions.read(TENANT, claimed.token)).toBeNull()
  })

  it("refuses an expired session in an operation that loads it without a read", async () => {
    const { sessions, clock } = setup()
    const issued = await sessions.signIn(TENANT, null, { subject: "a", evidence: [password()] })
    clock.advance(2 * HOUR)
    expect(await sessions.list(TENANT, issued.token)).toBeNull()
  })
})
