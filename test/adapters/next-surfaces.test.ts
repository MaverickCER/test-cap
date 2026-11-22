// The Next.js adapter's three surfaces (ADR 0024 §4): the route handler for /auth/*, the authoritative server
// helpers, and the optional proxy that only redirects early.
import { describe, expect, it } from "vitest"
import { nextAuthHandler, nextProxy, nextServerAuth } from "../../src/adapters/next/index.js"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import type { Auth } from "../../src/core/auth.js"
import type { PlainRequest } from "../../src/transport/types.js"
import { aal1, aal2, body, Browser, enrol, ORIGIN, seedSession, testAuth } from "../support/auth.js"
import { fetchTransport, replyOfResponse, webRequest } from "../support/fetch.js"

/** What Next's `headers()` from `next/headers` resolves to, for a request carrying `cookie`. */
function nextHeaders(cookie: string | null) {
  const headers = new Headers({ "user-agent": "test" })
  if (cookie !== null) headers.set("cookie", cookie)
  return () => Promise.resolve(headers)
}

describe("nextAuthHandler: app/auth/[...path]/route.ts", () => {
  it("serves GET and POST, running sign-up to an AAL2 session", async () => {
    const setup = testAuth()
    const { GET, POST } = nextAuthHandler(setup.auth)
    const browser = new Browser(
      fetchTransport((req) => (req.method === "GET" ? GET(req) : POST(req))),
    )
    const { subject } = await enrol(browser, setup.clock, setup.outbox)
    const session = body(await browser.get("/auth/session"))["session"] as Record<string, unknown>
    expect([session["subject"], session["level"]]).toEqual([subject, "AAL2"])
  })

  it("answers a 405 from the core when the method does not match the route", async () => {
    const { auth } = testAuth()
    const { POST } = nextAuthHandler(auth)
    const reply = await replyOfResponse(
      await POST(webRequest({ method: "POST", path: "/auth/session" })),
    )
    expect([reply.status, reply.headers.get("allow")]).toEqual([405, "GET"])
  })

  it("answers 404 when mounted somewhere other than /auth/", async () => {
    const { auth } = testAuth()
    const { GET } = nextAuthHandler(auth)
    const reply = await replyOfResponse(
      await GET(webRequest({ method: "GET", path: "/login/session" })),
    )
    expect([reply.status, reply.text]).toEqual([404, '{"error":"not-found"}'])
    expect(reply.headers.get("cache-control")).toBe("no-store")
  })

  it("keeps every Set-Cookie value", async () => {
    const setup = testAuth()
    const twoCookies = Object.create(setup.auth) as Auth<string>
    twoCookies.handle = () => {
      const headers = new Headers()
      headers.append("Set-Cookie", "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT")
      headers.append("Set-Cookie", "b=2")
      return Promise.resolve({ status: 200, headers, body: null })
    }
    const { GET } = nextAuthHandler(twoCookies)
    const response = await GET(webRequest({ method: "GET", path: "/auth/session" }))
    expect(response.headers.getSetCookie()).toEqual([
      "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT",
      "b=2",
    ])
  })

  it("refuses anything but the Auth createAuth returned", () => {
    const fake = {} as Auth<string>
    expect(() => nextAuthHandler(fake)).toThrow("Pass the Auth that createAuth returned.")
    expect(() => nextServerAuth(fake, { headers: nextHeaders(null) })).toThrow(
      "Pass the Auth that createAuth returned.",
    )
    expect(() => nextProxy(fake)).toThrow("Pass the Auth that createAuth returned.")
  })
})

describe("nextServerAuth: the authoritative check", () => {
  it("allows an AAL2 session and names its subject", async () => {
    const setup = testAuth()
    const { token } = await seedSession(setup, { evidence: aal2(setup.clock) })
    const server = nextServerAuth(setup.auth, { headers: nextHeaders(`__Host-test-cap=${token}`) })
    const result = await server.require()
    expect([result.outcome, "subject" in result ? result.subject : null]).toEqual([
      "allow",
      "acct-1",
    ])
    expect((await server.session())?.subject).toBe("acct-1")
  })

  it("answers unauthenticated with no cookie, or a cookie naming no session", async () => {
    const setup = testAuth()
    for (const cookie of [null, "__Host-test-cap=forged-value-that-names-nothing"]) {
      const server = nextServerAuth(setup.auth, { headers: nextHeaders(cookie) })
      expect(await server.require()).toEqual({ outcome: "unauthenticated" })
      expect(await server.session()).toBeNull()
    }
  })

  it("answers step-up for a session below the requirement, and enroll for one still enrolling", async () => {
    const setup = testAuth()
    const { token } = await seedSession(setup, { evidence: aal1(setup.clock) })
    const short = nextServerAuth(setup.auth, { headers: nextHeaders(`__Host-test-cap=${token}`) })
    expect((await short.require("default")).outcome).toBe("step-up")
    const enrolling = await seedSession(setup, { state: "pre-auth" })
    const pre = nextServerAuth(setup.auth, {
      headers: nextHeaders(`__Host-test-cap=${enrolling.token}`),
    })
    expect((await pre.require()).outcome).toBe("enroll")
  })

  it("checks the requirement it is asked for, by its policy id", async () => {
    const policy = defineAuthPolicy({
      version: "billing",
      requirements: { "billing.update": { level: "AAL3" } },
    })
    const setup = testAuth({ policy })
    const { token } = await seedSession(setup, { evidence: aal2(setup.clock) })
    const server = nextServerAuth(setup.auth as Auth<"billing.update">, {
      headers: nextHeaders(`__Host-test-cap=${token}`),
    })
    expect((await server.require()).outcome).toBe("allow")
    expect((await server.require("billing.update")).outcome).toBe("step-up")
  })

  it("hands the core a bodiless GET for the root, carrying the request's headers", async () => {
    const setup = testAuth()
    const seen: PlainRequest[] = []
    const spy = Object.create(setup.auth) as Auth<string>
    spy.session = (request) => {
      seen.push(request)
      return Promise.resolve(null)
    }
    spy.require = (request) => {
      seen.push(request)
      return Promise.resolve({ outcome: "unauthenticated" })
    }
    const server = nextServerAuth(spy, { headers: nextHeaders("__Host-test-cap=abc") })
    await server.session()
    await server.require()
    expect(
      seen.map((request) => [
        request.method,
        request.url,
        request.body,
        request.headers.get("cookie"),
        request.headers.get("user-agent"),
      ]),
    ).toEqual([
      ["GET", "/", null, "__Host-test-cap=abc", "test"],
      ["GET", "/", null, "__Host-test-cap=abc", "test"],
    ])
  })

  it("reads the request's headers on every call, never a value cached from an earlier request", async () => {
    const setup = testAuth()
    const { token } = await seedSession(setup, { evidence: aal2(setup.clock) })
    let cookie: string | null = `__Host-test-cap=${token}`
    const server = nextServerAuth(setup.auth, { headers: () => nextHeaders(cookie)() })
    expect((await server.require()).outcome).toBe("allow")
    cookie = null
    expect((await server.require()).outcome).toBe("unauthenticated")
    expect(await server.session()).toBeNull()
  })

  it("sees a revocation at once", async () => {
    const setup = testAuth()
    const { token } = await seedSession(setup, { evidence: aal2(setup.clock) })
    const server = nextServerAuth(setup.auth, { headers: nextHeaders(`__Host-test-cap=${token}`) })
    expect((await server.require()).outcome).toBe("allow")
    await setup.auth.admin.revoke("acct-1")
    expect((await server.require()).outcome).toBe("unauthenticated")
  })

  it("lets a store failure reach the caller as an error, never as allow", async () => {
    const setup = testAuth()
    const { token } = await seedSession(setup, { evidence: aal2(setup.clock) })
    const failing = testAuth({
      store: new Proxy(setup.store, {
        get: () => () => Promise.reject(new Error("store down")),
      }),
    })
    const server = nextServerAuth(failing.auth, {
      headers: nextHeaders(`__Host-test-cap=${token}`),
    })
    await expect(server.require()).rejects.toThrow("store down")
  })
})

describe("nextProxy: early redirects only", () => {
  const request = (path: string, cookie?: string) =>
    webRequest({ method: "GET", path, headers: cookie === undefined ? [] : [["Cookie", cookie]] })

  it("redirects a visitor with no session cookie to the sign-in path, with where they were going", () => {
    const { auth } = testAuth()
    const response = nextProxy(auth, { public: ["/"] })(request("/billing?tab=invoices"))
    expect(response?.status).toBe(307)
    expect(response?.headers.get("location")).toBe(
      `${ORIGIN}/auth/sign-in?returnTo=%2Fbilling%3Ftab%3Dinvoices`,
    )
  })

  it("redirects to the sign-in path the app names", () => {
    const { auth } = testAuth()
    const response = nextProxy(auth, { public: ["/"], signIn: "/welcome" })(request("/billing"))
    expect(response?.headers.get("location")).toBe(`${ORIGIN}/welcome?returnTo=%2Fbilling`)
  })

  it("may send visitors to the home page, which then passes through", () => {
    const { auth } = testAuth()
    const proxy = nextProxy(auth, { signIn: "/" })
    expect(proxy(request("/billing"))?.headers.get("location")).toBe(
      `${ORIGIN}/?returnTo=%2Fbilling`,
    )
    expect(proxy(request("/"))).toBeUndefined()
  })

  it("builds the redirect on APP_ORIGIN, never on the host the request names", () => {
    const { auth } = testAuth()
    const response = nextProxy(auth)(new Request("https://evil.example/billing"))
    expect(response?.headers.get("location")).toBe(`${ORIGIN}/auth/sign-in?returnTo=%2Fbilling`)
  })

  it("passes public paths, /auth/* and the sign-in path itself through", () => {
    const { auth } = testAuth()
    const proxy = nextProxy(auth, { public: ["/", "/blog/*"], signIn: "/welcome" })
    for (const path of ["/", "/blog/first", "/auth/session", "/auth", "/welcome"]) {
      expect(proxy(request(path)), path).toBeUndefined()
    }
  })

  it("passes any request that carries a session cookie, even a forged one: it is not the protection", () => {
    const { auth } = testAuth()
    const proxy = nextProxy(auth)
    expect(proxy(request("/billing", "__Host-test-cap=forged"))).toBeUndefined()
  })

  it("redirects when the session cookie is sent twice, since the core reads no session from it", () => {
    const { auth } = testAuth()
    const proxy = nextProxy(auth)
    expect(proxy(request("/billing", "__Host-test-cap=a; __Host-test-cap=b"))?.status).toBe(307)
  })

  it("protects every path but /auth/* by redirect when no public list is given", () => {
    const { auth } = testAuth()
    expect(nextProxy(auth)(request("/"))?.headers.get("location")).toBe(
      `${ORIGIN}/auth/sign-in?returnTo=%2F`,
    )
  })

  it("leaves an ambiguous path to the route that serves it, which refuses it", () => {
    const { auth } = testAuth()
    expect(nextProxy(auth)(request("/billing//x"))).toBeUndefined()
  })

  it("refuses a malformed public list or sign-in path when it is built", () => {
    const { auth } = testAuth()
    expect(() => nextProxy(auth, { public: ["/blog/"] })).toThrow("test-cap refused to start")
    for (const signIn of ["", "sign-in", "/sign-in/", "//evil.example", "/a/*", "https://x"]) {
      expect(() => nextProxy(auth, { signIn }), signIn).toThrow(
        `The sign-in path "${signIn}" must be a clean path such as /sign-in.`,
      )
    }
  })

  it("answers with a redirect that carries no body and is never cached", () => {
    const { auth } = testAuth()
    const response = nextProxy(auth)(request("/billing"))
    expect(response?.body).toBeNull()
    expect(response?.headers.get("cache-control")).toBe("no-store")
  })
})
