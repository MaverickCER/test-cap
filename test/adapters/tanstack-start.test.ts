// The TanStack Start adapter (ADR 0024 §1, §2, Open 2) driven with real Web Requests, in the order TanStack Start runs
// them: the global request middleware first, then the `/auth/$` server route or the app's own route.
import { createMiddleware } from "@tanstack/react-start"
import { describe, expect, it } from "vitest"
import {
  type TanstackStartContext,
  type TanstackStartMiddleware,
  tanstackStartAuth,
  tanstackStartMiddleware,
} from "../../src/adapters/tanstack-start/index.js"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import type { Auth } from "../../src/core/auth.js"
import { ConfigError } from "../../src/core/errors.js"
import type { PlainRequest } from "../../src/transport/types.js"
import {
  aal1,
  aal2,
  body,
  Browser,
  enrol,
  ORIGIN,
  type Outgoing,
  type Reply,
  seedSession,
  testAuth,
  type Transport,
} from "../support/auth.js"

const decoder = new TextDecoder()

/** A test request as the Web `Request` a server hands TanStack Start. */
function requestOf(outgoing: Outgoing, init: RequestInit = {}): Request {
  const body = outgoing.body
  return new Request(`${ORIGIN}${outgoing.path}`, {
    method: outgoing.method,
    headers: (outgoing.headers ?? []).map(([name, value]) => [name, value]),
    body: body === undefined ? null : typeof body === "string" ? body : new Uint8Array(body),
    ...init,
  })
}

/** What a `Response` carries, read whole. */
async function replyOf(response: Response): Promise<Reply> {
  const text = decoder.decode(await response.arrayBuffer())
  return {
    status: response.status,
    headers: response.headers,
    text,
    json: text === "" ? undefined : (JSON.parse(text) as unknown),
  }
}

/** The path the app's router reads. */
const pathnameOf = (request: Request): string => new URL(request.url).pathname

/**
 * Runs one request through the middleware the way TanStack Start does: `next` runs the route, and the middleware's
 * answer is either its own `Response` or what `next` returned.
 */
async function run(
  middleware: TanstackStartMiddleware,
  request: Request,
  route: (context: TanstackStartContext) => Promise<Response>,
): Promise<Response> {
  const result = await middleware({
    request,
    next: async (options) => ({ response: await route(options.context) }),
  })
  return result instanceof Response ? result : result.response
}

/** An app: test-cap's middleware, the `/auth/$` route, a public home page and pages that echo the context. */
function app(
  auth: Auth<string>,
  options: { public?: readonly string[] } = { public: ["/", "/blog/*"] },
): { transport: Transport; reached: () => number } {
  const middleware = tanstackStartMiddleware(auth, options)
  const { handlers } = tanstackStartAuth(auth)
  let reached = 0
  const transport: Transport = async (outgoing) => {
    const request = requestOf(outgoing)
    const response = await run(middleware, request, (context) => {
      if (pathnameOf(request).startsWith("/auth/")) return handlers.ANY({ request })
      reached += 1
      return Promise.resolve(Response.json({ page: pathnameOf(request), auth: context.auth }))
    })
    return replyOf(response)
  }
  return { transport, reached: () => reached }
}

/** The `/auth/$` route alone, as TanStack Start calls it. */
function route(auth: Auth<string>): Transport {
  const { handlers } = tanstackStartAuth(auth)
  return async (outgoing) => replyOf(await handlers.ANY({ request: requestOf(outgoing) }))
}

describe("the /auth/$ server route", () => {
  it("runs sign-up to an AAL2 session, then opens a protected route with the subject in the context", async () => {
    const setup = testAuth()
    const browser = new Browser(app(setup.auth).transport)
    const { subject } = await enrol(browser, setup.clock, setup.outbox)
    const reply = await browser.get("/account")
    expect([reply.status, body(reply)]).toEqual([200, { page: "/account", auth: { subject } }])
  })

  it("passes every security header and the status through unchanged", async () => {
    const setup = testAuth()
    const reply = await new Browser(route(setup.auth)).get("/auth/nope")
    expect([reply.status, reply.text]).toEqual([404, '{"error":"not-found"}'])
    expect(reply.headers.get("cache-control")).toBe("no-store")
    expect(reply.headers.get("content-security-policy")).toContain("frame-ancestors 'none'")
    expect(reply.headers.get("x-content-type-options")).toBe("nosniff")
    expect(reply.headers.get("referrer-policy")).toBe("no-referrer")
    expect(reply.headers.get("content-type")).toBe("application/json; charset=utf-8")
  })

  it("keeps every Set-Cookie value as its own header line", async () => {
    const setup = testAuth()
    const twoCookies = Object.create(setup.auth) as Auth<string>
    twoCookies.handle = () => {
      const headers = new Headers()
      headers.append("Set-Cookie", "a=1; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT")
      headers.append("Set-Cookie", "b=2; Path=/")
      headers.append("X-Other", "kept")
      return Promise.resolve({ status: 200, headers, body: null })
    }
    const reply = await new Browser(route(twoCookies)).get("/auth/session")
    expect(reply.headers.getSetCookie()).toEqual([
      "a=1; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT",
      "b=2; Path=/",
    ])
    expect(reply.headers.get("x-other")).toBe("kept")
    expect(reply.text).toBe("")
  })

  it("hands the core every repeated request header, so it can refuse the ambiguity", async () => {
    const setup = testAuth()
    const browser = new Browser(route(setup.auth))
    await browser.start()
    const reply = await browser.post(
      "/auth/sign-up",
      { identifier: "ada@example.com" },
      { headers: [["Origin", ORIGIN]] },
    )
    expect([reply.status, reply.text]).toEqual([400, '{"error":"ambiguous-header"}'])
  })

  it("refuses a body over 64 KiB with a 413", async () => {
    const setup = testAuth()
    const browser = new Browser(route(setup.auth))
    await browser.start()
    const large = await browser.post("/auth/sign-up", { identifier: "a".repeat(70_000) })
    expect([large.status, large.text]).toEqual([413, '{"error":"body-too-large"}'])
  })

  it("reads a streamed body one chunk past the limit at most, then cancels the stream", async () => {
    const setup = testAuth()
    let pulled = 0
    let cancelled = false
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled += 1
        controller.enqueue(new Uint8Array(pulled === 1 ? 65_536 : 1))
      },
      cancel() {
        cancelled = true
      },
    })
    const request = new Request(`${ORIGIN}/auth/sign-up`, {
      method: "POST",
      headers: [
        ["Content-Type", "application/json"],
        ["Origin", ORIGIN],
      ],
      body: stream,
      duplex: "half",
    } as RequestInit)
    const response = await tanstackStartAuth(setup.auth).handlers.ANY({ request })
    expect([response.status, await response.text()]).toEqual([413, '{"error":"body-too-large"}'])
    expect(cancelled).toBe(true)
    expect(pulled).toBeLessThanOrEqual(3)
  })

  it("joins a body streamed in chunks, in order", async () => {
    const setup = testAuth()
    const browser = new Browser(route(setup.auth))
    await browser.start()
    const payload = new TextEncoder().encode('{"identifier":"ada@example.com"}')
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(payload.slice(0, 10))
        controller.enqueue(payload.slice(10))
        controller.close()
      },
    })
    const cookies = [...browser.cookies].map(([name, value]) => `${name}=${value}`).join("; ")
    const request = new Request(`${ORIGIN}/auth/sign-up`, {
      method: "POST",
      headers: [
        ["Content-Type", "application/json"],
        ["Origin", ORIGIN],
        ["Cookie", cookies],
        ["X-CSRF-Token", String(browser.csrf)],
      ],
      body: stream,
      duplex: "half",
    } as RequestInit)
    const response = await tanstackStartAuth(setup.auth).handlers.ANY({ request })
    expect([response.status, await response.text()]).toEqual([
      200,
      '{"outcome":"enroll","returnTo":"/"}',
    ])
  })

  it("refuses a body something already read, without calling the core", async () => {
    const setup = testAuth()
    const request = requestOf({
      method: "POST",
      path: "/auth/sign-up",
      headers: [
        ["Content-Type", "application/json"],
        ["Origin", ORIGIN],
      ],
      body: '{"identifier":"ada@example.com"}',
    })
    await request.text()
    const response = await tanstackStartAuth(setup.auth).handlers.ANY({ request })
    expect([response.status, await response.text()]).toEqual([500, '{"error":"body-already-read"}'])
    expect(setup.events).toEqual([])
  })

  it("passes the abort signal through, so the core stops", async () => {
    const setup = testAuth()
    const controller = new AbortController()
    controller.abort()
    const request = requestOf(
      {
        method: "POST",
        path: "/auth/sign-up",
        headers: [
          ["Content-Type", "application/json"],
          ["Origin", ORIGIN],
        ],
        body: "{}",
      },
      { signal: controller.signal },
    )
    const response = await tanstackStartAuth(setup.auth).handlers.ANY({ request })
    expect([response.status, await response.text()]).toEqual([400, '{"error":"aborted"}'])
  })

  it("hands the core the method, the URL as received, the headers and no client address", async () => {
    const setup = testAuth()
    const seen: unknown[] = []
    const spy = Object.create(setup.auth) as Auth<string>
    spy.handle = (request: PlainRequest) => {
      seen.push([
        request.method,
        request.url,
        request.headers.get("origin"),
        request.clientAddress,
        request.signal?.aborted,
        request.body,
      ])
      return Promise.resolve({ status: 204, headers: new Headers(), body: null })
    }
    const get = await route(spy)({
      method: "GET",
      path: "/auth/session?x=1",
      headers: [["Origin", ORIGIN]],
    })
    const post = await route(spy)({ method: "POST", path: "/auth/sign-out", body: "ab" })
    expect([get.status, post.status]).toEqual([204, 204])
    expect(seen).toEqual([
      ["GET", `${ORIGIN}/auth/session?x=1`, ORIGIN, undefined, false, null],
      ["POST", `${ORIGIN}/auth/sign-out`, null, undefined, false, new TextEncoder().encode("ab")],
    ])
  })

  it("answers 404 when the router decoded a path the core reads as outside /auth/", async () => {
    const setup = testAuth()
    const reply = await route(setup.auth)({ method: "GET", path: "/%61uth/session" })
    expect([reply.status, reply.text]).toEqual([404, '{"error":"not-found"}'])
    expect(reply.headers.get("cache-control")).toBe("no-store")
  })

  it("answers a fixed 500 when the core throws", async () => {
    const setup = testAuth()
    const broken = Object.create(setup.auth) as Auth<string>
    broken.handle = () => Promise.reject(new Error("store down: secret detail"))
    const reply = await route(broken)({ method: "GET", path: "/auth/session" })
    expect([reply.status, reply.text]).toEqual([500, '{"error":"internal"}'])
  })
})

describe("the global request middleware: deny by default (ADR 0024 §2)", () => {
  it("protects every route not listed as public, before the route runs", async () => {
    const setup = testAuth()
    const { transport, reached } = app(setup.auth)
    const reply = await new Browser(transport).get("/account")
    expect([reply.status, reply.text]).toEqual([401, '{"error":"unauthenticated"}'])
    expect(reply.headers.get("cache-control")).toBe("no-store")
    expect(reached()).toBe(0)
  })

  it("answers a session below the default requirement with what it lacks", async () => {
    const setup = testAuth()
    const browser = new Browser(app(setup.auth).transport)
    const { token } = await seedSession(setup, { evidence: aal1(setup.clock) })
    browser.cookies.set("__Host-test-cap", token)
    const stepUp = await browser.get("/account")
    expect([stepUp.status, stepUp.text]).toEqual([403, '{"error":"step-up"}'])
    const enrolling = await seedSession(setup, { state: "pre-auth" })
    browser.cookies.set("__Host-test-cap", enrolling.token)
    expect((await browser.get("/account")).text).toBe('{"error":"enroll"}')
  })

  it("lets public routes through with a null auth context, and protected ones with the subject", async () => {
    const setup = testAuth()
    const browser = new Browser(app(setup.auth).transport)
    const { token } = await seedSession(setup, { evidence: aal2(setup.clock) })
    browser.cookies.set("__Host-test-cap", token)
    expect(body(await browser.get("/"))).toEqual({ page: "/", auth: null })
    expect(body(await browser.get("/blog/first"))).toEqual({ page: "/blog/first", auth: null })
    expect(body(await browser.get("/account"))).toEqual({
      page: "/account",
      auth: { subject: "acct-1" },
    })
  })

  it("passes /auth/* on to the server route with a null auth context, its body unread", async () => {
    const setup = testAuth()
    const middleware = tanstackStartMiddleware(setup.auth)
    const request = requestOf({ method: "POST", path: "/auth/sign-out", body: "{}" })
    const contexts: TanstackStartContext[] = []
    const response = await run(middleware, request, (context) => {
      contexts.push(context)
      return Promise.resolve(new Response("route"))
    })
    expect(await response.text()).toBe("route")
    expect(contexts).toEqual([{ auth: null }])
    expect(request.bodyUsed).toBe(false)
  })

  it("protects everything but /auth/* when no public list is given", async () => {
    const setup = testAuth()
    const browser = new Browser(app(setup.auth, {}).transport)
    expect((await browser.get("/")).status).toBe(401)
    expect((await browser.get("/auth/session")).status).toBe(200)
  })

  it.each(["//admin", "/blog/x%2Fadmin", "/blog/x%5Cadmin", "/admin/"])(
    "refuses the ambiguous path %s with a 400 before any route",
    async (path) => {
      const setup = testAuth()
      const { transport, reached } = app(setup.auth)
      const reply = await new Browser(transport).get(path)
      expect([reply.status, reply.text]).toEqual([400, '{"error":"invalid-path"}'])
      expect(reached()).toBe(0)
    },
  )

  it.each(["/blog/../admin", "/blog/%2e%2e/admin", "/x/../blog"])(
    "keeps %s protected: the Web URL parser resolves its dot segments, for the core and the router alike",
    async (path) => {
      const setup = testAuth()
      const { transport, reached } = app(setup.auth)
      const reply = await new Browser(transport).get(path)
      expect([reply.status, reply.text]).toEqual([401, '{"error":"unauthenticated"}'])
      expect(reached()).toBe(0)
    },
  )

  it.each(["/About", "/blog", "/%62log/x"])(
    "keeps %s protected: a public entry matches only its own clean raw path",
    async (path) => {
      const setup = testAuth()
      const { transport, reached } = app(setup.auth)
      const reply = await new Browser(transport).get(path)
      expect([reply.status, reply.text]).toEqual([401, '{"error":"unauthenticated"}'])
      expect(reached()).toBe(0)
    },
  )

  it("refuses a malformed public list when the middleware is built", () => {
    const { auth } = testAuth()
    expect(() => tanstackStartMiddleware(auth, { public: ["/blog/"] })).toThrow(ConfigError)
  })

  it("refuses anything but the Auth createAuth returned", () => {
    const fake = { handle: () => Promise.resolve(null) } as unknown as Auth<string>
    expect(() => tanstackStartMiddleware(fake)).toThrow("Pass the Auth that createAuth returned.")
  })

  it("is the server function TanStack Start's createMiddleware takes", async () => {
    const setup = testAuth()
    const server = tanstackStartMiddleware(setup.auth, { public: ["/"] })
    const middleware = createMiddleware().server(server)
    expect(middleware.options.server).toBe(server)
    const response = await run(server, requestOf({ method: "GET", path: "/private" }), () =>
      Promise.resolve(new Response("reached")),
    )
    expect(response.status).toBe(401)
  })
})

describe("the server helpers", () => {
  /** An `Auth` whose policy adds a requirement no password and TOTP session meets. */
  const policyAuth = () =>
    testAuth({
      policy: defineAuthPolicy({
        version: "tanstack-start test",
        requirements: { "billing.close": { level: "AAL3" } },
      }),
    })

  it("answer require with the core's outcome for the request's session", async () => {
    const setup = policyAuth()
    const helpers = tanstackStartAuth(setup.auth)
    const signedOut = await helpers.require(requestOf({ method: "GET", path: "/" }), "default")
    expect(signedOut.outcome).toBe("unauthenticated")
    const { token } = await seedSession(setup, { evidence: aal1(setup.clock) })
    const request = requestOf({
      method: "POST",
      path: "/_serverFn/abc",
      headers: [["Cookie", `__Host-test-cap=${token}`]],
      body: '{"data":1}',
    })
    const stepUp = await helpers.require(request, "default")
    expect(stepUp).toMatchObject({ outcome: "step-up", subject: "acct-1" })
    expect(request.bodyUsed).toBe(false)
  })

  it("answer allow with the subject for a session that meets the requirement", async () => {
    const setup = policyAuth()
    const { token } = await seedSession(setup, { evidence: aal2(setup.clock) })
    const request = requestOf({
      method: "GET",
      path: "/billing",
      headers: [["Cookie", `__Host-test-cap=${token}`]],
    })
    const helpers = tanstackStartAuth(setup.auth)
    expect(await helpers.require(request, "default")).toMatchObject({
      outcome: "allow",
      subject: "acct-1",
    })
    expect(await helpers.require(request, "billing.close")).toMatchObject({
      outcome: "step-up",
      subject: "acct-1",
    })
  })

  it("read the session, or null without one, and never the body", async () => {
    const setup = policyAuth()
    const helpers = tanstackStartAuth(setup.auth)
    expect(await helpers.session(requestOf({ method: "GET", path: "/" }))).toBeNull()
    const { token, id } = await seedSession(setup, { evidence: aal2(setup.clock) })
    const request = requestOf({
      method: "POST",
      path: "/_serverFn/abc",
      headers: [["Cookie", `__Host-test-cap=${token}`]],
      body: "{}",
    })
    expect(await helpers.session(request)).toMatchObject({
      id,
      subject: "acct-1",
      state: "authenticated",
      level: "AAL2",
    })
    expect(request.bodyUsed).toBe(false)
  })
})
