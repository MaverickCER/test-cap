// The fetch adapter (ADR 0024 §1, §2, Open 2) over real Web `Request` and `Response` objects.
import { describe, expect, it } from "vitest"
import { type FetchAuthInfo, fetchAuth, withAuth } from "../../src/adapters/fetch/index.js"
import type { Auth } from "../../src/core/auth.js"
import type { PlainRequest } from "../../src/transport/types.js"
import { aal1, aal2, body, Browser, enrol, ORIGIN, seedSession, testAuth } from "../support/auth.js"
import {
  chunkedBody,
  fetchTransport,
  replyOfResponse,
  streamedRequest,
  webRequest,
} from "../support/fetch.js"

/** An app handler: a public home page, a public blog, a protected account page and a notes route that reads JSON. */
async function appHandler(req: Request, auth: FetchAuthInfo): Promise<Response> {
  const path = new URL(req.url).pathname
  if (path === "/notes") return Response.json({ received: await req.json() })
  return Response.json({ page: path, auth })
}

function app(
  auth: Auth<string>,
  options: { public?: readonly string[] } = { public: ["/", "/blog/*"] },
) {
  return withAuth(auth, appHandler, options)
}

/** An `Auth` whose `handle` records what it was given and answers 204. */
function spyAuth(auth: Auth<string>) {
  const seen: PlainRequest[] = []
  const spy = Object.create(auth) as Auth<string>
  spy.handle = (request) => {
    seen.push(request)
    return Promise.resolve({ status: 204, headers: new Headers(), body: null })
  }
  return { spy, seen }
}

describe("withAuth: serving /auth/* from a Request", () => {
  it("runs sign-up to an AAL2 session, then opens a protected route with the subject handed over", async () => {
    const setup = testAuth()
    const browser = new Browser(fetchTransport(app(setup.auth)))
    const { subject } = await enrol(browser, setup.clock, setup.outbox)
    const reply = await browser.get("/account")
    expect([reply.status, body(reply)]).toEqual([200, { page: "/account", auth: { subject } }])
  })

  it("passes every security header, the status and the body through unchanged", async () => {
    const setup = testAuth()
    const reply = await new Browser(fetchTransport(app(setup.auth))).get("/auth/nope")
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
    for (const handler of [app(twoCookies), fetchAuth(twoCookies)]) {
      const reply = await new Browser(fetchTransport(handler)).get("/auth/session")
      expect(reply.headers.getSetCookie()).toEqual([
        "a=1; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT",
        "b=2; Path=/",
      ])
      expect(reply.headers.get("x-other")).toBe("kept")
      expect(reply.text).toBe("")
    }
  })

  it("hands the core every repeated request header, so it can refuse the ambiguity", async () => {
    const setup = testAuth()
    const browser = new Browser(fetchTransport(app(setup.auth)))
    await browser.start()
    const reply = await browser.post(
      "/auth/sign-up",
      { identifier: "ada@example.com" },
      { headers: [["Origin", ORIGIN]] },
    )
    expect([reply.status, reply.text]).toEqual([400, '{"error":"ambiguous-header"}'])
  })

  it("refuses a declared body over 64 KiB with a 413", async () => {
    const setup = testAuth()
    const browser = new Browser(fetchTransport(app(setup.auth)))
    await browser.start()
    const large = await browser.post("/auth/sign-up", { identifier: "a".repeat(70_000) })
    expect([large.status, large.text]).toEqual([413, '{"error":"body-too-large"}'])
  })

  it("stops reading a streamed body one chunk past 64 KiB, and the core refuses it", async () => {
    const { auth } = testAuth()
    const source = chunkedBody(100, 8_192)
    const reply = await replyOfResponse(
      await app(auth)(streamedRequest("/auth/sign-up", source.stream)),
    )
    expect([reply.status, reply.text]).toEqual([413, '{"error":"body-too-large"}'])
    expect(source.pulled()).toBe(9)
    expect(source.cancelled()).toBe(true)
  })

  it("reads a streamed body of exactly 64 KiB whole, in order, without cancelling it", async () => {
    const setup = testAuth()
    const { spy, seen } = spyAuth(setup.auth)
    const source = chunkedBody(8, 8_192)
    const response = await fetchAuth(spy)(streamedRequest("/auth/sign-up", source.stream))
    expect(response?.status).toBe(204)
    expect(source.cancelled()).toBe(false)
    expect(seen[0]?.body).toEqual(new Uint8Array(65_536).fill(0x78))
  })

  it("joins chunks of different sizes in order", async () => {
    const setup = testAuth()
    const { spy, seen } = spyAuth(setup.auth)
    const parts = ['{"identi', 'fier":', '"ada@example.com"}']
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        for (const part of parts) controller.enqueue(new TextEncoder().encode(part))
        controller.close()
      },
    })
    await fetchAuth(spy)(streamedRequest("/auth/sign-up", stream))
    expect(new TextDecoder().decode(seen[0]?.body ?? new Uint8Array())).toBe(parts.join(""))
  })

  it("hands a GET with no body to the core as a null body", async () => {
    const setup = testAuth()
    const { spy, seen } = spyAuth(setup.auth)
    await fetchAuth(spy)(webRequest({ method: "GET", path: "/auth/session" }))
    expect(seen[0]?.body).toBeNull()
  })

  it("answers a body stream that fails with a fixed 500", async () => {
    const { auth } = testAuth()
    const failing = () =>
      new ReadableStream<Uint8Array>({
        pull() {
          throw new Error("socket hang up: secret detail")
        },
      })
    const viaGate = await app(auth)(streamedRequest("/auth/sign-up", failing()))
    const direct = await fetchAuth(auth)(streamedRequest("/auth/sign-up", failing()))
    for (const response of [viaGate, direct]) {
      const reply = await replyOfResponse(response as Response)
      expect([reply.status, reply.text]).toEqual([500, '{"error":"internal"}'])
    }
  })

  it("refuses a body something already read, and never rebuilds it (ADR 0024 Open 2)", async () => {
    const setup = testAuth()
    for (const handler of [app(setup.auth), fetchAuth(setup.auth)]) {
      const req = webRequest({
        method: "POST",
        path: "/auth/sign-up",
        headers: [
          ["Content-Type", "application/json"],
          ["Origin", ORIGIN],
        ],
        body: '{"identifier":"ada@example.com"}',
      })
      await req.text()
      const reply = await replyOfResponse((await handler(req)) as Response)
      expect([reply.status, reply.text]).toEqual([500, '{"error":"body-already-read"}'])
    }
    expect(setup.events).toEqual([])
  })

  it("passes the method, the URL as received and the request's own abort signal through", async () => {
    const setup = testAuth()
    const { spy, seen } = spyAuth(setup.auth)
    const controller = new AbortController()
    const req = webRequest(
      { method: "POST", path: "/auth/sign-up?x=1", headers: [["Origin", ORIGIN]], body: "{}" },
      { signal: controller.signal },
    )
    await withAuth(spy, appHandler)(req)
    const [request] = seen
    expect([request?.method, request?.url, request?.headers.get("origin")]).toEqual([
      "POST",
      `${ORIGIN}/auth/sign-up?x=1`,
      ORIGIN,
    ])
    expect(request?.signal).toBe(req.signal)
    controller.abort()
    expect(request?.signal?.aborted).toBe(true)
  })

  it("stops the core's work when the client went away before the body was read", async () => {
    const { auth } = testAuth()
    const controller = new AbortController()
    controller.abort()
    const req = webRequest(
      {
        method: "POST",
        path: "/auth/sign-up",
        headers: [
          ["Content-Type", "application/json"],
          ["Origin", ORIGIN],
        ],
      },
      { signal: controller.signal },
    )
    const reply = await replyOfResponse((await fetchAuth(auth)(req)) as Response)
    expect([reply.status, reply.text]).toEqual([400, '{"error":"aborted"}'])
  })
})

describe("the client address", () => {
  it("comes from the option the runtime supplies, with the runtime's own arguments", async () => {
    const setup = testAuth()
    const { spy, seen } = spyAuth(setup.auth)
    const info = { remoteAddr: { hostname: "198.51.100.1" } }
    const options = {
      clientAddress: (_req: Request, given: typeof info) => given.remoteAddr.hostname,
    }
    await withAuth(
      spy,
      appHandler,
      options,
    )(webRequest({ method: "GET", path: "/auth/session" }), info)
    await fetchAuth(spy, options)(webRequest({ method: "GET", path: "/auth/session" }), info)
    expect(seen.map((request) => request.clientAddress)).toEqual(["198.51.100.1", "198.51.100.1"])
  })

  it("is never read from a forwarded header", async () => {
    const setup = testAuth()
    const { spy, seen } = spyAuth(setup.auth)
    const req = () =>
      webRequest({
        method: "GET",
        path: "/auth/session",
        headers: [
          ["X-Forwarded-For", "203.0.113.9"],
          ["X-Real-IP", "203.0.113.9"],
          ["Forwarded", "for=203.0.113.9"],
        ],
      })
    await withAuth(spy, appHandler)(req())
    await fetchAuth(spy)(req())
    expect(seen.map((request) => request.clientAddress)).toEqual([undefined, undefined])
  })
})

describe("withAuth: deny by default (ADR 0024 §2)", () => {
  it("protects every route not listed as public", async () => {
    const setup = testAuth()
    const reply = await new Browser(fetchTransport(app(setup.auth))).get("/account")
    expect([reply.status, reply.text]).toEqual([401, '{"error":"unauthenticated"}'])
    expect(reply.headers.get("cache-control")).toBe("no-store")
  })

  it("answers a session below the default requirement with what it lacks", async () => {
    const setup = testAuth()
    const browser = new Browser(fetchTransport(app(setup.auth)))
    const { token } = await seedSession(setup, { evidence: aal1(setup.clock) })
    browser.cookies.set("__Host-test-cap", token)
    expect((await browser.get("/account")).text).toBe('{"error":"step-up"}')
    const enrolling = await seedSession(setup, { state: "pre-auth" })
    browser.cookies.set("__Host-test-cap", enrolling.token)
    expect((await browser.get("/account")).text).toBe('{"error":"enroll"}')
  })

  it("lets public routes through with a null subject, and hands the subject to protected ones", async () => {
    const setup = testAuth()
    const browser = new Browser(fetchTransport(app(setup.auth)))
    const { token } = await seedSession(setup, { evidence: aal2(setup.clock) })
    browser.cookies.set("__Host-test-cap", token)
    expect(body(await browser.get("/"))).toEqual({ page: "/", auth: null })
    expect(body(await browser.get("/blog/first"))).toEqual({ page: "/blog/first", auth: null })
    expect(body(await browser.get("/account"))).toEqual({
      page: "/account",
      auth: { subject: "acct-1" },
    })
  })

  it("protects everything but /auth/* when no public list is given", async () => {
    const setup = testAuth()
    const browser = new Browser(fetchTransport(withAuth(setup.auth, appHandler)))
    expect((await browser.get("/")).status).toBe(401)
    expect((await browser.get("/auth/session")).status).toBe(200)
  })

  it("refuses an ambiguous path with a 400 before any public-path match", async () => {
    const setup = testAuth()
    const browser = new Browser(fetchTransport(app(setup.auth, { public: ["/*"] })))
    expect((await browser.get("/blog//first")).text).toBe('{"error":"invalid-path"}')
    expect((await browser.get("/blog/first")).status).toBe(200)
  })

  it("leaves the body of the app's own routes for the app to read", async () => {
    const setup = testAuth()
    const browser = new Browser(fetchTransport(app(setup.auth, { public: ["/notes"] })))
    const reply = await browser.send({
      method: "POST",
      path: "/notes",
      headers: [["Content-Type", "application/json"]],
      body: '{"text":"hi"}',
    })
    expect([reply.status, body(reply)]).toEqual([200, { received: { text: "hi" } }])
  })

  it("hands the app handler the runtime's own arguments after the subject", async () => {
    const setup = testAuth()
    const seen: unknown[] = []
    const handler = withAuth<[{ name: string }]>(
      setup.auth,
      (_req, auth, server) => {
        seen.push([auth, server.name])
        return new Response("ok")
      },
      { public: ["/"] },
    )
    await handler(webRequest({ method: "GET", path: "/" }), { name: "bun" })
    expect(seen).toEqual([[null, "bun"]])
  })

  it("lets an error the app handler throws reach the runtime, untouched", async () => {
    const setup = testAuth()
    const failure = new Error("the app's own bug")
    const handler = withAuth(
      setup.auth,
      () => {
        throw failure
      },
      { public: ["/"] },
    )
    await expect(handler(webRequest({ method: "GET", path: "/" }))).rejects.toBe(failure)
  })

  it("refuses a malformed public list when the handler is built", () => {
    const { auth } = testAuth()
    expect(() => withAuth(auth, appHandler, { public: ["/blog/"] })).toThrow(
      "test-cap refused to start",
    )
  })

  it("refuses anything but the Auth createAuth returned", () => {
    const fake = { handle: () => Promise.resolve(null) } as unknown as Auth<string>
    expect(() => withAuth(fake, appHandler)).toThrow("Pass the Auth that createAuth returned.")
    expect(() => fetchAuth(fake)).toThrow("Pass the Auth that createAuth returned.")
  })
})

describe("fetchAuth: the /auth routes alone", () => {
  it("answers null outside /auth/, leaving the body unread for the app", async () => {
    const { auth } = testAuth()
    const req = webRequest({
      method: "POST",
      path: "/notes",
      headers: [["Content-Type", "application/json"]],
      body: '{"text":"hi"}',
    })
    expect(await fetchAuth(auth)(req)).toBeNull()
    expect(req.bodyUsed).toBe(false)
    expect(await fetchAuth(auth)(webRequest({ method: "GET", path: "/" }))).toBeNull()
  })

  it("serves an /auth route", async () => {
    const setup = testAuth()
    const browser = new Browser(fetchTransport(fetchAuth(setup.auth)))
    await enrol(browser, setup.clock, setup.outbox)
    const reply = await browser.get("/auth/session")
    expect((body(reply)["session"] as { level: string }).level).toBe("AAL2")
  })

  it("refuses an ambiguous path with a 400 rather than passing it on", async () => {
    const { auth } = testAuth()
    const reply = await replyOfResponse(
      (await fetchAuth(auth)(webRequest({ method: "GET", path: "//auth/session" }))) as Response,
    )
    expect([reply.status, reply.text]).toEqual([400, '{"error":"invalid-path"}'])
  })
})

describe("on Bun and Deno", () => {
  it("is the handler Bun.serve and Deno.serve take, with the client address from each runtime", async () => {
    const setup = testAuth()
    const seen: (string | undefined)[] = []
    const handler = (_req: Request, auth: FetchAuthInfo) => {
      seen.push(auth?.subject)
      return new Response("home")
    }
    // Deno.serve(denoHandler): the second argument is Deno's ServeHandlerInfo.
    const denoHandler = withAuth(setup.auth, handler, {
      public: ["/"],
      clientAddress: (_req, info: { remoteAddr: { hostname: string } }) => info.remoteAddr.hostname,
    })
    // Bun.serve({ fetch: bunHandler }): the second argument is Bun's Server.
    const bunHandler = withAuth(setup.auth, handler, {
      public: ["/"],
      clientAddress: (req, server: { requestIP(req: Request): { address: string } | null }) =>
        server.requestIP(req)?.address,
    })
    const deno = await denoHandler(webRequest({ method: "GET", path: "/" }), {
      remoteAddr: { hostname: "198.51.100.1" },
    })
    const bun = await bunHandler(webRequest({ method: "GET", path: "/" }), {
      requestIP: () => ({ address: "198.51.100.2" }),
    })
    expect([await deno.text(), await bun.text()]).toEqual(["home", "home"])
    expect(seen).toEqual([undefined, undefined])
  })
})
