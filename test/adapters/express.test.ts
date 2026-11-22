// The Express adapter (ADR 0024 §1, §2, Open 2) over a real express app and a real socket, plus the stream edge cases
// driven through stand-in request and response objects.
import { EventEmitter } from "node:events"
import express from "express"
import { afterEach, describe, expect, it } from "vitest"
import {
  type ExpressLikeRequest,
  type ExpressLikeResponse,
  expressAuth,
} from "../../src/adapters/express/index.js"
import type { Auth } from "../../src/core/auth.js"
import { aal1, aal2, body, Browser, enrol, ORIGIN, seedSession, testAuth } from "../support/auth.js"
import { listen } from "../support/http.js"
import { within } from "../support/within.js"

const servers: (() => Promise<void>)[] = []
afterEach(async () => {
  await Promise.all(servers.splice(0).map((close) => close()))
})

async function serve(app: Parameters<typeof listen>[0]) {
  const server = await listen(app)
  servers.push(server.close)
  return server
}

/** An app with test-cap mounted first, a public home page and a protected page that echoes req.auth. */
function app(
  auth: Auth<string>,
  options: { public?: readonly string[] } = { public: ["/", "/blog/*"] },
) {
  const application = express()
  application.use(expressAuth(auth, options))
  application.use(express.json())
  application.get("/", (req, res) => {
    res.json({ page: "home", auth: (req as ExpressLikeRequest).auth })
  })
  application.get("/blog/:post", (req, res) => {
    res.json({ page: req.params.post, auth: (req as ExpressLikeRequest).auth })
  })
  application.get("/account", (req, res) => {
    res.json({ page: "account", auth: (req as ExpressLikeRequest).auth })
  })
  application.post("/notes", (req, res) => {
    res.json({ received: req.body as unknown })
  })
  return application
}

describe("serving /auth/* over HTTP", () => {
  it("runs sign-up to an AAL2 session, then opens a protected route with req.auth set", async () => {
    const setup = testAuth()
    const { transport } = await serve(app(setup.auth))
    const browser = new Browser(transport)
    const { subject } = await enrol(browser, setup.clock, setup.outbox)
    const reply = await browser.get("/account")
    expect([reply.status, body(reply)]).toEqual([200, { page: "account", auth: { subject } }])
  })

  it("passes every security header and the status through unchanged", async () => {
    const setup = testAuth()
    const { transport } = await serve(app(setup.auth))
    const reply = await new Browser(transport).get("/auth/nope")
    expect([reply.status, reply.text]).toEqual([404, '{"error":"not-found"}'])
    expect(reply.headers.get("cache-control")).toBe("no-store")
    expect(reply.headers.get("content-security-policy")).toContain("frame-ancestors 'none'")
    expect(reply.headers.get("x-content-type-options")).toBe("nosniff")
    expect(reply.headers.get("referrer-policy")).toBe("no-referrer")
    expect(reply.headers.get("content-type")).toBe("application/json; charset=utf-8")
  })

  it("writes every Set-Cookie value as its own header line", async () => {
    const setup = testAuth()
    const twoCookies = Object.create(setup.auth) as Auth<string>
    twoCookies.handle = () => {
      const headers = new Headers()
      headers.append("Set-Cookie", "a=1; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT")
      headers.append("Set-Cookie", "b=2; Path=/")
      headers.append("X-Other", "kept")
      return Promise.resolve({ status: 200, headers, body: null })
    }
    const { transport } = await serve(app(twoCookies))
    const reply = await new Browser(transport).get("/auth/session")
    expect(reply.headers.getSetCookie()).toEqual([
      "a=1; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT",
      "b=2; Path=/",
    ])
    expect(reply.headers.get("x-other")).toBe("kept")
    expect(reply.text).toBe("")
  })

  it("hands the core every repeated request header, so it can refuse the ambiguity", async () => {
    const setup = testAuth()
    const { transport } = await serve(app(setup.auth))
    const browser = new Browser(transport)
    await browser.start()
    const reply = await browser.post(
      "/auth/sign-up",
      { identifier: "ada@example.com" },
      {
        headers: [["Origin", ORIGIN]],
      },
    )
    expect([reply.status, reply.text]).toEqual([400, '{"error":"ambiguous-header"}'])
  })

  it("refuses a body over 64 KiB with a 413, declared or chunked", async () => {
    const setup = testAuth()
    const { transport, port } = await serve(app(setup.auth))
    const browser = new Browser(transport)
    await browser.start()
    const large = await within(
      browser.post("/auth/sign-up", { identifier: "a".repeat(70_000) }),
      2_000,
    )
    expect([large.status, large.text]).toEqual([413, '{"error":"body-too-large"}'])
    const { request } = await import("node:http")
    const sent = new Promise<{ status: number; text: string }>((resolve, reject) => {
      const req = request(
        {
          host: "127.0.0.1",
          port,
          method: "POST",
          path: "/auth/sign-up",
          headers: { "Content-Type": "application/json", Origin: ORIGIN },
        },
        (res) => {
          let text = ""
          res.on("data", (chunk: Buffer) => (text += chunk.toString()))
          res.on("end", () => resolve({ status: res.statusCode ?? 0, text }))
        },
      )
      req.on("error", reject)
      for (let i = 0; i < 10; i += 1) req.write("x".repeat(8_000))
      req.end()
    })
    const chunked = await within(sent, 2_000)
    expect(chunked).toEqual({ status: 413, text: '{"error":"body-too-large"}' })
  })

  it("leaves the stream of the app's own routes to the app's own body parser", async () => {
    const setup = testAuth()
    const { transport } = await serve(app(setup.auth, { public: ["/notes"] }))
    const reply = await new Browser(transport).send({
      method: "POST",
      path: "/notes",
      headers: [["Content-Type", "application/json"]],
      body: '{"text":"hi"}',
    })
    expect([reply.status, body(reply)]).toEqual([200, { received: { text: "hi" } }])
  })

  it("reads the URL as Express received it when mounted under a path", async () => {
    const setup = testAuth()
    const application = express()
    application.use("/api", expressAuth(setup.auth))
    application.get("/api/auth/session", (_req, res) => {
      res.json({ reached: "app" })
    })
    const { transport } = await serve(application)
    const reply = await new Browser(transport).get("/api/auth/session")
    expect([reply.status, reply.text]).toEqual([401, '{"error":"unauthenticated"}'])
  })

  it("works on a plain Node server, which has no originalUrl", async () => {
    const setup = testAuth()
    const middleware = expressAuth(setup.auth, { public: ["/"] })
    const { transport } = await serve((req, res) => {
      middleware(req as unknown as ExpressLikeRequest, res, () => {
        res.end("app")
      })
    })
    const browser = new Browser(transport)
    expect((await browser.get("/auth/session")).status).toBe(200)
    expect((await browser.get("/")).text).toBe("app")
    expect((await browser.get("/private")).status).toBe(401)
  })
})

describe("deny by default (ADR 0024 §2)", () => {
  it("protects every route not listed as public", async () => {
    const setup = testAuth()
    const { transport } = await serve(app(setup.auth))
    const browser = new Browser(transport)
    const reply = await browser.get("/account")
    expect([reply.status, reply.text]).toEqual([401, '{"error":"unauthenticated"}'])
    expect(reply.headers.get("cache-control")).toBe("no-store")
  })

  it("answers a session below the default requirement with what it lacks", async () => {
    const setup = testAuth()
    const { transport } = await serve(app(setup.auth))
    const { token } = await seedSession(setup, { evidence: aal1(setup.clock) })
    const browser = new Browser(transport)
    browser.cookies.set("__Host-test-cap", token)
    expect((await browser.get("/account")).text).toBe('{"error":"step-up"}')
    const enrolling = await seedSession(setup, { state: "pre-auth" })
    browser.cookies.set("__Host-test-cap", enrolling.token)
    expect((await browser.get("/account")).text).toBe('{"error":"enroll"}')
  })

  it("lets public routes through with req.auth null, without reading the session", async () => {
    const setup = testAuth()
    const { transport } = await serve(app(setup.auth))
    const { token } = await seedSession(setup, { evidence: aal2(setup.clock) })
    const browser = new Browser(transport)
    browser.cookies.set("__Host-test-cap", token)
    expect(body(await browser.get("/"))).toEqual({ page: "home", auth: null })
    expect(body(await browser.get("/blog/first"))).toEqual({ page: "first", auth: null })
    expect(body(await browser.get("/account"))).toEqual({
      page: "account",
      auth: { subject: "acct-1" },
    })
  })

  it("protects everything but /auth/* when no public list is given", async () => {
    const setup = testAuth()
    const { transport } = await serve(app(setup.auth, {}))
    const browser = new Browser(transport)
    expect((await browser.get("/")).status).toBe(401)
    expect((await browser.get("/auth/session")).status).toBe(200)
  })

  it("refuses a malformed public list when the adapter is built", () => {
    const { auth } = testAuth()
    expect(() => expressAuth(auth, { public: ["/blog/"] })).toThrow("test-cap refused to start")
  })
})

describe("a body parser mounted before the adapter (ADR 0024 Open 2)", () => {
  it("fails closed with a 500 on a POST to /auth/*, and never reads req.body", async () => {
    const setup = testAuth()
    const application = express()
    application.use(express.json())
    application.use(expressAuth(setup.auth, { public: ["/"] }))
    const { transport } = await serve(application)
    const browser = new Browser(transport)
    await browser.start()
    const reply = await browser.post("/auth/sign-up", { identifier: "ada@example.com" })
    expect([reply.status, reply.text]).toEqual([500, '{"error":"body-already-read"}'])
    expect(setup.events).toEqual([])
  })
})

/** A stand-in request whose stream a test drives event by event. */
function fakeRequest(overrides: Partial<ExpressLikeRequest> = {}) {
  const emitter = new EventEmitter()
  let paused = false
  const req = {
    method: "POST",
    url: "/auth/sign-up",
    rawHeaders: ["Content-Type", "application/json", "Origin", ORIGIN],
    socket: { remoteAddress: "198.51.100.1" },
    readableEnded: false,
    on(event: string, listener: Parameters<EventEmitter["on"]>[1]) {
      emitter.on(event, listener)
      return req
    },
    pause() {
      paused = true
      return req
    },
    ...overrides,
  } as ExpressLikeRequest
  return { req, emitter, paused: () => paused }
}

/** A stand-in response that records what the adapter wrote. */
function fakeResponse(writableFinished = false) {
  const emitter = new EventEmitter()
  const headers = new Map<string, string | readonly string[]>()
  let ended: Uint8Array | undefined
  let resolveEnd = (): void => undefined
  const done = new Promise<void>((resolve) => {
    resolveEnd = resolve
  })
  const res: ExpressLikeResponse & { emit(event: string): void } = {
    statusCode: 0,
    writableFinished,
    setHeader(name, value) {
      headers.set(name.toLowerCase(), value)
      return res
    },
    end(chunk) {
      ended = chunk
      resolveEnd()
      return res
    },
    once(event, listener) {
      emitter.once(event, listener)
      return res
    },
    emit(event) {
      emitter.emit(event)
    },
  }
  return { res, headers, done, text: () => new TextDecoder().decode(ended ?? new Uint8Array()) }
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 5))

describe("the stream, driven by hand", () => {
  it("reads past the limit by one chunk at most, then stops and lets the core refuse it", async () => {
    const { auth } = testAuth()
    const { req, emitter, paused } = fakeRequest()
    const { res, done, text } = fakeResponse()
    expressAuth(auth)(req, res, () => undefined)
    await tick()
    emitter.emit("data", new Uint8Array(65_536))
    expect(paused()).toBe(false)
    emitter.emit("data", new Uint8Array(1))
    expect(paused()).toBe(true)
    await within(done, 1_000)
    expect([res.statusCode, text()]).toEqual([413, '{"error":"body-too-large"}'])
  })

  it("joins the chunks in order", async () => {
    const setup = testAuth()
    const start = await setup.auth.handle({
      method: "GET",
      url: "/auth/session",
      headers: new Headers(),
      body: null,
    })
    const cookie = start?.headers.getSetCookie()[0]?.split(";")[0] ?? ""
    const token = JSON.parse(new TextDecoder().decode(start?.body ?? new Uint8Array())) as {
      csrfToken: string
    }
    const { req, emitter } = fakeRequest({
      rawHeaders: [
        "Content-Type",
        "application/json",
        "Origin",
        ORIGIN,
        "Cookie",
        cookie,
        "X-CSRF-Token",
        token.csrfToken,
      ],
    })
    const { res, done, text } = fakeResponse()
    expressAuth(setup.auth)(req, res, () => undefined)
    await tick()
    const payload = new TextEncoder().encode('{"identifier":"ada@example.com"}')
    emitter.emit("data", payload.slice(0, 10))
    emitter.emit("data", payload.slice(10))
    emitter.emit("end")
    await done
    expect([res.statusCode, text()]).toEqual([200, '{"outcome":"enroll","returnTo":"/"}'])
  })

  it("answers a stream error with a fixed 500", async () => {
    const { auth } = testAuth()
    const { req, emitter } = fakeRequest()
    const { res, done, text } = fakeResponse()
    expressAuth(auth)(req, res, () => undefined)
    await tick()
    emitter.emit("error", new Error("socket hang up: secret detail"))
    await within(done, 1_000)
    expect([res.statusCode, text()]).toEqual([500, '{"error":"internal"}'])
  })

  it("refuses a stream something already read, even with no req.body", async () => {
    const { auth } = testAuth()
    const { req } = fakeRequest({ readableEnded: true })
    const { res, done, text } = fakeResponse()
    expressAuth(auth)(req, res, () => undefined)
    await done
    expect([res.statusCode, text()]).toEqual([500, '{"error":"body-already-read"}'])
  })

  it("aborts the core's work when the client goes away before the reply", async () => {
    const { auth } = testAuth()
    const { req, emitter } = fakeRequest()
    const { res, done, text } = fakeResponse(false)
    expressAuth(auth)(req, res, () => undefined)
    await tick()
    res.emit("close")
    emitter.emit("data", new TextEncoder().encode("{}"))
    emitter.emit("end")
    await done
    expect([res.statusCode, text()]).toEqual([400, '{"error":"aborted"}'])
  })

  it("does not abort when the close comes after the reply finished", async () => {
    const { auth } = testAuth()
    const { req, emitter } = fakeRequest()
    const { res, done, text } = fakeResponse(true)
    expressAuth(auth)(req, res, () => undefined)
    await tick()
    res.emit("close")
    emitter.emit("data", new TextEncoder().encode("{}"))
    emitter.emit("end")
    await done
    expect([res.statusCode, text()]).toEqual([400, '{"error":"missing-field"}'])
  })

  it("passes the socket address and the method through", async () => {
    const setup = testAuth()
    const seen: unknown[] = []
    const spy = Object.create(setup.auth) as Auth<string>
    spy.handle = (request) => {
      seen.push([request.method, request.url, request.clientAddress, request.headers.get("origin")])
      return Promise.resolve({ status: 204, headers: new Headers(), body: null })
    }
    const { req, emitter } = fakeRequest({ originalUrl: "/auth/sign-up?x=1", url: "/ignored" })
    const { res, done } = fakeResponse()
    expressAuth(spy)(req, res, () => undefined)
    await tick()
    emitter.emit("end")
    await done
    expect(seen).toEqual([["POST", "/auth/sign-up?x=1", "198.51.100.1", ORIGIN]])
    expect(res.statusCode).toBe(204)
  })
})
