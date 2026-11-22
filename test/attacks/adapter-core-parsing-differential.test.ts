// Attack: an adapter and the core disagree on path, duplicate headers, `Set-Cookie`, or body bytes.
// Stopped by: adapters convert bytes only; every scenario runs through each adapter and must give the same answer
// (ADR 0003, 0024). This file covers the four Web and Node adapters built so far: express, fetch, next and
// tanstack-start.
import express from "express"
import { afterEach, describe, expect, it } from "vitest"
import { expressAuth } from "../../src/adapters/express/index.js"
import { fetchAuth, withAuth } from "../../src/adapters/fetch/index.js"
import { nextAuthHandler } from "../../src/adapters/next/index.js"
import {
  tanstackStartAuth,
  tanstackStartMiddleware,
} from "../../src/adapters/tanstack-start/index.js"
import type { Auth } from "../../src/core/auth.js"
import { rawPath } from "../../src/transport/path.js"
import type { PlainRequest } from "../../src/transport/types.js"
import {
  aal2,
  ORIGIN,
  type Outgoing,
  seedSession,
  testAuth,
  type Transport,
} from "../support/auth.js"
import { fetchTransport, webRequest } from "../support/fetch.js"
import { listen } from "../support/http.js"

const closers: (() => Promise<void>)[] = []
afterEach(async () => {
  await Promise.all(closers.splice(0).map((close) => close()))
})

/** The app's own answer for a route it reaches: the path and query exactly as the request carries them. */
function reached(req: Request): Response {
  return new Response(JSON.stringify({ reached: rawPath(req.url) + new URL(req.url).search }), {
    headers: { "Content-Type": "application/json; charset=utf-8" },
  })
}

/**
 * TanStack Start as the adapter meets it: the global request middleware runs for every request, then the router sends
 * a path under `/auth/` (matched decoded, as the router does) to the `/auth/$` server route and anything else to the
 * app.
 */
function tanstackStart(auth: Auth<string>): (req: Request) => Promise<Response> {
  const { handlers } = tanstackStartAuth(auth)
  const middleware = tanstackStartMiddleware(auth, { public: ["/"] })
  return (request) =>
    middleware({
      request,
      next: () =>
        decodeURIComponent(new URL(request.url).pathname).startsWith("/auth/")
          ? handlers.ANY({ request })
          : Promise.resolve(reached(request)),
    })
}

/** The app every adapter fronts: a public `/`, everything else protected, every reachable route answering its path. */
async function adapters(auth: Auth<string>): Promise<Record<string, Transport>> {
  const application = express()
  application.use(expressAuth(auth, { public: ["/"] }))
  application.all("/{*any}", (req, res) => {
    res.json({ reached: req.originalUrl })
  })
  const server = await listen(application)
  closers.push(server.close)
  const { GET, POST } = nextAuthHandler(auth)
  return {
    express: server.transport,
    fetch: fetchTransport(withAuth(auth, reached, { public: ["/"] })),
    // Next.js mounts the handler at app/auth/[...path], so only /auth/* reaches it.
    next: fetchTransport((req) => (req.method === "GET" ? GET(req) : POST(req))),
    tanstack: fetchTransport(tanstackStart(auth)),
  }
}

/** The parts of a reply the scenarios compare: status, body, content type and each cookie. */
async function answers(transports: Record<string, Transport>, request: Outgoing) {
  const result: Record<string, unknown> = {}
  for (const [name, transport] of Object.entries(transports)) {
    const reply = await transport(request)
    result[name] = {
      status: reply.status,
      text: reply.text,
      type: reply.headers.get("content-type"),
      cookies: reply.headers.getSetCookie(),
    }
  }
  return result
}

function same(result: Record<string, unknown>, names: readonly string[]) {
  const first = result[names[0] as string]
  for (const name of names) expect(result[name], name).toEqual(first)
  return first
}

const json = [
  ["Content-Type", "application/json"],
  ["Origin", ORIGIN],
] as const

describe("adapter-core-parsing-differential", () => {
  it.each([
    ["//auth/session", "GET"],
    ["/auth//session", "GET"],
    ["/auth/session/", "GET"],
    ["/auth%2Fsession", "GET"],
    ["/auth/sign%2Dup", "POST"],
    ["/auth/%5Csession", "GET"],
  ])("refuses the ambiguous path %s the same way through every adapter", async (path, method) => {
    const { auth } = testAuth()
    const result = await answers(await adapters(auth), {
      method,
      path,
      headers: json,
      body: method === "POST" ? "{}" : undefined,
    })
    expect(same(result, ["express", "fetch", "next", "tanstack"])).toEqual({
      status: 400,
      text: '{"error":"invalid-path"}',
      type: "application/json; charset=utf-8",
      cookies: [],
    })
  })

  it("refuses a repeated Origin header the same way through every adapter", async () => {
    const { auth } = testAuth()
    const result = await answers(await adapters(auth), {
      method: "POST",
      path: "/auth/sign-up",
      headers: [...json, ["Origin", ORIGIN]],
      body: '{"identifier":"ada@example.com"}',
    })
    expect(same(result, ["express", "fetch", "next", "tanstack"])).toMatchObject({
      status: 400,
      text: '{"error":"ambiguous-header"}',
    })
  })

  it("answers an undeclared field, a wrong method and an unknown route the same way through every adapter", async () => {
    const { auth } = testAuth()
    const transports = await adapters(auth)
    for (const request of [
      { method: "POST", path: "/auth/sign-up", headers: json, body: '{"verified":true}' },
      { method: "POST", path: "/auth/session", headers: json, body: "{}" },
      { method: "GET", path: "/auth/nope" },
    ]) {
      same(await answers(transports, request), ["express", "fetch", "next", "tanstack"])
    }
  })

  it("keeps every Set-Cookie value the core sets, through every adapter", async () => {
    const setup = testAuth()
    const twoCookies = Object.create(setup.auth) as Auth<string>
    twoCookies.handle = () => {
      const headers = new Headers()
      headers.append("Set-Cookie", "a=1; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT")
      headers.append("Set-Cookie", "b=2; Path=/")
      return Promise.resolve({ status: 200, headers, body: null })
    }
    const result = await answers(await adapters(twoCookies), {
      method: "GET",
      path: "/auth/session",
    })
    expect(same(result, ["express", "fetch", "next", "tanstack"])).toMatchObject({
      cookies: ["a=1; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT", "b=2; Path=/"],
    })
  })

  it("hands the core the same method, path, header values and body bytes through every adapter", async () => {
    const setup = testAuth()
    const seen: PlainRequest[] = []
    const spy = Object.create(setup.auth) as Auth<string>
    spy.handle = (request) => {
      seen.push(request)
      return Promise.resolve({ status: 204, headers: new Headers(), body: null })
    }
    const bytes = new Uint8Array([
      0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xc3, 0xa9, 0x22, 0x7d, 0x00, 0xff,
    ])
    await answers(await adapters(spy), {
      method: "POST",
      path: "/auth/sign-up?x=1",
      headers: [...json, ["X-Repeated", "one"], ["X-Repeated", "two"]],
      body: bytes,
    })
    const views = seen.map((request) => ({
      method: request.method,
      path: rawPath(request.url),
      query: request.url.slice(request.url.indexOf("?")),
      origin: request.headers.get("origin"),
      repeated: request.headers.get("x-repeated"),
      type: request.headers.get("content-type"),
      body: request.body,
    }))
    expect(views).toHaveLength(4)
    for (const view of views) {
      expect(view).toEqual({
        method: "POST",
        path: "/auth/sign-up",
        query: "?x=1",
        origin: ORIGIN,
        repeated: "one, two",
        type: "application/json",
        body: bytes,
      })
    }
  })

  it("applies deny by default identically through express, fetch and tanstack-start", async () => {
    const setup = testAuth()
    const transports = await adapters(setup.auth)
    const { token } = await seedSession(setup, { evidence: aal2(setup.clock) })
    const cookie = [["Cookie", `__Host-test-cap=${token}`]] as const
    for (const request of [
      { method: "GET", path: "/" },
      { method: "GET", path: "/account" },
      { method: "OPTIONS", path: "/account" },
      { method: "GET", path: "/Account" },
      { method: "GET", path: "/account?x=1", headers: cookie },
      { method: "GET", path: "/", headers: cookie },
    ]) {
      same(await answers(transports, request), ["express", "fetch", "tanstack"])
    }
  })

  it("lets a fetch runtime's handler see exactly the URL the core judged", async () => {
    // The runtime parses the URL before the adapter runs, so `/x/../about` arrives as `/about`; the core and
    // the app's router both read that one `req.url`, so they cannot disagree about which route it is.
    const { auth } = testAuth()
    const judged: string[] = []
    const spy = Object.create(auth) as Auth<string>
    const handler = withAuth(
      spy,
      (req) => {
        judged.push(req.url)
        return new Response("about")
      },
      { public: ["/about"] },
    )
    const req = webRequest({ method: "GET", path: "/x/../about" })
    expect(req.url).toBe(`${ORIGIN}/about`)
    expect(await (await handler(req)).text()).toBe("about")
    expect(judged).toEqual([`${ORIGIN}/about`])
    expect(await fetchAuth(auth)(webRequest({ method: "GET", path: "/auth/../y" }))).toBeNull()
  })

  it("lets TanStack Start's routes see exactly the URL the core judged", async () => {
    // TanStack Start hands the middleware the same WHATWG-parsed `request.url` its router matches, so a dot segment
    // is resolved before either reads it.
    const { auth } = testAuth()
    const judged: string[] = []
    const middleware = tanstackStartMiddleware(auth, { public: ["/about"] })
    const req = webRequest({ method: "GET", path: "/x/../about" })
    const response = await middleware({
      request: req,
      next: () => {
        judged.push(req.url)
        return new Response("about")
      },
    })
    expect(await (response as Response).text()).toBe("about")
    expect(judged).toEqual([`${ORIGIN}/about`])
  })
})
