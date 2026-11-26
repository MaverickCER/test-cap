// The request limiter through `auth.handle` (ADR 0009 §8): a default on every route, each value changeable, a rule
// per route, `false` for one route or all of them, and the app's own RateLimiter in place of the store's counters.
import { describe, expect, it } from "vitest"
import { type AuthDiagnostic, createAuth, internalsOf } from "../../src/core/auth.js"
import { memoryStore } from "../../src/store/memory.js"
import type { SecurityEvent } from "../../src/ocsf/events.js"
import {
  DEFAULT_RATE_LIMIT,
  DEFAULT_RATE_RULES,
  RATE_LIMIT_ROUTES,
  type LimiterOptions,
  type RateLimitRouteId,
  type RateRule,
} from "../../src/security/rate-limit.js"
import {
  Browser,
  discardEmail,
  ENV,
  hibpClear,
  PASSWORD,
  plainRequest,
  seedAccount,
  testAuth,
} from "../support/auth.js"
import RateLimiterMemory from "rate-limiter-flexible/lib/RateLimiterMemory.js"
import { CLIENT, fakeLimiter, recordingStore, sendFrom, type Shape } from "../support/requests.js"

const LIMITED = '{"error":"rate-limited"}'

/** The header a browser sends on a same-origin post; without it the CSRF check tells the operator. */
const SAME_SITE = [["Origin", "https://app.example"]] as const

/** One request that falls under each route id. */
function sampleOf(id: RateLimitRouteId, auth: ReturnType<typeof testAuth>["auth"]): Shape {
  if (id === "pages") return { method: "GET", path: "/auth/sign-in" }
  if (id === "assets") return { method: "GET", path: "/auth/assets/missing.js" }
  if (id === "unmatched") return { method: "GET", path: "/auth/no-such-route" }
  const route = internalsOf(auth)
    .routes()
    .find((each) => each.path === `/auth/${id}`)
  if (route === undefined) throw new Error(`no route ${id}`)
  return { method: route.method, path: route.path }
}

/** The rule a route id gets by default. */
function defaultRule(id: RateLimitRouteId): RateRule {
  return DEFAULT_RATE_RULES[id] ?? DEFAULT_RATE_LIMIT
}

/** Sends `request` `times` times from one client and returns each status. */
async function statuses(send: ReturnType<typeof sendFrom>, request: Shape, times: number) {
  const seen: number[] = []
  for (let n = 0; n < times; n += 1) seen.push((await send(request)).status)
  return seen
}

describe("the default limits", () => {
  it("have an id for every route the dispatcher answers, and no other", () => {
    const { auth } = testAuth()
    const routeIds = internalsOf(auth)
      .routes()
      .map((route) => route.path.slice("/auth/".length))
    expect([...RATE_LIMIT_ROUTES].sort()).toEqual(
      [...routeIds, "pages", "assets", "unmatched"].sort(),
    )
  })

  it("answer each route's own count, then 429 rate-limited with the window's wait in Retry-After", async () => {
    for (const id of RATE_LIMIT_ROUTES) {
      const { auth } = testAuth()
      const send = sendFrom(auth)
      const rule = defaultRule(id)
      const request = sampleOf(id, auth)
      const before = await statuses(send, request, rule.max)
      expect(
        before.filter((status) => status === 429),
        id,
      ).toEqual([])
      const over = await send(request)
      expect([over.status, over.text, over.headers.get("retry-after")], id).toEqual([
        429,
        LIMITED,
        String(rule.windowMs / 1000),
      ])
      expect(over.headers.get("cache-control"), id).toBe("no-store")
    }
  })

  it("are on in development too", async () => {
    const auth = createAuth({
      store: memoryStore(),
      env: { ...ENV, APP_ENV: "development" },
      hibpFetch: hibpClear,
      sendEmail: discardEmail,
    })
    const send = sendFrom(auth)
    const signUp = await statuses(
      send,
      { method: "POST", path: "/auth/sign-up", headers: SAME_SITE },
      21,
    )
    expect(signUp.indexOf(429)).toBe(20)
  })

  it("count each request under the id of what runs for it", async () => {
    for (const id of RATE_LIMIT_ROUTES) {
      const { limiter, keys } = fakeLimiter(() => ({ allowed: true }))
      const { auth } = testAuth({ rateLimit: limiter })
      await sendFrom(auth)(sampleOf(id, auth))
      expect(keys, id).toEqual([`${id}|${CLIENT}`])
    }
  })

  it("count each client on its own", async () => {
    const { auth } = testAuth()
    const request = { method: "POST", path: "/auth/sign-in" }
    await statuses(sendFrom(auth, "192.0.2.1"), request, 10)
    expect((await sendFrom(auth, "192.0.2.1")(request)).status).toBe(429)
    expect((await sendFrom(auth, "192.0.2.2")(request)).status).toBe(403)
  })

  it("let a client in again once the window ends, and tell it the wait that remains before then", async () => {
    const setup = testAuth()
    const send = sendFrom(setup.auth)
    const request = { method: "POST", path: "/auth/sign-in" }
    await statuses(send, request, 10)
    setup.clock.advance(7_500)
    expect((await send(request)).headers.get("retry-after")).toBe("3")
    setup.clock.advance(2_500)
    expect((await send(request)).status).toBe(403)
  })

  it("count a request before anything else runs, so a refused one runs nothing but the count and its event mark", async () => {
    const recorded = recordingStore()
    const { auth } = testAuth({ store: recorded.store })
    const send = sendFrom(auth)
    const browser = new Browser(send)
    await browser.start()
    for (let n = 0; n < 10; n += 1) {
      await browser.post("/auth/sign-in", { identifier: "ada@example.com", password: "wrong" })
    }
    recorded.calls.length = 0
    const over = await browser.post("/auth/sign-in", {
      identifier: "ada@example.com",
      password: "x",
    })
    expect(over.status).toBe(429)
    // Besides the request's count, a refused post counts its refusal, so only the first of the window emits an event.
    expect(recorded.calls).toEqual(["increment", "increment"])
  })
})

describe("the reply to a limited request", () => {
  it("is the same for an account that exists and one that does not", async () => {
    const setup = testAuth()
    await seedAccount(setup, { password: true, identifier: "ada@example.com" })
    const send = sendFrom(setup.auth)
    const browser = new Browser(send)
    await browser.start()
    for (let n = 0; n < 10; n += 1) {
      await browser.post("/auth/sign-in", { identifier: "nobody@example.com", password: "x" })
    }
    const real = await browser.post("/auth/sign-in", {
      identifier: "ada@example.com",
      password: PASSWORD,
    })
    const missing = await browser.post("/auth/sign-in", {
      identifier: "nobody@example.com",
      password: "x",
    })
    expect([real.status, real.text]).toEqual([429, LIMITED])
    expect([missing.status, missing.text]).toEqual([real.status, real.text])
    expect(missing.headers.get("retry-after")).toBe(real.headers.get("retry-after"))
  })

  it("is the sign-in page with the wait, for a form post that wants a page", async () => {
    const { auth } = testAuth()
    const send = sendFrom(auth)
    const form = {
      method: "POST",
      path: "/auth/sign-in",
      headers: [
        ["Origin", "https://app.example"],
        ["Accept", "text/html"],
        ["Content-Type", "application/x-www-form-urlencoded"],
      ] as const,
      body: "identifier=ada%40example.com&password=x",
    }
    await statuses(send, form, 10)
    const over = await send(form)
    expect(over.status).toBe(429)
    expect(over.headers.get("content-type")).toBe("text/html; charset=utf-8")
    expect(over.headers.get("retry-after")).toBe("10")
    expect(over.text).toContain("Too many attempts. Try again in 10 seconds.")
    expect(over.text).toContain('data-form="sign-in"')
  })

  it("is JSON for a form post whose page would start a ceremony to open, so a refusal writes nothing", async () => {
    const recorded = recordingStore()
    const { auth } = testAuth({ store: recorded.store })
    const send = sendFrom(auth)
    const form = {
      method: "POST",
      path: "/auth/totp/confirm",
      headers: [
        ["Origin", "https://app.example"],
        ["Accept", "text/html"],
        ["Content-Type", "application/x-www-form-urlencoded"],
      ] as const,
      body: "code=123456",
    }
    await statuses(send, form, 10)
    recorded.calls.length = 0
    const over = await send(form)
    expect([over.status, over.text]).toEqual([429, LIMITED])
    expect(recorded.calls).toEqual(["increment", "increment"])
  })

  it("is JSON for a form post to a route no default page posts to", async () => {
    const { auth } = testAuth()
    const send = sendFrom(auth)
    const form = {
      method: "POST",
      path: "/auth/recovery",
      headers: [
        ["Origin", "https://app.example"],
        ["Accept", "text/html"],
        ["Content-Type", "application/x-www-form-urlencoded"],
      ] as const,
      body: "identifier=ada%40example.com&code=x",
    }
    await statuses(send, form, 10)
    const over = await send(form)
    expect([over.status, over.text]).toEqual([429, LIMITED])
  })

  it("emits the route's failure event with the detail request-limit and no account", async () => {
    const setup = testAuth()
    const send = sendFrom(setup.auth)
    await statuses(send, { method: "POST", path: "/auth/sign-up" }, 20)
    setup.events.length = 0
    await send({ method: "POST", path: "/auth/sign-up" })
    expect(setup.events).toHaveLength(1)
    const event = setup.events[0] as SecurityEvent
    expect(event).toMatchObject({
      class_uid: 3007,
      activity_name: "Create",
      status: "Failure",
      status_detail: "request-limit",
      user: { uid: "unknown" },
    })
  })

  it("emits nothing for a limited read, as a refused read emits nothing", async () => {
    const setup = testAuth()
    const send = sendFrom(setup.auth)
    await statuses(send, { method: "GET", path: "/auth/session" }, 100)
    setup.events.length = 0
    expect((await send({ method: "GET", path: "/auth/session" })).status).toBe(429)
    expect(setup.events).toEqual([])
  })
})

describe("changing the limits", () => {
  it("changes the default rule's values, and leaves the stricter routes as they are", async () => {
    const { auth } = testAuth({ rateLimit: { max: 3, windowMs: 60_000 } })
    const send = sendFrom(auth)
    expect(await statuses(send, { method: "GET", path: "/auth/session" }, 4)).toEqual([
      200, 200, 200, 429,
    ])
    expect((await send({ method: "GET", path: "/auth/session" })).headers.get("retry-after")).toBe(
      "60",
    )
    const signIn = await statuses(send, { method: "POST", path: "/auth/sign-in" }, 11)
    expect(signIn.indexOf(429)).toBe(10)
  })

  it("gives one route its own rule", async () => {
    const { auth } = testAuth({ rateLimit: { rules: { "sign-in": { windowMs: 60_000, max: 2 } } } })
    const send = sendFrom(auth)
    expect(await statuses(send, { method: "POST", path: "/auth/sign-in" }, 3)).toEqual([
      403, 403, 429,
    ])
    expect(await statuses(send, { method: "POST", path: "/auth/step-up" }, 3)).toEqual([
      403, 403, 403,
    ])
  })

  it("turns one route's limit off with false, and keeps the others", async () => {
    const { auth } = testAuth({ rateLimit: { rules: { "sign-in": false } } })
    const send = sendFrom(auth)
    const signIn = await statuses(send, { method: "POST", path: "/auth/sign-in" }, 30)
    expect(signIn.filter((status) => status === 429)).toEqual([])
    expect((await statuses(send, { method: "POST", path: "/auth/step-up" }, 11))[10]).toBe(429)
  })

  it("asks a rule function about each request", async () => {
    const { auth } = testAuth({
      rateLimit: {
        rules: {
          "sign-in": (request) =>
            request.headers.get("x-internal") === "yes" ? false : { windowMs: 10_000, max: 1 },
        },
      },
    })
    const send = sendFrom(auth)
    const internal = {
      method: "POST",
      path: "/auth/sign-in",
      headers: [["X-Internal", "yes"]] as const,
    }
    expect(await statuses(send, internal, 5)).toEqual([403, 403, 403, 403, 403])
    expect(await statuses(send, { method: "POST", path: "/auth/sign-in" }, 2)).toEqual([403, 429])
  })

  it("refuses to start on a rule for a route that does not exist, naming the route ids", () => {
    expect(() => testAuth({ rateLimit: { rules: { sign_in: false } as never } })).toThrow(
      'rateLimit.rules has no route "sign_in". Rules are keyed by route id:',
    )
  })

  it("turns every limit off with rateLimit: false, in any mode, and tells the operator once", async () => {
    for (const mode of ["test", "development"]) {
      const diagnostics: AuthDiagnostic[] = []
      const auth = createAuth({
        store: memoryStore(),
        env: { ...ENV, APP_ENV: mode },
        hibpFetch: hibpClear,
        sendEmail: discardEmail,
        rateLimit: false,
        onDiagnostic: (diagnostic) => diagnostics.push(diagnostic),
      })
      expect(diagnostics, mode).toHaveLength(1)
      const send = sendFrom(auth)
      const signUp = await statuses(
        send,
        { method: "POST", path: "/auth/sign-up", headers: SAME_SITE },
        30,
      )
      expect(
        signUp.filter((status) => status === 429),
        mode,
      ).toEqual([])
      await statuses(send, { method: "GET", path: "/auth/session" }, 120)
      expect(diagnostics, mode).toEqual([
        {
          code: "rate-limit-off",
          message:
            "rateLimit is false, so test-cap limits no request to /auth. Limit them in front of the app, at its gateway or proxy (ADR 0009 §8).",
        },
      ])
    }
  })

  it("builds each rule's limiter over the app's own backend in place of the store's counters", async () => {
    const recorded = recordingStore()
    const seen: { key: string; options: LimiterOptions }[] = []
    const factory = (options: LimiterOptions) =>
      fakeLimiter((key) => {
        seen.push({ key, options })
        return seen.length < 3 ? { allowed: true } : { allowed: false, msBeforeNext: 4_200 }
      }).limiter
    const { auth } = testAuth({ store: recorded.store, rateLimit: { limiter: factory } })
    const send = sendFrom(auth, "2001:db8:1:2::9")
    expect(await statuses(send, { method: "POST", path: "/auth/sign-in" }, 3)).toEqual([
      403, 403, 429,
    ])
    expect((await send({ method: "GET", path: "/auth/session" })).headers.get("retry-after")).toBe(
      "5",
    )
    expect(seen.map((each) => each.key)).toEqual([
      "sign-in|2001:db8:1:2::/64",
      "sign-in|2001:db8:1:2::/64",
      "sign-in|2001:db8:1:2::/64",
      "session|2001:db8:1:2::/64",
    ])
    expect(seen[0]?.options).toEqual({ points: 10, duration: 10, keyPrefix: "rate:10000:10" })
    expect(recorded.counters.filter((name) => name.startsWith("rate:"))).toEqual([])
  })

  it("takes a stock rate-limiter-flexible limiter for a route, or for every route", async () => {
    const perRoute = testAuth({
      rateLimit: { rules: { session: new RateLimiterMemory({ points: 2, duration: 60 }) } },
    })
    const routeSend = sendFrom(perRoute.auth)
    expect(await statuses(routeSend, { method: "GET", path: "/auth/session" }, 3)).toEqual([
      200, 200, 429,
    ])
    const everyRoute = testAuth({ rateLimit: new RateLimiterMemory({ points: 1, duration: 60 }) })
    const everySend = sendFrom(everyRoute.auth)
    expect(await statuses(everySend, { method: "GET", path: "/auth/session" }, 2)).toEqual([
      200, 429,
    ])
    expect((await everySend({ method: "GET", path: "/auth/sign-in" })).status).toBe(200)
  })
})

describe("a request with no client address", () => {
  it("is not limited, as the throttle keeps no client key for it, and the operator hears of it once", async () => {
    const diagnostics: AuthDiagnostic[] = []
    const { auth } = testAuth({ onDiagnostic: (diagnostic) => diagnostics.push(diagnostic) })
    const send = sendFrom(auth, null)
    const signIn = await statuses(
      send,
      { method: "POST", path: "/auth/sign-in", headers: SAME_SITE },
      25,
    )
    expect(signIn.filter((status) => status === 429)).toEqual([])
    expect(diagnostics).toEqual([
      {
        code: "client-address-missing",
        message:
          "A request reached test-cap with no client address, so the per-client limits did not count it. Give the adapter the socket address (its clientAddress option), or limit requests at the gateway (ADR 0009 §8).",
      },
    ])
  })

  it("is still counted per client once the adapter supplies one", async () => {
    const { auth } = testAuth()
    await statuses(sendFrom(auth, null), { method: "POST", path: "/auth/sign-in" }, 25)
    const counted = await statuses(
      sendFrom(auth, CLIENT),
      { method: "POST", path: "/auth/sign-in" },
      11,
    )
    expect(counted.indexOf(429)).toBe(10)
  })
})

describe("the server-side calls", () => {
  it("count nothing: auth.session, auth.require and auth.admin never touch a limit", async () => {
    const recorded = recordingStore()
    const setup = testAuth({ store: recorded.store })
    const request = plainRequest({
      method: "GET",
      path: "/account",
      headers: [],
      clientAddress: CLIENT,
    })
    const before = recorded.calls.filter((call) => call === "increment").length
    for (let i = 0; i < 200; i += 1) {
      await setup.auth.session(request)
      await setup.auth.require(request, "default")
    }
    await setup.auth.admin.revoke("nobody")
    await setup.auth.admin.deprovision("nobody")
    expect(recorded.calls.filter((call) => call === "increment").length).toBe(before)
  })
})

describe("a diagnostic", () => {
  it("reaches only onDiagnostic: no security event, and nothing written to the store", () => {
    const recorded = recordingStore()
    const diagnostics: AuthDiagnostic[] = []
    const setup = testAuth({
      store: recorded.store,
      rateLimit: false,
      onDiagnostic: (diagnostic) => diagnostics.push(diagnostic),
    })
    expect(diagnostics.map((diagnostic) => diagnostic.code)).toEqual(["rate-limit-off"])
    expect(setup.events).toEqual([])
    expect(recorded.calls).toEqual([])
  })
})
