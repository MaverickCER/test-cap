// Sentinels for the request limiter (ADR 0009 §8): every request to /auth passes through it, so a mutant there is
// covered by nearly every test. These checks see its decisions directly, through a rate-limiter-flexible-compatible
// limiter that records each key and answers as told, and run no flow.
import { describe, expect, it } from "vitest"
import type { AuthDiagnostic } from "../../src/core/auth.js"
import {
  createRequestLimits,
  type RateRule,
  rateLimitProblems,
} from "../../src/security/rate-limit.js"
import { testAuth } from "../support/auth.js"
import { fakeLimiter, recordingStore, sendFrom } from "../support/requests.js"

/** A limiter that records each key and refuses once `allowed` keys were let through. */
function limiterAllowing(allowed: number) {
  return fakeLimiter((_key, seen) =>
    seen <= allowed ? { allowed: true } : { allowed: false, msBeforeNext: 2_500 },
  )
}

const FORM_HEADERS = [
  ["Origin", "https://app.example"],
  ["Accept", "text/html"],
  ["Content-Type", "application/x-www-form-urlencoded"],
] as const

describe("the request limiter's decisions", () => {
  it("keys a page, an asset, a route, a wrong method and an unknown path by what runs", async () => {
    const { keys, limiter } = limiterAllowing(99)
    const send = sendFrom(testAuth({ rateLimit: limiter }).auth, "192.0.2.3")
    await send({ method: "GET", path: "/auth/sign-in" })
    await send({ method: "GET", path: "/auth/assets/x.js" })
    await send({ method: "POST", path: "/auth/sign-in" })
    await send({ method: "GET", path: "/auth/session" })
    await send({ method: "PUT", path: "/auth/sign-in" })
    await send({ method: "GET", path: "/auth/nope" })
    expect(keys).toEqual([
      "pages|192.0.2.3",
      "assets|192.0.2.3",
      "sign-in|192.0.2.3",
      "session|192.0.2.3",
      "unmatched|192.0.2.3",
      "unmatched|192.0.2.3",
    ])
  })

  it("answers a refused request 429 with the wait in whole seconds, rounded up, and runs nothing", async () => {
    const recorded = recordingStore()
    const { limiter } = limiterAllowing(0)
    const setup = testAuth({ store: recorded.store, rateLimit: limiter })
    const reply = await sendFrom(setup.auth)({ method: "GET", path: "/auth/session" })
    expect([reply.status, reply.text, reply.headers.get("retry-after")]).toEqual([
      429,
      '{"error":"rate-limited"}',
      "3",
    ])
    expect(recorded.calls).toEqual([])
    expect(setup.events).toEqual([])
  })

  it("emits a refused post's failure event, and answers a form post with its still page", async () => {
    const { limiter } = limiterAllowing(0)
    const setup = testAuth({ rateLimit: limiter })
    const send = sendFrom(setup.auth)
    const page = await send({ method: "POST", path: "/auth/sign-up", headers: FORM_HEADERS })
    expect([page.status, page.headers.get("retry-after")]).toEqual([429, "3"])
    expect(page.text).toContain("Too many attempts. Try again in 3 seconds.")
    expect(setup.events).toMatchObject([
      { status_detail: "request-limit", activity_name: "Create" },
    ])
    const json = await send({ method: "POST", path: "/auth/totp/confirm", headers: FORM_HEADERS })
    const noPage = await send({ method: "POST", path: "/auth/sign-in" })
    expect([json.text, noPage.text]).toEqual([
      '{"error":"rate-limited"}',
      '{"error":"rate-limited"}',
    ])
  })

  it("counts nothing with rateLimit: false, or with no client address, which it reports once", async () => {
    const off = limiterAllowing(0)
    const diagnostics: AuthDiagnostic["code"][] = []
    const { auth } = testAuth({
      rateLimit: off.limiter,
      onDiagnostic: (diagnostic) => diagnostics.push(diagnostic.code),
    })
    expect((await sendFrom(auth, null)({ method: "GET", path: "/auth/session" })).status).toBe(200)
    await sendFrom(auth, null)({ method: "GET", path: "/auth/session" })
    expect(off.keys).toEqual([])
    expect(diagnostics).toEqual(["client-address-missing"])
    const none = testAuth({ rateLimit: false })
    expect((await sendFrom(none.auth)({ method: "GET", path: "/auth/session" })).status).toBe(200)
  })
})

describe("the request limiter's rule check", () => {
  it("names a null rule as a problem, and refuses a rule function that answers null", async () => {
    expect(rateLimitProblems({ rules: { "sign-in": null as never } })).toEqual([
      'rateLimit.rules["sign-in"] must be { windowMs, max } with whole numbers 1 or more, false, a rate-limiter-flexible limiter, or a function of the request.',
    ])
    const limits = createRequestLimits(
      { rules: { "sign-in": () => null as unknown as RateRule } },
      () => limiterAllowing(9).limiter,
    )
    await expect(
      limits.check(
        "sign-in",
        { method: "POST", url: "/", headers: new Headers(), body: null },
        "c",
      ),
    ).rejects.toThrow(
      'The rateLimit rule for "sign-in" returned something that is not { windowMs, max } or false.',
    )
  })
})
