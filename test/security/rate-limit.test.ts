// The request limiter's parts (ADR 0009 §8, ADR 0030): how a rate-limiter-flexible answer becomes a decision, the rule
// and the limiter each route gets, and the startup check of the `rateLimit` option.
import RateLimiterMemory from "rate-limiter-flexible/lib/RateLimiterMemory.js"
import { describe, expect, it } from "vitest"
import {
  createRequestLimits,
  decide,
  DEFAULT_RATE_LIMIT,
  DEFAULT_RATE_RULES,
  isLimiter,
  isRule,
  type LimiterOptions,
  limitersBy,
  RATE_LIMIT_ROUTES,
  rateLimitProblems,
  type RateRule,
} from "../../src/security/rate-limit.js"
import { plainRequest } from "../support/auth.js"
import { fakeLimiter } from "../support/requests.js"

const request = plainRequest({ method: "POST", path: "/auth/sign-in" })

/** A factory that records the options of each limiter it builds, each allowing everything and recording its keys. */
function recordingFactory() {
  const built: LimiterOptions[] = []
  const keys: string[] = []
  const factory = (options: LimiterOptions) => {
    built.push(options)
    return fakeLimiter((key) => {
      keys.push(`${options.keyPrefix} ${key}`)
      return { allowed: true }
    }).limiter
  }
  return { built, keys, factory }
}

describe("decide", () => {
  it("allows what the limiter resolves, with no wait while the window has room", async () => {
    const { limiter } = fakeLimiter(() => ({
      allowed: true,
      remainingPoints: 3,
      msBeforeNext: 900,
    }))
    expect(await decide(limiter, "k")).toEqual({ allowed: true, retryAfterMs: 0 })
  })

  it("tells the rest of the window once the last place is used", async () => {
    const { limiter } = fakeLimiter(() => ({
      allowed: true,
      remainingPoints: 0,
      msBeforeNext: 900,
    }))
    expect(await decide(limiter, "k")).toEqual({ allowed: true, retryAfterMs: 900 })
  })

  it("refuses what the limiter rejects with its RateLimiterRes, with the wait it gives", async () => {
    const { limiter } = fakeLimiter(() => ({ allowed: false, msBeforeNext: 4_200 }))
    expect(await decide(limiter, "k")).toEqual({ allowed: false, retryAfterMs: 4_200 })
  })

  it("never answers a negative wait, as a limiter whose key never expires gives -1", async () => {
    const refused = fakeLimiter(() => ({ allowed: false, msBeforeNext: -1 }))
    const allowed = fakeLimiter(() => ({ allowed: true, remainingPoints: 0, msBeforeNext: -1 }))
    expect(await decide(refused.limiter, "k")).toEqual({ allowed: false, retryAfterMs: 0 })
    expect(await decide(allowed.limiter, "k")).toEqual({ allowed: true, retryAfterMs: 0 })
  })

  it("passes on an error, so a failing limiter fails the request, never lets it through", async () => {
    const { limiter } = fakeLimiter(() => new Error("redis is down"))
    await expect(decide(limiter, "k")).rejects.toThrow("redis is down")
  })

  it("works with a stock rate-limiter-flexible limiter", async () => {
    const memory = new RateLimiterMemory({ points: 2, duration: 60 })
    const decisions = []
    for (let n = 0; n < 3; n += 1) decisions.push((await decide(memory, "k")).allowed)
    expect(decisions).toEqual([true, true, false])
  })
})

describe("isRule and isLimiter", () => {
  it("tell a rule of whole numbers from anything else", () => {
    expect(isRule({ windowMs: 1, max: 1 })).toBe(true)
    for (const value of [
      null,
      true,
      "1/1",
      { windowMs: 0, max: 1 },
      { windowMs: 1, max: 1.5 },
      { windowMs: 1 },
    ]) {
      expect(isRule(value), JSON.stringify(value)).toBe(false)
    }
  })

  it("tell a limiter, anything with consume, from anything else", () => {
    expect(isLimiter(new RateLimiterMemory({ points: 1, duration: 1 }))).toBe(true)
    expect(isLimiter({ consume: () => undefined })).toBe(true)
    for (const value of [null, undefined, {}, { consume: 1 }, () => undefined]) {
      expect(isLimiter(value), String(value)).toBe(false)
    }
  })
})

describe("limitersBy", () => {
  it("builds one limiter per rule, with the library's options, and keeps it", () => {
    const { built, factory } = recordingFactory()
    const limiterOf = limitersBy(factory, "rate")
    const first = limiterOf({ windowMs: 10_000, max: 10 })
    expect(limiterOf({ windowMs: 10_000, max: 10 })).toBe(first)
    limiterOf({ windowMs: 3_600_000, max: 20 })
    expect(built).toEqual([
      { points: 10, duration: 10, keyPrefix: "rate:10000:10" },
      { points: 20, duration: 3_600, keyPrefix: "rate:3600000:20" },
    ])
  })

  it("passes a limiter instance through as it is", () => {
    const { built, factory } = recordingFactory()
    const memory = new RateLimiterMemory({ points: 1, duration: 1 })
    expect(limitersBy(factory, "rate")(memory)).toBe(memory)
    expect(built).toEqual([])
  })
})

describe("the default rules", () => {
  it("are 100 requests per 10 seconds for a route without its own rule", () => {
    expect(DEFAULT_RATE_LIMIT).toEqual({ windowMs: 10_000, max: 100 })
  })

  it("are 10 per 10 seconds where a secret is checked, and 20 an hour for sign-up", () => {
    expect(DEFAULT_RATE_RULES).toEqual({
      "sign-in": { windowMs: 10_000, max: 10 },
      "step-up": { windowMs: 10_000, max: 10 },
      "totp/verify": { windowMs: 10_000, max: 10 },
      "totp/enrol": { windowMs: 10_000, max: 10 },
      "totp/confirm": { windowMs: 10_000, max: 10 },
      "email/confirm": { windowMs: 10_000, max: 10 },
      recovery: { windowMs: 10_000, max: 10 },
      "sign-up": { windowMs: 60 * 60_000, max: 20 },
    })
  })

  it("name only routes the limiter knows", () => {
    for (const id of Object.keys(DEFAULT_RATE_RULES)) {
      expect(RATE_LIMIT_ROUTES, id).toContain(id)
    }
  })
})

describe("createRequestLimits", () => {
  it("counts under the route and the client, with the limiter of the route's default rule", async () => {
    const { built, keys, factory } = recordingFactory()
    const limits = createRequestLimits({}, factory)
    await limits.check("sign-in", request, "192.0.2.7")
    await limits.check("session", request, "2001:db8:1:2::/64")
    expect(built.map((options) => options.keyPrefix)).toEqual(["rate:10000:10", "rate:10000:100"])
    expect(keys).toEqual([
      "rate:10000:10 sign-in|192.0.2.7",
      "rate:10000:100 session|2001:db8:1:2::/64",
    ])
  })

  it("changes the default rule's values and leaves the stricter routes as they are", async () => {
    const { built, factory } = recordingFactory()
    const limits = createRequestLimits({ windowMs: 60_000, max: 500 }, factory)
    await limits.check("session", request, "c")
    await limits.check("sign-in", request, "c")
    expect(built.map((options) => [options.points, options.duration])).toEqual([
      [500, 60],
      [10, 10],
    ])
  })

  it("keeps the default window when only max changes, and the default max when only the window does", async () => {
    const one = recordingFactory()
    const two = recordingFactory()
    await createRequestLimits({ max: 7 }, one.factory).check("session", request, "c")
    await createRequestLimits({ windowMs: 5_000 }, two.factory).check("session", request, "c")
    expect([one.built[0]?.keyPrefix, two.built[0]?.keyPrefix]).toEqual([
      "rate:10000:7",
      "rate:5000:100",
    ])
  })

  it("uses a route's own rule, or its own limiter instance, in place of its default", async () => {
    const { built, factory } = recordingFactory()
    const own = fakeLimiter(() => ({ allowed: true }))
    const limits = createRequestLimits(
      { rules: { "sign-in": { windowMs: 1_000, max: 2 }, session: own.limiter } },
      factory,
    )
    await limits.check("sign-in", request, "c")
    await limits.check("session", request, "c")
    expect(built.map((options) => options.keyPrefix)).toEqual(["rate:1000:2"])
    expect(own.keys).toEqual(["session|c"])
  })

  it("allows every request on a route whose rule is false, without counting", async () => {
    const { built, keys, factory } = recordingFactory()
    const limits = createRequestLimits({ rules: { "sign-up": false } }, factory)
    expect(await limits.check("sign-up", request, "c")).toEqual({ allowed: true, retryAfterMs: 0 })
    expect([built, keys]).toEqual([[], []])
  })

  it("asks a rule function for each request, and follows its answer", async () => {
    const { built, keys, factory } = recordingFactory()
    const seen: string[] = []
    const limits = createRequestLimits(
      {
        rules: {
          "sign-in": (req) => {
            seen.push(req.method)
            return req.method === "POST" ? { windowMs: 2_000, max: 1 } : false
          },
        },
      },
      factory,
    )
    await limits.check("sign-in", request, "c")
    expect(await limits.check("sign-in", { ...request, method: "GET" }, "c")).toEqual({
      allowed: true,
      retryAfterMs: 0,
    })
    expect(seen).toEqual(["POST", "GET"])
    expect(built.map((options) => options.keyPrefix)).toEqual(["rate:2000:1"])
    expect(keys).toEqual(["rate:2000:1 sign-in|c"])
  })

  it("refuses a rule function's answer that is not a rule, so a broken rule fails closed", async () => {
    const { factory } = recordingFactory()
    for (const answer of [{ windowMs: 0, max: 1 }, { windowMs: 1_000, max: 0.5 }, null, true]) {
      const limits = createRequestLimits(
        { rules: { "sign-in": () => answer as unknown as RateRule } },
        factory,
      )
      await expect(limits.check("sign-in", request, "c"), JSON.stringify(answer)).rejects.toThrow(
        'The rateLimit rule for "sign-in" returned something that is not { windowMs, max } or false.',
      )
    }
  })

  it("fails closed when a rule function throws, passing its error on", async () => {
    const { factory } = recordingFactory()
    const limits = createRequestLimits(
      {
        rules: {
          "sign-in": () => {
            throw new Error("the app's rule broke")
          },
        },
      },
      factory,
    )
    await expect(limits.check("sign-in", request, "c")).rejects.toThrow("the app's rule broke")
  })

  it("builds each rule's limiter with the option's own factory in place of the default", async () => {
    const fallback = recordingFactory()
    const own = recordingFactory()
    await createRequestLimits({ limiter: own.factory }, fallback.factory).check(
      "sign-in",
      request,
      "c",
    )
    expect([fallback.built, own.built.length]).toEqual([[], 1])
  })

  it("counts every route with one limiter when rateLimit is a limiter instance", async () => {
    const { built, factory } = recordingFactory()
    const one = fakeLimiter((_key, seen) =>
      seen < 3 ? { allowed: true } : { allowed: false, msBeforeNext: 50 },
    )
    const limits = createRequestLimits(one.limiter, factory)
    await limits.check("sign-in", request, "c")
    await limits.check("session", request, "c")
    expect(await limits.check("sign-up", request, "c")).toEqual({
      allowed: false,
      retryAfterMs: 50,
    })
    expect(one.keys).toEqual(["sign-in|c", "session|c", "sign-up|c"])
    expect(built).toEqual([])
  })
})

describe("rateLimitProblems", () => {
  it("finds nothing wrong with the defaults, false, a limiter, or a full set of valid values", () => {
    const memory = new RateLimiterMemory({ points: 1, duration: 1 })
    expect(rateLimitProblems(undefined)).toEqual([])
    expect(rateLimitProblems(false)).toEqual([])
    expect(rateLimitProblems(memory)).toEqual([])
    expect(rateLimitProblems({})).toEqual([])
    expect(
      rateLimitProblems({
        windowMs: 1,
        max: 1,
        rules: {
          "sign-in": { windowMs: 1, max: 1 },
          "sign-up": false,
          session: () => false,
          sessions: memory,
        },
        limiter: () => memory,
      }),
    ).toEqual([])
  })

  it("names a window or max that is not a whole number, 1 or more", () => {
    for (const value of [
      0,
      -1,
      1.5,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      "10" as unknown as number,
    ]) {
      expect(rateLimitProblems({ windowMs: value }), String(value)).toEqual([
        "rateLimit.windowMs must be a whole number of milliseconds, 1 or more.",
      ])
      expect(rateLimitProblems({ max: value }), String(value)).toEqual([
        "rateLimit.max must be a whole number, 1 or more.",
      ])
    }
  })

  it("names a rule key that is no route, and lists the route ids", () => {
    expect(rateLimitProblems({ rules: { "/auth/sign-in": false } as never })).toEqual([
      `rateLimit.rules has no route "/auth/sign-in". Rules are keyed by route id: ${RATE_LIMIT_ROUTES.join(", ")}.`,
    ])
  })

  it("names a rule that is not { windowMs, max }, false, a limiter or a function", () => {
    for (const rule of [
      { windowMs: 0, max: 1 },
      { windowMs: 1, max: 0 },
      { windowMs: 1 },
      true,
      null,
      "10/10s",
    ]) {
      expect(
        rateLimitProblems({ rules: { "sign-in": rule as never } }),
        JSON.stringify(rule),
      ).toEqual([
        'rateLimit.rules["sign-in"] must be { windowMs, max } with whole numbers 1 or more, false, a rate-limiter-flexible limiter, or a function of the request.',
      ])
    }
  })

  it("names a limiter factory that is not a function", () => {
    for (const limiter of [{}, new RateLimiterMemory({ points: 1, duration: 1 }), null]) {
      expect(rateLimitProblems({ limiter: limiter as never }), String(limiter)).toEqual([
        "rateLimit.limiter must be a function that builds a rate-limiter-flexible limiter from { points, duration, keyPrefix }.",
      ])
    }
  })

  it("names every problem at once", () => {
    expect(
      rateLimitProblems({ windowMs: 0, max: 0, rules: { nope: false } as never }),
    ).toHaveLength(3)
  })

  it("names a rateLimit that is neither false, a limiter nor an object", () => {
    for (const value of [true, 100, "off", null]) {
      expect(rateLimitProblems(value as never), String(value)).toEqual([
        "rateLimit must be false, a rate-limiter-flexible limiter, or an object such as { max, windowMs, rules, limiter }.",
      ])
    }
  })
})
