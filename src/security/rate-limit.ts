/**
 * The request limiter (ADR 0009 §8, ADR 0030): every request the dispatcher answers is counted per client before its
 * route runs, so no route, sign-up included, can be called without bound.
 *
 * - A request is counted under its route id and its client key (an IPv4 address, or an IPv6 /64), with the rule for
 *   that route: its own rule when the app or the defaults give one, else the default rule.
 * - Counting is rate-limiter-flexible's. Each rule is a limiter the factory builds once: by default one over the app's
 *   `AuthStore` (`createStoreLimiter`), so instances sharing a store share the counts; an app can build them over its
 *   own backend instead, or give a route, or every route, a limiter instance of its own.
 * - Every value can be changed, a route's rule can be `false` or a function of the request, and the whole limiter can
 *   be turned off with `rateLimit: false`.
 */

import type { RateLimiterLike } from "rate-limiter-flexible"
import type { PlainRequest } from "../transport/types.js"

/** One limit: at most `max` requests from a client in each window of `windowMs`. */
export interface RateRule {
  /** The window requests are counted in, in milliseconds. */
  readonly windowMs: number
  /** The requests a client may make in one window. */
  readonly max: number
}

/** A limiter test-cap can count with: any rate-limiter-flexible limiter, or one compatible with it. */
export type { RateLimiterLike }

/**
 * A route's rule: a `RateRule`, `false` for no limit, a rate-limiter-flexible limiter of its own, or a function that
 * decides per request.
 */
export type RateRuleSetting =
  RateRule | false | RateLimiterLike | ((request: PlainRequest) => RateRule | false)

/** What a limiter factory is asked for: rate-limiter-flexible's own options for one rule. */
export interface LimiterOptions {
  /** Requests allowed per key in each window: the rule's `max`. */
  readonly points: number
  /** The window, in seconds: the rule's `windowMs` / 1000. */
  readonly duration: number
  /** A prefix that keeps this rule's keys apart from every other's. */
  readonly keyPrefix: string
}

/** Builds the limiter for one rule, such as `(options) => new RateLimiterRedis({ storeClient, ...options })`. */
export type LimiterFactory = (options: LimiterOptions) => RateLimiterLike

/** What a limit decides for one request. */
export interface RateDecision {
  /** True when the request may go ahead. */
  readonly allowed: boolean
  /**
   * How long until the key's next request would be allowed, in milliseconds: for a refused request, the wait; for an
   * allowed one, 0 while the window has room, or the rest of the window once this request used its last place.
   */
  readonly retryAfterMs: number
}

/**
 * A route id a rule can be keyed by. A route's id is its path after `/auth/`, such as `sign-in`. `pages` is every
 * default page shown by `GET`, `assets` the hashed page assets, and `unmatched` every request no route answers (a 404
 * or a 405).
 */
export type RateLimitRouteId =
  | "session"
  | "sign-up"
  | "email/confirm"
  | "email/resend"
  | "password"
  | "totp/enrol"
  | "totp/confirm"
  | "sign-in"
  | "totp/verify"
  | "step-up/start"
  | "step-up"
  | "recovery-codes"
  | "recovery"
  | "recovery/finish"
  | "sign-out"
  | "sessions"
  | "sessions/revoke"
  | "pages"
  | "assets"
  | "unmatched"

/** Every route id, in the dispatcher's order; a test keeps it equal to the routes the dispatcher answers. */
export const RATE_LIMIT_ROUTES: readonly RateLimitRouteId[] = [
  "session",
  "sign-up",
  "email/confirm",
  "email/resend",
  "password",
  "totp/enrol",
  "totp/confirm",
  "sign-in",
  "totp/verify",
  "step-up/start",
  "step-up",
  "recovery-codes",
  "recovery",
  "recovery/finish",
  "sign-out",
  "sessions",
  "sessions/revoke",
  "pages",
  "assets",
  "unmatched",
]

/** The `rateLimit` option of `createAuth`. Each value left out keeps its default. */
export interface RateLimitConfig {
  /** The default rule's window, in milliseconds: 10 seconds by default. */
  readonly windowMs?: number | undefined
  /** The default rule's count: 100 by default. */
  readonly max?: number | undefined
  /** A rule per route id, in place of that route's default. */
  readonly rules?: Readonly<Partial<Record<RateLimitRouteId, RateRuleSetting>>> | undefined
  /** Builds the limiter for each `{ windowMs, max }` rule, over the app's own backend; the `AuthStore` by default. */
  readonly limiter?: LimiterFactory | undefined
}

/** The rule of every route without its own: 100 requests per 10 seconds, as Better Auth's default. */
export const DEFAULT_RATE_LIMIT: RateRule = { windowMs: 10_000, max: 100 }

/** Where a secret is checked: 10 per 10 seconds, above the 5 free failures of the guessing throttle. */
const SECRET_CHECK: RateRule = { windowMs: 10_000, max: 10 }

/**
 * The routes whose default is stricter than `DEFAULT_RATE_LIMIT` (ADR 0009 §8 says why each). Sign-up's is the same
 * 20 an hour per client as confirmation mail (ADR 0009 Open 1): a 21st sign-up would send no mail.
 */
export const DEFAULT_RATE_RULES: Readonly<Partial<Record<RateLimitRouteId, RateRule>>> = {
  "sign-in": SECRET_CHECK,
  "step-up": SECRET_CHECK,
  "totp/verify": SECRET_CHECK,
  "totp/enrol": SECRET_CHECK,
  "totp/confirm": SECRET_CHECK,
  "email/confirm": SECRET_CHECK,
  recovery: SECRET_CHECK,
  "sign-up": { windowMs: 60 * 60_000, max: 20 },
}

/** True for a whole number, 1 or more. */
function positive(value: unknown): boolean {
  return Number.isSafeInteger(value) && (value as number) >= 1
}

/** True for a `RateRule` whose values are whole numbers, 1 or more. */
export function isRule(value: unknown): value is RateRule {
  if (typeof value !== "object" || value === null) return false
  const rule = value as Partial<RateRule>
  return positive(rule.windowMs) && positive(rule.max)
}

/** True for a rate-limiter-flexible limiter, or anything with its `consume`. */
export function isLimiter(value: unknown): value is RateLimiterLike {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { readonly consume?: unknown }).consume === "function"
  )
}

/** The library's answer to a `consume`, a resolved or a rejected `RateLimiterRes`. */
interface LimiterAnswer {
  readonly msBeforeNext: number
  readonly remainingPoints: number
}

/** True for a `RateLimiterRes`, which a limiter rejects with when it refuses; an `Error` is a failure instead. */
function isAnswer(value: unknown): value is LimiterAnswer {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as Partial<LimiterAnswer>).msBeforeNext === "number"
  )
}

/**
 * Counts one request under `key` and decides it. A limiter that refuses rejects with its `RateLimiterRes`; one that
 * fails rejects with an error, which ends the request with a 500, never lets it through.
 */
export async function decide(limiter: RateLimiterLike, key: string): Promise<RateDecision> {
  try {
    const answer = await limiter.consume(key)
    return {
      allowed: true,
      retryAfterMs: answer.remainingPoints > 0 ? 0 : Math.max(answer.msBeforeNext, 0),
    }
  } catch (refusal) {
    if (!isAnswer(refusal)) throw refusal
    return { allowed: false, retryAfterMs: Math.max(refusal.msBeforeNext, 0) }
  }
}

/** The limiter of each `RateRule`, built by `factory` the first time the rule is used and kept after. */
export function limitersBy(
  factory: LimiterFactory,
  prefix: string,
): (setting: RateRule | RateLimiterLike) => RateLimiterLike {
  const built = new Map<string, RateLimiterLike>()
  return (setting) => {
    if (isLimiter(setting)) return setting
    const name = `${prefix}:${setting.windowMs}:${setting.max}`
    const known = built.get(name)
    if (known !== undefined) return known
    const limiter = factory({
      points: setting.max,
      duration: setting.windowMs / 1000,
      keyPrefix: name,
    })
    built.set(name, limiter)
    return limiter
  }
}

const ROUTE_IDS: ReadonlySet<string> = new Set(RATE_LIMIT_ROUTES)

/** Each problem with a `rules` entry, named. */
function ruleProblems(rules: Readonly<Record<string, unknown>>): readonly string[] {
  return Object.entries(rules).flatMap(([id, setting]) => {
    if (!ROUTE_IDS.has(id)) {
      return [
        `rateLimit.rules has no route ${JSON.stringify(id)}. Rules are keyed by route id: ${RATE_LIMIT_ROUTES.join(", ")}.`,
      ]
    }
    if (
      setting === false ||
      typeof setting === "function" ||
      isRule(setting) ||
      isLimiter(setting)
    ) {
      return []
    }
    return [
      `rateLimit.rules[${JSON.stringify(id)}] must be { windowMs, max } with whole numbers 1 or more, false, a rate-limiter-flexible limiter, or a function of the request.`,
    ]
  })
}

/** The values a `rateLimit` object may hold. */
const RATE_LIMIT_KEYS: readonly string[] = ["windowMs", "max", "rules", "limiter"]

/** Each problem with the `rateLimit` option, named; empty when it may start. */
export function rateLimitProblems(
  config: RateLimitConfig | RateLimiterLike | false | undefined,
): readonly string[] {
  if (config === undefined || config === false || isLimiter(config)) return []
  if (typeof config !== "object" || config === null) {
    return [
      "rateLimit must be false, a rate-limiter-flexible limiter, or an object such as { max, windowMs, rules, limiter }.",
    ]
  }
  const problems: string[] = Object.keys(config)
    .filter((key) => !RATE_LIMIT_KEYS.includes(key))
    .map(
      (key) =>
        `rateLimit has no value ${JSON.stringify(key)}: its values are windowMs, max, rules and limiter.`,
    )
  if (config.windowMs !== undefined && !positive(config.windowMs)) {
    problems.push("rateLimit.windowMs must be a whole number of milliseconds, 1 or more.")
  }
  if (config.max !== undefined && !positive(config.max)) {
    problems.push("rateLimit.max must be a whole number, 1 or more.")
  }
  problems.push(...ruleProblems(config.rules ?? {}))
  if (config.limiter !== undefined && typeof config.limiter !== "function") {
    problems.push(
      "rateLimit.limiter must be a function that builds a rate-limiter-flexible limiter from { points, duration, keyPrefix }.",
    )
  }
  return problems
}

/** The request limits of one `Auth`: each request's rule, counted by its limiter. */
export interface RequestLimits {
  /**
   * Counts one request to the route `id` from the client key `client`, and decides it. A route whose rule is `false`
   * for this request is allowed without counting.
   */
  check(id: RateLimitRouteId, request: PlainRequest, client: string): Promise<RateDecision>
}

const ALLOWED: RateDecision = { allowed: true, retryAfterMs: 0 }

/** A rule function's answer, once checked: a `RateRule` or `false`; a `TypeError` for anything else. */
function answered(id: RateLimitRouteId, rule: unknown): RateRule | false {
  if (rule === false || isRule(rule)) return rule
  throw new TypeError(
    `The rateLimit rule for ${JSON.stringify(id)} returned something that is not { windowMs, max } or false.`,
  )
}

/**
 * Builds the request limits from a `rateLimit` option whose problems were checked. A limiter instance counts every
 * route; otherwise each `{ windowMs, max }` rule gets a limiter from the option's `limiter`, or from `factory`.
 */
export function createRequestLimits(
  config: RateLimitConfig | RateLimiterLike,
  factory: LimiterFactory,
): RequestLimits {
  if (isLimiter(config)) {
    return { check: (id, _request, client) => decide(config, `${id}|${client}`) }
  }
  const fallback: RateRule = {
    windowMs: config.windowMs ?? DEFAULT_RATE_LIMIT.windowMs,
    max: config.max ?? DEFAULT_RATE_LIMIT.max,
  }
  const settings: Readonly<Partial<Record<RateLimitRouteId, RateRuleSetting>>> = {
    ...DEFAULT_RATE_RULES,
    ...config.rules,
  }
  const limiterOf = limitersBy(config.limiter ?? factory, "rate")
  return {
    async check(id, request, client) {
      const setting = settings[id] ?? fallback
      // A rule given as a value was checked at startup; only a function's answer is checked here.
      const rule = typeof setting === "function" ? answered(id, setting(request)) : setting
      if (rule === false) return ALLOWED
      return decide(limiterOf(rule), `${id}|${client}`)
    },
  }
}
