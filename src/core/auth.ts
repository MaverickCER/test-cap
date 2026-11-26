/**
 * `createAuth` (ADR 0003 §6, ADR 0026): checks that the deployment may start, then wires the store, policy, sessions,
 * methods, CSRF keys and event sink into one `Auth`. Its `handle` serves every `/auth/*` route; `session` and
 * `require` read the session from the store on every call; `admin` holds the server-side calls.
 */

import { deactivateAccount } from "./accounts.js"
import {
  ownProxies,
  platformProblems,
  platformTrust,
  rangeProblems,
  type ForwardedHeader,
  type PlatformTrust,
  type ProxyTrust,
} from "./proxy-trust.js"
import { createFailureCeiling, FAILURE_CEILING } from "../security/ceiling.js"
import { createStoreLimiter } from "../security/store-limiter.js"
import {
  createRequestLimits,
  isLimiter,
  isRule,
  type LimiterFactory,
  type RateLimitConfig,
  type RateLimiterLike,
  rateLimitProblems,
  type RequestLimits,
} from "../security/rate-limit.js"
import {
  type ChallengeHook,
  createStuffingDetector,
  DEFAULT_STUFFING,
  NO_STUFFING,
  type StuffingConfig,
  type StuffingDetector,
} from "../security/stuffing.js"
import {
  createThrottle,
  DEFAULT_THROTTLE,
  NO_THROTTLE,
  type Throttle,
  type ThrottleConfig,
} from "../security/throttle.js"
import { defineAuthPolicy, type AuthPolicy, type RequireResult } from "../assurance/policy.js"
import { randomBytes, systemClock, systemRandom, type Clock, type RandomSource } from "./clock.js"
import {
  BASE_PATH,
  createDispatcher,
  failure,
  type RouteSummary,
  type Runtime,
  type SessionInfo,
} from "./dispatcher.js"
import {
  checkReadiness,
  type DeploymentMode,
  isProductionLike,
  parseKeyRing,
  resolveDeploymentMode,
  type RingKey,
} from "./mode.js"
import { ConfigError } from "./errors.js"
import { systemIdProblem } from "../env/validators.js"
import type { EventSink } from "../ocsf/events.js"
import { compilePublicPaths } from "./public-paths.js"
import {
  argon2CostProblem,
  createHasher,
  type Argon2Cost,
  type Argon2Hasher,
} from "../methods/password/argon2.js"
import type { HibpFetch } from "../methods/password/hibp.js"
import { createCsrfTokens } from "../security/csrf.js"
import { errorResponse } from "../security/headers.js"
import { limitKeyName, limitStore } from "../security/limit-store.js"
import { createSessions, readSessionToken } from "../sessions/sessions.js"
import type { AuthStore, TenantId } from "../store/port.js"
import { matchAuthPath, rawPath } from "../transport/path.js"
import type { PlainRequest, PlainResponse } from "../transport/types.js"

import {
  CONFIRMATION_FAILURE_LIMIT,
  DEFAULT_EMAIL_LIMITS,
  type EmailLimitConfig,
  type EmailSendLimits,
  emailSendLimits,
  type SendEmail,
} from "./email.js"

export type { SessionInfo } from "./dispatcher.js"
export type { EmailLimitConfig, EmailMessage, SendEmail } from "./email.js"

/** The app's own proxies, as IP addresses or CIDR ranges, whose forwarding header may be read (ADR 0009 §5). */
export type TrustedProxies = readonly string[]

/** What `createAuth` takes (ADR 0026). `Id` is the union of the policy's requirement ids. */
export interface AuthConfig<Id extends string = "default"> {
  /** The app's store. Production refuses a store that is not durable. */
  readonly store: AuthStore
  /** The policy from `defineAuthPolicy`; without one, every requirement is the default AAL2. */
  readonly policy?: AuthPolicy<Id> | undefined
  /**
   * The environment: `process.env`, env-cap's parsed values or a plain object with the same names. Read are
   * `APP_ENV`, `APP_ORIGIN`, `APP_SYSTEM_ID` (required in every mode: it names the system in every security event),
   * `AUTH_ENCRYPTION_KEY` and `AUTH_CSRF_KEY` (ADR 0022).
   */
  readonly env: Readonly<Record<string, string | undefined>>
  /** The tenant every operation is scoped to (ADR 0012); `default` when absent. */
  readonly tenant?: TenantId | undefined
  /** A clock for tests. Any mode but `test` refuses to start with one (ADR 0026 §4). */
  readonly clock?: Clock | undefined
  /** A random source for tests. Any mode but `test` refuses to start with one (ADR 0026 §4). */
  readonly random?: RandomSource | undefined
  /**
   * An argon2id cost for tests, so a suite does not spend the ADR 0018 cost on every sign-in. Any mode but `test`
   * refuses to start with one (ADR 0018 §1, ADR 0026 §4).
   */
  readonly argon2Cost?: Argon2Cost | undefined
  /**
   * The app's own argon2id, in place of hash-wasm and its `@noble/hashes` fallback (ADR 0031), such as a native
   * binding on a server that has one. It is allowed in every mode, at the fixed cost test-cap passes it; see
   * `Argon2Hasher` for what test-cap still checks and what the app takes on.
   */
  readonly argon2Hasher?: Argon2Hasher | undefined
  /**
   * The fetch the HIBP breach check calls (ADR 0010), usually the global `fetch`. test-cap reaches no network on its
   * own, so the app hands it the capability.
   */
  readonly hibpFetch: HibpFetch
  /**
   * The app's mail sender. Sign-up mails the address a confirmation code through it (ADR 0021); test-cap does not
   * wait for it, and a sender that throws changes no reply.
   */
  readonly sendEmail: SendEmail
  /** Receives every security event (ADR 0015). A sink that throws never changes an outcome. */
  readonly onEvent?: EventSink | undefined
  /**
   * Who stands in front of the app (ADR 0009 §5): its own proxies, as IP addresses or CIDR ranges, or a platform
   * preset from `platform`. Only from such a peer is a forwarding header read, for the client the throttle counts.
   * Empty by default: the socket is the client.
   */
  readonly trustedProxies?: TrustedProxies | PlatformTrust | undefined
  /**
   * The one forwarding header the app's own proxies set: `"x-forwarded-for"` (the default) or `"forwarded"` (RFC
   * 7239). The other is never read, because a proxy that sets one passes a client's forged copy of the other through.
   * A platform preset names its own header instead.
   */
  readonly forwardedHeader?: ForwardedHeader | undefined
  /**
   * Whether production and staging refuse a request with no client address, which the per-client limits cannot count
   * (ADR 0009 §8): `true` by default. There, a Web-Request adapter with no `clientAddress` option refuses to start,
   * unless a platform preset reads its header from every request, and a request that still has none gets the fixed
   * 500. `false` serves such a request uncounted, for an app that limits requests at its gateway; the operator is told
   * once. Development and test always serve it uncounted.
   */
  readonly requireClientAddress?: boolean | undefined
  /**
   * The guessing throttle (ADR 0009 §1 to §3, §8): changed values, each one left out keeping its default
   * (`DEFAULT_THROTTLE`); the app's own `Throttle`; or `false` for none, which production and staging refuse.
   */
  readonly throttle?: Partial<ThrottleConfig> | Throttle | false | undefined
  /**
   * Consecutive failures an authenticator accepts before it stops (ADR 0009 §3): 100 by default, and never more, as
   * NIST SP 800-63B-4 allows. A lower number is allowed.
   */
  readonly failureCeiling?: number | undefined
  /**
   * The request limits on every `/auth` route (ADR 0009 §8): changed values, rules per route id and the app's own
   * `RateLimiter`; or `false` for none, for an app that limits requests at its gateway. On by default in every mode.
   */
  readonly rateLimit?: RateLimitConfig | RateLimiterLike | false | undefined
  /**
   * The credential-stuffing detector (ADR 0009 §4, §8): changed values, each one left out keeping its default; the
   * app's own `StuffingDetector`; or `false` for none, which production and staging refuse.
   */
  readonly stuffing?: Partial<StuffingConfig> | StuffingDetector | false | undefined
  /**
   * The confirmation-mail send limits (ADR 0009 §7, §8): changed rules per address and per client and the app's own
   * `RateLimiter`; or `false` for none, which production and staging refuse.
   */
  readonly emailLimit?: EmailLimitConfig | false | undefined
  /**
   * Attempts an emailed confirmation code allows over its life (ADR 0009 Open 1): 5 by default, and never more; a
   * lower number is allowed.
   */
  readonly emailCodeAttempts?: number | undefined
  /**
   * Which refusals of a limit emit their failure event (ADR 0009 §8): `"first"` (the default), one per key per window,
   * so a flood is one event; or `"every"` refusal.
   */
  readonly refusalEvents?: "first" | "every" | undefined
  /**
   * The app's challenge for a client the stuffing detector flagged (ADR 0009 §4). Without one, every failure from a
   * flagged client blocks at once.
   */
  readonly challengeHook?: ChallengeHook | undefined
  /**
   * The path a gateway in front of the app adds before every path, such as `/accounts` when the gateway serves the
   * app's `/auth/sign-in` as `/accounts/auth/sign-in` (ADR 0024 §6). Every link, redirect and email URL test-cap builds
   * starts with it; routes are still matched on the path the app receives. Empty by default.
   */
  readonly publicBasePath?: string | undefined
  /**
   * Receives each operator diagnostic once per `Auth`: a deployment problem test-cap can see from requests, such as
   * forwarding headers arriving with no trusted proxy (ADR 0009 §5). Not a security event; nothing is stored.
   */
  readonly onDiagnostic?: ((diagnostic: AuthDiagnostic) => void) | undefined
}

/** One operator diagnostic (ADR 0009 §5, ADR 0011): what was seen, and what to change. */
export interface AuthDiagnostic {
  /**
   * `forwarded-header-ignored`: a forwarding header arrived that test-cap did not read, because the peer is not a
   * trusted proxy or the header is not the one declared. `origin-unverifiable`: a state-changing request carried neither a usable `Origin` nor
   * `Sec-Fetch-Site`, so the CSRF check refused it. `client-address-missing`: a request had no client address, so the
   * per-client limits did not count it, or production and staging refused it. `client-address-optional`: the app set
   * `requireClientAddress: false`. `rate-limit-off`, `throttle-off`, `email-limit-off` and `stuffing-off`: the app
   * turned that limit off. `argon2-fallback`: the runtime cannot compile WebAssembly, so argon2id runs on
   * `@noble/hashes`, slower (ADR 0031).
   */
  readonly code:
    | "forwarded-header-ignored"
    | "origin-unverifiable"
    | "client-address-missing"
    | "client-address-optional"
    | "rate-limit-off"
    | "throttle-off"
    | "email-limit-off"
    | "stuffing-off"
    | "argon2-fallback"
  /** A sentence for the operator, naming the setting to check. */
  readonly message: string
}

/** The server-side calls (ADR 0012, ADR 0014): `revoke` (phase 3) and `deprovision` (phase 4). */
export interface AuthAdmin {
  /** Revokes every session of the account, with immediate visibility; resolves to how many it revoked. */
  revoke(subject: string): Promise<number>
  /**
   * Deprovisions the account (ADR 0012 Open 15, the SCIM hook): disables it, so no ceremony, recovery or session of it
   * works, and revokes every session. Resolves to `false` when there is no such account.
   */
  deprovision(subject: string): Promise<boolean>
}

/** What `createAuth` returns (ADR 0003 §6). */
export interface Auth<Id extends string = "default"> {
  /** Serves every `/auth/*` route; `null` for a path outside them, so the adapter passes the request on. */
  handle(req: PlainRequest): Promise<PlainResponse | null>
  /** The request's session, read from the store; `null` when it has none, or it is revoked or expired. */
  session(req: PlainRequest): Promise<SessionInfo | null>
  /** Whether the request's session meets the requirement under `requirementId`, as one of five outcomes. */
  require(req: PlainRequest, requirementId: Id): Promise<RequireResult>
  /** The server-side calls. */
  readonly admin: AuthAdmin
}

/** What deny by default decides for a request outside `/auth/*` (ADR 0024 §2). */
type GateDecision =
  | { readonly kind: "dispatch" }
  | { readonly kind: "respond"; readonly response: PlainResponse }
  | { readonly kind: "next"; readonly subject: string | null }

/** What an adapter needs beyond the public `Auth`. */
export interface AuthInternals {
  /** `APP_ORIGIN`, checked at startup: the one origin an adapter builds an absolute URL on, never the `Host` header. */
  readonly origin: string
  /** The gateway's path prefix (`publicBasePath`), `""` for none: added to every path an adapter puts in a URL. */
  readonly publicBasePath: string
  /** Compiles a public-path list; a malformed entry is a `ConfigError`. */
  publicPaths(entries: readonly string[]): (path: string) => boolean
  /**
   * Decides a request before its body is read: an ambiguous path is a 400, a path under `/auth/` goes to `handle`, a
   * public path passes, and any other path passes only for a session meeting the default requirement.
   */
  gate(head: PlainRequest, isPublic: (path: string) => boolean): Promise<GateDecision>
  /** The `/auth/*` route table, for the OpenAPI document (docs/api-reference/). */
  routes(): readonly RouteSummary[]
  /**
   * Refuses to start an adapter with no source of client addresses where `requireClientAddress` holds (ADR 0009 §8): a
   * `ConfigError` when `hasSource` is false and no platform preset reads its header from every request.
   */
  requireAddressSource(hasSource: boolean): void
}

/** A registry symbol, so the adapters' bundles find the internals of an `Auth` built by another bundle. */
const INTERNALS = Symbol.for("test-cap.auth.internals")

/** The internals of an `Auth` built by `createAuth`; a `TypeError` for anything else. */
export function internalsOf(auth: object): AuthInternals {
  const internals = (auth as { readonly [INTERNALS]?: AuthInternals })[INTERNALS]
  if (internals === undefined) throw new TypeError("Pass the Auth that createAuth returned.")
  return internals
}

const SECRETS = ["AUTH_ENCRYPTION_KEY", "AUTH_CSRF_KEY"] as const

/** Each problem with `trustedProxies` and `forwardedHeader`, named. */
function proxyProblems(
  proxies: TrustedProxies | PlatformTrust,
  header: ForwardedHeader | undefined,
): readonly string[] {
  if (isPlatform(proxies)) {
    return [
      ...platformProblems(proxies),
      ...(header === undefined
        ? []
        : [
            "forwardedHeader applies to the app's own proxies; a platform preset names its own header.",
          ]),
    ]
  }
  if (!Array.isArray(proxies)) {
    return [
      'trustedProxies must be a list of IP addresses and CIDR ranges, or a platform() preset, such as ["10.0.0.0/8"].',
    ]
  }
  return [
    ...rangeProblems("trustedProxies", proxies),
    ...(header !== undefined && proxies.length === 0
      ? [
          "forwardedHeader names the header the app's own proxies set; list those proxies in trustedProxies, or test-cap reads no header.",
        ]
      : []),
    ...(header === undefined || header === "x-forwarded-for" || header === "forwarded"
      ? []
      : [
          `forwardedHeader must be "x-forwarded-for" or "forwarded", not ${JSON.stringify(header)}.`,
        ]),
  ]
}

/** True for a policy from `defineAuthPolicy`: its three methods and its list of deviations. */
function isAuthPolicy(value: unknown): boolean {
  return (
    implementsAll(Object(value) as object, ["require", "assurance", "requirement"]) === true &&
    Array.isArray((value as { readonly deviations?: unknown }).deviations)
  )
}

/** True for a preset from `platform`, rather than a list of the app's own proxies. */
function isPlatform(proxies: TrustedProxies | PlatformTrust): proxies is PlatformTrust {
  return (proxies as Partial<PlatformTrust>).kind === "platform"
}

/** The trust `trustedProxies` gives, once its problems were checked. */
function trustOf(
  proxies: TrustedProxies | PlatformTrust,
  header: ForwardedHeader | undefined,
): ProxyTrust | null {
  return isPlatform(proxies)
    ? platformTrust(proxies)
    : ownProxies(proxies, header ?? "x-forwarded-for")
}

/** The sink for an app that set no `onDiagnostic`. */
const ignoreDiagnostic = (): void => undefined

/** Hands each diagnostic code to `sink` the first time only; a sink that throws changes nothing. */
function onceEach(
  sink: ((diagnostic: AuthDiagnostic) => void) | undefined,
): (diagnostic: AuthDiagnostic) => void {
  // Bound here, so a missing sink is found when the Auth is built, not swallowed with a sink's own errors.
  const deliver = (sink ?? ignoreDiagnostic).bind(undefined)
  const seen = new Set<AuthDiagnostic["code"]>()
  return (diagnostic) => {
    if (seen.has(diagnostic.code)) return
    seen.add(diagnostic.code)
    try {
      deliver(diagnostic)
    } catch {
      // A diagnostic is advice; a failing sink must not fail the request that prompted it.
    }
  }
}

/** A gateway prefix: empty, or `/`-separated clean segments with no trailing slash and no `.` or `..` segment. */
const PUBLIC_BASE_PATH = /^(?:\/(?!\.{1,2}(?:\/|$))[A-Za-z0-9._~-]+)*$/

/** True when `option` has every method in `names` as a function; `partial` when it has some but not all. */
function implementsAll(option: object, names: readonly string[]): boolean | "partial" {
  const present = names.filter(
    (name) => typeof (option as Partial<Record<string, unknown>>)[name] === "function",
  ).length
  if (present === 0) return false
  return present === names.length || "partial"
}

/** `a and b`, `a, b and c`: the names of two or more things. */
function listed(names: readonly string[]): string {
  return `${names.slice(0, -1).join(", ")} and ${String(names.at(-1))}`
}

/** The smallest value of a whole-number field, and whether it is milliseconds (at most `MAX_LIMIT_MS`). */
interface FieldRule {
  readonly min: 0 | 1
  readonly ms?: true
}

/**
 * The longest window or delay a limit takes: a year. Past it the store's expiry times leave the safe-integer range, and
 * every blocked attempt would fail instead of waiting.
 */
const MAX_LIMIT_MS = 365 * 24 * 60 * 60_000

/**
 * One limit option of ADR 0009 §8: changed values, the app's own implementation, or `false`. Each option is a spec,
 * read the same way by `optionProblems` at startup and by `chosen` when the `Auth` is built.
 */
interface LimitOption<T> {
  readonly name: string
  /** The app's own implementation: what it is called, and the methods it must have. */
  readonly own?: { readonly type: string; readonly methods: readonly string[] }
  /** The changed values: each field's rule and its default; the extra problems a field rule cannot say. */
  readonly fields?: Readonly<Record<string, FieldRule>>
  readonly defaults?: object
  readonly extra?: (merged: Readonly<Record<string, number>>) => readonly string[]
  /** The problems of an option `fields` does not describe. */
  readonly check?: (value: unknown) => readonly string[]
  /**
   * Why production and staging refuse `false`, and what to pass instead (`[reason, "its" | "their", thing]`);
   * absent when `false` is allowed in any mode.
   */
  readonly refuseOff?: readonly [string, string, string]
  /** What turning it off means, for the diagnostic; and what to do about it, when production does not refuse it. */
  readonly off: { readonly value: T; readonly so: string; readonly then?: string }
  readonly code: AuthDiagnostic["code"]
}

/** Each problem with `value` for the limit option `spec` in `mode`, named. */
function optionProblems(
  spec: LimitOption<unknown>,
  value: unknown,
  mode: DeploymentMode,
): readonly string[] {
  if (value === false) {
    const refusal = spec.refuseOff
    return refusal !== undefined && isProductionLike(mode)
      ? [
          `${spec.name}: false is refused in production and staging: ${refusal[0]}. Change ${refusal[1]} values or pass your own ${refusal[2]} instead.`,
        ]
      : []
  }
  if (spec.check !== undefined) return spec.check(value)
  const own = spec.own as NonNullable<LimitOption<unknown>["own"]>
  const fields = spec.fields as Readonly<Record<string, FieldRule>>
  const kind =
    value === undefined || (typeof value === "object" && value !== null)
      ? implementsAll(value ?? {}, own.methods)
      : "partial"
  if (kind === true) return []
  if (kind === "partial") {
    return [
      `${spec.name} must be changed values ({ ${Object.keys(fields).join(", ")} }), a ${own.type} with ${listed(own.methods)}, or false.`,
    ]
  }
  const merged = { ...spec.defaults, ...(value as object) } as Readonly<Record<string, number>>
  const names = Object.keys(fields)
  return [
    ...Object.keys(value ?? {})
      .filter((key) => !names.includes(key))
      .map(
        (key) =>
          `${spec.name} has no value ${JSON.stringify(key)}: its values are ${listed(names)}.`,
      ),
    ...Object.entries(fields)
      .filter(
        ([field, rule]) =>
          !Number.isSafeInteger(merged[field]) ||
          (merged[field] as number) < rule.min ||
          (rule.ms === true && (merged[field] as number) > MAX_LIMIT_MS),
      )
      .map(([field, rule]) =>
        rule.ms === true
          ? `${spec.name}.${field} must be a whole number of milliseconds, from ${rule.min} to ${MAX_LIMIT_MS} (a year).`
          : `${spec.name}.${field} must be a whole number, ${rule.min} or more.`,
      ),
    ...(spec.extra?.(merged) ?? []),
  ]
}

/**
 * The limit an option chooses: turned off with `false`, which is reported once; the app's own implementation, an
 * object with every one of its methods; or the default, which `build` makes from changed values.
 */
function chosen<T>(
  spec: LimitOption<T>,
  value: unknown,
  build: () => T,
  diagnose: (diagnostic: AuthDiagnostic) => void,
): T {
  if (value === false) {
    diagnose({
      code: spec.code,
      message: `${spec.name} is false, so ${spec.off.so}. ${spec.off.then ?? "Production and staging refuse this"} (ADR 0009 §8).`,
    })
    return spec.off.value
  }
  return spec.own !== undefined && implementsAll(value ?? {}, spec.own.methods) === true
    ? (value as T)
    : build()
}

/** True for a mail limit: a `{ windowMs, max }` of whole numbers, or a rate-limiter-flexible limiter. */
function mailLimit(value: unknown): boolean {
  return isRule(value) || isLimiter(value)
}

/** Each problem with an `emailLimit` object, named. */
function emailLimitProblems(option: unknown): readonly string[] {
  if (option === undefined) return []
  if (typeof option !== "object" || option === null) {
    return ["emailLimit must be false or an object such as { perAddress, perClient, limiter }."]
  }
  const {
    perAddress = DEFAULT_EMAIL_LIMITS.perAddress,
    perClient,
    limiter,
  } = option as EmailLimitConfig
  return [
    ...(!Array.isArray(perAddress) || perAddress.length === 0 || !perAddress.every(mailLimit)
      ? [
          "emailLimit.perAddress must list at least one { windowMs, max } with whole numbers 1 or more, or a rate-limiter-flexible limiter.",
        ]
      : []),
    ...(perClient !== undefined && perClient !== false && !mailLimit(perClient)
      ? [
          "emailLimit.perClient must be { windowMs, max } with whole numbers 1 or more, a rate-limiter-flexible limiter, or false.",
        ]
      : []),
    ...(limiter !== undefined && typeof limiter !== "function"
      ? [
          "emailLimit.limiter must be a function that builds a rate-limiter-flexible limiter from { points, duration, keyPrefix }.",
        ]
      : []),
  ]
}

const THROTTLE: LimitOption<Throttle> = {
  name: "throttle",
  own: { type: "Throttle", methods: ["attempt", "failed", "succeeded"] },
  fields: {
    freeFailures: { min: 0 },
    windowMs: { min: 1, ms: true },
    firstDelayMs: { min: 1, ms: true },
    maxDelayMs: { min: 1, ms: true },
  },
  defaults: DEFAULT_THROTTLE,
  extra: (merged) =>
    (merged["firstDelayMs"] as number) > (merged["maxDelayMs"] as number)
      ? ["throttle.firstDelayMs must not exceed throttle.maxDelayMs."]
      : [],
  refuseOff: [
    "NIST SP 800-63B-4 §3.2.2 requires throttling failed authentication attempts",
    "its",
    "Throttle",
  ],
  off: { value: NO_THROTTLE, so: "password, TOTP and recovery-code guesses are not slowed" },
  code: "throttle-off",
}

const STUFFING: LimitOption<StuffingDetector> = {
  name: "stuffing",
  own: { type: "StuffingDetector", methods: ["flagged", "failed"] },
  fields: { distinctAccounts: { min: 1 }, windowMs: { min: 1, ms: true } },
  defaults: DEFAULT_STUFFING,
  refuseOff: [
    "without it, credential stuffing spread across many accounts is never slowed past the per-account throttle",
    "its",
    "detector",
  ],
  off: { value: NO_STUFFING, so: "a client failing across many accounts is never flagged" },
  code: "stuffing-off",
}

const EMAIL_LIMIT: LimitOption<EmailSendLimits | false> = {
  name: "emailLimit",
  check: emailLimitProblems,
  refuseOff: [
    "the send limits are what stop sign-up and resend from flooding someone's inbox with mail from the app's domain",
    "their",
    "limiter",
  ],
  off: { value: false, so: "confirmation mail is sent without limit" },
  code: "email-limit-off",
}

const RATE_LIMIT: LimitOption<RequestLimits | null> = {
  name: "rateLimit",
  check: (value) => rateLimitProblems(value as RateLimitConfig | undefined),
  off: {
    value: null,
    so: "test-cap limits no request to /auth",
    then: "Limit them in front of the app, at its gateway or proxy",
  },
  code: "rate-limit-off",
}

const CLIENT_ADDRESS: LimitOption<boolean> = {
  name: "requireClientAddress",
  check: (value) =>
    value === undefined || value === true ? [] : ["requireClientAddress must be true or false."],
  off: {
    value: false,
    so: "a request with no client address is served, uncounted by the per-client limits",
    then: "Limit requests at the gateway, or give the adapter the socket address",
  },
  code: "client-address-optional",
}

/** The problem with a whole number that must lie from 1 to `max`, with the reason for `max`. */
function upTo(name: string, value: unknown, max: number, reason: string): readonly string[] {
  return value === undefined ||
    (Number.isSafeInteger(value) && (value as number) >= 1 && (value as number) <= max)
    ? []
    : [`${name} must be a whole number from 1 to ${max}: ${reason}.`]
}

/** The problem with `refusalEvents`, if any. */
function refusalEventProblems(value: unknown): readonly string[] {
  return value === undefined || value === "first" || value === "every"
    ? []
    : ['refusalEvents must be "first" or "every".']
}

/** Each problem with the limit options in `mode`, named, in the order the options are listed. */
function limitProblems(config: AuthConfig<string>, mode: DeploymentMode): readonly string[] {
  return [
    ...optionProblems(THROTTLE as LimitOption<unknown>, config.throttle, mode),
    ...upTo(
      "failureCeiling",
      config.failureCeiling,
      FAILURE_CEILING,
      `NIST SP 800-63B-4 §3.2.2 allows at most ${FAILURE_CEILING} consecutive failed attempts on one authenticator`,
    ),
    ...optionProblems(RATE_LIMIT as LimitOption<unknown>, config.rateLimit, mode),
    ...optionProblems(STUFFING as LimitOption<unknown>, config.stuffing, mode),
    ...optionProblems(EMAIL_LIMIT as LimitOption<unknown>, config.emailLimit, mode),
    ...upTo(
      "emailCodeAttempts",
      config.emailCodeAttempts,
      CONFIRMATION_FAILURE_LIMIT,
      `a 6-digit code stays hard to guess only while it allows at most ${CONFIRMATION_FAILURE_LIMIT} attempts over its life, a 1 in 200,000 chance`,
    ),
    ...refusalEventProblems(config.refusalEvents),
    ...optionProblems(CLIENT_ADDRESS as LimitOption<unknown>, config.requireClientAddress, mode),
  ]
}

/** What `limitsOf` hands the dispatcher. */
type Limits = Pick<
  Runtime<string>,
  "throttle" | "stuffing" | "emailLimits" | "requestLimits" | "emailCodeAttempts" | "refusalEvents"
>

/** Every limit of one `Auth`, from options whose problems were checked; each one turned off is reported once. */
function limitsOf(
  config: AuthConfig<string>,
  deps: { readonly store: AuthStore; readonly tenant: TenantId; readonly clock: Clock },
  diagnose: (diagnostic: AuthDiagnostic) => void,
): Limits {
  /** Builds each rule's limiter over the app's store: the default behind every limit (ADR 0030). */
  const storeLimiters: LimiterFactory = (options) =>
    createStoreLimiter({ ...options, ...deps, blocks: false })
  const { emailLimit, rateLimit } = config
  return {
    throttle: chosen(
      THROTTLE,
      config.throttle,
      () =>
        createThrottle({
          ...deps,
          config: {
            ...DEFAULT_THROTTLE,
            ...(config.throttle as Partial<ThrottleConfig> | undefined),
          },
        }),
      diagnose,
    ),
    stuffing: chosen(
      STUFFING,
      config.stuffing,
      () =>
        createStuffingDetector({
          ...deps,
          config: {
            ...DEFAULT_STUFFING,
            ...(config.stuffing as Partial<StuffingConfig> | undefined),
          },
        }),
      diagnose,
    ),
    emailLimits: chosen(
      EMAIL_LIMIT,
      emailLimit,
      () => emailSendLimits((emailLimit || {}) as EmailLimitConfig, storeLimiters),
      diagnose,
    ),
    requestLimits: chosen(
      RATE_LIMIT,
      rateLimit,
      () =>
        createRequestLimits((rateLimit || {}) as RateLimitConfig | RateLimiterLike, storeLimiters),
      diagnose,
    ),
    emailCodeAttempts: config.emailCodeAttempts,
    refusalEvents: config.refusalEvents ?? "first",
  }
}

/** The options whose shape is wrong, named before anything is built (ADR 0026 §4), so none fails on first use. */
function shapeProblems(config: AuthConfig<string>, envGiven: boolean): readonly string[] {
  return [
    ...(envGiven ? [] : ["env must be an object of settings, such as process.env."]),
    ...(config.onDiagnostic === undefined || typeof config.onDiagnostic === "function"
      ? []
      : ["onDiagnostic must be a function that receives each operator diagnostic."]),
    ...(typeof config.hibpFetch === "function"
      ? []
      : [
          "hibpFetch is required: the fetch the breached-password check calls, usually the global fetch.",
        ]),
    ...(typeof config.sendEmail === "function"
      ? []
      : [
          "sendEmail is required: the function that delivers each email test-cap builds, such as sign-up's code.",
        ]),
    ...(config.tenant === undefined || (typeof config.tenant === "string" && config.tenant !== "")
      ? []
      : [`tenant must be a non-empty string, not ${JSON.stringify(config.tenant)}.`]),
    ...(config.policy === undefined || isAuthPolicy(config.policy)
      ? []
      : ["policy must come from defineAuthPolicy."]),
  ]
}

/** Checks the deployment, then builds the `Auth`. Throws one `ConfigError` naming every problem (ADR 0026 §4). */
export function createAuth<Id extends string = "default">(config: AuthConfig<Id>): Auth<Id> {
  const envGiven = typeof config.env === "object" && (config.env as unknown) !== null
  const env: Readonly<Record<string, string | undefined>> = envGiven ? config.env : {}
  const read = (name: string): string | undefined => env[name]
  const { mode } = resolveDeploymentMode(read("APP_ENV"))
  // A missing origin reads as "undefined", which the origin check refuses like any other non-origin.
  const origin = String(read("APP_ORIGIN"))
  const secrets = Object.fromEntries(SECRETS.map((name) => [name, read(name)]))
  const systemId = read("APP_SYSTEM_ID")
  const systemProblem =
    systemId === undefined ? "APP_SYSTEM_ID is missing." : systemIdProblem(systemId)
  const costProblem =
    config.argon2Cost === undefined ? undefined : argon2CostProblem(config.argon2Cost)
  const trustedProxies = config.trustedProxies ?? []
  const publicBasePath = config.publicBasePath ?? ""
  const problems = [
    ...checkReadiness({
      mode,
      origin,
      store: config.store,
      secrets,
      custom: {
        clock: config.clock !== undefined,
        random: config.random !== undefined,
        argon2Cost: config.argon2Cost !== undefined,
      },
    }),
    ...(systemProblem === true ? [] : [systemProblem]),
    ...(costProblem === undefined ? [] : [costProblem]),
    ...(config.argon2Hasher === undefined ||
    implementsAll(Object(config.argon2Hasher) as object, ["hash", "verify"]) === true
      ? []
      : ["argon2Hasher must be an object with hash and verify functions."]),
    ...shapeProblems(config, envGiven),
    ...proxyProblems(trustedProxies, config.forwardedHeader),
    ...(PUBLIC_BASE_PATH.test(publicBasePath)
      ? []
      : [
          `publicBasePath ${JSON.stringify(publicBasePath)} must be empty or a path such as /accounts, with no trailing slash.`,
        ]),
    ...limitProblems(config, mode),
  ]
  if (problems.length > 0) throw new ConfigError(problems)

  const clock = config.clock ?? systemClock
  const random = config.random ?? systemRandom
  /** The parsed ring, or outside production and staging, a key generated for this process (ADR 0026 Open 1). */
  const ring = (name: (typeof SECRETS)[number]): readonly RingKey[] => {
    const value = secrets[name]
    return value === undefined
      ? [{ id: "generated", bytes: randomBytes(random, 32) }]
      : parseKeyRing(name, value).keys
  }
  const store = config.store
  const tenant = config.tenant ?? "default"
  const policy = (config.policy ?? defineAuthPolicy({ version: "test-cap default" })) as AuthPolicy<
    Id | "default"
  >
  const sessions = createSessions({ store, clock, random, policy })
  // The limits count in a view of the store that names each counter and block by an HMAC of its key (ADR 0032).
  const limited = limitStore(store, limitKeyName(ring("AUTH_ENCRYPTION_KEY")[0] as RingKey))
  const ceiling = createFailureCeiling({
    store: limited,
    tenant,
    clock,
    limit: config.failureCeiling,
  })
  const diagnose = onceEach(config.onDiagnostic)
  const limits = limitsOf(config, { store: limited, tenant, clock }, diagnose)
  const requireClientAddress = chosen(
    CLIENT_ADDRESS,
    config.requireClientAddress,
    () => isProductionLike(mode),
    diagnose,
  )
  const proxyTrust = trustOf(trustedProxies, config.forwardedHeader)
  const dispatcher = createDispatcher({
    store,
    limitStore: limited,
    tenant,
    clock,
    random,
    policy,
    sessions,
    csrf: createCsrfTokens(ring("AUTH_CSRF_KEY")),
    origin,
    systemId: systemId as string,
    sink: config.onEvent,
    password: {
      clock,
      random,
      store,
      hibp: config.hibpFetch,
      hasher: createHasher(config.argon2Cost, config.argon2Hasher, diagnose),
      ceiling,
    },
    totp: { clock, random, store, keyRing: ring("AUTH_ENCRYPTION_KEY"), ceiling },
    sendEmail: config.sendEmail,
    ...limits,
    challengeHook: config.challengeHook,
    proxyTrust,
    requireClientAddress,
    publicBasePath,
    diagnose,
  })

  const internals: AuthInternals = {
    origin,
    publicBasePath,
    publicPaths: compilePublicPaths,
    routes: () => dispatcher.routes(),
    requireAddressSource(hasSource) {
      if (requireClientAddress && !hasSource && proxyTrust?.peers !== "platform") {
        throw new ConfigError([
          "requireClientAddress: production and staging refuse a request with no client address, and this adapter has no clientAddress option. Pass one, use the preset of a platform every request comes through (vercel, fly or netlify), or set requireClientAddress: false and limit requests at the gateway (ADR 0009 §8).",
        ])
      }
    },
    async gate(head, isPublic) {
      try {
        if (matchAuthPath(head.url, BASE_PATH).kind === "route") return { kind: "dispatch" }
        if (isPublic(rawPath(head.url))) return { kind: "next", subject: null }
        const result = await sessions.require(tenant, readSessionToken(head.headers), "default")
        if (result.outcome === "allow") return { kind: "next", subject: result.subject }
        const status = result.outcome === "unauthenticated" ? 401 : 403
        return { kind: "respond", response: errorResponse(status, result.outcome) }
      } catch (error) {
        return { kind: "respond", response: failure(error) }
      }
    },
  }

  const auth: Auth<Id> = {
    handle: (req) => dispatcher.handle(req),
    async session(req) {
      return dispatcher.sessionInfo(await sessions.read(tenant, readSessionToken(req.headers)))
    },
    require: (req, requirementId) =>
      sessions.require(tenant, readSessionToken(req.headers), requirementId),
    admin: {
      revoke: (subject) => dispatcher.revokeAll(subject),
      async deprovision(subject) {
        if (!(await deactivateAccount(store, tenant, subject, clock.now()))) return false
        await dispatcher.revokeAll(subject)
        return true
      },
    },
  }
  Object.defineProperty(auth, INTERNALS, { value: internals })
  return auth
}
