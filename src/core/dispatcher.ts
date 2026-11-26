/**
 * The dispatcher (ADR 0003 §6): the one entry for every `/auth/*` route. Every request passes the same checks in the
 * same order, in one place:
 *
 * 1. the raw path, refused with a 400 when two parsers could read it differently (ADR 0003 §2);
 * 2. the request limit of the route that path names, counted per client before anything else runs (ADR 0009 §8);
 * 3. the route and its method;
 * 4. for a state-changing route, the origin check, the body parsed under its declared fields, and the synchronizer
 *    token (ADR 0011 §2);
 * 5. the route itself.
 *
 * Every response carries the security headers and `Cache-Control: no-store` (ADR 0011 §3, §4); only the hashed page
 * assets are cached, as immutable. An error a flow throws becomes a fixed 500 body, and a transport refusal its fixed
 * code (ADR 0003 §8).
 *
 * The default pages (ADR 0025 §4) are the `GET` side of the routes they post to. A form post that accepts HTML is
 * answered as a browser needs: a 303 to the next step, or the page again with the refusal in its form.
 *
 * Replies never say whether an account exists (ADR 0009 §6): sign-up never looks one up, and every failed sign-in
 * gives one reply after the same argon2id work.
 */

import { generateRecoveryCodes, redeemRecoveryCode } from "../methods/recovery/codes.js"
import type { AuthenticationEvidence, AuthenticationMethod } from "../assurance/evidence.js"
import type { AuthPolicy, RequireResult, SessionAssurance } from "../assurance/policy.js"
import { hexEncode, sha256, utf8Decode, utf8Encode } from "./encoding.js"
import { TransportError } from "./errors.js"
import {
  authenticationEvent,
  deliver,
  type EventSink,
  type EventSubject,
  type FactorKind,
  type SessionRef,
  userManagementEvent,
} from "../ocsf/events.js"
import type { Clock, RandomSource } from "./clock.js"
import {
  accountActive,
  claimIdentifier,
  createAccount,
  hasConfirmedIdentifier,
  identifierValues,
  resolveConfirmed,
} from "./accounts.js"
import { clientKey } from "./client-address.js"
import { resolveClient, unreadForwarding, type ProxyTrust } from "./proxy-trust.js"
import type { AuthDiagnostic } from "./auth.js"
import {
  type EmailDeps,
  type EmailSendLimits,
  redeemConfirmation,
  type SendEmail,
  sendConfirmation,
} from "./email.js"
import { normaliseEmail } from "./identifier.js"
import {
  PASSWORD_COLLECTION,
  type PasswordDeps,
  setPassword,
  signInWithPassword,
} from "../methods/password/method.js"
import { QueueFullError } from "../methods/password/semaphore.js"
import {
  beginTotpEnrolment,
  confirmedTotpCount,
  confirmTotpEnrolment,
  totpEnrolmentAllowed,
  type TotpDeps,
  verifyTotp,
} from "../methods/totp/method.js"
import {
  createForm,
  DEFAULT_MESSAGES,
  type FlowOutcome,
  type FormId,
  type FormModel,
  isValid,
  validateForm,
  withFieldError,
  withOutcome,
} from "../forms/model.js"
import { pageAssets } from "../pages/assets.js"
import { type PageContext, renderPage, renderSignOutPage } from "../pages/render.js"
import { type CsrfTokens, newPreSession, readPreSession, sameOrigin } from "../security/csrf.js"
import {
  emptyResponse,
  errorResponse,
  htmlResponse,
  jsonResponse,
  type ResponseExtras,
} from "../security/headers.js"
import { safeReturnTo } from "../security/redirect.js"
import { createStoreLimiter } from "../security/store-limiter.js"
import type { RateLimitRouteId, RequestLimits } from "../security/rate-limit.js"
import type { ChallengeHook, StuffingDetector } from "../security/stuffing.js"
import type { Throttle, ThrottleSubject } from "../security/throttle.js"
import {
  clearSessionCookie,
  type createSessions,
  type IssuedSession,
  type ReadSession,
  readSessionToken,
  SESSION_COLLECTION,
} from "../sessions/sessions.js"
import type { AuthStore, JsonValue, StoreOperations, TenantId } from "../store/port.js"
import { type Fields, parseBody, throwIfAborted } from "../transport/body.js"
import { singleHeader } from "../transport/headers.js"
import { matchAuthPath } from "../transport/path.js"
import type { PlainRequest, PlainResponse } from "../transport/types.js"

/**
 * How recent a multi-factor ceremony must be for a signed-in session to change a credential: enrol TOTP or make
 * recovery codes (ADR 0005 §8). Fifteen minutes, as for the policy's own fresh-MFA requirements in the examples.
 */
export const CREDENTIAL_CHANGE_WITHIN_MS = 15 * 60_000

/** The path every test-cap route lives under. */
export const BASE_PATH = "/auth"

/** Everything the routes run on, built once by `createAuth`. */
export interface Runtime<Id extends string> {
  readonly store: AuthStore
  /** The store the limits count in: `store`, with each counter and block named by an HMAC of its key (ADR 0032). */
  readonly limitStore: AuthStore
  readonly tenant: TenantId
  readonly clock: Clock
  readonly random: RandomSource
  readonly policy: AuthPolicy<Id | "default">
  readonly sessions: ReturnType<typeof createSessions<Id | "default">>
  readonly csrf: CsrfTokens
  readonly origin: string
  readonly systemId: string
  readonly sink: EventSink | undefined
  readonly password: PasswordDeps
  readonly totp: TotpDeps
  /** The app's mail sender, for confirmation codes (ADR 0021). */
  readonly sendEmail: SendEmail
  /** The throttle every guessable secret goes through (ADR 0009 §1 to §3). */
  readonly throttle: Throttle
  /** Which forwarding header names the client, from which peers (ADR 0009 §5); `null` when the socket is the client. */
  readonly proxyTrust: ProxyTrust | null
  /** True when a request with no client address is refused with the fixed 500 (ADR 0009 §8). */
  readonly requireClientAddress: boolean
  /** The gateway's path prefix, `""` for none: every link, redirect and email URL starts with it (ADR 0024 §6). */
  readonly publicBasePath: string
  /** Hands an operator diagnostic on, once per code (ADR 0009 §5). */
  readonly diagnose: (diagnostic: AuthDiagnostic) => void
  /** The credential-stuffing detector (ADR 0009 §4). */
  readonly stuffing: StuffingDetector
  /** The app's challenge for a flagged client, if it has one (ADR 0009 §4). */
  readonly challengeHook: ChallengeHook | undefined
  /** The request limits every request is counted against (ADR 0009 §8); `null` when the app turned them off. */
  readonly requestLimits: RequestLimits | null
  /** The confirmation-mail send limits (ADR 0009 §7, §8); `false` when the app turned them off. */
  readonly emailLimits: EmailSendLimits | false
  /** Attempts an emailed code allows over its life, from 1 to 5; 5 when absent (ADR 0009 Open 1). */
  readonly emailCodeAttempts: number | undefined
  /** Which refusals of a limit emit their failure event: the first per key and window, or every one (ADR 0009 §8). */
  readonly refusalEvents: "first" | "every"
}

/** A session as the session endpoint reports it (ADR 0006): what it is, never its token. */
export interface SessionInfo {
  /** The session's public id, the one the session list and remote revoke use. */
  readonly id: string
  /** The account it belongs to. */
  readonly subject: string
  /** `authenticated`, or `pre-auth` while MFA is not yet set up, or `recovery-only`. */
  readonly state: "authenticated" | "pre-auth" | "recovery-only"
  /** The level its still-valid evidence supports; `null` when none does. */
  readonly level: "AAL1" | "AAL2" | "AAL3" | null
  /** The methods of its still-valid evidence. */
  readonly methods: readonly AuthenticationMethod[]
  /** When the session ends unless it serves a request first (epoch ms). */
  readonly idleExpiresAt: number
  /** When the session ends whatever it does (epoch ms). */
  readonly absoluteExpiresAt: number
}

/** What a reading route runs with. */
interface GetContext {
  readonly req: PlainRequest
  /** The session cookie's value, if any. */
  readonly token: string | null
}

/** What a state-changing route runs with: its checked body fields as well. */
interface Context extends GetContext {
  readonly fields: Fields
  /** True when the body was a form, so a finished sign-in answers with a redirect. */
  readonly form: boolean
}

/** A route that only reads. */
interface GetRoute {
  readonly method: "GET"
  readonly run: (ctx: GetContext) => Promise<PlainResponse>
}

/** A state-changing route: the body fields it reads, and the event a CSRF refusal counts as (ADR 0015 §2). */
interface PostRoute {
  readonly method: "POST"
  /** Each field the route reads, `true` when it is required. */
  readonly fields: Readonly<Record<string, boolean>>
  /**
   * The format of each field the route uses as a store key; a value outside it is a malformed body, refused before
   * the store sees it.
   */
  readonly keys?: Readonly<Record<string, RegExp>>
  readonly refused: EventKind
  readonly run: (ctx: Context) => Promise<PlainResponse>
}

type Route = GetRoute | PostRoute

/** What a page's context holds besides the token and the assets, which the dispatcher adds. */
type PagePart = Omit<PageContext, "csrfToken" | "assets">

/**
 * A default page (ADR 0025 §4): the form it shows (`null` for sign-out), and its context or a redirect. `still` is
 * true when opening it touches no store, so a refused request may be answered with it.
 */
interface Page {
  readonly form: FormId | null
  readonly open: (token: string | null) => Promise<PagePart | PlainResponse>
  readonly still: boolean
}

/**
 * Each route a default page posts to: the page it shows again on a refusal, and the next step after a success.
 * `own: false` marks a post from a second form, whose fields are not the page's, so the page shows again empty.
 */
interface FormPost {
  readonly page: string
  readonly next: string
  readonly own?: false
  /** Where a success whose outcome is `enroll` goes instead of `next`. */
  readonly enroll?: string
}

/**
 * Each route a default page posts to, with its page and next step. A finished `totp/confirm` ceremony at `allow` is
 * already a 303 to `returnTo`; any other success still needs a step-up.
 */
const FORM_POSTS: ReadonlyMap<string, FormPost> = new Map<string, FormPost>([
  ["sign-up", { page: "sign-up", next: "/auth/email/confirm" }],
  ["email/confirm", { page: "email/confirm", next: "/auth/password" }],
  ["email/resend", { page: "email/confirm", next: "/auth/email/confirm", own: false }],
  ["password", { page: "password", next: "/auth/totp/enrol" }],
  ["totp/confirm", { page: "totp/enrol", next: "/auth/step-up" }],
  // A password sign-in to an account with no second factor yet goes back to enrolment.
  ["sign-in", { page: "sign-in", next: "/auth/step-up", enroll: "/auth/totp/enrol" }],
  ["step-up", { page: "step-up", next: "/auth/step-up" }],
  ["sign-out", { page: "sign-out", next: "/auth/sign-in" }],
])

/** The refusal codes a page names in its error row; any other code shows the unexpected-failure message. */
const OUTCOMES: Readonly<Record<string, FlowOutcome["error"]>> = {
  "invalid-credentials": "invalid-credentials",
  "invalid-code": "invalid-code",
  "too-common": "too-common",
  breached: "breached",
  "rate-limited": "rate-limited",
  "challenge-required": "challenge-required",
  "invalid-challenge": "invalid-challenge",
}

/** The media type of the forms the default pages post. */
const FORM_MEDIA_TYPE = "application/x-www-form-urlencoded"

/** A TOTP authenticator id: 32 random bytes in unpadded base64url (`beginTotpEnrolment`). */
const AUTHENTICATOR_ID = /^[A-Za-z0-9_-]{43}$/

/** How long a browser may keep a hashed asset: a year, never revalidated, since its name changes with its content. */
const IMMUTABLE = "public, max-age=31536000, immutable"

/** A 303 to `location` on this origin. */
function redirect(location: string, cookies: readonly string[] = []): PlainResponse {
  return emptyResponse(303, { cookies, headers: { Location: location } })
}

/**
 * True for a form post from a browser that wants a page back, not JSON. An absent header reads as the four letters
 * "null", which matches neither.
 */
function wantsHtml(req: PlainRequest): boolean {
  return (
    String(req.headers.get("accept")).includes("text/html") &&
    String(req.headers.get("content-type")).toLowerCase().startsWith(FORM_MEDIA_TYPE)
  )
}

/** The code of a refusal: every error the routes give is `{ "error": code }`. */
function refusalCode(response: PlainResponse): string {
  return (JSON.parse(utf8Decode(response.body as Uint8Array)) as { readonly error: string }).error
}

/** One route as data, for the OpenAPI document and the test that keeps it complete. */
export interface RouteSummary {
  /** The full path, such as `/auth/sign-in`. */
  readonly path: string
  /** The one method the route answers. */
  readonly method: "GET" | "POST"
  /** Each body field the route reads, `true` when it is required; empty for a `GET`. */
  readonly fields: Readonly<Record<string, boolean>>
}

/**
 * The ADR 0015 §2 activities the phase 3 flows emit: Authentication Logon and Logoff, User Management Create, Update
 * and Enable MFA Factors.
 */
type EventKind = "logon" | "logoff" | "create" | "update" | "enable-mfa-factors"

/** The subject of an event about a request that named no account test-cap could resolve. */
const UNKNOWN: EventSubject = { kind: "user", id: "unknown" }

type Denial = Exclude<RequireResult["outcome"], "allow">

/** The `RequireResult` outcomes as replies: no session is a 401, any other shortfall a 403 naming it. */
function denied(outcome: Denial): PlainResponse {
  return errorResponse(outcome === "unauthenticated" ? 401 : 403, outcome)
}

async function tokenHash(token: string): Promise<string> {
  return hexEncode(await sha256(utf8Encode(token)))
}

const SET_PASSWORD_STATUS = {
  "too-short": 400,
  "too-long": 400,
  "too-common": 400,
  breached: 400,
  busy: 503,
  conflict: 409,
} as const

/** Builds `auth.handle` and the session reads it shares with `auth.session`. */
export function createDispatcher<Id extends string>(rt: Runtime<Id>) {
  const { store, tenant, clock, policy, sessions, csrf } = rt
  /** Counts refusals per key, so `refuse` reports only the first of each wait (ADR 0009 §8). */
  const refusals = createStoreLimiter({
    store: rt.limitStore,
    tenant,
    clock,
    points: 1,
    duration: 1,
    keyPrefix: "refusal-event",
    blocks: false,
  })
  const assets = pageAssets(`${BASE_PATH}/assets/`)
  /** `/auth` as the browser sees it, behind any gateway prefix: the base of every link and redirect test-cap builds. */
  const AUTH = `${rt.publicBasePath}${BASE_PATH}`
  /** A deviation that lets a password alone pass the default requirement raises its minimum (ADR 0010). */
  const passwordAlone = policy.deviations.some((item) => item.kind === "default-below-aal2")
  const email: EmailDeps = {
    store,
    tenant,
    clock,
    random: rt.random,
    linkBase: `${rt.origin}${AUTH}`,
    sendEmail: rt.sendEmail,
    keyRing: rt.totp.keyRing,
    sendLimits: rt.emailLimits,
    attemptLimit: rt.emailCodeAttempts,
  }

  /**
   * Builds the OCSF event of one point and hands it to the sink without waiting: `deliver` never rejects, so neither
   * a slow nor a failing sink changes the outcome (ADR 0015 §3, Open 5).
   */
  const event = (
    kind: EventKind,
    succeeded: boolean,
    subject: string | null,
    extra: {
      readonly method?: FactorKind | undefined
      readonly stepUp?: true | undefined
      readonly detail?: string | undefined
      readonly session?: SessionRef | undefined
      readonly assurance?: SessionAssurance["level"] | undefined
    } = {},
  ): void => {
    const input = {
      time: clock.now(),
      system: rt.systemId,
      tenant,
      subject: subject === null ? UNKNOWN : { kind: "user" as const, id: subject },
      // Stryker disable next-line StringLiteral: equivalent -- the OCSF builder reads every outcome but "success" as a failure
      outcome: succeeded ? ("success" as const) : ("failure" as const),
      detail: extra.detail,
      factors: extra.method === undefined ? undefined : [extra.method],
    }
    void deliver(
      rt.sink,
      kind === "logon" || kind === "logoff"
        ? authenticationEvent({
            ...input,
            activity: kind,
            session: extra.session,
            stepUp: extra.stepUp,
            assurance: extra.assurance,
          })
        : userManagementEvent({ ...input, activity: kind }),
    )
  }

  /** A session as an event names it: by its stored hash, which the builder cuts to a 16-character prefix. */
  const sessionRef = async (
    token: string,
    state: { readonly startedAt: number },
    assurance: SessionAssurance,
  ): Promise<SessionRef> => ({
    hash: await tokenHash(token),
    mfa: assurance.lastMultiFactorAt !== null,
    createdAt: state.startedAt,
    expiresAt: assurance.absoluteExpiresAt,
  })

  /** The Logon of a ceremony that issued `issued`: its session and the level it now holds. */
  const loggedOn = async (
    subject: string,
    method: FactorKind,
    issued: IssuedSession,
    stepUp?: true,
  ): Promise<void> => {
    // A session just issued is inside every limit, so its assurance is never null.
    const assurance = policy.assurance(issued.state, clock.now()) as SessionAssurance
    event("logon", true, subject, {
      method,
      stepUp,
      session: await sessionRef(issued.token, issued.state, assurance),
      assurance: assurance.level,
    })
  }

  /** What a synchronizer token binds to: the session's stored hash, else the pre-session value, else nothing. */
  const binding = async (headers: Headers): Promise<string | null> => {
    const token = readSessionToken(headers)
    if (token !== null) return `session:${await tokenHash(token)}`
    const pre = readPreSession(headers)
    return pre === null ? null : `pre:${pre}`
  }

  /** A synchronizer token for the browser, and the pre-session cookie to bind it to when it holds no cookie yet. */
  const tokenFor = async (
    headers: Headers,
  ): Promise<{ readonly csrfToken: string; readonly cookies: readonly string[] }> => {
    const bound = await binding(headers)
    if (bound !== null) return { csrfToken: await csrf.issue(bound, clock.now()), cookies: [] }
    const pre = newPreSession(rt.random)
    return { csrfToken: await csrf.issue(`pre:${pre.value}`, clock.now()), cookies: [pre.cookie] }
  }

  const sessionInfo = (read: ReadSession | null): SessionInfo | null =>
    read === null
      ? null
      : {
          id: read.id,
          subject: read.state.subject,
          state: read.state.state,
          level: read.assurance.level,
          methods: read.assurance.evidence.map((item) => item.method),
          idleExpiresAt: read.assurance.idleExpiresAt,
          absoluteExpiresAt: read.assurance.absoluteExpiresAt,
        }

  /** The validated `returnTo`, the app's root when absent, or `null` when it is not a same-origin relative path. */
  const returnToOf = (fields: Fields): string | null =>
    fields["returnTo"] === undefined
      ? `${rt.publicBasePath}/`
      : safeReturnTo(fields["returnTo"] as string, rt.origin)

  /** The reply to a ceremony that issued a session: its cookie, a token bound to it, and what to do next. */
  /** The cookie of a session just issued, and the CSRF token bound to it for the next post. */
  const issuedExtras = async (issued: IssuedSession, now: number): Promise<ResponseExtras> => ({
    cookies: [issued.cookie],
    headers: {
      "X-CSRF-Token": await csrf.issue(`session:${await tokenHash(issued.token)}`, now),
    },
  })

  const issuedResponse = async (
    ctx: Context,
    issued: IssuedSession,
    returnTo: string,
  ): Promise<PlainResponse> => {
    const now = clock.now()
    const outcome = policy.require(issued.state, "default", now).outcome
    const extras = await issuedExtras(issued, now)
    if (ctx.form && outcome === "allow") {
      return emptyResponse(303, { ...extras, headers: { ...extras.headers, Location: returnTo } })
    }
    return jsonResponse(200, { outcome, returnTo }, extras)
  }

  /** The session behind the cookie when it has signed in (with or without its second factor). */
  const signedIn = (current: ReadSession | null): { readonly subject: string } | PlainResponse => {
    const result = policy.require(current?.state ?? null, "default", clock.now())
    if (result.outcome === "allow" || result.outcome === "step-up")
      return { subject: result.subject }
    return denied(result.outcome)
  }

  /** The session behind the cookie when it meets the default requirement. */
  const allowed = (current: ReadSession | null): { readonly subject: string } | PlainResponse => {
    const result = policy.require(current?.state ?? null, "default", clock.now())
    return result.outcome === "allow" ? { subject: result.subject } : denied(result.outcome)
  }

  /**
   * True when a signed-in session may change a credential now: it proved multiple factors within
   * `CREDENTIAL_CHANGE_WITHIN_MS` (ADR 0005 §8; the `sensitive-change-without-reauth` attack). A pre-auth or
   * recovery-only session follows its own rules instead.
   */
  const recentlyVerified = (current: ReadSession): boolean => {
    if (current.state.state !== "authenticated") return true
    const at = current.assurance.lastMultiFactorAt
    return at !== null && clock.now() - at <= CREDENTIAL_CHANGE_WITHIN_MS
  }

  /** The refusal for a credential change without a recent step-up: what the step-up must add. */
  const staleForChange = (): PlainResponse =>
    jsonResponse(403, {
      error: "step-up",
      missing: [{ kind: "fresh-multi-factor", withinMs: CREDENTIAL_CHANGE_WITHIN_MS }],
    })

  /**
   * A session that may add an authenticator: one still enrolling, one recovering (ADR 0007 §3: it may only replace
   * authenticators, and doing so adds no evidence), or one meeting the default requirement.
   */
  const enrolling = (
    current: ReadSession | null,
  ): { readonly subject: string; readonly preAuth: boolean } | PlainResponse => {
    if (current?.state.state === "pre-auth")
      return { subject: current.state.subject, preAuth: true }
    if (current?.state.state === "recovery-only")
      return { subject: current.state.subject, preAuth: false }
    const result = policy.require(current?.state ?? null, "default", clock.now())
    return result.outcome === "allow"
      ? { subject: result.subject, preAuth: false }
      : denied(result.outcome)
  }

  /**
   * True while the account of a pre-auth session has no confirmed second factor. Once it has one, the session cannot
   * prove it, so it is signed out: whoever knew only the password while enrolment was unfinished must not add a TOTP
   * of their own afterwards and reach AAL2.
   */
  const stillEnrolling = async (subject: string, token: string): Promise<boolean> => {
    if ((await confirmedTotpCount(rt.totp, { tenant, accountId: subject })) === 0) return true
    await sessions.signOut(tenant, token)
    return false
  }

  /** The account of a session still enrolling (pre-auth); else the refusal. */
  const enrollingOnly = (
    current: ReadSession | null,
  ): { readonly subject: string } | PlainResponse => {
    if (current?.state.state === "pre-auth") return { subject: current.state.subject }
    return current === null ? denied("unauthenticated") : errorResponse(403, "not-enrolling")
  }

  /** The address the account typed at sign-up, or `null` when it typed none. */
  const addressOf = async (accountId: string): Promise<string | null> =>
    (await identifierValues(store, tenant, accountId))[0] ?? null

  /** Begins a TOTP enrolment for the account, or refuses one past the limit of ADR 0027. */
  const startTotp = async (
    subject: string,
  ): Promise<{ readonly authenticatorId: string; readonly secret: string } | PlainResponse> =>
    (await totpEnrolmentAllowed(rt.totp, { tenant, accountId: subject }))
      ? beginTotpEnrolment(rt.totp, { tenant, accountId: subject })
      : errorResponse(409, "too-many-authenticators")

  /** The password authenticator id of an account, or `null` when it has none yet. */
  const passwordAuthenticator = async (accountId: string): Promise<string | null> => {
    const stored = await store.get(tenant, PASSWORD_COLLECTION, accountId)
    const id = (stored?.data as Readonly<Record<string, JsonValue>> | null | undefined)?.[
      "authenticatorId"
    ]
    return typeof id === "string" ? id : null
  }

  /** The request's client: the socket, or through the app's declared proxies their forwarded client (ADR 0009 §5). */
  const clientOf = (req: PlainRequest): string | undefined =>
    resolveClient(req.clientAddress, req.headers, rt.proxyTrust)

  /** The 429 a throttled attempt gets, with the wait in seconds the page shows (ADR 0009, ADR 0025). */
  const rateLimited = (retryAfterMs: number): PlainResponse =>
    errorResponse(429, "rate-limited", {
      headers: { "Retry-After": String(Math.ceil(retryAfterMs / 1000)) },
    })

  /**
   * Refuses a request a limit stopped, as every limit refuses (ADR 0009 §8): the 429 with `Retry-After`, and the
   * route's failure event for the first refusal of `key` until its wait ends, or for every refusal with
   * `refusalEvents: "every"`. Refusals are counted in the store; one the store cannot count is reported, as the
   * refusal stands either way.
   */
  const refuse = async (
    key: string,
    retryAfterMs: number,
    kind: EventKind,
    subject: string | null,
    extra: Parameters<typeof event>[3] = {},
  ): Promise<PlainResponse> => {
    let first = true
    if (rt.refusalEvents === "first") {
      // One point per key in a window as long as the wait: the first refusal takes it, the rest are refused.
      first = await refusals.consume(key, 1, { customDuration: retryAfterMs / 1000 }).then(
        () => true,
        (refusal: unknown) => refusal instanceof Error,
      )
    }
    if (first) event(kind, false, subject, { detail: "rate-limited", ...extra })
    return rateLimited(retryAfterMs)
  }

  /**
   * Checks a guessable secret under the throttle (ADR 0009): refused before any check while the subject is blocked;
   * a failure counts against every key, a success clears the account's. `busy` is the server's refusal, not a guess,
   * so it counts for nothing.
   */
  const throttled = async <R extends { readonly ok: boolean; readonly reason?: string }>(
    subject: ThrottleSubject,
    check: () => Promise<R>,
    strict = false,
  ): Promise<
    | R
    | {
        readonly ok: false
        readonly reason: "rate-limited"
        readonly retryAfterMs: number
        /** The key the refusal is reported under: the subject's identifier and client. */
        readonly key: string
      }
  > => {
    const wait = await rt.throttle.attempt(subject, strict)
    if (wait > 0) {
      const key = `guess|${subject.account}|${String(clientKey(subject.clientAddress))}`
      return { ok: false, reason: "rate-limited", retryAfterMs: wait, key }
    }
    const result = await check()
    if (result.ok) await rt.throttle.succeeded(subject)
    else if (result.reason !== "busy") await rt.throttle.failed(subject, strict)
    return result
  }

  /** Runs a password or TOTP ceremony for the account; a disabled account fails as a wrong secret does. */
  const ceremony = async (
    subject: string,
    secret: { readonly password: string } | { readonly code: string },
    req: PlainRequest,
  ) => {
    const active = await accountActive(store, tenant, subject)
    // Keyed on the account's address, as sign-in and recovery are, so the flows that check one secret of an account
    // share its budget.
    const who = { account: (await addressOf(subject)) ?? subject, clientAddress: clientOf(req) }
    if ("password" in secret) {
      const result = await throttled({ ...who, secret: "password" }, () =>
        signInWithPassword(rt.password, {
          tenant,
          accountId: active ? subject : null,
          password: secret.password,
        }),
      )
      return { method: "password" as const, result }
    }
    const result = await throttled({ ...who, secret: "totp" }, async () =>
      active
        ? verifyTotp(rt.totp, { tenant, accountId: subject, code: secret.code })
        : ({ ok: false, reason: "invalid" } as const),
    )
    return { method: "totp" as const, result }
  }

  /** Adds evidence to the session behind `token` through a step-up challenge it opens itself, and rotates it. */
  const addEvidence = async (
    token: string,
    evidence: AuthenticationEvidence,
  ): Promise<IssuedSession | null> => {
    const challenge = await sessions.beginStepUp(tenant, token)
    return sessions.stepUp(tenant, token, String(challenge), evidence)
  }

  /**
   * Rotates the session on a credential change and revokes the account's other sessions (ADR 0006 §7); `apply`, when
   * given, writes the change in the same transaction. When the rotation fails or finds the session gone, every
   * session of the account is revoked instead, so no session outlives the change (ADR 0029, finding F-1).
   */
  const afterCredentialChange = async (
    token: string,
    subject: string,
    apply?: (ops: StoreOperations) => Promise<boolean>,
  ): Promise<IssuedSession | null> => {
    let issued: IssuedSession | null = null
    try {
      issued = await sessions.credentialChanged(tenant, token, apply)
    } finally {
      if (issued === null)
        await store.revokeByOwner(tenant, SESSION_COLLECTION, subject, clock.now())
    }
    return issued
  }

  const recovery = {
    store,
    clock,
    random: rt.random,
    hasher: rt.password.hasher,
  }

  /**
   * Sets a new password from a recovery-only session (ADR 0007 §3): the password, the session's rotation and the
   * revocation of the account's others commit together, and the session stays recovery-only, with no level. A session
   * gone by the time the hash is ready writes no password.
   */
  const replacePassword = async (
    ctx: Context,
    current: ReadSession & { readonly state: { readonly subject: string } },
  ): Promise<PlainResponse> => {
    const subject = current.state.subject
    let issued: IssuedSession | null = null
    const result = await setPassword(rt.password, {
      tenant,
      accountId: subject,
      password: ctx.fields["password"] as string,
      alone: passwordAlone,
      contextWords: [rt.systemId, ...(await identifierValues(store, tenant, subject))],
      commit: async (write) =>
        (issued = await afterCredentialChange(ctx.token as string, subject, write)) !== null,
    })
    if (!result.ok) {
      event("update", false, subject, { method: "password", detail: result.reason })
      // A change that wrote nothing revoked every session of the account, this one included.
      return result.reason === "conflict"
        ? denied("unauthenticated")
        : errorResponse(SET_PASSWORD_STATUS[result.reason], result.reason)
    }
    event("update", true, subject, { method: "password", detail: "recovery" })
    // No returnTo is asked for here: the reply names the app's root, behind any gateway prefix.
    return issuedResponse(ctx, issued as unknown as IssuedSession, returnToOf({}) as string)
  }

  /** The active account a normalised identifier confirms, or `null`, as for text that is no address. */
  const confirmedAccount = async (identifier: string | null): Promise<string | null> =>
    identifier === null ? null : resolveConfirmed(store, tenant, identifier)

  /** Tells the account's confirmed address that a recovery started, without waiting on the mailer. */
  const notifyRecovered = (address: string): void => {
    void (async () =>
      rt.sendEmail({
        to: address,
        subject: "A recovery of your account started",
        text: "A saved recovery code was just used on your account, and its other sessions were signed out. If this was not you, recover the account at once with another of your codes and replace every sign-in method.",
      }))().catch(() => undefined)
  }

  const routes = new Map<string, Route>([
    [
      "session",
      {
        method: "GET",
        async run(ctx) {
          const { csrfToken, cookies } = await tokenFor(ctx.req.headers)
          const session = sessionInfo(await sessions.read(tenant, ctx.token))
          return jsonResponse(200, { session, csrfToken }, { cookies })
        },
      },
    ],
    [
      "sign-up",
      {
        method: "POST",
        fields: { identifier: true, returnTo: false },
        refused: "create",
        async run(ctx) {
          const returnTo = returnToOf(ctx.fields)
          if (returnTo === null) return errorResponse(400, "invalid-return-to")
          const identifier = normaliseEmail(ctx.fields["identifier"] as string)
          if (identifier === null) return errorResponse(400, "invalid-identifier")
          const accountId = await createAccount(store, tenant, rt.random, {
            identifier,
            now: clock.now(),
          })
          event("create", true, accountId)
          await sendConfirmation(email, {
            accountId,
            address: identifier,
            clientAddress: clientOf(ctx.req),
          })
          const issued = await sessions.begin(tenant, ctx.token, {
            subject: accountId,
            state: "pre-auth",
          })
          return issuedResponse(ctx, issued, returnTo)
        },
      },
    ],
    [
      "email/confirm",
      {
        method: "POST",
        fields: { code: true },
        refused: "update",
        async run(ctx) {
          const who = enrollingOnly(await sessions.read(tenant, ctx.token))
          if (!("subject" in who)) return who
          const address = await addressOf(who.subject)
          if (address === null) return errorResponse(409, "no-identifier")
          const result = await redeemConfirmation(email, {
            accountId: who.subject,
            address,
            code: ctx.fields["code"] as string,
          })
          if (!result.ok) {
            if (result.reason === "rate-limited") {
              return refuse(`email-code|${who.subject}`, result.retryAfterMs, "update", who.subject)
            }
            event("update", false, who.subject, { detail: result.reason })
            return errorResponse(400, "invalid-code")
          }
          const claimed = await claimIdentifier(store, tenant, {
            accountId: who.subject,
            identifier: address,
            now: clock.now(),
          })
          // The reply is the same either way; only the app's event says the address was already taken.
          event("update", claimed, who.subject, {
            detail: claimed ? "email-confirmed" : "identifier-taken",
          })
          return jsonResponse(200, { outcome: "enroll" })
        },
      },
    ],
    [
      "email/resend",
      {
        method: "POST",
        fields: {},
        refused: "update",
        async run(ctx) {
          const who = enrollingOnly(await sessions.read(tenant, ctx.token))
          if (!("subject" in who)) return who
          const address = await addressOf(who.subject)
          if (address === null) return errorResponse(409, "no-identifier")
          if (await hasConfirmedIdentifier(store, tenant, who.subject)) {
            return errorResponse(409, "already-confirmed")
          }
          const { retryAfterMs } = await sendConfirmation(email, {
            accountId: who.subject,
            address,
            clientAddress: clientOf(ctx.req),
          })
          return jsonResponse(200, { outcome: "enroll", retryAfterMs })
        },
      },
    ],
    [
      "password",
      {
        method: "POST",
        fields: { password: true },
        refused: "enable-mfa-factors",
        async run(ctx) {
          const current = await sessions.read(tenant, ctx.token)
          if (current?.state.state === "recovery-only") return replacePassword(ctx, current)
          const who = enrollingOnly(current)
          if (!("subject" in who)) return who
          const subject = who.subject
          if (!(await hasConfirmedIdentifier(store, tenant, subject))) {
            return errorResponse(409, "confirm-email-first")
          }
          // A password, once set, changes only through recovery, which signs the account's other sessions out
          // (ADR 0007 §3). A session sent back to enrolment by a password sign-in may not replace it.
          if ((await passwordAuthenticator(subject)) !== null)
            return errorResponse(409, "password-set")
          const result = await setPassword(rt.password, {
            tenant,
            accountId: subject,
            password: ctx.fields["password"] as string,
            alone: passwordAlone,
            contextWords: [rt.systemId, ...(await identifierValues(store, tenant, subject))],
          })
          if (!result.ok) {
            event("enable-mfa-factors", false, subject, {
              method: "password",
              detail: result.reason,
            })
            return errorResponse(SET_PASSWORD_STATUS[result.reason], result.reason)
          }
          event("enable-mfa-factors", true, subject, { method: "password" })
          return jsonResponse(200, { outcome: "enroll", enrolled: ["password"] })
        },
      },
    ],
    [
      "totp/enrol",
      {
        method: "POST",
        fields: {},
        refused: "enable-mfa-factors",
        async run(ctx) {
          const current = await sessions.read(tenant, ctx.token)
          const who = enrolling(current)
          if (!("subject" in who)) return who
          if (who.preAuth && !(await stillEnrolling(who.subject, ctx.token as string))) {
            return denied("unauthenticated")
          }
          // `who` holds a subject, so a session was read.
          if (!recentlyVerified(current as ReadSession)) return staleForChange()
          if (who.preAuth && (await passwordAuthenticator(who.subject)) === null) {
            return errorResponse(409, "password-first")
          }
          const begun = await startTotp(who.subject)
          if ("status" in begun) return begun
          return jsonResponse(200, { authenticatorId: begun.authenticatorId, secret: begun.secret })
        },
      },
    ],
    [
      "totp/confirm",
      {
        method: "POST",
        fields: { authenticatorId: true, code: true, returnTo: false },
        keys: { authenticatorId: AUTHENTICATOR_ID },
        refused: "enable-mfa-factors",
        async run(ctx) {
          const returnTo = returnToOf(ctx.fields)
          if (returnTo === null) return errorResponse(400, "invalid-return-to")
          const current = await sessions.read(tenant, ctx.token)
          const who = enrolling(current)
          if (!("subject" in who)) return who
          if (who.preAuth && !(await stillEnrolling(who.subject, ctx.token as string))) {
            return denied("unauthenticated")
          }
          // `who` holds a subject, so a session was read.
          if (!recentlyVerified(current as ReadSession)) return staleForChange()
          const passwordId = await passwordAuthenticator(who.subject)
          if (who.preAuth && passwordId === null) return errorResponse(409, "password-first")
          const result = await confirmTotpEnrolment(rt.totp, {
            tenant,
            accountId: who.subject,
            authenticatorId: ctx.fields["authenticatorId"] as string,
            code: ctx.fields["code"] as string,
          })
          if (!result.ok) {
            event("enable-mfa-factors", false, who.subject, {
              method: "totp",
              detail: result.reason,
            })
            return errorResponse(400, "invalid-code")
          }
          event("enable-mfa-factors", true, who.subject, { method: "totp" })
          const token = ctx.token as string
          // Choosing the password in this session proved it; the evidence is dated at the end of enrolment.
          const issued = who.preAuth
            ? await sessions.completeEnrolment(tenant, token, [
                {
                  method: "password",
                  authenticatorId: passwordId as string,
                  factors: ["knowledge"],
                  phishingResistant: false,
                  replayResistant: false,
                  keyProtection: "unknown",
                  userVerified: false,
                  attestationVerified: false,
                  at: result.evidence.at,
                },
                result.evidence,
              ])
            : await afterCredentialChange(token, who.subject)
          if (issued === null) return denied("unauthenticated")
          return issuedResponse(ctx, issued, returnTo)
        },
      },
    ],
    [
      "sign-in",
      {
        method: "POST",
        fields: { identifier: true, password: true, returnTo: false },
        refused: "logon",
        async run(ctx) {
          const returnTo = returnToOf(ctx.fields)
          if (returnTo === null) return errorResponse(400, "invalid-return-to")
          const typed = ctx.fields["identifier"] as string
          const identifier = normaliseEmail(typed)
          const client = clientOf(ctx.req)
          // A client the stuffing detector flagged answers the app's challenge first, before any password is checked.
          const flagged = await rt.stuffing.flagged(client)
          if (flagged !== null && rt.challengeHook !== undefined) {
            if (!(await rt.challengeHook({ request: ctx.req, client: flagged }))) {
              event("logon", false, null, { method: "password", detail: "challenge-required" })
              return errorResponse(403, "challenge-required")
            }
          }
          const accountId = await confirmedAccount(identifier)
          // The throttle keys on what was typed, so an address no account holds is throttled exactly like one that is.
          const account = identifier ?? typed
          const result = await throttled(
            { account, clientAddress: client, secret: "password" },
            () =>
              signInWithPassword(rt.password, {
                tenant,
                accountId,
                password: ctx.fields["password"] as string,
              }),
            flagged !== null && rt.challengeHook === undefined,
          )
          if (!result.ok) {
            if (result.reason === "rate-limited") {
              // A refused attempt still names an identifier this client tried. Counting it lets the detector see a
              // spray the client's own throttle slows first (ADR 0009 §4): about 15 checked failures fit in a window.
              await rt.stuffing.failed(account, client)
              return refuse(result.key, result.retryAfterMs, "logon", accountId, {
                method: "password",
              })
            }
            const stuffing = result.reason !== "busy" && (await rt.stuffing.failed(account, client))
            event("logon", false, accountId, {
              method: "password",
              detail: stuffing ? "credential-stuffing" : result.reason,
            })
            return result.reason === "busy"
              ? errorResponse(503, "busy")
              : errorResponse(401, "invalid-credentials")
          }
          throwIfAborted(ctx.req.signal)
          // A verified password exists only for a resolved account.
          const subject = accountId as string
          // An account that set its password but never confirmed a second factor goes back to enrolment, as after
          // sign-up, unless a deviation lets a password alone meet the default requirement. Signed in, it could
          // reach nothing and enrol nothing, since enrolling needs a recent multi-factor proof.
          const enrolled =
            passwordAlone || (await confirmedTotpCount(rt.totp, { tenant, accountId: subject })) > 0
          const issued = enrolled
            ? await sessions.signIn(tenant, ctx.token, { subject, evidence: [result.evidence] })
            : await sessions.begin(tenant, ctx.token, { subject, state: "pre-auth" })
          // A password change that finished while this password was checked revoked the account's sessions before
          // this one was written (ADR 0006 §7). Every change gives the password a new id, so a changed id, or no
          // password at all, revokes the session just written. Read after the write, it misses no change.
          const current = await store.get(tenant, PASSWORD_COLLECTION, subject)
          const currentId =
            current === null
              ? null
              : (current.data as { readonly authenticatorId?: unknown }).authenticatorId
          if (currentId !== result.evidence.authenticatorId) {
            await sessions.signOut(tenant, issued.token)
            event("logon", false, subject, { method: "password", detail: "invalid" })
            return errorResponse(401, "invalid-credentials")
          }
          if (enrolled) await loggedOn(subject, "password", issued)
          else event("logon", true, subject, { method: "password", detail: "enroll" })
          return issuedResponse(ctx, issued, returnTo)
        },
      },
    ],
    [
      "totp/verify",
      {
        method: "POST",
        fields: { code: true, returnTo: false },
        refused: "logon",
        async run(ctx) {
          const returnTo = returnToOf(ctx.fields)
          if (returnTo === null) return errorResponse(400, "invalid-return-to")
          const who = signedIn(await sessions.read(tenant, ctx.token))
          if (!("subject" in who)) return who
          const { result } = await ceremony(
            who.subject,
            { code: ctx.fields["code"] as string },
            ctx.req,
          )
          if (!result.ok) {
            if (result.reason === "rate-limited") {
              return refuse(result.key, result.retryAfterMs, "logon", who.subject, {
                method: "totp",
              })
            }
            event("logon", false, who.subject, { method: "totp", detail: result.reason })
            return errorResponse(401, "invalid-code")
          }
          throwIfAborted(ctx.req.signal)
          const issued = await addEvidence(ctx.token as string, result.evidence)
          if (issued === null) return denied("unauthenticated")
          await loggedOn(who.subject, "totp", issued)
          return issuedResponse(ctx, issued, returnTo)
        },
      },
    ],
    [
      "step-up/start",
      {
        method: "POST",
        fields: {},
        refused: "logon",
        async run(ctx) {
          const who = signedIn(await sessions.read(tenant, ctx.token))
          if (!("subject" in who)) return who
          return jsonResponse(200, {
            challenge: await sessions.beginStepUp(tenant, ctx.token as string),
          })
        },
      },
    ],
    [
      "step-up",
      {
        method: "POST",
        fields: { challenge: true, password: false, code: false, returnTo: false },
        refused: "logon",
        async run(ctx) {
          const returnTo = returnToOf(ctx.fields)
          if (returnTo === null) return errorResponse(400, "invalid-return-to")
          const password = ctx.fields["password"] as string | undefined
          const code = ctx.fields["code"] as string | undefined
          if ((password === undefined) === (code === undefined)) {
            return errorResponse(400, "one-secret")
          }
          const who = signedIn(await sessions.read(tenant, ctx.token))
          if (!("subject" in who)) return who
          const challenge = ctx.fields["challenge"] as string
          // The challenge is checked before the secret, so an expired or foreign one spends no TOTP time step and
          // touches no throttle key. `stepUp` still takes it atomically below.
          if (!(await sessions.challengeOpen(tenant, ctx.token as string, challenge))) {
            event("logon", false, who.subject, {
              method: password === undefined ? "totp" : "password",
              stepUp: true,
              detail: "invalid-challenge",
            })
            return errorResponse(403, "invalid-challenge")
          }
          const { method, result } = await ceremony(
            who.subject,
            password === undefined ? { code: code as string } : { password },
            ctx.req,
          )
          if (!result.ok) {
            if (result.reason === "rate-limited") {
              return refuse(result.key, result.retryAfterMs, "logon", who.subject, {
                method,
                stepUp: true,
              })
            }
            event("logon", false, who.subject, { method, stepUp: true, detail: result.reason })
            return result.reason === "busy"
              ? errorResponse(503, "busy")
              : errorResponse(401, "invalid-credentials")
          }
          throwIfAborted(ctx.req.signal)
          const token = ctx.token as string
          const issued = await sessions.stepUp(tenant, token, challenge, result.evidence)
          if (issued === null) {
            event("logon", false, who.subject, {
              method,
              stepUp: true,
              detail: "invalid-challenge",
            })
            return errorResponse(403, "invalid-challenge")
          }
          await loggedOn(who.subject, method, issued, true)
          return issuedResponse(ctx, issued, returnTo)
        },
      },
    ],
    [
      "recovery-codes",
      {
        method: "POST",
        fields: {},
        refused: "enable-mfa-factors",
        async run(ctx) {
          // A signed-in person at the default requirement makes a set; so does one recovering, to replace a lost set.
          const current = await sessions.read(tenant, ctx.token)
          const who =
            current?.state.state === "recovery-only"
              ? { subject: current.state.subject }
              : allowed(current)
          if (!("subject" in who)) return who
          // `who` holds a subject, so a session was read.
          if (!recentlyVerified(current as ReadSession)) return staleForChange()
          // A new set is a credential change: the switch, this session's rotation and the revocation of the account's
          // other sessions commit together (ADR 0006 §7).
          let issued: IssuedSession | null = null
          let codes: readonly string[] | null
          try {
            codes = await generateRecoveryCodes(
              recovery,
              { tenant, accountId: who.subject },
              async (apply) =>
                (issued = await afterCredentialChange(ctx.token as string, who.subject, apply)) !==
                null,
            )
          } catch (error) {
            if (!(error instanceof QueueFullError)) throw error
            // A full hashing queue stops the set before anything is written, so the old set still redeems and every
            // session stays as it was (ADR 0018 §2).
            event("enable-mfa-factors", false, who.subject, {
              method: "recovery-code",
              detail: "busy",
            })
            return errorResponse(503, "busy")
          }
          // A parallel request made its set current first, or the session went: this set never redeems, and every
          // session of the account was revoked (ADR 0007 §1).
          if (codes === null) {
            event("enable-mfa-factors", false, who.subject, {
              method: "recovery-code",
              detail: "conflict",
            })
            return denied("unauthenticated")
          }
          event("enable-mfa-factors", true, who.subject, { method: "recovery-code" })
          return jsonResponse(
            200,
            { codes },
            await issuedExtras(issued as unknown as IssuedSession, clock.now()),
          )
        },
      },
    ],
    [
      "recovery",
      {
        method: "POST",
        fields: { identifier: true, code: true },
        refused: "logon",
        async run(ctx) {
          const typed = ctx.fields["identifier"] as string
          const identifier = normaliseEmail(typed)
          const accountId = await confirmedAccount(identifier)
          const result = await throttled(
            {
              account: identifier ?? typed,
              clientAddress: clientOf(ctx.req),
              secret: "recovery-code",
            },
            () =>
              // The code is spent, and the session it starts written, in one transaction (ADR 0007 §4).
              redeemRecoveryCode(
                recovery,
                { tenant, accountId, code: ctx.fields["code"] as string },
                async (ops) => {
                  throwIfAborted(ctx.req.signal)
                  // Recovery is a credential change: every session of the account is revoked, and the new one is
                  // recovery-only, with no level. A redeemed code exists only for a resolved account.
                  await ops.revokeByOwner(
                    tenant,
                    SESSION_COLLECTION,
                    accountId as string,
                    clock.now(),
                  )
                  return sessions.begin(
                    tenant,
                    ctx.token,
                    { subject: accountId as string, state: "recovery-only" },
                    ops,
                  )
                },
              ),
          )
          if (!result.ok) {
            if (result.reason === "rate-limited") {
              return refuse(result.key, result.retryAfterMs, "logon", accountId, {
                method: "recovery-code",
              })
            }
            event("logon", false, accountId, { method: "recovery-code", detail: result.reason })
            return result.reason === "busy"
              ? errorResponse(503, "busy")
              : errorResponse(401, "invalid-credentials")
          }
          event("logon", true, accountId, { method: "recovery-code", detail: "recovery" })
          // ADR 0007 Open 6: the account hears of a recovery as it starts, before anything is replaced, so one the
          // owner did not start is visible even if that session never finishes. A redeemed code means the identifier
          // resolved, so it is the account's confirmed address.
          notifyRecovered(identifier as string)
          return issuedResponse(ctx, result.value as IssuedSession, returnToOf({}) as string)
        },
      },
    ],
    [
      "recovery/finish",
      {
        method: "POST",
        fields: {},
        refused: "update",
        async run(ctx) {
          const current = await sessions.read(tenant, ctx.token)
          if (current?.state.state !== "recovery-only") {
            return current === null
              ? denied("unauthenticated")
              : errorResponse(403, "not-recovering")
          }
          const subject = current.state.subject
          const cleared = await sessions.endRecovery(tenant, ctx.token as string)
          event("update", true, subject, { detail: "recovery-complete" })
          return jsonResponse(200, { outcome: "unauthenticated" }, { cookies: [cleared] })
        },
      },
    ],
    [
      "sign-out",
      {
        method: "POST",
        fields: {},
        refused: "logoff",
        async run(ctx) {
          const current = await sessions.read(tenant, ctx.token)
          const cleared = await sessions.signOut(tenant, ctx.token)
          if (current !== null) {
            event("logoff", true, current.state.subject, {
              session: await sessionRef(ctx.token as string, current.state, current.assurance),
              assurance: current.assurance.level,
              detail: "sign-out",
            })
          }
          return jsonResponse(200, { outcome: "unauthenticated" }, { cookies: [cleared] })
        },
      },
    ],
    [
      "sessions",
      {
        method: "GET",
        async run(ctx) {
          const who = allowed(await sessions.read(tenant, ctx.token))
          if (!("subject" in who)) return who
          return jsonResponse(200, { sessions: await sessions.list(tenant, ctx.token) })
        },
      },
    ],
    [
      "sessions/revoke",
      {
        method: "POST",
        fields: { sessionId: true },
        refused: "logoff",
        async run(ctx) {
          const current = await sessions.read(tenant, ctx.token)
          const who = allowed(current)
          if (!("subject" in who)) return who
          const sessionId = ctx.fields["sessionId"] as string
          if (!(await sessions.revoke(tenant, ctx.token, sessionId))) {
            return errorResponse(404, "not-found")
          }
          event("logoff", true, who.subject, { detail: "remote-revoke" })
          // `allowed` passed, so the session was read.
          const cookies = sessionId === (current as ReadSession).id ? [clearSessionCookie()] : []
          return jsonResponse(200, { revoked: true }, { cookies })
        },
      },
    ],
  ])

  const page = (
    form: FormId | null,
    open: (token: string | null) => Promise<PagePart | PlainResponse>,
  ): Page => ({ form, open, still: false })
  /** A page whose context is the same for every request, so opening it touches no store. */
  const fixed = (form: FormId | null, part: PagePart): Page => ({
    form,
    open: () => Promise.resolve(part),
    still: true,
  })
  const signInPage = (): PlainResponse => redirect(`${AUTH}/sign-in`)

  const pages = new Map<string, Page>([
    [
      "sign-up",
      fixed("sign-up", {
        action: `${AUTH}/sign-up`,
        links: [{ href: `${AUTH}/sign-in`, text: DEFAULT_MESSAGES.signInLink }],
      }),
    ],
    [
      "email/confirm",
      fixed("email-confirm", { action: `${AUTH}/email/confirm`, resend: `${AUTH}/email/resend` }),
    ],
    ["password", fixed("password", { action: `${AUTH}/password` })],
    [
      "totp/enrol",
      page("totp-enrol", async (token) => {
        const current = await sessions.read(tenant, token)
        const who = enrolling(current)
        if (!("subject" in who)) return signInPage()
        // As the POST does: without fresh proof of both factors the confirmation would be refused, so the page starts no
        // enrolment and sends the person to sign in again, which proves both (ADR 0005).
        if (!recentlyVerified(current as ReadSession)) return signInPage()
        if (who.preAuth && (await passwordAuthenticator(who.subject)) === null) {
          return redirect(`${AUTH}/password`)
        }
        // A setup key is shown once (ADR 0027): after a wrong code the page begins a new enrolment.
        const begun = await startTotp(who.subject)
        if ("status" in begun) return begun
        return {
          action: `${AUTH}/totp/confirm`,
          totpSecret: begun.secret,
          hidden: { authenticatorId: begun.authenticatorId },
        }
      }),
    ],
    [
      "sign-in",
      fixed("sign-in", {
        action: `${AUTH}/sign-in`,
        links: [{ href: `${AUTH}/sign-up`, text: DEFAULT_MESSAGES.signUpLink }],
      }),
    ],
    [
      "step-up",
      page("step-up", async (token) => {
        const who = signedIn(await sessions.read(tenant, token))
        if (!("subject" in who)) return signInPage()
        // The session was just read; one revoked since then gets a challenge no step-up accepts.
        const challenge = String(await sessions.beginStepUp(tenant, token as string))
        return { action: `${AUTH}/step-up`, hidden: { challenge } }
      }),
    ],
    ["sign-out", fixed(null, { action: `${AUTH}/sign-out` })],
  ])

  /** The empty form of a page. */
  const formOf = (form: FormId): FormModel => createForm(form, { passwordAlone })

  /** Renders the page under `key` with `model` (its empty form by default), or the redirect its `open` gives. */
  const servePage = async (
    req: PlainRequest,
    token: string | null,
    key: string,
    status = 200,
    model?: FormModel,
  ): Promise<PlainResponse> => {
    const { form, open } = pages.get(key) as Page
    const part = await open(token)
    if ("status" in part) return part
    const { csrfToken, cookies } = await tokenFor(req.headers)
    const { script, style } = await assets
    const context: PageContext = {
      ...part,
      csrfToken,
      assets: {
        script: `${rt.publicBasePath}${script.path}`,
        style: `${rt.publicBasePath}${style.path}`,
      },
    }
    const html =
      form === null
        ? renderSignOutPage(DEFAULT_MESSAGES, context)
        : renderPage(model ?? formOf(form), context)
    return htmlResponse(status, html, { cookies })
  }

  /**
   * A route's reply as a browser on a default page needs it: the next step, or the page again with the refusal.
   * `fields` is `null` when the body was refused before the route ran, so nothing typed is shown again.
   */
  const htmlAnswer = async (
    req: PlainRequest,
    token: string | null,
    post: FormPost,
    response: PlainResponse,
    fields: Fields | null,
  ): Promise<PlainResponse> => {
    if (response.status === 303) return response
    // Every success a route answers with JSON is a 200.
    if (response.status === 200) {
      const outcome = (JSON.parse(utf8Decode(response.body as Uint8Array)) as { outcome?: unknown })
        .outcome
      const next = outcome === "enroll" ? (post.enroll ?? post.next) : post.next
      return redirect(`${rt.publicBasePath}${next}`, response.headers.getSetCookie())
    }
    const code = refusalCode(response)
    if (code === "unauthenticated") return signInPage()
    const { form } = pages.get(post.page) as Page
    let model: FormModel | undefined
    if (form !== null) {
      const checked =
        fields === null || post.own === false ? formOf(form) : validateForm(formOf(form), fields)
      // On the step-up page the one secret is a code, so a refused secret is a wrong code.
      const error =
        code === "invalid-credentials" && form === "step-up"
          ? "invalid-code"
          : (OUTCOMES[code] ?? "unexpected")
      model =
        code === "invalid-identifier"
          ? withFieldError(checked, "identifier", checked.messages.badEmail)
          : isValid(checked)
            ? withOutcome(checked, {
                error,
                retryAfterMs: Number(response.headers.get("retry-after")) * 1000,
              })
            : checked
    }
    const page = await servePage(req, token, post.page, response.status, model)
    const wait = response.headers.get("retry-after")
    if (wait !== null) page.headers.set("Retry-After", wait)
    return page
  }

  /** Serves a hashed asset: immutable, with its content type, and a 404 for any other name. */
  const serveAsset = async (req: PlainRequest, path: string): Promise<PlainResponse> => {
    const { script, style } = await assets
    const asset = [script, style].find((each) => each.path === path)
    if (asset === undefined) return errorResponse(404, "not-found")
    if (req.method !== "GET") {
      return errorResponse(405, "method-not-allowed", { headers: { Allow: "GET" } })
    }
    const response = emptyResponse(200, {
      headers: { "Content-Type": asset.contentType, "Cache-Control": IMMUTABLE },
    })
    return { ...response, body: asset.body }
  }

  /** The fields of a state-changing request, or the refusal: CSRF, an undeclared or non-string field, a missing one. */
  const checkPost = async (
    req: PlainRequest,
    route: PostRoute,
  ): Promise<{ readonly fields: Fields; readonly form: boolean } | PlainResponse> => {
    const refuse = (): PlainResponse => {
      event(route.refused, false, null, { detail: "csrf" })
      return errorResponse(403, "csrf")
    }
    if (!sameOrigin(req.headers, rt.origin)) {
      const origin = req.headers.get("origin")
      if ((origin === null || origin === "null") && !req.headers.has("sec-fetch-site")) {
        rt.diagnose({
          code: "origin-unverifiable",
          message:
            "A state-changing request carried neither an Origin header naming a site nor Sec-Fetch-Site, so the CSRF check refused it. Browsers send both; a proxy or CDN in front of the app may be removing them. See specs/dependency-failures.md.",
        })
      }
      return refuse()
    }
    const parsed = await parseBody(req)
    for (const [name, value] of Object.entries(parsed.fields)) {
      if (name !== "csrfToken" && !Object.hasOwn(route.fields, name)) {
        return errorResponse(400, "undeclared-field")
      }
      if (typeof value !== "string") return errorResponse(400, "invalid-field")
    }
    const missing = Object.entries(route.fields).some(
      ([name, required]) => required && parsed.fields[name] === undefined,
    )
    if (missing) return errorResponse(400, "missing-field")
    for (const [name, format] of Object.entries(route.keys ?? {})) {
      if (!format.test(parsed.fields[name] as string)) return errorResponse(400, "malformed-body")
    }
    const header = singleHeader(req.headers, "x-csrf-token")
    const field = parsed.fields["csrfToken"] as string | undefined
    // Exactly one place carries the token, so no two readers can disagree on which one counts.
    if ((header === null) === (field === undefined)) return refuse()
    // A browser with neither cookie binds to "null", a binding no token is ever issued for.
    const bound = String(await binding(req.headers))
    if (!(await csrf.verify(String(header ?? field), bound, clock.now()))) return refuse()
    return { fields: parsed.fields, form: parsed.kind === "form" }
  }

  /**
   * The id a request is counted under (ADR 0009 §8): the route the steps below run for it, `pages` or `assets`, or
   * `unmatched` for every request they refuse with a 404 or 405, so no spelling of a path mints a counter of its own.
   */
  const limitIdOf = (req: PlainRequest, segments: readonly string[]): RateLimitRouteId => {
    const key = segments.join("/")
    if (segments[0] === "assets") return "assets"
    if (req.method === "GET" && pages.has(key)) return "pages"
    return routes.get(key)?.method === req.method ? (key as RateLimitRouteId) : "unmatched"
  }

  /**
   * Counts the request against its route's limit; the wait in milliseconds when it is over, else `null`. A request
   * with no client address is not counted, as the throttle keeps no client key for it, or where `requireClientAddress`
   * holds, fails closed with the fixed 500 (ADR 0009 §8).
   */
  const overLimit = async (
    req: PlainRequest,
    id: RateLimitRouteId,
  ): Promise<{ readonly client: string; readonly retryAfterMs: number } | null> => {
    const client = clientKey(clientOf(req))
    if (client === null) {
      const required = rt.requireClientAddress
      rt.diagnose({
        code: "client-address-missing",
        message: `A request reached test-cap with no client address, so ${required ? "it was refused with a 500: production and staging need one for the per-client limits" : "the per-client limits did not count it"}. Give the adapter the socket address (its clientAddress option), or ${required ? "set requireClientAddress: false and " : ""}limit requests at the gateway (ADR 0009 §8).`,
      })
      // Stryker disable next-line StringLiteral: equivalent -- the error becomes the fixed 500 body, which never carries its message
      if (required) throw new Error("No client address.")
      return null
    }
    if (rt.requestLimits === null) return null
    const decision = await rt.requestLimits.check(id, req, client)
    return decision.allowed ? null : { client, retryAfterMs: decision.retryAfterMs }
  }

  /**
   * The reply to a request over its limit: the 429 every rate-limited reply gives. A state-changing route also emits
   * its failure event, and a form post that wants a page gets the page with the wait, unless opening that page would
   * touch the store.
   */
  const limited = async (
    req: PlainRequest,
    id: RateLimitRouteId,
    over: { readonly client: string; readonly retryAfterMs: number },
  ): Promise<PlainResponse> => {
    const route = routes.get(id)
    if (route?.method !== "POST") return rateLimited(over.retryAfterMs)
    const response = await refuse(
      `request|${id}|${over.client}`,
      over.retryAfterMs,
      route.refused,
      null,
      {
        detail: "request-limit",
      },
    )
    const post = FORM_POSTS.get(id)
    if (post === undefined || !wantsHtml(req) || !(pages.get(post.page) as Page).still) {
      return response
    }
    return htmlAnswer(req, readSessionToken(req.headers), post, response, null)
  }

  const dispatch = async (req: PlainRequest): Promise<PlainResponse | null> => {
    const match = matchAuthPath(req.url, BASE_PATH)
    if (match.kind === "outside") return null
    const id = limitIdOf(req, match.segments)
    const over = await overLimit(req, id)
    if (over !== null) return limited(req, id, over)
    const key = match.segments.join("/")
    if (id === "assets") return serveAsset(req, `${BASE_PATH}/${key}`)
    const token = readSessionToken(req.headers)
    const hasPage = pages.has(key)
    if (id === "pages") return servePage(req, token, key)
    const route = routes.get(key)
    if (route === undefined) return errorResponse(404, "not-found")
    if (req.method !== route.method) {
      const allow = hasPage ? `GET, ${route.method}` : route.method
      return errorResponse(405, "method-not-allowed", { headers: { Allow: allow } })
    }
    if (route.method === "GET") return route.run({ req, token })
    const checked = await checkPost(req, route)
    const fields = "status" in checked ? null : checked.fields
    const response = "status" in checked ? checked : await route.run({ req, ...checked, token })
    const post = FORM_POSTS.get(key)
    if (post === undefined || !wantsHtml(req)) return response
    return htmlAnswer(req, token, post, response, fields)
  }

  return {
    sessionInfo,

    /** The route table as data, in the order the routes are declared. */
    routes(): readonly RouteSummary[] {
      return [...routes].map(([path, route]) => ({
        path: `${BASE_PATH}/${path}`,
        method: route.method,
        fields: route.method === "POST" ? route.fields : {},
      }))
    },

    /** Revokes every session of the account at once; a Logoff reports it when any was live (ADR 0015 §2, F14). */
    async revokeAll(subject: string): Promise<number> {
      const revoked = await store.revokeByOwner(tenant, SESSION_COLLECTION, subject, clock.now())
      if (revoked > 0) event("logoff", true, subject, { detail: "admin-revoke" })
      return revoked
    },

    /** Serves one request: `null` outside the base path, else a response, never a thrown error. */
    async handle(req: PlainRequest): Promise<PlainResponse | null> {
      const unread = unreadForwarding(req.clientAddress, req.headers, rt.proxyTrust)
      if (unread !== null) {
        rt.diagnose({
          code: "forwarded-header-ignored",
          message: `${req.clientAddress === undefined ? "A request with no socket address" : `A request from ${req.clientAddress}`} carried ${unread}, which test-cap did not read: it reads only the declared header, from a trusted proxy. Behind an undeclared proxy, every client shares its address in the throttle: declare it in trustedProxies, or use the platform preset (ADR 0009 §5).`,
        })
      }
      try {
        return await dispatch(req)
      } catch (error) {
        return failure(error)
      }
    },
  }
}

/** The fixed reply to a thrown error: its code for a transport refusal, a bare 500 for anything else. */
export function failure(error: unknown): PlainResponse {
  return error instanceof TransportError
    ? errorResponse(error.status, error.code)
    : errorResponse(500, "internal")
}
