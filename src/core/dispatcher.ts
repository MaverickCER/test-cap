/**
 * The dispatcher (ADR 0003 §6): the one entry for every `/auth/*` route. Every request passes the same checks in the
 * same order, in one place:
 *
 * 1. the raw path, refused with a 400 when two parsers could read it differently (ADR 0003 §2);
 * 2. the route and its method;
 * 3. for a state-changing route, the origin check, the body parsed under its declared fields, and the synchronizer
 *    token (ADR 0011 §2);
 * 4. the route itself.
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
import { type EmailDeps, redeemConfirmation, type SendEmail, sendConfirmation } from "./email.js"
import { normaliseEmail } from "./identifier.js"
import {
  PASSWORD_COLLECTION,
  type PasswordDeps,
  setPassword,
  signInWithPassword,
} from "../methods/password/method.js"
import {
  beginTotpEnrolment,
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
import {
  clearSessionCookie,
  type createSessions,
  type IssuedSession,
  type ReadSession,
  readSessionToken,
  SESSION_COLLECTION,
} from "../sessions/sessions.js"
import type { AuthStore, JsonValue, TenantId } from "../store/port.js"
import { type Fields, parseBody, throwIfAborted } from "../transport/body.js"
import { singleHeader } from "../transport/headers.js"
import { matchAuthPath } from "../transport/path.js"
import type { PlainRequest, PlainResponse } from "../transport/types.js"

/** The path every test-cap route lives under. */
export const BASE_PATH = "/auth"

/** Everything the routes run on, built once by `createAuth`. */
export interface Runtime<Id extends string> {
  readonly store: AuthStore
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

/** A default page (ADR 0025 §4): the form it shows (`null` for sign-out), and its context or a redirect. */
interface Page {
  readonly form: FormId | null
  readonly open: (token: string | null) => Promise<PagePart | PlainResponse>
}

/**
 * Each route a default page posts to: the page it shows again on a refusal, and the next step after a success.
 * `own: false` marks a post from a second form, whose fields are not the page's, so the page shows again empty.
 */
interface FormPost {
  readonly page: string
  readonly next: string
  readonly own?: false
}

const FORM_POSTS: ReadonlyMap<string, FormPost> = new Map<string, FormPost>([
  ["sign-up", { page: "sign-up", next: "/auth/email/confirm" }],
  ["email/confirm", { page: "email/confirm", next: "/auth/password" }],
  ["email/resend", { page: "email/confirm", next: "/auth/email/confirm", own: false }],
  ["password", { page: "password", next: "/auth/totp/enrol" }],
  // A finished ceremony at `allow` is already a 303 to `returnTo`; any other success still needs a step-up.
  ["totp/confirm", { page: "totp/enrol", next: "/auth/step-up" }],
  ["sign-in", { page: "sign-in", next: "/auth/step-up" }],
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

/** True for a form post from a browser that wants a page back, not JSON. */
function wantsHtml(req: PlainRequest): boolean {
  return (
    // An absent header reads as the four letters "null", which matches neither.
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
  const assets = pageAssets(`${BASE_PATH}/assets/`)
  /** A deviation that lets a password alone pass the default requirement raises its minimum (ADR 0010). */
  const passwordAlone = policy.deviations.some((item) => item.kind === "default-below-aal2")
  const email: EmailDeps = {
    store,
    tenant,
    clock,
    random: rt.random,
    origin: rt.origin,
    sendEmail: rt.sendEmail,
    keyRing: rt.totp.keyRing,
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

  /** The validated `returnTo`, `/` when absent, or `null` when it is not a same-origin relative path. */
  const returnToOf = (fields: Fields): string | null =>
    fields["returnTo"] === undefined ? "/" : safeReturnTo(fields["returnTo"] as string, rt.origin)

  /** The reply to a ceremony that issued a session: its cookie, a token bound to it, and what to do next. */
  const issuedResponse = async (
    ctx: Context,
    issued: IssuedSession,
    returnTo: string,
  ): Promise<PlainResponse> => {
    const now = clock.now()
    const outcome = policy.require(issued.state, "default", now).outcome
    const extras: ResponseExtras = {
      cookies: [issued.cookie],
      headers: {
        "X-CSRF-Token": await csrf.issue(`session:${await tokenHash(issued.token)}`, now),
      },
    }
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

  /** A session that may add an authenticator: one still enrolling, or one meeting the default requirement. */
  const enrolling = (
    current: ReadSession | null,
  ): { readonly subject: string; readonly preAuth: boolean } | PlainResponse => {
    if (current?.state.state === "pre-auth")
      return { subject: current.state.subject, preAuth: true }
    const result = policy.require(current?.state ?? null, "default", clock.now())
    return result.outcome === "allow"
      ? { subject: result.subject, preAuth: false }
      : denied(result.outcome)
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

  /** Runs a password or TOTP ceremony for the account; a disabled account fails as a wrong secret does. */
  const ceremony = async (
    subject: string,
    secret: { readonly password: string } | { readonly code: string },
  ) => {
    const active = await accountActive(store, tenant, subject)
    if ("password" in secret) {
      const result = await signInWithPassword(rt.password, {
        tenant,
        accountId: active ? subject : null,
        password: secret.password,
      })
      return { method: "password" as const, result }
    }
    const result = active
      ? await verifyTotp(rt.totp, { tenant, accountId: subject, code: secret.code })
      : ({ ok: false, reason: "invalid" } as const)
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
   * Rotates the session after a credential change that is already stored, and revokes the account's other sessions
   * (ADR 0006 §7). When the rotation fails or finds the session gone, every session of the account is revoked
   * instead, so no session outlives the change (ADR 0029, finding F-1).
   */
  const afterCredentialChange = async (
    token: string,
    subject: string,
  ): Promise<IssuedSession | null> => {
    let issued: IssuedSession | null = null
    try {
      issued = await sessions.credentialChanged(tenant, token)
    } finally {
      if (issued === null)
        await store.revokeByOwner(tenant, SESSION_COLLECTION, subject, clock.now())
    }
    return issued
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
            clientAddress: ctx.req.clientAddress,
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
            event("update", false, who.subject, { detail: result.reason })
            return result.reason === "rate-limited"
              ? errorResponse(429, "rate-limited", {
                  headers: { "Retry-After": String(Math.ceil(result.retryAfterMs / 1000)) },
                })
              : errorResponse(400, "invalid-code")
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
            clientAddress: ctx.req.clientAddress,
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
          const who = enrollingOnly(await sessions.read(tenant, ctx.token))
          if (!("subject" in who)) return who
          const subject = who.subject
          if (!(await hasConfirmedIdentifier(store, tenant, subject))) {
            return errorResponse(409, "confirm-email-first")
          }
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
          const who = enrolling(await sessions.read(tenant, ctx.token))
          if (!("subject" in who)) return who
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
          const who = enrolling(await sessions.read(tenant, ctx.token))
          if (!("subject" in who)) return who
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
          const issued = who.preAuth
            ? await sessions.completeEnrolment(tenant, token, [
                // Choosing the password in this session proved it; the evidence is dated at the end of enrolment.
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
          const identifier = normaliseEmail(ctx.fields["identifier"] as string)
          const accountId =
            identifier === null ? null : await resolveConfirmed(store, tenant, identifier)
          const result = await signInWithPassword(rt.password, {
            tenant,
            accountId,
            password: ctx.fields["password"] as string,
          })
          if (!result.ok) {
            event("logon", false, accountId, {
              method: "password",
              detail: result.reason,
            })
            return result.reason === "busy"
              ? errorResponse(503, "busy")
              : errorResponse(401, "invalid-credentials")
          }
          throwIfAborted(ctx.req.signal)
          // A verified password exists only for a resolved account.
          const subject = accountId as string
          const issued = await sessions.signIn(tenant, ctx.token, {
            subject,
            evidence: [result.evidence],
          })
          await loggedOn(subject, "password", issued)
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
          const { result } = await ceremony(who.subject, { code: ctx.fields["code"] as string })
          if (!result.ok) {
            event("logon", false, who.subject, {
              method: "totp",
              detail: result.reason,
            })
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
          const { method, result } = await ceremony(
            who.subject,
            password === undefined ? { code: code as string } : { password },
          )
          if (!result.ok) {
            event("logon", false, who.subject, {
              method,
              stepUp: true,
              detail: result.reason,
            })
            return result.reason === "busy"
              ? errorResponse(503, "busy")
              : errorResponse(401, "invalid-credentials")
          }
          throwIfAborted(ctx.req.signal)
          const token = ctx.token as string
          const issued = await sessions.stepUp(
            tenant,
            token,
            ctx.fields["challenge"] as string,
            result.evidence,
          )
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
  ): Page => ({ form, open })
  const fixed = (part: PagePart) => () => Promise.resolve(part)
  const signInPage = (): PlainResponse => redirect(`${BASE_PATH}/sign-in`)

  const pages = new Map<string, Page>([
    [
      "sign-up",
      page(
        "sign-up",
        fixed({
          action: `${BASE_PATH}/sign-up`,
          links: [{ href: `${BASE_PATH}/sign-in`, text: DEFAULT_MESSAGES.signInLink }],
        }),
      ),
    ],
    [
      "email/confirm",
      page(
        "email-confirm",
        fixed({ action: `${BASE_PATH}/email/confirm`, resend: `${BASE_PATH}/email/resend` }),
      ),
    ],
    ["password", page("password", fixed({ action: `${BASE_PATH}/password` }))],
    [
      "totp/enrol",
      page("totp-enrol", async (token) => {
        const who = enrolling(await sessions.read(tenant, token))
        if (!("subject" in who)) return signInPage()
        if (who.preAuth && (await passwordAuthenticator(who.subject)) === null) {
          return redirect(`${BASE_PATH}/password`)
        }
        // A setup key is shown once (ADR 0027): after a wrong code the page begins a new enrolment.
        const begun = await startTotp(who.subject)
        if ("status" in begun) return begun
        return {
          action: `${BASE_PATH}/totp/confirm`,
          totpSecret: begun.secret,
          hidden: { authenticatorId: begun.authenticatorId },
        }
      }),
    ],
    [
      "sign-in",
      page(
        "sign-in",
        fixed({
          action: `${BASE_PATH}/sign-in`,
          links: [{ href: `${BASE_PATH}/sign-up`, text: DEFAULT_MESSAGES.signUpLink }],
        }),
      ),
    ],
    [
      "step-up",
      page("step-up", async (token) => {
        const who = signedIn(await sessions.read(tenant, token))
        if (!("subject" in who)) return signInPage()
        // The session was just read; one revoked since then gets a challenge no step-up accepts.
        const challenge = String(await sessions.beginStepUp(tenant, token as string))
        return { action: `${BASE_PATH}/step-up`, hidden: { challenge } }
      }),
    ],
    ["sign-out", page(null, fixed({ action: `${BASE_PATH}/sign-out` }))],
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
      assets: { script: script.path, style: style.path },
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
    if (response.status === 200) return redirect(post.next, response.headers.getSetCookie())
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
    return servePage(req, token, post.page, response.status, model)
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
    if (!sameOrigin(req.headers, rt.origin)) return refuse()
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

  const dispatch = async (req: PlainRequest): Promise<PlainResponse | null> => {
    const match = matchAuthPath(req.url, BASE_PATH)
    if (match.kind === "outside") return null
    const key = match.segments.join("/")
    if (match.segments[0] === "assets") return serveAsset(req, `${BASE_PATH}/${key}`)
    const token = readSessionToken(req.headers)
    const hasPage = pages.has(key)
    if (hasPage && req.method === "GET") return servePage(req, token, key)
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
