/**
 * `createAuth` (ADR 0003 §6, ADR 0026): checks that the deployment may start, then wires the store, policy, sessions,
 * methods, CSRF keys and event sink into one `Auth`. Its `handle` serves every `/auth/*` route; `session` and
 * `require` read the session from the store on every call; `admin` holds the server-side calls.
 */

import { defineAuthPolicy, type AuthPolicy, type RequireResult } from "../assurance/policy.js"
import { randomBytes, systemClock, systemRandom, type Clock, type RandomSource } from "./clock.js"
import {
  BASE_PATH,
  createDispatcher,
  failure,
  type RouteSummary,
  type SessionInfo,
} from "./dispatcher.js"
import { checkReadiness, parseKeyRing, resolveDeploymentMode, type RingKey } from "./mode.js"
import { ConfigError } from "./errors.js"
import { systemIdProblem } from "../env/validators.js"
import type { EventSink } from "../ocsf/events.js"
import { compilePublicPaths } from "./public-paths.js"
import { argon2CostProblem, createHasher, type Argon2Cost } from "../methods/password/argon2.js"
import type { HibpFetch } from "../methods/password/hibp.js"
import { createCsrfTokens } from "../security/csrf.js"
import { errorResponse } from "../security/headers.js"
import { createSessions, readSessionToken } from "../sessions/sessions.js"
import type { AuthStore, TenantId } from "../store/port.js"
import { matchAuthPath, rawPath } from "../transport/path.js"
import type { PlainRequest, PlainResponse } from "../transport/types.js"

import type { SendEmail } from "./email.js"

export type { SessionInfo } from "./dispatcher.js"
export type { EmailMessage, SendEmail } from "./email.js"

/** The addresses of the app's own proxies, whose `X-Forwarded-For` may be read (ADR 0009 §5). */
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
  /** The app's own proxies (ADR 0009 §5); read by the throttles, which arrive in phase 4. */
  readonly trustedProxies?: TrustedProxies | undefined
}

/** The server-side calls (ADR 0012, ADR 0014). Phase 3 has `revoke`. */
export interface AuthAdmin {
  /** Revokes every session of the account, with immediate visibility; resolves to how many it revoked. */
  revoke(subject: string): Promise<number>
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
  /** Compiles a public-path list; a malformed entry is a `ConfigError`. */
  publicPaths(entries: readonly string[]): (path: string) => boolean
  /**
   * Decides a request before its body is read: an ambiguous path is a 400, a path under `/auth/` goes to `handle`, a
   * public path passes, and any other path passes only for a session meeting the default requirement.
   */
  gate(head: PlainRequest, isPublic: (path: string) => boolean): Promise<GateDecision>
  /** The `/auth/*` route table, for the OpenAPI document (docs/api-reference/). */
  routes(): readonly RouteSummary[]
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

/** Checks the deployment, then builds the `Auth`. Throws one `ConfigError` naming every problem (ADR 0026 §4). */
export function createAuth<Id extends string = "default">(config: AuthConfig<Id>): Auth<Id> {
  const read = (name: string): string | undefined => config.env[name]
  const { mode } = resolveDeploymentMode(read("APP_ENV"))
  // A missing origin reads as "undefined", which the origin check refuses like any other non-origin.
  const origin = String(read("APP_ORIGIN"))
  const secrets = Object.fromEntries(SECRETS.map((name) => [name, read(name)]))
  const systemId = read("APP_SYSTEM_ID")
  const systemProblem =
    systemId === undefined ? "APP_SYSTEM_ID is missing." : systemIdProblem(systemId)
  const costProblem =
    config.argon2Cost === undefined ? undefined : argon2CostProblem(config.argon2Cost)
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
  const dispatcher = createDispatcher({
    store,
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
      hasher: createHasher(config.argon2Cost),
    },
    totp: { clock, random, store, keyRing: ring("AUTH_ENCRYPTION_KEY") },
    sendEmail: config.sendEmail,
  })

  const internals: AuthInternals = {
    origin,
    publicPaths: compilePublicPaths,
    routes: () => dispatcher.routes(),
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
    },
  }
  Object.defineProperty(auth, INTERNALS, { value: internals })
  return auth
}
