/**
 * test-cap/next: the Next.js App Router adapter (Next.js 16), built on test-cap/fetch (ADR 0024 §4). It has three
 * surfaces, and only the second protects anything:
 *
 * - `nextAuthHandler(auth)` is the route handler for `app/auth/[...path]/route.ts`: it serves every `/auth/*` route.
 * - `nextServerAuth(auth, { headers })` is the authoritative check. Call it inside every route handler, server
 *   function and data-access function that needs a session, as close to the data as the app can.
 * - `nextProxy(auth, { public })` is an optional `proxy` that sends a visitor without a session cookie to the sign-in
 *   page early. It is not protection. Next.js's own guide says a proxy "should not be your only line of defense in
 *   protecting your data": it passes any request that carries a session cookie, forged or not, and a route the
 *   proxy's matcher misses never meets it.
 *
 * Next.js has no global check that covers every route, so a route handler or server function that never calls a
 * server helper is unprotected (ADR 0024, Limits). Next.js is typed structurally: this entry has no dependency on it.
 * Next.js gives a route handler no socket address, so the core sees none here; the address is never read from a
 * header (ADR 0009).
 * @packageDocumentation
 */

import { internalsOf, type Auth, type SessionInfo } from "../../core/auth.js"
import type { RequireResult } from "../../assurance/policy.js"
import { BASE_PATH } from "../../core/dispatcher.js"
import { ConfigError } from "../../core/errors.js"
import { errorResponse } from "../../security/headers.js"
import { readSessionToken } from "../../sessions/sessions.js"
import { matchAuthPath } from "../../transport/path.js"
import type { PlainRequest } from "../../transport/types.js"
import { toResponse } from "../fetch/convert.js"
import { fetchAuth } from "../fetch/index.js"

/** A route handler for one HTTP method, as a `route.ts` file exports it. */
export type NextRouteHandler = (req: Request) => Promise<Response>

/** What `nextAuthHandler` returns: `export const { GET, POST } = nextAuthHandler(auth)`. */
export interface NextAuthHandlers {
  /** Serves the reading routes, such as `/auth/session`. */
  readonly GET: NextRouteHandler
  /** Serves the state-changing routes, such as `/auth/sign-in`. */
  readonly POST: NextRouteHandler
}

/**
 * The route handler for `app/auth/[...path]/route.ts`. Mounted anywhere else, every request is a 404, because the
 * core serves only paths under `/auth/`.
 */
export function nextAuthHandler(auth: Auth<string>): NextAuthHandlers {
  const serve = fetchAuth(auth)
  const handler: NextRouteHandler = async (req) =>
    (await serve(req)) ?? toResponse(errorResponse(404, "not-found"))
  return { GET: handler, POST: handler }
}

/** The request headers Next.js's `headers()` from `next/headers` returns. */
export type NextHeaders = Iterable<readonly [string, string]>

/** What `nextServerAuth` takes. */
export interface NextServerAuthOptions {
  /** Next.js's `headers` function from `next/headers`, passed in so this entry needs no dependency on Next.js. */
  readonly headers: () => Promise<NextHeaders>
}

/** The server helpers. Each call reads the current request's headers and the session from the store. */
export interface NextServerAuth<Id extends string> {
  /** The current request's session; `null` when it has none, or it is revoked or expired. */
  session(): Promise<SessionInfo | null>
  /**
   * Whether the current request's session meets the requirement (the default requirement when none is named), as
   * one of the five outcomes. Act on anything but `allow` before touching the data. A store failure rejects; it is
   * never an `allow`.
   */
  require(requirementId?: Id | "default"): Promise<RequireResult>
}

/**
 * The authoritative check for route handlers, server functions and the app's data-access layer:
 *
 * ```ts
 * import { headers } from "next/headers"
 * export const serverAuth = nextServerAuth(auth, { headers })
 * ```
 */
export function nextServerAuth<Id extends string>(
  auth: Auth<Id>,
  options: NextServerAuthOptions,
): NextServerAuth<Id> {
  internalsOf(auth)
  /**
   * The current request as the core reads it. Server helpers see no URL, method or body, and the core reads only the
   * session cookie from these headers.
   */
  const current = async (): Promise<PlainRequest> => {
    const headers = new Headers()
    for (const [name, value] of await options.headers()) headers.append(name, value)
    return { method: "GET", url: "/", headers, body: null }
  }
  return {
    session: async () => auth.session(await current()),
    require: async (requirementId = "default") =>
      auth.require(await current(), requirementId as Id),
  }
}

/** What `nextProxy` takes. */
export interface NextProxyOptions {
  /** The paths a visitor without a session cookie may reach; the same form as `withAuth`'s `public` list. */
  readonly public?: readonly string[] | undefined
  /**
   * The path on `APP_ORIGIN` a visitor without a session cookie is sent to, with `returnTo`; `/auth/sign-in` when
   * absent.
   */
  readonly signIn?: string | undefined
}

/** A Next.js `proxy` function: a response ends the request, `undefined` lets it continue. */
export type NextProxy = (req: Request) => Response | undefined

const CLEAN_PATH = /^(?:\/|(?:\/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)+)$/

/** True for a clean path under `/auth/`, or an ambiguous one, which the route that serves it refuses. */
function servedElsewhere(url: string): boolean {
  try {
    return matchAuthPath(url, BASE_PATH).kind === "route"
  } catch {
    return true
  }
}

/**
 * An optional Next.js `proxy` for early redirects only. It is not protection: Next.js's guide says a proxy "should
 * not be your only line of defense in protecting your data". It never reads the store: a visitor whose request
 * carries no session cookie, on a path that is not public, is redirected to the sign-in path; every other request
 * continues, and the server helpers decide. A malformed public list or sign-in path throws a `ConfigError` here.
 *
 * ```ts
 * // proxy.ts
 * export const proxy = nextProxy(auth, { public: ["/"] })
 * ```
 */
export function nextProxy(auth: Auth<string>, options: NextProxyOptions = {}): NextProxy {
  const internals = internalsOf(auth)
  const isPublic = internals.publicPaths(options.public ?? [])
  const signIn = options.signIn ?? `${BASE_PATH}/sign-in`
  if (!CLEAN_PATH.test(signIn)) {
    throw new ConfigError([`The sign-in path "${signIn}" must be a clean path such as /sign-in.`])
  }
  return (req) => {
    if (servedElsewhere(req.url)) return undefined
    const url = new URL(req.url)
    if (isPublic(url.pathname) || url.pathname === signIn) return undefined
    if (readSessionToken(req.headers) !== null) return undefined
    // Next.js wants an absolute Location from a proxy; it is built on APP_ORIGIN, never on the request's Host.
    const location = `${internals.origin}${signIn}?returnTo=${encodeURIComponent(url.pathname + url.search)}`
    return new Response(null, {
      status: 307,
      headers: { Location: location, "Cache-Control": "no-store" },
    })
  }
}
