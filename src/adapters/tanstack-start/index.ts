/**
 * test-cap/tanstack-start: the TanStack Start adapter (ADR 0024). It converts and decides nothing:
 *
 * - `tanstackStartMiddleware(auth, { public })` is the server function of a global request middleware. TanStack
 *   Start runs it for every request, pages, server routes and server function calls alike. It sends the request's
 *   head to the core's gate, which refuses an ambiguous path with a 400 and applies deny by default with the public
 *   list; a refusal is answered here, and every other request continues with `context.auth` set.
 * - `tanstackStartAuth(auth).handlers` serves the `/auth/$` server route: the body is read here, once, as bytes, and
 *   goes to `auth.handle`.
 * - `tanstackStartAuth(auth).require` and `.session` let a server function check a requirement itself, close to the
 *   data, and answer with the core's outcome.
 *
 * TanStack Start is typed structurally, so this entry has no dependency on it.
 * @packageDocumentation
 */

import type { RequireResult } from "../../assurance/policy.js"
import { internalsOf, type Auth, type SessionInfo } from "../../core/auth.js"
import { errorResponse } from "../../security/headers.js"
import { headOf, serveAuth, toResponse } from "../fetch/convert.js"

/** What `context.auth` holds: the subject on a protected route, `null` on a public one and under `/auth/`. */
export type TanstackStartAuthInfo = {
  /** The account the request's session belongs to. */
  readonly subject: string
} | null

/** The context the middleware adds for the routes and server functions after it. */
export interface TanstackStartContext {
  /** The subject deny by default let through, or `null`. */
  readonly auth: TanstackStartAuthInfo
}

/** The parts of TanStack Start's request middleware options the adapter reads. */
export interface TanstackStartMiddlewareInput<Next> {
  /** The request as TanStack Start received it. */
  readonly request: Request
  /** Continues to the next middleware, the route or the server function, with the adapter's context added. */
  readonly next: (options: { context: TanstackStartContext }) => Next
}

/** The server function of a request middleware: a refusal as a `Response`, or whatever `next` answered. */
export type TanstackStartMiddleware = <Next>(
  input: TanstackStartMiddlewareInput<Next>,
) => Promise<Awaited<Next> | Response>

/** What `tanstackStartMiddleware` takes. */
export interface TanstackStartMiddlewareOptions {
  /**
   * The paths that need no session. An entry matches exactly (`"/"` is the root only), or ends in `/*` to match one or
   * more segments below it (`"/blog/*"`). Matching is case-sensitive. Everything else needs the default requirement,
   * server function calls included.
   */
  readonly public?: readonly string[] | undefined
}

/** A server route handler: TanStack Start passes more than the request, and the adapter reads only the request. */
export type TanstackStartRouteHandler = (input: {
  /** The request as TanStack Start received it. */
  readonly request: Request
}) => Promise<Response>

/** The handlers for the `/auth/$` server route. */
export interface TanstackStartRouteHandlers {
  /** Every method: the core answers a method a route does not take with a 405. */
  readonly ANY: TanstackStartRouteHandler
}

/** What `tanstackStartAuth` returns. */
export interface TanstackStartAuth<Id extends string> {
  /** The `/auth/$` server route's handlers. */
  readonly handlers: TanstackStartRouteHandlers
  /** The request's session, read from the store; `null` when it has none, or it is revoked or expired. */
  session(request: Request): Promise<SessionInfo | null>
  /** Whether the request's session meets the requirement under `requirementId`, as one of five outcomes. */
  require(request: Request, requirementId: Id): Promise<RequireResult>
}

/** What `tanstackStartAuth` takes. */
export interface TanstackStartAuthOptions {
  /**
   * The client's address for the throttle, read from what the app's server knows, such as srvx's remote address.
   * A Web `Request` carries none. Behind a platform preset whose header every request carries, leave it out: the core
   * reads the preset's header (ADR 0009 §5). Otherwise production and staging refuse to start without it, unless the
   * app set `requireClientAddress: false` (ADR 0009 §8).
   */
  readonly clientAddress?: ((request: Request) => string | undefined) | undefined
}

/**
 * The `/auth/$` server route and the server helpers. Serve the route with
 * `server: { handlers: tanstackStartAuth(auth).handlers }`.
 */
export function tanstackStartAuth<Id extends string>(
  auth: Auth<Id>,
  options: TanstackStartAuthOptions = {},
): TanstackStartAuth<Id> {
  internalsOf(auth).requireAddressSource(options.clientAddress !== undefined)
  return {
    handlers: {
      async ANY({ request }) {
        try {
          // A Web `Request` carries no socket: the core sees the address only from `clientAddress`, or reads a
          // platform preset's header (ADR 0009 §5).
          const response = await serveAuth(
            auth,
            request,
            headOf(request, options.clientAddress?.(request)),
          )
          // The router decodes the path before matching `/auth/$`; the core reads it raw, so `/%61uth/session`
          // reaches this route but is outside `/auth/` for the core.
          return response ?? toResponse(errorResponse(404, "not-found"))
        } catch {
          return toResponse(errorResponse(500, "internal"))
        }
      },
    },
    session: (request) => auth.session(headOf(request, undefined)),
    require: (request, requirementId) => auth.require(headOf(request, undefined), requirementId),
  }
}

/**
 * The global request middleware's server function: protects every route and server function at the default
 * requirement unless `options.public` lists its path. Register it with
 * `createStart(() => ({ requestMiddleware: [createMiddleware().server(tanstackStartMiddleware(auth, options))] }))`.
 */
export function tanstackStartMiddleware(
  auth: Auth<string>,
  options: TanstackStartMiddlewareOptions = {},
): TanstackStartMiddleware {
  const internals = internalsOf(auth)
  const isPublic = internals.publicPaths(options.public ?? [])
  return async function middleware<Next>({
    request,
    next,
  }: TanstackStartMiddlewareInput<Next>): Promise<Awaited<Next> | Response> {
    const decision = await internals.gate(headOf(request, undefined), isPublic)
    if (decision.kind === "respond") return toResponse(decision.response)
    // A path under /auth/ continues to the server route, which reads the body and calls the core.
    const subject = decision.kind === "next" ? decision.subject : null
    return await next({ context: { auth: subject === null ? null : { subject } } })
  }
}
