/**
 * test-cap/fetch: the adapter for any runtime whose server hands the app a Web `Request` and takes a `Response` back,
 * such as `Bun.serve` and `Deno.serve` (ADR 0024). It converts and decides nothing:
 *
 * - `withAuth(auth, handler, { public })` wraps the app's handler with deny by default: every request first goes to
 *   the core's gate, which refuses an ambiguous path with a 400; a path under `/auth/` is served by the core; a public
 *   path reaches the handler with a `null` subject; any other path reaches it only for a session meeting the default
 *   requirement, with that session's subject.
 * - `fetchAuth(auth)` serves the `/auth/` routes alone and answers `null` for every other path, for an app that
 *   routes by itself.
 *
 * The body of an `/auth/` request is read once, as bytes, and at most one chunk past the core's limit; the body of
 * every other request is left unread for the app. Every `Set-Cookie` value stays its own header line. The client's
 * address comes only from the `clientAddress` option, which reads what the runtime hands its handler, never from a
 * header (ADR 0009).
 *
 * The runtime has parsed the URL before the adapter sees it, and the app's router reads that same `req.url`, so the
 * two cannot disagree about the path; the core still refuses any ambiguous path the parsed URL keeps, such as `//`.
 * @packageDocumentation
 */

import { internalsOf, type Auth } from "../../core/auth.js"
import { errorResponse } from "../../security/headers.js"
import { type ClientAddress, gate, headOf, serveAuth, toResponse } from "./convert.js"

export type { ClientAddress } from "./convert.js"

/** What the handler receives with each request: the subject on a protected route, `null` on a public one. */
export type FetchAuthInfo = {
  /** The account the request's session belongs to. */
  readonly subject: string
} | null

/**
 * The app's handler. `Args` are the runtime's own arguments after the request (Deno's `info`, Bun's `server`), passed
 * on unchanged after the auth info.
 */
export type FetchHandler<Args extends unknown[]> = (
  req: Request,
  auth: FetchAuthInfo,
  ...args: Args
) => Response | Promise<Response>

/** What `fetchAuth` takes. */
export interface FetchAuthOptions<Args extends unknown[]> {
  /**
   * Reads the client's address from the runtime's arguments: `(req, info) => info.remoteAddr.hostname` on Deno,
   * `(req, server) => server.requestIP(req)?.address` on Bun. Without it the core sees no address.
   */
  readonly clientAddress?: ClientAddress<Args> | undefined
}

/** What `withAuth` takes. */
export interface WithAuthOptions<Args extends unknown[]> extends FetchAuthOptions<Args> {
  /**
   * The paths that need no session. An entry matches exactly (`"/"` is the root only), or ends in `/*` to match one or
   * more segments below it (`"/blog/*"`). Matching is case-sensitive. Everything else needs the default requirement.
   */
  readonly public?: readonly string[] | undefined
}

/**
 * Wraps the app's fetch handler with test-cap: serves `/auth/*` and protects every other route at the default
 * requirement unless `options.public` lists it. A malformed public list throws a `ConfigError` here. An error the
 * app's handler throws reaches the runtime untouched; any other failure is a fixed 500.
 *
 * ```ts
 * Deno.serve(withAuth(auth, handler, { public: ["/"], clientAddress: (req, info) => info.remoteAddr.hostname }))
 * ```
 */
export function withAuth<Args extends unknown[] = []>(
  auth: Auth<string>,
  // The runtime's arguments are inferred from `clientAddress`, which reads them; a handler that reads them without it
  // names them: `withAuth<[Server]>(...)`.
  handler: NoInfer<FetchHandler<Args>>,
  options: WithAuthOptions<Args> = {},
): (req: Request, ...args: Args) => Promise<Response> {
  const isPublic = internalsOf(auth).publicPaths(options.public ?? [])
  return async (req, ...args) => {
    const gated = await gate(auth, isPublic, req, options.clientAddress?.(req, ...args))
    if (gated.kind === "respond") return gated.response
    return handler(req, gated.subject === null ? null : { subject: gated.subject }, ...args)
  }
}

/**
 * Serves test-cap's `/auth/*` routes from a `Request`, and answers `null` for any other path, leaving its body unread,
 * so the app routes it itself. It protects nothing else: `withAuth` adds deny by default.
 */
export function fetchAuth<Args extends unknown[] = []>(
  auth: Auth<string>,
  options: FetchAuthOptions<Args> = {},
): (req: Request, ...args: Args) => Promise<Response | null> {
  internalsOf(auth)
  return async (req, ...args) => {
    try {
      return await serveAuth(auth, req, headOf(req, options.clientAddress?.(req, ...args)))
    } catch {
      return toResponse(errorResponse(500, "internal"))
    }
  }
}
