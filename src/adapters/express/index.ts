/**
 * test-cap/express: the Express adapter (ADR 0024). It converts and decides nothing:
 *
 * - every request first goes to the core's gate, which refuses an ambiguous path with a 400 and applies deny by
 *   default with the public list this adapter passes it;
 * - a request under `/auth/` has its body read here, from the raw stream, never from `req.body`, and goes to
 *   `auth.handle`; when a body parser already consumed the stream, the request fails closed with a 500;
 * - every other request continues to the app with `req.auth` set, and its stream untouched for the app's own parsers.
 *
 * Express is typed structurally, so this entry has no dependency on it.
 * @packageDocumentation
 */

import { internalsOf, type Auth } from "../../core/auth.js"
import { errorResponse } from "../../security/headers.js"
import type { PlainRequest, PlainResponse } from "../../transport/types.js"

/** What `req.auth` holds: the subject on a protected route, `null` on a public one. */
export type ExpressAuthInfo = {
  /** The account the request's session belongs to. */
  readonly subject: string
} | null

/** The parts of an Express (Node) request the adapter reads. */
export interface ExpressLikeRequest {
  /** The HTTP method as received. */
  readonly method?: string | undefined
  /** The request target; `originalUrl` wins when Express has rewritten it. */
  readonly url?: string | undefined
  /** Express's unrewritten URL; the adapter prefers it to `url`. */
  readonly originalUrl?: string | undefined
  /** Every header line as received, name and value alternating. */
  readonly rawHeaders: readonly string[]
  /** The socket the request came in on. */
  readonly socket: {
    /** The peer's address, never a forwarded header (ADR 0009). */
    readonly remoteAddress?: string | undefined
  }
  /** True once something has read the whole body stream. */
  readonly readableEnded: boolean
  /** Set by a body parser; its presence means the stream is no longer the core's to read. */
  readonly body?: unknown
  /** Set by the adapter. */
  auth?: ExpressAuthInfo | undefined
  /** Receives one chunk of the raw body. */
  on(event: "data", listener: (chunk: Uint8Array) => void): unknown
  /** The body has been read whole. */
  on(event: "end", listener: () => void): unknown
  /** The stream failed. */
  on(event: "error", listener: (error: Error) => void): unknown
  /** Stops reading the body. */
  pause(): unknown
}

/** The parts of an Express (Node) response the adapter writes. */
export interface ExpressLikeResponse {
  /** The status to send. */
  statusCode: number
  /** True once the whole response has been handed to the socket. */
  readonly writableFinished: boolean
  /** Sets one header; an array writes one line per value. */
  setHeader(name: string, value: string | readonly string[]): unknown
  /** Sends the body, if any, and ends the response. */
  end(body?: Uint8Array): unknown
  /** The connection closed, before or after the response finished. */
  once(event: "close", listener: () => void): unknown
}

/** What `expressAuth` takes. */
export interface ExpressAuthOptions {
  /**
   * The paths that need no session. An entry matches exactly (`"/"` is the root only), or ends in `/*` to match one or
   * more segments below it (`"/blog/*"`). Matching is case-sensitive. Everything else needs the default requirement.
   */
  readonly public?: readonly string[] | undefined
}

/** An Express middleware. */
export type ExpressAuthMiddleware = (
  req: ExpressLikeRequest,
  res: ExpressLikeResponse,
  next: (error?: unknown) => void,
) => void

function write(res: ExpressLikeResponse, response: PlainResponse): void {
  res.statusCode = response.status
  // `keys()` names set-cookie once per cookie; each name is written once.
  for (const name of new Set(response.headers.keys())) {
    // Each cookie stays its own header line: joining them would corrupt the commas inside cookie attributes.
    res.setHeader(
      name,
      name === "set-cookie" ? response.headers.getSetCookie() : String(response.headers.get(name)),
    )
  }
  res.end(response.body ?? undefined)
}

/** Every header line as received, repeated names included (ADR 0003 §3). */
function headersOf(raw: readonly string[]): Headers {
  const headers = new Headers()
  // `rawHeaders` alternates name and value, so every even index is a name followed by its value.
  for (const [index, name] of raw.entries()) {
    if (index % 2 === 0) headers.append(name, raw[index + 1] as string)
  }
  return headers
}

/**
 * Reads the raw body. Past `limit` it stops reading and hands over what it has, which is over the core's limit, so
 * the core refuses it (413) without the adapter keeping an unbounded body.
 */
function readStream(req: ExpressLikeRequest, limit: number): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const chunks: Uint8Array[] = []
    let size = 0
    const finish = (): void => {
      const body = new Uint8Array(size)
      let offset = 0
      for (const chunk of chunks) {
        body.set(chunk, offset)
        offset += chunk.length
      }
      resolve(body)
    }
    req.on("data", (chunk) => {
      chunks.push(chunk)
      size += chunk.length
      if (size > limit) {
        req.pause()
        finish()
      }
    })
    req.on("end", finish)
    req.on("error", reject)
  })
}

/** The core's body limit (ADR 0003 Open 1): the adapter reads at most one chunk past it. */
const READ_LIMIT = 65_536

/**
 * Mounts test-cap on an Express app: serves `/auth/*` and protects every other route at the default requirement
 * unless `options.public` lists it. Mount it before any body parser.
 */
export function expressAuth(
  auth: Auth<string>,
  options: ExpressAuthOptions = {},
): ExpressAuthMiddleware {
  const internals = internalsOf(auth)
  const isPublic = internals.publicPaths(options.public ?? [])

  const run = async (
    req: ExpressLikeRequest,
    res: ExpressLikeResponse,
    next: (error?: unknown) => void,
  ): Promise<void> => {
    const controller = new AbortController()
    res.once("close", () => {
      if (!res.writableFinished) controller.abort()
    })
    const head: PlainRequest = {
      method: String(req.method),
      url: req.originalUrl ?? String(req.url),
      headers: headersOf(req.rawHeaders),
      body: null,
      clientAddress: req.socket.remoteAddress,
      signal: controller.signal,
    }
    const decision = await internals.gate(head, isPublic)
    if (decision.kind === "next") {
      req.auth = decision.subject === null ? null : { subject: decision.subject }
      next()
      return
    }
    if (decision.kind === "respond") {
      write(res, decision.response)
      return
    }
    // A body parser mounted before the adapter has read the stream: the core cannot see the bytes, so it refuses
    // rather than trust a body another parser built (ADR 0024 Open 2).
    if (req.body !== undefined || req.readableEnded) {
      write(res, errorResponse(500, "body-already-read"))
      return
    }
    const response = await auth.handle({ ...head, body: await readStream(req, READ_LIMIT) })
    // The gate sent the request here because its path is under /auth/, where `handle` always answers.
    write(res, response as PlainResponse)
  }

  return (req, res, next) => {
    run(req, res, next).catch(() => {
      write(res, errorResponse(500, "internal"))
    })
  }
}
