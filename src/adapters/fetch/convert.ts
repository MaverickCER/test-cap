/**
 * The conversions every Web `Request` adapter shares (ADR 0024 §1): a `Request` into a `PlainRequest`, its body into
 * bytes, and a `PlainResponse` back into a `Response`. `test-cap/fetch`, `test-cap/next` and `test-cap/tanstack-start`
 * use them, so the three cannot convert differently. Nothing here parses a body, reads a cookie or decides anything.
 */

import { internalsOf, type Auth } from "../../core/auth.js"
import { BASE_PATH } from "../../core/dispatcher.js"
import { errorResponse } from "../../security/headers.js"
import { DEFAULT_BODY_LIMIT } from "../../transport/body.js"
import { matchAuthPath } from "../../transport/path.js"
import type { PlainRequest, PlainResponse } from "../../transport/types.js"

/**
 * Reads the client's address from what the runtime hands its fetch handler, never from a header (ADR 0009): Deno's
 * `info.remoteAddr.hostname`, Bun's `server.requestIP(req)?.address`. `Args` are the arguments after the request.
 */
export type ClientAddress<Args extends unknown[]> = (
  req: Request,
  ...args: Args
) => string | undefined

/** The request's head as the core reads it: no body yet, so deny by default decides before anything is read. */
export function headOf(req: Request, clientAddress: string | undefined): PlainRequest {
  return {
    method: req.method,
    url: req.url,
    headers: req.headers,
    body: null,
    clientAddress,
    signal: req.signal,
  }
}

/**
 * Reads the body once, as bytes. Past the core's body limit it stops reading and hands over what it has, which is over
 * that limit, so the core refuses it (413) without the adapter holding an unbounded body.
 */
async function bodyOf(req: Request): Promise<Uint8Array | null> {
  if (req.body === null) return null
  const reader = req.body.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  // The next read is in the loop's own update, so every pass makes progress towards the stream's end.
  for (let read = await reader.read(); !read.done; read = await reader.read()) {
    chunks.push(read.value)
    size += read.value.length
    if (size > DEFAULT_BODY_LIMIT) break
  }
  // Stops the stream past the limit; a stream read to its end has nothing left to cancel.
  await reader.cancel()
  const body = new Uint8Array(size)
  let offset = 0
  for (const chunk of chunks) {
    body.set(chunk, offset)
    offset += chunk.length
  }
  return body
}

/** The `PlainResponse` as a `Response`, each `Set-Cookie` value kept as its own header line (ADR 0003 §3). */
export function toResponse(plain: PlainResponse): Response {
  const headers = new Headers()
  for (const [name, value] of plain.headers) {
    // Iterating `Headers` lists each cookie on its own; they are copied below with `getSetCookie()` instead, the one
    // form every runtime keeps separate.
    if (name !== "set-cookie") headers.append(name, value)
  }
  for (const cookie of plain.headers.getSetCookie()) headers.append("set-cookie", cookie)
  return new Response(plain.body as Uint8Array<ArrayBuffer> | null, {
    status: plain.status,
    headers,
  })
}

/** True for a path under `/auth/`, and for an ambiguous one, which the core then refuses. */
function forTheCore(url: string): boolean {
  try {
    return matchAuthPath(url, BASE_PATH).kind === "route"
  } catch {
    return true
  }
}

/**
 * Serves one request under `/auth/` with its body: refuses a body something already read (the core cannot see those
 * bytes, ADR 0024 Open 2), else reads it once and calls `auth.handle`. `null`, with the body unread, when the path is
 * a clean one outside `/auth/`.
 */
export async function serveAuth(
  auth: Auth<string>,
  req: Request,
  head: PlainRequest,
): Promise<Response | null> {
  // Outside /auth/ the body stays unread, for the app.
  if (!forTheCore(req.url)) return null
  if (req.bodyUsed) return toResponse(errorResponse(500, "body-already-read"))
  // Under /auth/, or ambiguous, `handle` always answers.
  return toResponse((await auth.handle({ ...head, body: await bodyOf(req) })) as PlainResponse)
}

/** What deny by default decided: the response to send, or the subject (`null` on a public path) to hand the app. */
export type Gated =
  | { readonly kind: "respond"; readonly response: Response }
  | { readonly kind: "next"; readonly subject: string | null }

/**
 * Runs deny by default for one request (ADR 0024 §2): an ambiguous path is a 400, a path under `/auth/` is served
 * here, a public path passes, and any other path passes only for a session meeting the default requirement. Never
 * throws: a failure is a fixed 500.
 */
export async function gate(
  auth: Auth<string>,
  isPublic: (path: string) => boolean,
  req: Request,
  clientAddress: string | undefined,
): Promise<Gated> {
  try {
    const head = headOf(req, clientAddress)
    const decision = await internalsOf(auth).gate(head, isPublic)
    if (decision.kind === "next") return decision
    const response =
      decision.kind === "respond"
        ? toResponse(decision.response)
        : // The gate sends only a path under /auth/ here, where `handle` always answers.
          ((await serveAuth(auth, req, head)) as Response)
    return { kind: "respond", response }
  } catch {
    return { kind: "respond", response: toResponse(errorResponse(500, "internal")) }
  }
}
