/**
 * The headers every response test-cap produces carries (ADR 0011 §3, §4 and Open 2), and the one way the core builds
 * a JSON response. Auth responses are never cached, never framed, never sniffed and never leak a URL through
 * `Referer`. There is no list of exempt responses: an error carries them as a success does.
 */

import { utf8Encode } from "../core/encoding.js"
import type { PlainResponse } from "../transport/types.js"

/** The strict policy of ADR 0011 Open 2: nothing inline, nothing from another origin, never framed. */
export const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "connect-src 'self'",
  "form-action 'self'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
].join("; ")

/** The fixed security headers, as name and value pairs. */
const SECURITY_HEADERS: readonly (readonly [string, string])[] = [
  ["Cache-Control", "no-store"],
  ["Content-Security-Policy", CONTENT_SECURITY_POLICY],
  ["X-Content-Type-Options", "nosniff"],
  ["Referrer-Policy", "no-referrer"],
]

/** What a response adds to the fixed headers. */
export interface ResponseExtras {
  /** `Set-Cookie` values, each kept as its own header line. */
  readonly cookies?: readonly string[] | undefined
  /** Further headers, such as `Location` or `Allow`. */
  readonly headers?: Readonly<Record<string, string>> | undefined
}

/** A response with the security headers and the extras, and no body. */
export function emptyResponse(status: number, extras: ResponseExtras = {}): PlainResponse {
  const headers = new Headers(SECURITY_HEADERS.map(([name, value]) => [name, value]))
  for (const [name, value] of Object.entries(extras.headers ?? {})) headers.set(name, value)
  for (const cookie of extras.cookies ?? []) headers.append("Set-Cookie", cookie)
  return { status, headers, body: null }
}

/** A JSON response with the security headers. */
export function jsonResponse(
  status: number,
  body: unknown,
  extras: ResponseExtras = {},
): PlainResponse {
  const response = emptyResponse(status, extras)
  response.headers.set("Content-Type", "application/json; charset=utf-8")
  return { ...response, body: utf8Encode(JSON.stringify(body)) }
}

/** An HTML page with the security headers: the default pages (ADR 0025 §4), never cached like every auth response. */
export function htmlResponse(
  status: number,
  html: string,
  extras: ResponseExtras = {},
): PlainResponse {
  const response = emptyResponse(status, extras)
  response.headers.set("Content-Type", "text/html; charset=utf-8")
  return { ...response, body: utf8Encode(html) }
}

/** The fixed error body: a code and nothing else, so no message, stack or value reaches the client (ADR 0003 §8). */
export function errorResponse(
  status: number,
  code: string,
  extras: ResponseExtras = {},
): PlainResponse {
  return jsonResponse(status, { error: code }, extras)
}
