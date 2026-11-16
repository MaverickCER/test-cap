/**
 * Cookie parsing and serialising (RFC 6265). test-cap only ever sets `__Host-` cookies, so the browser refuses any
 * version set by a subdomain or for another path (ADR 0006). A cookie that arrives twice is ambiguous, which is how
 * cookie tossing shows itself, and is never resolved by picking one.
 */

/** What a request carries under one cookie name. */
export type CookieRead =
  | { readonly kind: "absent" }
  | { readonly kind: "value"; readonly value: string }
  | { readonly kind: "ambiguous" }

const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/
// cookie-octet: %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
const COOKIE_VALUE = /^[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]+$/

/** Reads one cookie by exact, case-sensitive name. */
export function readCookie(headers: Headers, name: string): CookieRead {
  const header = headers.get("cookie")
  if (header === null) return { kind: "absent" }
  const values: string[] = []
  for (const pair of header.split(/[;,]/)) {
    const trimmed = pair.trim()
    const equals = trimmed.indexOf("=")
    if (equals !== -1 && trimmed.slice(0, equals) === name) values.push(trimmed.slice(equals + 1))
  }
  if (values.length > 1) return { kind: "ambiguous" }
  const [value] = values
  return value !== undefined && COOKIE_VALUE.test(value)
    ? { kind: "value", value }
    : { kind: "absent" }
}

/** Attributes test-cap sets. `Secure`, `Path=/` and no `Domain` are fixed by the `__Host-` prefix. */
export interface CookieAttributes {
  readonly httpOnly: boolean
  readonly sameSite: "Strict" | "Lax" | "None"
  /** Seconds; omitted for a browser-session cookie. */
  readonly maxAge?: number | undefined
}

/** One `Set-Cookie` value for a `__Host-` cookie. */
export function serializeCookie(name: string, value: string, attributes: CookieAttributes): string {
  if (!name.startsWith("__Host-")) throw new TypeError("test-cap only sets __Host- cookies.")
  if (!TOKEN.test(name)) throw new TypeError("The cookie name is not an RFC 6265 token.")
  if (!COOKIE_VALUE.test(value))
    throw new TypeError("The cookie value has characters RFC 6265 does not allow.")
  const parts = [`${name}=${value}`, "Path=/"]
  if (attributes.maxAge !== undefined) {
    if (!Number.isInteger(attributes.maxAge) || attributes.maxAge < 0) {
      throw new RangeError("Max-Age must be a non-negative whole number of seconds.")
    }
    parts.push(`Max-Age=${attributes.maxAge}`)
  }
  parts.push("Secure")
  if (attributes.httpOnly) parts.push("HttpOnly")
  parts.push(`SameSite=${attributes.sameSite}`)
  return parts.join("; ")
}

/** A `Set-Cookie` value that removes the cookie: the same attributes and `Max-Age=0`. */
export function expireCookie(name: string, attributes: Omit<CookieAttributes, "maxAge">): string {
  return serializeCookie(name, "-", { ...attributes, maxAge: 0 })
}
