/**
 * CSRF on every state-changing route test-cap serves (ADR 0011 §2 and Open 1). Two independent checks:
 *
 * - **Origin.** `Origin` must equal `APP_ORIGIN`; without `Origin`, or with `Origin: null`, `Sec-Fetch-Site` must be
 *   `same-origin`; a request with neither is refused. A browser sends `null` for a form post from a page whose
 *   referrer policy is `no-referrer`, as the default pages' is; a sandboxed frame or a redirect from another origin
 *   also sends `null`, and says `cross-site`. The `Host` header is never read.
 * - **Synchronizer token.** HMAC-SHA-256 under `AUTH_CSRF_KEY` over a purpose label, the key id, an expiry and the
 *   browser state the token was issued to: the stored hash of the session token, or before sign-in a random value in
 *   the `__Host-test-cap-csrf` cookie. The token names its key id, so the key can rotate, and is compared in constant
 *   time.
 */

import { randomToken, type RandomSource } from "../core/clock.js"
import {
  base64UrlDecode,
  base64UrlEncode,
  constantTimeEqual,
  utf8Encode,
} from "../core/encoding.js"
import type { RingKey } from "../core/mode.js"
import { readCookie, serializeCookie } from "../transport/cookies.js"
import { singleHeader } from "../transport/headers.js"

/** The cookie holding the pre-session value a token binds to before any session exists. */
export const CSRF_COOKIE = "__Host-test-cap-csrf"
/** How long a token is accepted after it is issued. */
export const CSRF_TOKEN_LIFETIME_MS = 60 * 60_000

const PURPOSE = "test-cap csrf v1"
const PRE_SESSION_FORMAT = /^[A-Za-z0-9_-]{43}$/
const TOKEN_FORMAT = /^([A-Za-z0-9_-]{1,32})\.(\d{1,16})\.([A-Za-z0-9_-]{43})$/

/** True when the request comes from the app's own origin, by `Origin` or, without it or when it is `null`, by `Sec-Fetch-Site`. */
export function sameOrigin(headers: Headers, appOrigin: string): boolean {
  const origin = singleHeader(headers, "origin")
  if (origin !== null && origin !== "null") return origin === appOrigin
  return headers.get("sec-fetch-site") === "same-origin"
}

/** The pre-session value a request carries, or `null` when it carries none or an ambiguous or malformed one. */
export function readPreSession(headers: Headers): string | null {
  // An absent or ambiguous cookie carries no value, and "undefined" never matches the format.
  const { value } = readCookie(headers, CSRF_COOKIE) as { readonly value?: string }
  return PRE_SESSION_FORMAT.test(String(value)) ? (value as string) : null
}

/** A new pre-session value and the `Set-Cookie` value that carries it for the browser session. */
export function newPreSession(random: RandomSource): {
  readonly value: string
  readonly cookie: string
} {
  const value = randomToken(random)
  return { value, cookie: serializeCookie(CSRF_COOKIE, value, { httpOnly: true, sameSite: "Lax" }) }
}

async function mac(key: RingKey, expiresAt: string, binding: string): Promise<Uint8Array> {
  const hmac = await crypto.subtle.importKey(
    "raw",
    key.bytes,
    { name: "HMAC", hash: "SHA-256" },
    // Stryker disable next-line BooleanLiteral: equivalent, extractability only matters to exportKey, which nothing calls
    false,
    ["sign"],
  )
  const message = utf8Encode(`${PURPOSE}\n${key.id}\n${expiresAt}\n${binding}`)
  return new Uint8Array(await crypto.subtle.sign("HMAC", hmac, message))
}

/** Issues and checks synchronizer tokens under one key ring, current key first. */
export function createCsrfTokens(ring: readonly RingKey[]) {
  const [current] = ring
  if (current === undefined) throw new TypeError("The CSRF key ring needs at least one key.")
  return {
    /** A token for `binding`, valid until `now` plus the token lifetime. */
    async issue(binding: string, now: number): Promise<string> {
      const expiresAt = String(now + CSRF_TOKEN_LIFETIME_MS)
      return `${current.id}.${expiresAt}.${base64UrlEncode(await mac(current, expiresAt, binding))}`
    },

    /** True when `token` was issued for `binding` under a key still in the ring and has not expired at `now`. */
    async verify(token: string, binding: string, now: number): Promise<boolean> {
      const parts = TOKEN_FORMAT.exec(token)
      if (parts === null) return false
      // The pattern has exactly three groups and each must match, so all three are strings.
      const [, keyId, expiresAt, tag] = parts as unknown as readonly [
        string,
        string,
        string,
        string,
      ]
      const key = ring.find((candidate) => candidate.id === keyId)
      if (key === undefined || now >= Number(expiresAt)) return false
      return constantTimeEqual(base64UrlDecode(tag), await mac(key, expiresAt, binding))
    },
  }
}

/** The token functions `createCsrfTokens` returns. */
export type CsrfTokens = ReturnType<typeof createCsrfTokens>
