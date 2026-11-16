/**
 * Path matching for the dispatcher. The raw path is inspected as received, never normalised: `new URL()` would
 * resolve `/auth/../admin` to `/admin` before anything could see it. A path that two parsers could read differently
 * (an empty segment, a dot segment, an encoded slash, dot or backslash, a backslash, a control character) is refused
 * wherever it appears (ADR 0003; Better Auth's double-slash advisory, GHSA-x732-6j76-qmhm).
 */

import { TransportError } from "../core/errors.js"

const ABSOLUTE = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*/

/** The path of an absolute or origin-form URL, exactly as sent. */
export function rawPath(url: string): string {
  let rest: string
  if (url.startsWith("/") && !url.startsWith("//")) {
    rest = url
  } else {
    const authority = ABSOLUTE.exec(url)
    if (authority === null)
      throw new TransportError("invalid-path", "The request URL is not absolute or origin-form.")
    rest = url.slice(authority[0].length)
  }
  const end = rest.search(/[?#]/)
  const path = end === -1 ? rest : rest.slice(0, end)
  return path === "" ? "/" : path
}

/** Where a request falls relative to the auth base path. */
export type PathMatch =
  { readonly kind: "outside" } | { readonly kind: "route"; readonly segments: readonly string[] }

const CLEAN_BASE = /^(\/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)+$/
// eslint-disable-next-line no-control-regex -- control characters are exactly what this pattern looks for
const UNSAFE = /[\\\s\x00-\x1f\x7f]|%2f|%5c|%2e/i

function refuse(reason: string): never {
  throw new TransportError("invalid-path", reason)
}

/** Matches a request URL against the auth base path (default `/auth`), refusing any ambiguous path. */
export function matchAuthPath(url: string, basePath = "/auth"): PathMatch {
  if (!CLEAN_BASE.test(basePath))
    throw new TypeError("The base path must be a clean absolute path such as /auth.")
  const path = rawPath(url)
  if (path === "/") return { kind: "outside" }
  if (UNSAFE.test(path))
    refuse("The path has a backslash, whitespace, a control character or an encoded separator.")
  const segments = path.slice(1).split("/")
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
    refuse("The path has an empty or dot segment.")
  }
  if (path !== basePath && !path.startsWith(`${basePath}/`)) return { kind: "outside" }
  if (path.includes("%")) refuse("Paths under the auth base path are never percent-encoded.")
  return {
    kind: "route",
    segments: path === basePath ? [] : path.slice(basePath.length + 1).split("/"),
  }
}
