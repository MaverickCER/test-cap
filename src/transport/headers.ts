import { TransportError } from "../core/errors.js"

/**
 * Reads a header that must appear at most once (`Host`, `Origin`, `Content-Type`, `Content-Length`). `Headers` joins
 * repeated values with a comma, and none of these headers has a comma in a valid value, so a comma means the header
 * was sent twice: refused rather than guessed at (ADR 0003).
 */
export function singleHeader(headers: Headers, name: string): string | null {
  const value = headers.get(name)
  if (value === null) return null
  if (value.includes(",")) {
    throw new TransportError("ambiguous-header", `The ${name} header was sent more than once.`)
  }
  return value
}
