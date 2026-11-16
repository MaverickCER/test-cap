/**
 * The byte transport contract between adapters and the core (ADR 0003). Adapters convert their framework's request
 * into a `PlainRequest` and write the `PlainResponse` back; they parse nothing.
 */

/** A request as bytes. */
export interface PlainRequest {
  /** The HTTP method exactly as received, such as `POST`. */
  readonly method: string
  /** Absolute (scheme, host, path and query) or origin-form (`/path?query`), exactly as received. */
  readonly url: string
  /** Repeated headers keep every value. */
  readonly headers: Headers
  /** The raw body, or `null` when there is none. */
  readonly body: Uint8Array | null
  /** The socket's peer address. Never a forwarded header (ADR 0009). */
  readonly clientAddress?: string | undefined
  /** Aborts when the client goes away; the core stops before its next store write. */
  readonly signal?: AbortSignal | undefined
}

/** A response as bytes. Each `Set-Cookie` value stays separate (`headers.getSetCookie()`). */
export interface PlainResponse {
  /** The HTTP status code. */
  readonly status: number
  /** The response headers; the adapter writes each `Set-Cookie` value as its own header line. */
  readonly headers: Headers
  /** The raw body, or `null` when there is none. */
  readonly body: Uint8Array | null
}
