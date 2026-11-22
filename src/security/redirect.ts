/**
 * `returnTo` (ADR 0026 §5): the only navigation target test-cap ever sends a browser to is a same-origin relative path.
 * The value is checked as text first, then parsed against `APP_ORIGIN`, and the parsed origin must be the app's own.
 * A protocol-relative target (`//host`, `/\host`), a scheme (`javascript:`, `data:`, `https:`) and an origin that only
 * starts with the app's are all refused, never repaired.
 */

/** The longest `returnTo` accepted, so a target cannot carry a body's worth of data through a redirect. */
export const RETURN_TO_MAX_LENGTH = 2_048

// eslint-disable-next-line no-control-regex -- control characters are exactly what this pattern looks for
const UNSAFE = /[\\\s\x00-\x1f\x7f]/

/** `value` when it is a same-origin relative path for `origin`; `null` otherwise. */
export function safeReturnTo(value: string, origin: string): string | null {
  if (value.length > RETURN_TO_MAX_LENGTH) return null
  if (!value.startsWith("/") || value.startsWith("//") || UNSAFE.test(value)) return null
  // Stryker disable next-line ConditionalExpression: equivalent -- the text checks above already refuse every value that resolves to another origin; the parse is the independent second check ADR 0026 asks for
  return new URL(value, origin).origin === origin ? value : null
}
