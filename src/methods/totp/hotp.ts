/**
 * HOTP (RFC 4226) on Web Crypto HMAC-SHA-1 (ADR 0027 §1). The HMAC is `crypto.subtle.sign`; this module only encodes
 * the counter and applies the dynamic truncation. HOTP is a building block: no counter-based authenticator is offered.
 */

const DIGIT_COUNTS: ReadonlySet<number> = new Set([6, 7, 8])

/** The `digits`-digit HOTP code of `key` at `counter`. */
export async function hotp(key: Uint8Array, counter: number, digits: number): Promise<string> {
  if (!Number.isSafeInteger(counter) || counter < 0) {
    throw new RangeError("The HOTP counter must be a whole number of at least 0.")
  }
  if (!DIGIT_COUNTS.has(digits)) throw new RangeError("An HOTP code has 6, 7 or 8 digits.")
  const message = new DataView(new ArrayBuffer(8))
  message.setUint32(0, Math.floor(counter / 2 ** 32))
  message.setUint32(4, counter % 2 ** 32)
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-1" },
    // Stryker disable next-line BooleanLiteral: equivalent, extractability only matters to exportKey, which nothing calls
    false,
    ["sign"],
  )
  const mac = new DataView(await crypto.subtle.sign("HMAC", hmacKey, message.buffer))
  const offset = mac.getUint8(19) & 0x0f
  const binary = mac.getUint32(offset) & 0x7fffffff
  return String(binary % 10 ** digits).padStart(digits, "0")
}
