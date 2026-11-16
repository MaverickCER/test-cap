/**
 * Byte encodings and the two digest helpers the core uses. Hashing runs on Web Crypto; nothing here is a
 * cryptographic primitive of its own (ADR 0003).
 */

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
const DECODE = new Map<string, number>([...ALPHABET].map((char, index) => [char, index]))

/** Encodes bytes as base64url without padding (RFC 4648 §5). */
export function base64UrlEncode(bytes: Uint8Array): string {
  let out = ""
  const groups = Math.ceil(bytes.length / 3)
  for (const group of Array.from({ length: groups }).keys()) {
    const i = group * 3
    const a = bytes[i] ?? 0
    const b = bytes[i + 1] ?? 0
    const c = bytes[i + 2] ?? 0
    const chunk = (a << 16) | (b << 8) | c
    const remaining = bytes.length - i
    out += ALPHABET[(chunk >> 18) & 63]
    out += ALPHABET[(chunk >> 12) & 63]
    if (remaining > 1) out += ALPHABET[(chunk >> 6) & 63]
    if (remaining > 2) out += ALPHABET[chunk & 63]
  }
  return out
}

/** Decodes unpadded base64url; throws on any character outside the alphabet or an impossible length. */
export function base64UrlDecode(text: string): Uint8Array {
  if (text.length % 4 === 1) throw new TypeError("Invalid base64url: impossible length.")
  const values: number[] = []
  for (const char of text) {
    const value = DECODE.get(char)
    if (value === undefined)
      throw new TypeError("Invalid base64url: character outside the alphabet.")
    values.push(value)
  }
  const out = new Uint8Array(Math.floor((values.length * 6) / 8))
  let buffer = 0
  let bits = 0
  let index = 0
  for (const value of values) {
    buffer = (buffer << 6) | value
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out[index] = (buffer >> bits) & 0xff
      index += 1
    }
  }
  return out
}

const encoder = new TextEncoder()
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })

/** UTF-8 bytes of a string. */
export function utf8Encode(text: string): Uint8Array {
  return encoder.encode(text)
}

/** Decodes UTF-8, throwing on malformed input rather than substituting U+FFFD. */
export function utf8Decode(bytes: Uint8Array): string {
  return decoder.decode(bytes)
}

/** Lowercase hexadecimal, two digits per byte. */
export function hexEncode(bytes: Uint8Array): string {
  let out = ""
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0")
  return out
}

/** SHA-256 on Web Crypto. */
export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))
}

/**
 * Compares two byte strings in time that depends only on their lengths. Lengths are not secret here: every
 * caller compares fixed-length digests or MACs.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let difference = 0
  for (const [i, byte] of a.entries()) difference |= byte ^ (b[i] ?? 0)
  return difference === 0
}
