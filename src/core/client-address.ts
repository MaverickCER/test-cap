/**
 * The key a client address counts under (ADR 0009 §2). An IPv4 address counts as itself, and so does its
 * IPv4-mapped IPv6 form; any other IPv6 address counts as its /64, because one host typically holds a whole /64 and
 * could otherwise rotate through it. The address is the socket's (`PlainRequest.clientAddress`), never a forwarded
 * header. Parsing is ipaddr.js's (ADR 0030): IPv4 in four decimal parts only, IPv6 in any RFC 4291 text form without a
 * zone.
 */

import ipaddr from "ipaddr.js"

/** An IPv6 address whose last 32 bits are written as a dotted IPv4 address (`::ffff:192.0.2.10`). */
const DOTTED_TAIL = /^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/

/**
 * `address` with a dotted IPv4 tail written as two hexadecimal groups. ipaddr.js reads `::192.0.2.10` as the
 * IPv4-mapped `::ffff:192.0.2.10`; RFC 4291 makes it `::c000:20a`, a different client, so test-cap converts the tail
 * itself. A tail that is no IPv4 address is left for the parser to refuse.
 */
function hexTail(address: string): string {
  const match = DOTTED_TAIL.exec(address)
  if (match === null || !ipaddr.IPv4.isValidFourPartDecimal(String(match[2]))) return address
  const [a = 0, b = 0, c = 0, d = 0] = ipaddr.IPv4.parse(String(match[2])).octets
  return `${String(match[1])}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`
}

/** An address, its IPv4-mapped IPv6 form read as IPv4; `null` when `address` is not an IP address. */
export function parseAddress(address: string): ipaddr.IPv4 | ipaddr.IPv6 | null {
  if (ipaddr.IPv4.isValidFourPartDecimal(address)) return ipaddr.IPv4.parse(address)
  const hex = hexTail(address)
  if (hex.includes("%") || !ipaddr.IPv6.isValid(hex)) return null
  const parsed = ipaddr.IPv6.parse(hex)
  return parsed.isIPv4MappedAddress() ? parsed.toIPv4Address() : parsed
}

/** The counter key of `address`; `null` when the adapter supplied none. A value that is no IP address keys as itself. */
export function clientKey(address: string | undefined): string | null {
  if (address === undefined) return null
  const parsed = parseAddress(address)
  if (parsed === null) return address
  if (parsed.kind() === "ipv4") return parsed.toString()
  return `${(parsed as ipaddr.IPv6).parts
    .slice(0, 4)
    .map((part) => part.toString(16))
    .join(":")}::/64`
}

/**
 * The canonical text of an IP address, so two spellings of one address compare equal: IPv4 as itself, an
 * IPv4-mapped IPv6 address as its IPv4 form, any other IPv6 address as eight lower-case hexadecimal groups. `null`
 * when `address` is not an IP address.
 */
export function canonicalAddress(address: string): string | null {
  return parseAddress(address)?.toNormalizedString() ?? null
}
