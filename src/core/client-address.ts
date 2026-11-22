/**
 * The key a client address counts under (ADR 0009 §2). An IPv4 address counts as itself, and so does its
 * IPv4-mapped IPv6 form; any other IPv6 address counts as its /64, because one host typically holds a whole /64 and
 * could otherwise rotate through it. The address is the socket's (`PlainRequest.clientAddress`), never a forwarded
 * header.
 */

const GROUP = /^[0-9a-f]{1,4}$/i
const DOTTED = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

/** The eight 16-bit groups of an IPv6 address in any RFC 4291 text form; `null` when it is not one, an IPv4 address included. */
function groups(address: string): readonly number[] | null {
  const halves = address.split("::").map((half) => (half === "" ? [] : half.split(":")))
  if (halves.length > 2) return null
  const compressed = halves.length === 2
  const left = halves[0] as string[]
  const right = halves[1] ?? []
  // A dotted IPv4 tail (`::ffff:192.0.2.10`) is the last two groups.
  const tail = compressed ? right : left
  const dotted = DOTTED.exec(String(tail.at(-1)))
  if (dotted !== null) {
    const bytes = dotted.slice(1).map(Number) as [number, number, number, number]
    if (bytes.some((byte) => byte > 255)) return null
    const high = (bytes[0] << 8) | bytes[1]
    const low = (bytes[2] << 8) | bytes[3]
    tail.splice(-1, 1, high.toString(16), low.toString(16))
  }
  if (![...left, ...right].every((part) => GROUP.test(part))) return null
  const missing = 8 - left.length - right.length
  if (compressed ? missing < 1 : missing !== 0) return null
  return [...left, ...Array<string>(missing).fill("0"), ...right].map((part) =>
    Number.parseInt(part, 16),
  )
}

/** The counter key of `address`; `null` when the adapter supplied none. A value that is no IP address keys as itself. */
export function clientKey(address: string | undefined): string | null {
  if (address === undefined) return null
  const parts = groups(address)
  if (parts === null) return address
  const [high = 0, low = 0] = parts.slice(6)
  if (parts.slice(0, 6).join(":") === "0:0:0:0:0:65535") {
    return [high >> 8, high & 255, low >> 8, low & 255].join(".")
  }
  return `${parts
    .slice(0, 4)
    .map((part) => part.toString(16))
    .join(":")}::/64`
}
