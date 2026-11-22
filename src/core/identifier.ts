/**
 * The one email identifier normalisation (ADR 0021 §6 and Open 3), applied wherever an identifier enters. A value with
 * surrounding whitespace, a control character or an invalid address form is refused, never trimmed or repaired. A
 * valid one becomes Unicode NFC, lower-cased whole, with its domain in IDNA A-label form, so two spellings of one
 * address are one value and stores can compare bytes.
 */

/** The longest address accepted (RFC 5321's path limit less the angle brackets). */
const MAX_LENGTH = 254
const MAX_LOCAL_LENGTH = 64

// eslint-disable-next-line no-control-regex -- control characters are exactly what this pattern looks for
const UNSAFE = /[\s\x00-\x1f\x7f-\x9f"(),:;<>[\\\]]/u
/** The characters a domain may have before IDNA conversion: no separator a URL parser would act on. */
const DOMAIN_INPUT = /^[^/?#@%:]+$/u
/**
 * An A-label domain of at least two labels, each 1 to 63 letters, digits or inner hyphens, ending in a label that
 * starts with a letter, so an IP address is not a domain.
 */
const DOMAIN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/

/** The normalised form of an email identifier, or `null` when `raw` is not one. */
export function normaliseEmail(raw: string): string | null {
  const value = raw.normalize("NFC").toLowerCase()
  if ([...value].length > MAX_LENGTH || UNSAFE.test(value)) return null
  const at = value.indexOf("@")
  // A second "@" lands in the domain, which the domain checks refuse.
  if (at === -1) return null
  const local = value.slice(0, at)
  const domain = value.slice(at + 1)
  if (local === "" || [...local].length > MAX_LOCAL_LENGTH) return null
  if (local.startsWith(".") || local.endsWith(".") || local.includes("..")) return null
  if (!DOMAIN_INPUT.test(domain)) return null
  const url = `http://${domain}`
  if (!URL.canParse(url)) return null
  const { hostname } = new URL(url)
  return DOMAIN.test(hostname) ? `${local}@${hostname}` : null
}
