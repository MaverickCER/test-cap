/**
 * Which client a request comes from when proxies stand in front of the app (ADR 0009 §5). The socket's peer is the
 * client unless the app said otherwise. It can say so in two ways, never ad hoc:
 *
 * - **Its own proxies**, as `trustedProxies: ["10.0.0.5", "10.1.0.0/16"]`: addresses or CIDR ranges. From a peer in
 *   the list, the one forwarding header the app named (`X-Forwarded-For`, or `Forwarded` from RFC 7239) is read from
 *   the right, each listed proxy skipped, and the client is the right-most hop that is not one of them.
 * - **A platform preset**, `platform(name, options)`, which names the one header that platform sets, how to read it,
 *   and the peers it may come from. Vendor headers such as `CF-Connecting-IP` are read only through a preset.
 *
 * A header from an untrusted peer is never read, and no other header is read at all, so a client cannot choose its own
 * counter key: a proxy that sets one header passes a client's forged copy of any other through untouched.
 */

import parseForwarded from "forwarded-parse"
import type ipaddr from "ipaddr.js"
import { canonicalAddress, parseAddress } from "./client-address.js"

/** The forwarding header an app's own proxies set (ADR 0009 §5); test-cap reads that one and no other. */
export type ForwardedHeader = "x-forwarded-for" | "forwarded"

/** How a forwarding header carries the client. */
type ForwardedFormat =
  /** `X-Forwarded-For`: a comma-separated list, each proxy appending the address it received from. */
  | "list"
  /** `Forwarded` (RFC 7239): elements of `for=` nodes, each proxy appending one. */
  | "forwarded"
  /** One address the platform sets, overwriting anything the client sent. */
  | "single"
  /** One `address:port`, IPv6 addresses unbracketed, the platform overwriting anything the client sent. */
  | "address-port"

/** A set of addresses: single addresses and CIDR ranges, matched in any spelling. */
export interface AddressRanges {
  /** True when `address` is an IP address inside one of the ranges. */
  has(address: string): boolean
}

/** What the resolver needs: the header, its format, where it may come from, and which hops are proxies. */
export interface ProxyTrust {
  /** The header's name, lower-case. */
  readonly header: string
  readonly format: ForwardedFormat
  /** The peers the header is read from; `"platform"` when every request reaches the app through the platform. */
  readonly peers: AddressRanges | "platform"
  /** The proxies a list or `Forwarded` header names as hops, skipped from the right. */
  readonly hops: AddressRanges
}

/** A range: a base address and how many of its leading bits a member shares. */
type Range = readonly [ipaddr.IPv4 | ipaddr.IPv6, number]

/** A range from an address (`10.0.0.5`) or a CIDR (`10.0.0.0/8`, `2001:db8::/32`); `null` when it is neither. */
function parseRange(entry: string): Range | null {
  // `split` always yields at least one part.
  const [address, prefixText, extra] = entry.split("/") as [string, string?, string?]
  const base = parseAddress(address)
  if (base === null || extra !== undefined) return null
  const bits = base.kind() === "ipv4" ? 32 : 128
  if (prefixText === undefined) return [base, bits]
  const prefix = /^\d{1,3}$/.test(prefixText) ? Number(prefixText) : Number.NaN
  return prefix <= bits ? [base, prefix] : null
}

/** Each entry of an address list that is neither an IP address nor a CIDR range, named. */
export function rangeProblems(name: string, entries: readonly string[]): readonly string[] {
  return entries
    .filter((entry) => typeof entry !== "string" || parseRange(entry) === null)
    .map((entry) => `${name}: ${JSON.stringify(entry)} is not an IP address or CIDR range.`)
}

/**
 * The trust an app's own proxy list gives: the named header, read from a peer in the list, each listed proxy skipped
 * as a hop. `null` for an empty list: the socket is the client.
 */
export function ownProxies(entries: readonly string[], header: ForwardedHeader): ProxyTrust | null {
  if (entries.length === 0) return null
  const ranges = addressRanges(entries)
  return {
    header,
    format: header === "x-forwarded-for" ? "list" : "forwarded",
    peers: ranges,
    hops: ranges,
  }
}

/** The addresses and ranges in `entries`; an entry that is neither matches nothing (`rangeProblems` names it). */
export function addressRanges(entries: readonly string[]): AddressRanges {
  const ranges = entries.flatMap((entry) => {
    const range = parseRange(entry)
    return range === null ? [] : [range]
  })
  return {
    has(address) {
      const parsed = parseAddress(address)
      return (
        parsed !== null &&
        ranges.some(
          ([base, prefix]) =>
            base.kind() === parsed.kind() &&
            (parsed as ipaddr.IPv4).match(base as ipaddr.IPv4, prefix),
        )
      )
    },
  }
}

/**
 * The hops of an `X-Forwarded-For` value, left to right. A hop may carry a port (`192.0.2.1:443`, `[2001:db8::1]:443`),
 * as an AWS load balancer adds one when told to; an address without one is kept whole. A hop that is still no address
 * once its port is gone is `unknown`, as `Forwarded` spells a hidden node, so no junk text becomes a client key.
 */
function listHops(value: string): readonly string[] {
  return value
    .split(",")
    .map((hop) => hop.trim())
    .filter((hop) => hop !== "")
    .map((hop) => (canonicalAddress(hop) === null ? withoutPort(hop) : hop))
    .map((hop) => (canonicalAddress(hop) === null ? "unknown" : hop))
}

/**
 * The node of each element of a `Forwarded` value (RFC 7239 §4 and §6), left to right: the `for=` parameter with its
 * IPv6 brackets and port removed. The value is split at each comma outside a quoted string, counting quotes from the
 * right, so the elements the app's proxies appended are read whatever a client put before them, and each run is parsed
 * on its own by forwarded-parse (ADR 0030). An empty run names no hop. A run that is not RFC 7239, and an element
 * without `for=` or with an empty one, is `unknown`, as the RFC spells a hidden node.
 */
function forwardedHops(value: string): readonly string[] {
  const hops: string[] = []
  let quoted = false
  let end = value.length
  /** Takes the run after the separator at `at` (-1 for the start of the value) up to the last run taken. */
  const take = (at: number): void => {
    const run = value.slice(at + 1, end).trim()
    end = at
    if (run !== "") hops.unshift(...forwardedNodes(run))
  }
  // Right to left, one UTF-16 unit at a time, so each index is the one `slice` counts in.
  for (const [at, char] of [...value.split("").entries()].reverse()) {
    if (char === '"') quoted = !quoted
    else if (char === "," && !quoted) take(at)
  }
  take(-1)
  return hops
}

/** The node of each element of one run of a `Forwarded` value; `unknown` for a run that is not RFC 7239. */
function forwardedNodes(run: string): readonly string[] {
  try {
    return parseForwarded(run).map((element) => {
      const node = element["for"] || "unknown"
      if (node.startsWith("["))
        return node.slice(1, node.indexOf("]") === -1 ? undefined : node.indexOf("]"))
      // An IPv4 address or a name may carry a port after one colon.
      return node.split(":").length === 2 ? (node.split(":")[0] as string) : node
    })
  } catch {
    return ["unknown"]
  }
}

/**
 * The address of an `address:port` value. A bracketed IPv6 address is what the brackets hold, alone or followed by a
 * port; any other value is everything before its last colon.
 */
function withoutPort(value: string): string {
  // Callers pass trimmed values: list hops are trimmed, and `Headers.get` trims a header's value.
  const bracketed = /^\[([^\]]*)\](?::\d+)?$/.exec(value)
  if (bracketed !== null) return bracketed[1] as string
  const colon = value.lastIndexOf(":")
  return colon === -1 ? value : value.slice(0, colon)
}

/** How each multi-hop format splits into hops. */
const HOPS: Readonly<Record<"list" | "forwarded", (value: string) => readonly string[]>> = {
  list: listHops,
  forwarded: forwardedHops,
}

/** True when `trust` says the header may be read from this peer: a platform's, or a listed one. */
function readable(
  socketAddress: string | undefined,
  trust: ProxyTrust | null,
): trust is ProxyTrust {
  if (trust === null) return false
  return (
    trust.peers === "platform" || (socketAddress !== undefined && trust.peers.has(socketAddress))
  )
}

/**
 * The client a request comes from: the socket's peer, unless `trust` says the peer is a proxy whose header names the
 * client. `undefined` only when the adapter supplied no socket address and no platform header applies.
 */
export function resolveClient(
  socketAddress: string | undefined,
  headers: Headers,
  trust: ProxyTrust | null,
): string | undefined {
  if (!readable(socketAddress, trust)) return socketAddress
  const value = headers.get(trust.header)
  if (value === null || value === "") return socketAddress
  if (trust.format === "single") return value
  if (trust.format === "address-port") return withoutPort(value)
  const hops = HOPS[trust.format](value)
  // Every hop a trusted proxy: the left-most one is as close to the client as the header can say.
  return [...hops].reverse().find((hop) => !trust.hops.has(hop)) ?? hops[0] ?? socketAddress
}

/** The forwarding headers proxies and platforms set, the ones an operator would expect test-cap to read. */
const FORWARDING_HEADERS = [
  "x-forwarded-for",
  "forwarded",
  "x-real-ip",
  "cf-connecting-ip",
  "true-client-ip",
  "cloudfront-viewer-address",
  "fly-client-ip",
  "x-nf-client-connection-ip",
  "x-vercel-forwarded-for",
] as const

/**
 * The forwarding header a request carries when `resolveClient` read none, or `null`, naming the declared one first: a sign that a proxy the app
 * has not declared stands in front of it, and every client behind it shares the proxy's address. When the declared
 * header came from a trusted peer, the other forwarding headers came through the same proxies (a platform sets its own
 * header beside `X-Forwarded-For`), so none is reported.
 */
export function unreadForwarding(
  socketAddress: string | undefined,
  headers: Headers,
  trust: ProxyTrust | null,
): string | null {
  if (readable(socketAddress, trust) && headers.has(trust.header)) return null
  // A declared header from a peer that may not send it is the likeliest forgery, so it is the one named.
  if (trust !== null && headers.has(trust.header)) return trust.header
  return FORWARDING_HEADERS.find((name) => headers.has(name)) ?? null
}

/** The platforms test-cap has a preset for (ADR 0009 §5). */
export type PlatformName =
  "aws-alb" | "cloudfront" | "cloudflare" | "vercel" | "fly" | "netlify" | "nginx"

/**
 * A platform preset, from `platform`: which header that platform sets with the client's address, how to read it, and
 * the peers it may come from. Built from the vendor's documentation and tested in simulation only, never on the
 * platform itself (ADR 0009 §5).
 */
export interface PlatformTrust {
  /** Marks a preset, so `createAuth` tells it apart from a list of addresses. */
  readonly kind: "platform"
  /** The platform the preset is for. */
  readonly name: PlatformName
  /** The addresses and CIDR ranges the platform's requests arrive from; empty for a platform every request comes through. */
  readonly peers: readonly string[]
  /** For `nginx`: the header its configuration sets. */
  readonly header?: "x-real-ip" | "x-forwarded-for" | undefined
}

/**
 * What each preset reads: its header, the header's format, and whether the app must name the peers.
 *
 * - `aws-alb`: The load balancer appends the address it received from to X-Forwarded-For (the default `append` mode): the client is the right-most hop that is not one of its nodes, which live in the app's own subnets.
 * - `cloudfront`: CloudFront-Viewer-Address, `address:port`, once an origin request policy adds it; peers are CloudFront's origin-facing ranges (AWS ip-ranges.json, service CLOUDFRONT_ORIGIN_FACING).
 * - `cloudflare`: CF-Connecting-IP; peers are Cloudflare's published ranges (ips-v4, ips-v6).
 * - `vercel`: x-real-ip, which Vercel's own `ipAddress()` helper reads; every request reaches a Vercel function through Vercel.
 * - `fly`: Fly-Client-IP, set by the Fly proxy every public request passes through.
 * - `netlify`: x-nf-client-connection-ip; every request reaches a Netlify function through Netlify.
 * - `nginx`: The header the app's nginx sets (`proxy_set_header X-Real-IP $remote_addr` by default here), from its addresses.
 */
const PRESETS: Readonly<
  Record<
    PlatformName,
    {
      readonly header: string
      readonly format: ForwardedFormat
      readonly peers: "named" | "platform"
    }
  >
> = {
  "aws-alb": { header: "x-forwarded-for", format: "list", peers: "named" },
  cloudfront: { header: "cloudfront-viewer-address", format: "address-port", peers: "named" },
  cloudflare: { header: "cf-connecting-ip", format: "single", peers: "named" },
  vercel: { header: "x-real-ip", format: "single", peers: "platform" },
  fly: { header: "fly-client-ip", format: "single", peers: "platform" },
  netlify: { header: "x-nf-client-connection-ip", format: "single", peers: "platform" },
  nginx: { header: "x-real-ip", format: "single", peers: "named" },
}

/**
 * The preset for a platform test-cap knows, for `trustedProxies`. Vendor headers are read only through one of these,
 * never named ad hoc (ADR 0009 §5).
 *
 * - `vercel`, `fly`, `netlify`: every request reaches the app through the platform, so the header is read from any
 *   peer. Do not use one where the app can also be reached another way.
 * - `aws-alb`, `cloudfront`, `cloudflare`: pass `peers`, the addresses or CIDR ranges requests arrive from: the load
 *   balancer's subnets, or the vendor's current published ranges. test-cap ships no ranges, so none go stale in it.
 * - `nginx`: pass `peers`, the nginx addresses, and `header` if it sets `X-Forwarded-For` rather than `X-Real-IP`.
 *
 * Each is tested in simulation only: none has been verified on the real platform.
 */
export function platform(name: "vercel" | "fly" | "netlify"): PlatformTrust
export function platform(
  name: "aws-alb" | "cloudfront" | "cloudflare",
  options: { readonly peers: readonly string[] },
): PlatformTrust
export function platform(
  name: "nginx",
  options: {
    readonly peers: readonly string[]
    readonly header?: "x-real-ip" | "x-forwarded-for" | undefined
  },
): PlatformTrust
export function platform(
  name: PlatformName,
  options: {
    readonly peers?: readonly string[] | undefined
    readonly header?: "x-real-ip" | "x-forwarded-for" | undefined
  } = {},
): PlatformTrust {
  return { kind: "platform", name, peers: options.peers ?? [], header: options.header }
}

/** What is wrong with a preset as given, each problem named; empty when it can be used. */
export function platformProblems(preset: PlatformTrust): readonly string[] {
  const known = Object.hasOwn(PRESETS, preset.name) ? PRESETS[preset.name] : undefined
  if (known === undefined)
    return [`platform ${JSON.stringify(preset.name)} is not a preset test-cap has.`]
  const named = known.peers === "named"
  return [
    ...rangeProblems(`platform("${preset.name}") peers`, preset.peers),
    ...(named && preset.peers.length === 0
      ? [
          `platform("${preset.name}") needs peers: the addresses or CIDR ranges its requests arrive from.`,
        ]
      : []),
    ...(!named && preset.peers.length > 0
      ? [`platform("${preset.name}") takes no peers: every request comes through the platform.`]
      : []),
    ...(preset.header === undefined ||
    (preset.name === "nginx" &&
      (preset.header === "x-real-ip" || preset.header === "x-forwarded-for"))
      ? []
      : [
          `platform("${preset.name}") takes no header option${preset.name === "nginx" ? " but x-real-ip or x-forwarded-for" : ""}.`,
        ]),
  ]
}

/** The trust a valid preset gives. */
export function platformTrust(preset: PlatformTrust): ProxyTrust {
  const known = PRESETS[preset.name]
  const header = preset.header ?? known.header
  const ranges = addressRanges(preset.peers)
  return {
    header,
    format: header === "x-forwarded-for" ? "list" : known.format,
    peers: known.peers === "platform" ? "platform" : ranges,
    hops: ranges,
  }
}
