// ADR 0009 §5: the client is the socket's peer; the named forwarding header is read only when that peer is a declared
// proxy, from the right, skipping every trusted proxy.
import { describe, expect, it } from "vitest"
import { canonicalAddress } from "../../src/core/client-address.js"
import {
  addressRanges,
  ownProxies,
  platform as presetPlatform,
  platformTrust,
  rangeProblems,
  resolveClient,
  type ForwardedHeader,
  type ProxyTrust,
} from "../../src/core/proxy-trust.js"
import { ConfigError } from "../../src/core/errors.js"
import { createAuth } from "../../src/core/auth.js"
import { memoryStore } from "../../src/store/memory.js"
import { ENV, hibpClear, outboxSender } from "../support/auth.js"

const trusted = ["10.0.0.1", "10.0.0.2", "2001:db8:0:0:0:0:0:1"]

/** The client of a request from `socket` carrying `value` in `header`, behind the app's own `proxies`. */
function resolveClientAddress(
  socket: string | undefined,
  value: string | null,
  proxies: readonly string[],
  header: ForwardedHeader = "x-forwarded-for",
): string | undefined {
  const headers = new Headers(value === null ? [] : [[header, value]])
  return resolveClient(socket, headers, ownProxies(proxies, header))
}

describe("canonicalAddress", () => {
  it("accepts every octet up to 255", () => {
    expect(canonicalAddress("255.255.255.255")).toBe("255.255.255.255")
    expect(canonicalAddress("192.0.2.256")).toBeNull()
  })

  it.each([
    ["192.0.2.7", "192.0.2.7"],
    ["::ffff:192.0.2.7", "192.0.2.7"],
    ["::FFFF:c000:0207", "192.0.2.7"],
    ["2001:DB8::1", "2001:db8:0:0:0:0:0:1"],
    ["2001:db8:0:0:0:0:0:1", "2001:db8:0:0:0:0:0:1"],
  ])("reads %s as %s", (address, canonical) => {
    expect(canonicalAddress(address)).toBe(canonical)
  })

  it.each(["unknown", "192.0.2.256", "1.2.3", "2001:db8::1::2", "", "example.com"])(
    "refuses %j",
    (address) => {
      expect(canonicalAddress(address)).toBeNull()
    },
  )
})

describe("address ranges", () => {
  const ranges = addressRanges([
    "10.0.0.0/8",
    "192.0.2.128/25",
    "2001:db8::/32",
    "198.51.100.7",
    "::/0x",
  ])

  it("matches every address inside a CIDR range, in any spelling, and nothing outside it", () => {
    for (const inside of [
      "10.0.0.1",
      "10.255.255.255",
      "::ffff:10.1.2.3",
      "192.0.2.128",
      "192.0.2.255",
    ]) {
      expect(ranges.has(inside), inside).toBe(true)
    }
    for (const outside of [
      "11.0.0.0",
      "9.255.255.255",
      "192.0.2.127",
      "198.51.100.8",
      "unknown",
      "",
    ]) {
      expect(ranges.has(outside), outside).toBe(false)
    }
  })

  it("matches IPv6 ranges by their prefix bits", () => {
    expect(ranges.has("2001:db8:ffff::1")).toBe(true)
    expect(ranges.has("2001:DB8::")).toBe(true)
    expect(ranges.has("2001:db9::1")).toBe(false)
    expect(ranges.has("10.0.0.1".replace("10", "::ffff:a00:1"))).toBe(false)
  })

  it("keeps IPv4 and IPv6 apart, and treats /0 as every address of its family", () => {
    const all = addressRanges(["0.0.0.0/0"])
    expect([all.has("203.0.113.1"), all.has("2001:db8::1")]).toEqual([true, false])
    const all6 = addressRanges(["::/0"])
    expect([all6.has("2001:db8::1"), all6.has("203.0.113.1")]).toEqual([true, false])
  })

  it("matches prefixes that end inside a byte", () => {
    const odd = addressRanges(["192.0.2.64/27", "2001:db8:8000::/33"])
    expect([odd.has("192.0.2.95"), odd.has("192.0.2.96"), odd.has("192.0.2.63")]).toEqual([
      true,
      false,
      false,
    ])
    expect([odd.has("2001:db8:ffff::1"), odd.has("2001:db8:7fff::1")]).toEqual([true, false])
  })
})

describe("CIDR prefixes", () => {
  it("accepts a whole-address prefix, /32 and /128", () => {
    expect(addressRanges(["10.0.0.1/32"]).has("10.0.0.1")).toBe(true)
    expect(addressRanges(["10.0.0.1/32"]).has("10.0.0.2")).toBe(false)
    expect(addressRanges(["2001:db8::1/128"]).has("2001:db8::1")).toBe(true)
    expect(rangeProblems("x", ["10.0.0.1/32", "2001:db8::1/128"])).toEqual([])
  })

  it.each([
    "10.0.0.0/1e1",
    "10.0.0.0/ 8",
    "10.0.0.0/+8",
    "10.0.0.0/08x",
    "10.0.0.0/",
    "2001:db8::/129",
  ])("refuses the prefix in %j", (entry) => {
    expect(rangeProblems("x", [entry])).toEqual([
      `x: ${JSON.stringify(entry)} is not an IP address or CIDR range.`,
    ])
    expect(addressRanges([entry]).has("10.0.0.1")).toBe(false)
  })
})

describe("X-Forwarded-For hops", () => {
  const read = (value: string) =>
    resolveClient(
      "10.0.0.1",
      new Headers([["X-Forwarded-For", value]]),
      ownProxies(["10.0.0.1"], "x-forwarded-for"),
    )

  it("keeps a bare IPv6 hop whole, with or without spaces around it", () => {
    expect(read("6.6.6.6, 2001:db8::5")).toBe("2001:db8::5")
    expect(read("6.6.6.6,2001:db8::5 ")).toBe("2001:db8::5")
  })

  it("removes a port a hop carries, from IPv4 and bracketed IPv6", () => {
    expect(read("6.6.6.6, 198.51.100.7:443")).toBe("198.51.100.7")
    expect(read("6.6.6.6, [2001:db8::5]:443")).toBe("2001:db8::5")
  })

  it("reads a bracketed IPv6 hop with no port as the address the brackets hold", () => {
    expect(read("6.6.6.6, [2001:db8:aaaa:1::7]")).toBe("2001:db8:aaaa:1::7")
    expect(read("6.6.6.6, [2001:db8:bbbb:2::9]")).toBe("2001:db8:bbbb:2::9")
    // Anything after the brackets but a port leaves no address, so the hop is unknown, never keyed by its text.
    for (const junk of [
      "[2001:db8::5]x",
      "[2001:db8::5]:4x",
      "[2001:db8::5]:",
      "[::1",
      "[ 2001:db8::1 ]",
    ]) {
      expect(read(`6.6.6.6, ${junk}`), junk).toBe("unknown")
    }
  })
})

describe("resolveClient with a platform header", () => {
  const platform = (format: ProxyTrust["format"], peers: ProxyTrust["peers"]): ProxyTrust => ({
    header: "x-client",
    format,
    peers,
    hops: addressRanges([]),
  })
  const headers = (value: string) => new Headers([["X-Client", value]])

  it("reads a single address the platform set, from a trusted peer only", () => {
    const trust = platform("single", addressRanges(["10.0.0.0/8"]))
    expect(resolveClient("10.0.0.9", headers(" 198.51.100.4 "), trust)).toBe("198.51.100.4")
    expect(resolveClient("192.0.2.1", headers("198.51.100.4"), trust)).toBe("192.0.2.1")
    expect(resolveClient("10.0.0.9", headers("  "), trust)).toBe("10.0.0.9")
    expect(resolveClient("10.0.0.9", new Headers(), trust)).toBe("10.0.0.9")
    expect(resolveClient(undefined, headers("198.51.100.4"), trust)).toBeUndefined()
  })

  it("reads the header from any peer on a platform every request comes through", () => {
    const trust = platform("single", "platform")
    expect(resolveClient(undefined, headers("198.51.100.4"), trust)).toBe("198.51.100.4")
    expect(resolveClient("192.0.2.1", headers("198.51.100.4"), trust)).toBe("198.51.100.4")
  })

  it("removes brackets only when they wrap the whole address", () => {
    const trust = platform("address-port", "platform")
    expect(resolveClient(undefined, headers("[::1]x:443"), trust)).toBe("[::1]x")
    expect(resolveClient(undefined, headers("x[::1]:443"), trust)).toBe("x[::1]")
  })

  it("removes the port from an address:port value, IPv6 unbracketed or bracketed", () => {
    const trust = platform("address-port", "platform")
    expect(resolveClient(undefined, headers("198.51.100.4:46532"), trust)).toBe("198.51.100.4")
    expect(resolveClient(undefined, headers("2001:db8::17:46532"), trust)).toBe("2001:db8::17")
    expect(resolveClient(undefined, headers("[2001:db8::17]:46532"), trust)).toBe("2001:db8::17")
    expect(resolveClient(undefined, headers("198.51.100.4"), trust)).toBe("198.51.100.4")
  })

  it("never splits a preset's single-address header into hops, even when it holds a list", () => {
    const vercel = platformTrust(presetPlatform("vercel"))
    const listed = new Headers([["x-real-ip", "6.6.6.6, 198.51.100.7"]])
    expect(resolveClient(undefined, listed, vercel)).toBe("6.6.6.6, 198.51.100.7")
  })

  it("leaves the socket as the client without any trust", () => {
    expect(resolveClient("192.0.2.1", headers("198.51.100.4"), null)).toBe("192.0.2.1")
  })

  it("trusts no one for an empty proxy list", () => {
    expect(ownProxies([], "x-forwarded-for")).toBeNull()
  })
})

describe("resolveClientAddress", () => {
  it("never reads the header the app did not name", () => {
    const both = new Headers([
      ["X-Forwarded-For", "203.0.113.9"],
      ["Forwarded", "for=198.51.100.1"],
    ])
    expect(resolveClient("10.0.0.1", both, ownProxies(trusted, "forwarded"))).toBe("198.51.100.1")
    expect(resolveClient("10.0.0.1", both, ownProxies(trusted, "x-forwarded-for"))).toBe(
      "203.0.113.9",
    )
  })

  it("skips every hop inside a trusted range, so a CDN in front of a load balancer resolves to the visitor", () => {
    const ranges = ["10.0.0.0/16", "203.0.113.0/24"]
    expect(resolveClientAddress("10.0.4.2", "198.51.100.77, 203.0.113.40", ranges)).toBe(
      "198.51.100.77",
    )
    expect(resolveClientAddress("10.0.4.2", "6.6.6.6, 198.51.100.77, 203.0.113.40", ranges)).toBe(
      "198.51.100.77",
    )
  })

  it("uses the socket and ignores the header when the peer is not a declared proxy", () => {
    expect(resolveClientAddress("192.0.2.7", "198.51.100.1", trusted)).toBe("192.0.2.7")
  })

  it("reads the right-most address that is not a trusted proxy", () => {
    expect(resolveClientAddress("10.0.0.1", "203.0.113.5, 198.51.100.1, 10.0.0.2", trusted)).toBe(
      "198.51.100.1",
    )
  })

  it("matches a trusted proxy in any spelling", () => {
    expect(resolveClientAddress("2001:DB8::1", "198.51.100.1", trusted)).toBe("198.51.100.1")
    expect(resolveClientAddress("::ffff:10.0.0.1", "198.51.100.1", trusted)).toBe("198.51.100.1")
  })

  it("falls back to the socket when a trusted proxy sent no header, and to the left-most hop when every hop is trusted", () => {
    expect(resolveClientAddress("10.0.0.1", null, trusted)).toBe("10.0.0.1")
    expect(resolveClientAddress("10.0.0.1", "10.0.0.2, 10.0.0.1", trusted)).toBe("10.0.0.2")
    expect(resolveClientAddress("10.0.0.1", " , ", trusted)).toBe("10.0.0.1")
  })

  it("reads X-Forwarded-For unless told the proxies set Forwarded", () => {
    const value = "198.51.100.1, for=198.51.100.2"
    // As X-Forwarded-For, "for=198.51.100.2" is no address: it is read as unknown, never keyed by its text.
    expect(resolveClientAddress("10.0.0.1", value, trusted)).toBe("unknown")
    expect(resolveClientAddress("10.0.0.1", value, trusted, "x-forwarded-for")).toBe("unknown")
    // As Forwarded, the first element is not RFC 7239, and the walk from the right stops before reaching it.
    expect(resolveClientAddress("10.0.0.1", value, trusted, "forwarded")).toBe("198.51.100.2")
  })

  it("keeps an adapter without a socket address as it is", () => {
    expect(resolveClientAddress(undefined, "198.51.100.1", trusted)).toBeUndefined()
  })
})

describe("resolveClientAddress with the Forwarded header (RFC 7239)", () => {
  const read = (value: string, socket = "10.0.0.1") =>
    resolveClientAddress(socket, value, trusted, "forwarded")

  it("reads the right-most for= node that is not a trusted proxy", () => {
    expect(read("for=198.51.100.7, for=10.0.0.2")).toBe("198.51.100.7")
    expect(read("for=192.0.2.60;proto=http;by=203.0.113.43")).toBe("192.0.2.60")
    expect(read("For=198.51.100.7;Proto=https")).toBe("198.51.100.7")
  })

  it("removes quotes, IPv6 brackets and ports", () => {
    expect(read('for="[2001:db8:cafe::17]:4711"')).toBe("2001:db8:cafe::17")
    expect(read('for="[2001:db8:cafe::17]"')).toBe("2001:db8:cafe::17")
    expect(read('for="198.51.100.7:8080"')).toBe("198.51.100.7")
    expect(read('for="[2001:db8::1]", for=198.51.100.9')).toBe("198.51.100.9")
    expect(read('for="[2001:db8::1]"')).toBe("2001:db8::1")
  })

  it("keeps a hidden or obfuscated node as the client, and names one without for= unknown", () => {
    expect(read("for=unknown")).toBe("unknown")
    expect(read("for=_hidden, for=10.0.0.2")).toBe("_hidden")
    expect(read("proto=https;by=10.0.0.2")).toBe("unknown")
    expect(read('for="[2001:db8::1"')).toBe("2001:db8::1")
  })

  it("keeps a comma inside a quoted value in its element", () => {
    expect(read('for=198.51.100.7;host="a,b", for=10.0.0.2')).toBe("198.51.100.7")
  })

  it("reads each element on its own from the right, so a malformed element left of the client changes nothing", () => {
    for (const value of [
      'for="6.6.6.6, for=198.51.100.7',
      "for=6.6.6.6;;, for=198.51.100.7",
      '"for=6.6.6.6", for=198.51.100.7',
      "garbage, for=198.51.100.7, for=10.0.0.2",
      'for=198.51.100.7;host="a,b", , for=10.0.0.2',
    ]) {
      expect(read(value), value).toBe("198.51.100.7")
    }
  })

  it("names a malformed element the walk reaches unknown, never the socket or a hop inside it", () => {
    for (const value of [
      'for=_x"y"',
      'for="_x"y',
      "for=2001:db8::5",
      'for="198.51.100.7, for=10.0.0.2',
      "for=198.51.100.7;;, for=10.0.0.2",
      'for="", for=10.0.0.2',
    ]) {
      expect(read(value), value).toBe("unknown")
    }
  })

  it("reads every element of a run its own scan could not split, as RFC 7239 reads them", () => {
    // The escaped quote in the right element hides the comma from the quote count; the parser still splits them.
    expect(read('for=198.51.100.7, for=10.0.0.2;x="\\""')).toBe("198.51.100.7")
    expect(read('for=10.0.0.2, for=10.0.0.1;x="\\""')).toBe("10.0.0.2")
  })

  it("reads an element whose quoted value holds an escaped quote beside a comma as unknown, a stated limit", () => {
    expect(read('for=198.51.100.7;a="\\"x,y\\"", for=10.0.0.2')).toBe("unknown")
  })

  it("finds the client behind a thousand elements the client prepended", () => {
    const prepended = Array.from(
      { length: 1000 },
      (_, n) => `for=6.6.${String(n >> 8)}.${String(n & 255)}`,
    )
    expect(read(`${prepended.join(", ")}, for=198.51.100.7, for=10.0.0.2`)).toBe("198.51.100.7")
    expect(read(`for="${prepended.join(", ")}, for=198.51.100.7`)).toBe("198.51.100.7")
  })

  it("falls back to the socket when every element is empty", () => {
    expect(read(" , ")).toBe("10.0.0.1")
    expect(read(",,")).toBe("10.0.0.1")
  })

  it("never reads the header from an untrusted peer", () => {
    expect(read("for=198.51.100.7", "192.0.2.1")).toBe("192.0.2.1")
  })

  it("finds for= after other parameters and the spaces around them", () => {
    expect(read("proto=https; for=198.51.100.7")).toBe("198.51.100.7")
    expect(read("by=10.0.0.2 ;  for=198.51.100.8 ; host=app.example")).toBe("198.51.100.8")
  })

  it("removes the quotes, the IPv6 brackets and the port of a quoted node", () => {
    expect(read('for="_hidden"')).toBe("_hidden")
    expect(read('for="[2001:db8::5]:4711"')).toBe("2001:db8::5")
    expect(read('for="198.51.100.9:443"')).toBe("198.51.100.9")
  })

  it("falls back to the socket when the value holds no element at all", () => {
    expect(read(",")).toBe("10.0.0.1")
    expect(read("")).toBe("10.0.0.1")
  })
})

describe("createAuth's trustedProxies and throttle settings", () => {
  const base = { store: memoryStore(), env: ENV, hibpFetch: hibpClear, sendEmail: outboxSender([]) }

  it("names every entry that is not an IP address and every throttle value out of range", () => {
    let error: unknown
    try {
      createAuth({
        ...base,
        trustedProxies: [
          "10.0.0.1",
          "proxy.internal",
          "10.0.0.300",
          "10.0.0.0/33",
          "10.0.0.0/8/8",
          "10.0.0.0/x",
          "2001:db8::/128",
        ],
        forwardedHeader: "x-real-ip" as never,
        throttle: { freeFailures: -1, windowMs: 0, firstDelayMs: 2_000, maxDelayMs: 1_000.5 },
      })
    } catch (caught) {
      error = caught
    }
    expect(error).toBeInstanceOf(ConfigError)
    expect((error as ConfigError).problems).toEqual(
      expect.arrayContaining([
        'trustedProxies: "proxy.internal" is not an IP address or CIDR range.',
        'trustedProxies: "10.0.0.300" is not an IP address or CIDR range.',
        'trustedProxies: "10.0.0.0/33" is not an IP address or CIDR range.',
        'trustedProxies: "10.0.0.0/8/8" is not an IP address or CIDR range.',
        'trustedProxies: "10.0.0.0/x" is not an IP address or CIDR range.',
        'forwardedHeader must be "x-forwarded-for" or "forwarded", not "x-real-ip".',
        "throttle.freeFailures must be a whole number, 0 or more.",
        "throttle.windowMs must be a whole number of milliseconds, from 1 to 31536000000 (a year).",
        "throttle.maxDelayMs must be a whole number of milliseconds, from 1 to 31536000000 (a year).",
        "throttle.firstDelayMs must not exceed throttle.maxDelayMs.",
      ]),
    )
    expect((error as ConfigError).problems).not.toContainEqual(
      expect.stringContaining('"10.0.0.1"'),
    )
  })

  it("accepts the defaults and partial overrides", () => {
    expect(() =>
      createAuth({ ...base, trustedProxies: ["10.0.0.1", "2001:db8::1", "10.0.0.0/8", "::/0"] }),
    ).not.toThrow()
    expect(() =>
      createAuth({ ...base, throttle: { windowMs: 1, firstDelayMs: 1, maxDelayMs: 1 } }),
    ).not.toThrow()
    expect(() =>
      createAuth({ ...base, stuffing: { distinctAccounts: 1, windowMs: 1 } }),
    ).not.toThrow()
    for (const forwardedHeader of ["x-forwarded-for", "forwarded"] as const) {
      expect(() =>
        createAuth({ ...base, trustedProxies: ["10.0.0.1"], forwardedHeader }),
      ).not.toThrow()
    }
    expect(() =>
      createAuth({ ...base, throttle: { freeFailures: 0, firstDelayMs: 1, maxDelayMs: 1 } }),
    ).not.toThrow()
  })
})
