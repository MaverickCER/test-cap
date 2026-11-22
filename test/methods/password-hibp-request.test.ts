import { describe, expect, it } from "vitest"
import { hexEncode } from "../../src/core/encoding.js"
import { type HibpFetch, screenWithHibp } from "../../src/methods/password/hibp.js"
import { normalisePassword } from "../../src/methods/password/rules.js"
import { within } from "../support/within.js"

const screen = (...args: Parameters<typeof screenWithHibp>) => within(screenWithHibp(...args))

// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
const PREFIX = "5BAA6"
const SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
const OTHER = "0018A45C4D1DEF81644B54AB7F969B88D65"

function respond(body: string, status = 200): { fetch: HibpFetch; calls: unknown[][] } {
  const calls: unknown[][] = []
  return {
    calls,
    fetch: (url, init) => {
      calls.push([url, init])
      return Promise.resolve({
        ok: status >= 200 && status < 300,
        status,
        text: () => Promise.resolve(body),
      })
    },
  }
}

describe("the HIBP range request (ADR 0010 §2)", () => {
  it("sends only the 5-character SHA-1 prefix, to the fixed host, with Add-Padding", async () => {
    const { fetch, calls } = respond(`${OTHER}:3\r\n`)
    await screen(normalisePassword("password"), fetch)
    expect(calls).toHaveLength(1)
    const [url, init] = calls[0] as [
      string,
      { method: string; headers: Record<string, string>; signal: AbortSignal },
    ]
    expect(url).toBe(`https://api.pwnedpasswords.com/range/${PREFIX}`)
    expect(init.method).toBe("GET")
    expect(init.headers).toEqual({ "Add-Padding": "true" })
    expect(init.signal).toBeInstanceOf(AbortSignal)
    expect(JSON.stringify(calls)).not.toContain(SUFFIX)
  })

  it("hashes the NFC form", async () => {
    const { fetch, calls } = respond(`${OTHER}:3`)
    await screen(normalisePassword("café"), fetch)
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-1", new TextEncoder().encode("café")),
    )
    expect(calls[0]?.[0]).toBe(
      `https://api.pwnedpasswords.com/range/${hexEncode(digest).slice(0, 5).toUpperCase()}`,
    )
  })

  it("reports a matching suffix with a count above zero as breached", async () => {
    expect(
      await screen(normalisePassword("password"), respond(`${OTHER}:3\r\n${SUFFIX}:1\r\n`).fetch),
    ).toBe("breached")
    expect(await screen(normalisePassword("password"), respond(`${SUFFIX}:9545824`).fetch)).toBe(
      "breached",
    )
  })

  it("treats a matching suffix with a count of 0 as padding, never a match", async () => {
    expect(
      await screen(normalisePassword("password"), respond(`${OTHER}:2\r\n${SUFFIX}:0`).fetch),
    ).toBe("clear")
  })

  it("reports clear when no row matches", async () => {
    expect(
      await screen(normalisePassword("password"), respond(`${OTHER}:5\n${OTHER}:0`).fetch),
    ).toBe("clear")
  })

  it("skips lines that are not rows, wherever they are", async () => {
    expect(
      await screen(
        normalisePassword("password"),
        respond(`\r\nnot a row\r\n${SUFFIX}:2\r\n`).fetch,
      ),
    ).toBe("breached")
  })

  it("matches the suffix in either case", async () => {
    expect(
      await screen(normalisePassword("password"), respond(`${SUFFIX.toLowerCase()}:2`).fetch),
    ).toBe("breached")
  })
})
