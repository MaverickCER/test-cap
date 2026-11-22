import { describe, expect, it } from "vitest"
import { sequenceRandom } from "../../src/core/clock.js"
import { base64UrlEncode } from "../../src/core/encoding.js"
import {
  createCsrfTokens,
  CSRF_COOKIE,
  CSRF_TOKEN_LIFETIME_MS,
  newPreSession,
  readPreSession,
  sameOrigin,
} from "../../src/security/csrf.js"
import { refusal } from "../support/refusal.js"

const ORIGIN = "https://app.example"
const T = 1_800_000_000_000
const key = (id: string, seed: number) => ({
  id,
  bytes: Uint8Array.from({ length: 32 }, (_, i) => (i * 37 + seed) % 256),
})

describe("the origin check (ADR 0011 §2)", () => {
  it("accepts Origin equal to APP_ORIGIN and nothing else", () => {
    expect(sameOrigin(new Headers({ Origin: ORIGIN }), ORIGIN)).toBe(true)
    for (const origin of [
      "https://evil.example",
      "https://app.example.evil.example",
      "http://app.example",
      "https://app.example:443",
    ]) {
      expect(
        sameOrigin(new Headers({ Origin: origin, "Sec-Fetch-Site": "same-origin" }), ORIGIN),
      ).toBe(false)
    }
  })

  it("treats Origin: null, which a browser sends from a no-referrer page, like an absent Origin", () => {
    // The default pages send Referrer-Policy: no-referrer (ADR 0011 §2), so a browser serializes their form posts'
    // origin as "null". Sec-Fetch-Site then decides: a sandboxed frame or a cross-origin redirect says cross-site.
    expect(
      sameOrigin(new Headers({ Origin: "null", "Sec-Fetch-Site": "same-origin" }), ORIGIN),
    ).toBe(true)
    for (const site of ["same-site", "cross-site", "none"]) {
      expect(
        sameOrigin(new Headers({ Origin: "null", "Sec-Fetch-Site": site }), ORIGIN),
        site,
      ).toBe(false)
    }
    expect(sameOrigin(new Headers({ Origin: "null" }), ORIGIN)).toBe(false)
  })

  it("falls back to Sec-Fetch-Site only when Origin is absent or null", () => {
    expect(sameOrigin(new Headers({ "Sec-Fetch-Site": "same-origin" }), ORIGIN)).toBe(true)
    expect(sameOrigin(new Headers({ "Sec-Fetch-Site": "same-site" }), ORIGIN)).toBe(false)
    expect(sameOrigin(new Headers({ "Sec-Fetch-Site": "cross-site" }), ORIGIN)).toBe(false)
    expect(sameOrigin(new Headers(), ORIGIN)).toBe(false)
  })

  it("never reads Host", () => {
    expect(sameOrigin(new Headers({ Host: "app.example" }), ORIGIN)).toBe(false)
  })

  it("refuses a repeated Origin rather than pick one", () => {
    const headers = new Headers()
    headers.append("Origin", ORIGIN)
    headers.append("Origin", "https://evil.example")
    expect(refusal(() => sameOrigin(headers, ORIGIN))).toBe(
      "ambiguous-header 400: The origin header was sent more than once.",
    )
  })
})

describe("the pre-session cookie", () => {
  it("is a __Host- cookie holding 256 random bits for the browser session", () => {
    const pre = newPreSession(sequenceRandom([1, 2, 3]))
    expect(pre.value).toBe(
      base64UrlEncode(Uint8Array.from({ length: 32 }, (_, i) => [1, 2, 3][i % 3] ?? 0)),
    )
    expect(pre.cookie).toBe(`${CSRF_COOKIE}=${pre.value}; Path=/; Secure; HttpOnly; SameSite=Lax`)
  })

  it("is read only when present once and well formed", () => {
    const value = "A".repeat(43)
    expect(readPreSession(new Headers({ Cookie: `${CSRF_COOKIE}=${value}` }))).toBe(value)
    expect(readPreSession(new Headers())).toBeNull()
    expect(readPreSession(new Headers({ Cookie: `${CSRF_COOKIE}=${"A".repeat(42)}` }))).toBeNull()
    expect(readPreSession(new Headers({ Cookie: `${CSRF_COOKIE}=${"A".repeat(44)}` }))).toBeNull()
    expect(readPreSession(new Headers({ Cookie: `${CSRF_COOKIE}=${"A".repeat(42)}.` }))).toBeNull()
    expect(
      readPreSession(new Headers({ Cookie: `${CSRF_COOKIE}=${value}; ${CSRF_COOKIE}=${value}` })),
    ).toBeNull()
  })
})

describe("synchronizer tokens (ADR 0011 Open 1)", () => {
  const tokens = createCsrfTokens([key("k2", 2), key("k1", 1)])

  it("names the current key and the expiry, and verifies for its own binding", async () => {
    const token = await tokens.issue("session:abc", T)
    expect(token).toMatch(new RegExp(`^k2\\.${T + CSRF_TOKEN_LIFETIME_MS}\\.[A-Za-z0-9_-]{43}$`))
    expect(await tokens.verify(token, "session:abc", T)).toBe(true)
  })

  it("is the same token for the same binding, key and time, and a different one for another binding", async () => {
    expect(await tokens.issue("pre:x", T)).toBe(await tokens.issue("pre:x", T))
    expect(await tokens.issue("pre:x", T)).not.toBe(await tokens.issue("pre:y", T))
  })

  it("refuses another binding", async () => {
    const token = await tokens.issue("session:abc", T)
    expect(await tokens.verify(token, "session:abd", T)).toBe(false)
    expect(await tokens.verify(token, "pre:abc", T)).toBe(false)
  })

  it("expires after an hour, to the millisecond", async () => {
    const token = await tokens.issue("pre:x", T)
    expect(await tokens.verify(token, "pre:x", T + CSRF_TOKEN_LIFETIME_MS - 1)).toBe(true)
    expect(await tokens.verify(token, "pre:x", T + CSRF_TOKEN_LIFETIME_MS)).toBe(false)
  })

  it("keeps verifying under a previous key still in the ring, and stops once it is removed", async () => {
    const old = await createCsrfTokens([key("k1", 1)]).issue("pre:x", T)
    expect(old.startsWith("k1.")).toBe(true)
    expect(await tokens.verify(old, "pre:x", T)).toBe(true)
    expect(await createCsrfTokens([key("k2", 2)]).verify(old, "pre:x", T)).toBe(false)
  })

  it("refuses a token whose key id names a key with other bytes", async () => {
    const forged = await createCsrfTokens([key("k2", 9)]).issue("pre:x", T)
    expect(await tokens.verify(forged, "pre:x", T)).toBe(false)
  })

  it("binds the expiry and the key id into the MAC", async () => {
    const token = await tokens.issue("pre:x", T)
    const [, , tag] = token.split(".")
    expect(await tokens.verify(`k2.${T + CSRF_TOKEN_LIFETIME_MS + 1}.${tag}`, "pre:x", T)).toBe(
      false,
    )
    expect(await tokens.verify(`k1.${T + CSRF_TOKEN_LIFETIME_MS}.${tag}`, "pre:x", T)).toBe(false)
  })

  it.each([
    ["empty", ""],
    ["no parts", "abc"],
    ["a short tag", `k2.${T}.${"A".repeat(42)}`],
    ["a long tag", `k2.${T}.${"A".repeat(44)}`],
    ["a non-numeric expiry", `k2.soon.${"A".repeat(43)}`],
    ["an extra part", `k2.${T}.${"A".repeat(43)}.x`],
    ["a leading part", `x.k2.${T}.${"A".repeat(43)}`],
    ["an empty key id", `.${T}.${"A".repeat(43)}`],
    ["a key id over 32 characters", `${"k".repeat(33)}.${T}.${"A".repeat(43)}`],
    ["an expiry over 16 digits", `k2.${"9".repeat(17)}.${"A".repeat(43)}`],
  ])("refuses a malformed token: %s", async (_name, token) => {
    expect(await tokens.verify(token, "pre:x", T)).toBe(false)
  })

  it("accepts a key id of 32 characters", async () => {
    const id = "k".repeat(32)
    const ring = createCsrfTokens([key(id, 4)])
    expect(await ring.verify(await ring.issue("pre:x", T), "pre:x", T)).toBe(true)
  })

  it("needs at least one key", () => {
    expect(() => createCsrfTokens([])).toThrow("The CSRF key ring needs at least one key.")
  })
})
