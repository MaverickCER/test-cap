import { describe, expect, it } from "vitest"
import { expireCookie, readCookie, serializeCookie } from "../../src/transport/cookies.js"
import { singleHeader } from "../../src/transport/headers.js"
import { matchAuthPath, rawPath } from "../../src/transport/path.js"
import { refusal } from "../support/refusal.js"

describe("singleHeader", () => {
  it("returns null when absent and the value when present once", () => {
    const headers = new Headers({ origin: "https://app.example" })
    expect(singleHeader(headers, "host")).toBeNull()
    expect(singleHeader(headers, "Origin")).toBe("https://app.example")
  })

  it("refuses a header sent more than once, which Headers joins with a comma", () => {
    const headers = new Headers()
    headers.append("origin", "https://app.example")
    headers.append("origin", "https://evil.example")
    expect(refusal(() => singleHeader(headers, "origin"))).toBe(
      "ambiguous-header 400: The origin header was sent more than once.",
    )
  })
})

describe("readCookie", () => {
  const name = "__Host-test-cap"

  it("is absent when there is no cookie header or no such cookie", () => {
    expect(readCookie(new Headers(), name)).toEqual({ kind: "absent" })
    expect(readCookie(new Headers({ cookie: "other=1" }), name)).toEqual({ kind: "absent" })
  })

  it("reads the cookie among others, ignoring spaces around pairs", () => {
    expect(readCookie(new Headers({ cookie: `a=1;  ${name}=tok_en-1 ; b=2` }), name)).toEqual({
      kind: "value",
      value: "tok_en-1",
    })
  })

  it("is ambiguous when the cookie appears twice (cookie tossing)", () => {
    expect(readCookie(new Headers({ cookie: `${name}=a; ${name}=b` }), name)).toEqual({
      kind: "ambiguous",
    })
    const headers = new Headers()
    headers.append("cookie", `${name}=a`)
    headers.append("cookie", `${name}=b`)
    expect(readCookie(headers, name)).toEqual({ kind: "ambiguous" })
  })

  it("matches the name exactly and case-sensitively", () => {
    expect(readCookie(new Headers({ cookie: "__host-test-cap=a" }), name)).toEqual({
      kind: "absent",
    })
    expect(readCookie(new Headers({ cookie: `${name}x=a` }), name)).toEqual({ kind: "absent" })
  })

  it("treats a value outside the cookie-octet set as absent", () => {
    expect(readCookie(new Headers({ cookie: `${name}="quoted"` }), name)).toEqual({
      kind: "absent",
    })
    expect(readCookie(new Headers({ cookie: `${name}=a\\b` }), name)).toEqual({ kind: "absent" })
    expect(readCookie(new Headers({ cookie: `${name}=` }), name)).toEqual({ kind: "absent" })
  })

  it("ignores pairs with no equals sign, even one that starts with the name", () => {
    expect(readCookie(new Headers({ cookie: `junk; ${name}=v` }), name)).toEqual({
      kind: "value",
      value: "v",
    })
    expect(readCookie(new Headers({ cookie: `${name}x` }), name)).toEqual({ kind: "absent" })
  })

  it("reads a one-character name", () => {
    expect(readCookie(new Headers({ cookie: "a=1" }), "a")).toEqual({ kind: "value", value: "1" })
  })
})

describe("serializeCookie", () => {
  it("writes a __Host- cookie with Secure, Path=/ and no Domain", () => {
    expect(
      serializeCookie("__Host-test-cap", "abc", { httpOnly: true, sameSite: "Lax", maxAge: 3600 }),
    ).toBe("__Host-test-cap=abc; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax")
  })

  it("omits Max-Age for a session cookie and HttpOnly when not asked", () => {
    expect(serializeCookie("__Host-x", "v", { httpOnly: false, sameSite: "None" })).toBe(
      "__Host-x=v; Path=/; Secure; SameSite=None",
    )
  })

  it("refuses a cookie name without the __Host- prefix", () => {
    expect(() => serializeCookie("session", "v", { httpOnly: true, sameSite: "Lax" })).toThrow(
      /__Host-/,
    )
  })

  it("refuses names and values outside the RFC 6265 grammar", () => {
    const badValue = new TypeError("The cookie value has characters RFC 6265 does not allow.")
    expect(() => serializeCookie("__Host-a b", "v", { httpOnly: true, sameSite: "Lax" })).toThrow(
      new TypeError("The cookie name is not an RFC 6265 token."),
    )
    expect(() =>
      serializeCookie("__Host-a", "v;Domain=evil", { httpOnly: true, sameSite: "Lax" }),
    ).toThrow(badValue)
    expect(() => serializeCookie("__Host-a", "", { httpOnly: true, sameSite: "Lax" })).toThrow(
      badValue,
    )
  })

  it("refuses a Max-Age that is not a non-negative integer", () => {
    const badMaxAge = new RangeError("Max-Age must be a non-negative whole number of seconds.")
    expect(() =>
      serializeCookie("__Host-a", "v", { httpOnly: true, sameSite: "Lax", maxAge: -1 }),
    ).toThrow(badMaxAge)
    expect(() =>
      serializeCookie("__Host-a", "v", { httpOnly: true, sameSite: "Lax", maxAge: 1.5 }),
    ).toThrow(badMaxAge)
  })

  it("expires a cookie with Max-Age=0 and the same attributes", () => {
    expect(expireCookie("__Host-test-cap", { httpOnly: true, sameSite: "Lax" })).toBe(
      "__Host-test-cap=-; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
    )
  })
})

describe("rawPath", () => {
  it("takes the path from an absolute or origin-form URL without normalising it", () => {
    expect(rawPath("https://app.example/auth/../admin?x=1")).toBe("/auth/../admin")
    expect(rawPath("/auth/session#frag")).toBe("/auth/session")
    expect(rawPath("https://app.example")).toBe("/")
    expect(rawPath("http://app.example:8080/a")).toBe("/a")
    expect(rawPath("https://app.example\\ignored/auth/session")).toBe("\\ignored/auth/session")
  })

  it("refuses a URL that is neither absolute nor origin-form", () => {
    for (const url of ["auth/session", "//evil.example/auth"]) {
      expect(refusal(() => rawPath(url))).toBe(
        "invalid-path 400: The request URL is not absolute or origin-form.",
      )
    }
  })
})

describe("matchAuthPath", () => {
  it("returns the route segments under the base path", () => {
    expect(matchAuthPath("https://app.example/auth/sign-in/password")).toEqual({
      kind: "route",
      segments: ["sign-in", "password"],
    })
    expect(matchAuthPath("https://app.example/auth")).toEqual({ kind: "route", segments: [] })
  })

  it("reports paths outside the base path, including look-alike prefixes", () => {
    expect(matchAuthPath("https://app.example/billing")).toEqual({ kind: "outside" })
    expect(matchAuthPath("https://app.example/authx/session")).toEqual({ kind: "outside" })
    expect(matchAuthPath("https://app.example/")).toEqual({ kind: "outside" })
  })

  it("supports another base path", () => {
    expect(matchAuthPath("https://app.example/api/auth/session", "/api/auth")).toEqual({
      kind: "route",
      segments: ["session"],
    })
  })

  it("refuses an empty or dot segment anywhere instead of normalising it", () => {
    for (const url of [
      "https://app.example//auth/session",
      "https://app.example/auth//session",
      "https://app.example/auth/session/",
      "https://app.example/auth/./session",
      "https://app.example/auth/../billing",
      "https://app.example/billing/../auth/session",
    ]) {
      expect(
        refusal(() => matchAuthPath(url)),
        url,
      ).toBe("invalid-path 400: The path has an empty or dot segment.")
    }
  })

  it("refuses a backslash, whitespace, a control character or an encoded separator anywhere", () => {
    for (const url of [
      "https://app.example/auth%2fsession",
      "https://app.example/auth/%2e%2e/billing",
      "https://app.example/auth\\session",
      "https://app.example/auth/sess%5cion",
      "https://app.example/auth/se\tssion",
      // A URL parser reads this backslash as the first path separator, so it must never be taken as authority.
      "https://app.example\\ignored/auth/session",
      "https://app.example\\",
    ]) {
      expect(
        refusal(() => matchAuthPath(url)),
        url,
      ).toBe(
        "invalid-path 400: The path has a backslash, whitespace, a control character or an encoded separator.",
      )
    }
  })

  it("refuses any percent-encoding inside the auth base path but allows it in app paths", () => {
    expect(refusal(() => matchAuthPath("https://app.example/auth/sign%2Din"))).toBe(
      "invalid-path 400: Paths under the auth base path are never percent-encoded.",
    )
    expect(matchAuthPath("https://app.example/files/a%20b")).toEqual({ kind: "outside" })
  })

  it("refuses a base path that is not a clean absolute path", () => {
    const unclean = new TypeError("The base path must be a clean absolute path such as /auth.")
    expect(() => matchAuthPath("https://app.example/auth", "auth")).toThrow(unclean)
    expect(() => matchAuthPath("https://app.example/auth", "/auth/")).toThrow(unclean)
    expect(() => matchAuthPath("https://app.example/auth", "/")).toThrow(unclean)
  })
})
