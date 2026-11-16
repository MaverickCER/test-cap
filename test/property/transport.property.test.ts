// Property tests for the byte transport (ADR 0003: "fast-check over the form, JSON, cookie and header parsers").
// Each property states an invariant over generated inputs. The seed is fixed, so a failure replays exactly in CI and
// under mutation testing.
import fc from "fast-check"
import { beforeAll, describe, expect, it } from "vitest"
import {
  base64UrlDecode,
  base64UrlEncode,
  constantTimeEqual,
  utf8Encode,
} from "../../src/core/encoding.js"
import { TransportError } from "../../src/core/errors.js"
import { parseForm, parseJsonObject, readBody } from "../../src/transport/body.js"
import { readCookie, serializeCookie } from "../../src/transport/cookies.js"
import { matchAuthPath, rawPath } from "../../src/transport/path.js"

beforeAll(() => {
  fc.configureGlobal({ seed: 0x7e57ca9, numRuns: 300 })
})

/** The path of every non-array object under `value` that has a prototype (each should have none). */
function objectsWithPrototype(value: unknown, path = "$"): string[] {
  if (value === null || typeof value !== "object") return []
  if (Array.isArray(value))
    return value.flatMap((item, index) => objectsWithPrototype(item, `${path}[${index}]`))
  const own = Object.getPrototypeOf(value) === null ? [] : [path]
  return [
    ...own,
    ...Object.entries(value).flatMap(([key, item]) => objectsWithPrototype(item, `${path}.${key}`)),
  ]
}

/** Runs `parse`; returns its result, or `null` when it threw a TransportError. Any other throw fails the property. */
function settle<T>(parse: () => T): T | null {
  try {
    return parse()
  } catch (error) {
    if (error instanceof TransportError) return null
    throw error
  }
}

/** A cookie name with the prefix test-cap uses, then RFC 6265 token characters. */
const cookieName = fc.stringMatching(/^__Host-[A-Za-z0-9_-]{1,12}$/)
/** A cookie value: cookie-octets only. */
const cookieValue = fc.stringMatching(/^[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]{1,40}$/)
/** A path segment the dispatcher accepts. */
const segment = fc
  .stringMatching(/^[A-Za-z0-9_~-][A-Za-z0-9._~-]{0,11}$/)
  .filter((s) => s !== "." && s !== "..")
/** Text that may hold anything, including separators and control characters. */
const anyText = fc.string({ unit: "binary", maxLength: 80 })

describe("encoding properties", () => {
  it("base64url round-trips every byte string and uses only its alphabet", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 64 }), (bytes) => {
        const text = base64UrlEncode(bytes)
        expect(text).toMatch(/^[A-Za-z0-9_-]*$/)
        expect([...base64UrlDecode(text)]).toEqual([...bytes])
      }),
    )
  })

  it("constantTimeEqual agrees with ordinary equality", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 16 }), fc.uint8Array({ maxLength: 16 }), (a, b) => {
        const equal = a.length === b.length && a.every((byte, index) => byte === b[index])
        expect(constantTimeEqual(a, b)).toBe(equal)
        expect(constantTimeEqual(a, a.slice())).toBe(true)
      }),
    )
  })
})

describe("cookie properties", () => {
  it("reads back any cookie it writes, among any other cookies", () => {
    fc.assert(
      fc.property(
        cookieName,
        cookieValue,
        fc.array(fc.tuple(fc.stringMatching(/^[a-z]{1,8}$/), cookieValue), { maxLength: 4 }),
        (name, value, others) => {
          const set = serializeCookie(name, value, { httpOnly: true, sameSite: "Lax" })
          const pair = set.split(";")[0] ?? ""
          const header = [...others.map(([n, v]) => `${n}=${v}`), pair].join("; ")
          expect(readCookie(new Headers({ cookie: header }), name)).toEqual({
            kind: "value",
            value,
          })
        },
      ),
    )
  })

  it("calls a cookie sent twice ambiguous, whatever the two values", () => {
    fc.assert(
      fc.property(cookieName, cookieValue, cookieValue, (name, first, second) => {
        const header = `${name}=${first}; ${name}=${second}`
        expect(readCookie(new Headers({ cookie: header }), name)).toEqual({ kind: "ambiguous" })
      }),
    )
  })

  it("never throws on any header, and always answers absent, value or ambiguous", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 120 }), cookieName, (header, name) => {
        const clean = [...header].filter((char) => char >= " " && char !== "\u007f").join("")
        expect(["absent", "value", "ambiguous"]).toContain(
          readCookie(new Headers({ cookie: clean }), name).kind,
        )
      }),
    )
  })
})

describe("form and JSON body properties", () => {
  it("parses back any form of distinct fields exactly", () => {
    fc.assert(
      fc.property(
        fc.dictionary(fc.string({ minLength: 1, maxLength: 12 }), fc.string({ maxLength: 40 }), {
          maxKeys: 20,
        }),
        (fields) => {
          const body = utf8Encode(new URLSearchParams(fields).toString())
          expect({ ...parseForm(body) }).toEqual(fields)
        },
      ),
    )
  })

  it("parses back any JSON object within the depth limit, with no prototype on any object", () => {
    fc.assert(
      fc.property(
        fc.dictionary(fc.string({ maxLength: 10 }), fc.jsonValue({ maxDepth: 3 }), { maxKeys: 10 }),
        (value) => {
          const parsed = parseJsonObject(utf8Encode(JSON.stringify(value)))
          expect(JSON.parse(JSON.stringify(parsed))).toEqual(JSON.parse(JSON.stringify(value)))
          expect(Object.getPrototypeOf(parsed)).toBeNull()
          expect(objectsWithPrototype(parsed)).toEqual([])
        },
      ),
    )
  })

  it("settles any bytes as a body: a result or a TransportError, and never pollutes Object.prototype", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 120 }), (bytes) => {
        settle(() => parseJsonObject(bytes))
        settle(() => parseForm(bytes))
        expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined()
      }),
    )
  })

  it("settles any text that looks like JSON or a form", () => {
    const jsonish = fc.stringMatching(/^[{}[\]":,\\a-z0-9 _-]{0,60}$/)
    fc.assert(
      fc.property(jsonish, (text) => {
        settle(() => parseJsonObject(utf8Encode(text)))
        settle(() => parseForm(utf8Encode(text)))
      }),
    )
  })

  it("refuses a body over the limit and accepts one at it, for any limit", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 64 }),
        fc.integer({ min: 0, max: 80 }),
        (limit, size) => {
          const request = {
            method: "POST",
            url: "/auth/x",
            headers: new Headers(),
            body: new Uint8Array(size),
          }
          expect(settle(() => readBody(request, { limit })) === null).toBe(size > limit)
        },
      ),
    )
  })
})

describe("path properties", () => {
  it("returns the segments of any clean path under the base, unchanged", () => {
    fc.assert(
      fc.property(fc.array(segment, { maxLength: 5 }), (segments) => {
        const url = ["https://app.example/auth", ...segments].join("/")
        expect(matchAuthPath(url)).toEqual({ kind: "route", segments })
      }),
    )
  })

  it("refuses any path with an empty or dot segment, wherever it is, under the base path or not", () => {
    const bad = fc.constantFrom("", ".", "..")
    fc.assert(
      fc.property(
        fc.constantFrom<readonly string[]>([], ["auth"]),
        fc.array(segment, { maxLength: 3 }),
        bad,
        fc.array(segment, { maxLength: 3 }),
        (base, before, middle, after) => {
          const url = `https://app.example/${[...base, ...before, middle, ...after, "end"].join("/")}`
          expect(settle(() => matchAuthPath(url))).toBeNull()
        },
      ),
    )
  })

  it("settles any URL, and never matches a route whose raw path differs from what it reports", () => {
    fc.assert(
      fc.property(anyText, (text) => {
        const url = `https://app.example/${text}`
        const match = settle(() => matchAuthPath(url))
        if (match?.kind === "route") {
          expect(rawPath(url)).toBe(["/auth", ...match.segments].join("/"))
        }
      }),
    )
  })
})
