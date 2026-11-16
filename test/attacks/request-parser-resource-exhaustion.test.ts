// Attack: a request body that is huge, deeply nested, has thousands of fields, or is malformed in ways that make a
// parser slow or crash.
// Stopped by: the body limit applies before any parsing; field-count and depth limits; parsers refuse rather than
// guess (ADR 0003). The fuzzing below uses a seeded generator, so a failure replays exactly.
import { describe, expect, it } from "vitest"
import { utf8Encode } from "../../src/core/encoding.js"
import { TransportError } from "../../src/core/errors.js"
import { parseBody, parseForm, parseJsonObject, readBody } from "../../src/transport/body.js"
import { readCookie } from "../../src/transport/cookies.js"
import { matchAuthPath } from "../../src/transport/path.js"
import type { PlainRequest } from "../../src/transport/types.js"

/** mulberry32: a small seeded PRNG, for reproducible fuzz inputs only. */
function prng(seed: number): () => number {
  let state = seed >>> 0
  return () => {
    state = (state + 0x6d2b79f5) >>> 0
    let t = state
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296
  }
}

const ALPHABET = [
  "{",
  "}",
  "[",
  "]",
  '"',
  "\\",
  ":",
  ",",
  "a",
  "0",
  "-",
  "e",
  "u",
  "=",
  "&",
  "%",
  "+",
  " ",
  "\u0000",
  "é",
]

function fuzzText(next: () => number, maxLength: number): string {
  const length = Math.floor(next() * maxLength)
  let out = ""
  for (let i = 0; i < length; i += 1) out += ALPHABET[Math.floor(next() * ALPHABET.length)] ?? ""
  return out
}

function fuzzBytes(next: () => number, maxLength: number): Uint8Array {
  return Uint8Array.from({ length: Math.floor(next() * maxLength) }, () => Math.floor(next() * 256))
}

/** Drops the characters `Headers` itself refuses, so the parser under test, not `Headers`, sees the rest. */
function headerSafe(text: string): string {
  return [...text].filter((char) => char !== "\u0000" && char !== "\r" && char !== "\n").join("")
}

/** The only acceptable outcomes for hostile input: a result, or a TransportError. */
function settles(run: () => unknown): void {
  try {
    run()
  } catch (error) {
    expect(error).toBeInstanceOf(TransportError)
  }
}

function post(body: Uint8Array, contentType: string): PlainRequest {
  return {
    method: "POST",
    url: "https://app.example/auth/x",
    headers: new Headers({ "content-type": contentType }),
    body,
  }
}

describe("request-parser-resource-exhaustion", () => {
  it("refuses an oversized body before parsing it", async () => {
    const huge = utf8Encode(`{"a":"${"x".repeat(70_000)}"}`)
    await expect(parseBody(post(huge, "application/json"))).rejects.toMatchObject({
      code: "body-too-large",
    })
  })

  it("refuses deep nesting without recursing through it", () => {
    const deep = utf8Encode(`${'{"a":'.repeat(5_000)}1${"}".repeat(5_000)}`)
    expect(() => parseJsonObject(deep)).toThrow(TransportError)
    const arrays = utf8Encode(`{"a":${"[".repeat(5_000)}${"]".repeat(5_000)}}`)
    expect(() => parseJsonObject(arrays)).toThrow(TransportError)
  })

  it("refuses the deepest nesting a body under the limit can carry, with a 400 and not a stack overflow", () => {
    const depth = 32_000
    const deep = utf8Encode(`{"a":${"[".repeat(depth)}${"]".repeat(depth)}}`)
    expect(deep.length).toBeLessThan(65_536)
    let caught: unknown
    try {
      parseJsonObject(deep)
    } catch (error) {
      caught = error
    }
    expect(caught).toBeInstanceOf(TransportError)
    expect((caught as TransportError).code).toBe("malformed-body")
    expect((caught as TransportError).message).toBe("The JSON body is nested too deeply.")
  })

  it("refuses thousands of fields", () => {
    const form = utf8Encode(Array.from({ length: 5_000 }, (_, i) => `f${i}=1`).join("&"))
    expect(() => parseForm(form)).toThrow(TransportError)
    const json = utf8Encode(`{${Array.from({ length: 5_000 }, (_, i) => `"f${i}":1`).join(",")}}`)
    expect(() => parseJsonObject(json)).toThrow(TransportError)
  })

  it("settles every fuzzed JSON and form body with a result or a TransportError", () => {
    const next = prng(0x7e57ca9)
    for (let i = 0; i < 2_000; i += 1) {
      const text = fuzzText(next, 64)
      settles(() => parseJsonObject(utf8Encode(text)))
      settles(() => parseForm(utf8Encode(text)))
      const bytes = fuzzBytes(next, 64)
      settles(() => parseJsonObject(bytes))
      settles(() => parseForm(bytes))
    }
  })

  it("settles every fuzzed path, cookie and declared length", () => {
    const next = prng(0xc00c1e)
    for (let i = 0; i < 2_000; i += 1) {
      const text = fuzzText(next, 40)
      settles(() => matchAuthPath(`https://app.example/${text}`))
      settles(() => matchAuthPath(`/auth/${text}`))
      expect(["absent", "value", "ambiguous"]).toContain(
        readCookie(new Headers({ cookie: headerSafe(text) }), "__Host-test-cap").kind,
      )
      const request: PlainRequest = {
        method: "POST",
        url: "/auth/x",
        headers: new Headers({ "content-length": headerSafe(text) || "0" }),
        body: utf8Encode(text),
      }
      settles(() => readBody(request))
    }
  })

  it("keeps parsed JSON free of prototype pollution for any key", () => {
    const value = parseJsonObject(
      utf8Encode('{"__proto__":{"polluted":1},"constructor":{"prototype":{"p":1}}}'),
    )
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined()
    expect(({} as Record<string, unknown>)["p"]).toBeUndefined()
    expect(Object.keys(value)).toEqual(["__proto__", "constructor"])
  })
})
