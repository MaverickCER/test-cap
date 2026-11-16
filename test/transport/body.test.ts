import { describe, expect, it } from "vitest"
import { utf8Encode } from "../../src/core/encoding.js"
import {
  DEFAULT_BODY_LIMIT,
  parseBody,
  parseContentType,
  parseForm,
  parseJsonObject,
  readBody,
} from "../../src/transport/body.js"
import type { PlainRequest } from "../../src/transport/types.js"
import { refusal, refusalAsync } from "../support/refusal.js"

function request(
  body: string | Uint8Array | null,
  headers: Record<string, string> = {},
): PlainRequest {
  return {
    method: "POST",
    url: "https://app.example/auth/sign-in",
    headers: new Headers(headers),
    body: typeof body === "string" ? utf8Encode(body) : body,
  }
}

function json(text: string): Uint8Array {
  return utf8Encode(text)
}

const FORM = { "content-type": "application/x-www-form-urlencoded" }
const JSON_TYPE = { "content-type": "application/json" }

describe("readBody", () => {
  it("defaults to a 64 KiB limit", () => {
    expect(DEFAULT_BODY_LIMIT).toBe(65_536)
    expect(readBody(request(new Uint8Array(DEFAULT_BODY_LIMIT)))).toHaveLength(DEFAULT_BODY_LIMIT)
    expect(refusal(() => readBody(request(new Uint8Array(DEFAULT_BODY_LIMIT + 1))))).toBe(
      "body-too-large 413: The body is over the limit.",
    )
  })

  it("returns an empty body for a request with none", () => {
    expect(readBody(request(null))).toHaveLength(0)
  })

  it("accepts a body exactly at the limit and refuses one byte more", () => {
    expect(readBody(request(new Uint8Array(10)), { limit: 10 })).toHaveLength(10)
    expect(refusal(() => readBody(request(new Uint8Array(11)), { limit: 10 }))).toBe(
      "body-too-large 413: The body is over the limit.",
    )
  })

  it("accepts a declared length exactly at the limit", () => {
    expect(
      readBody(request(new Uint8Array(10), { "content-length": "10" }), { limit: 10 }),
    ).toHaveLength(10)
  })

  it("refuses a declared length over the limit even when the bytes are short", () => {
    expect(refusal(() => readBody(request("a", { "content-length": "11" }), { limit: 10 }))).toBe(
      "body-too-large 413: The declared body is over the limit.",
    )
  })

  it("refuses a declared length that disagrees with the bytes received", () => {
    expect(refusal(() => readBody(request("abc", { "content-length": "2" })))).toBe(
      "malformed-body 400: Content-Length does not match the body received.",
    )
  })

  it("refuses a declared length that is not one decimal number", () => {
    expect(refusal(() => readBody(request("ab", { "content-length": "2, 2" })))).toBe(
      "ambiguous-header 400: The content-length header was sent more than once.",
    )
    expect(refusal(() => readBody(request("ab", { "content-length": "+2" })))).toBe(
      "malformed-body 400: Content-Length is not a decimal number.",
    )
    expect(refusal(() => readBody(request("ab", { "content-length": "0x2" })))).toBe(
      "malformed-body 400: Content-Length is not a decimal number.",
    )
  })

  it("accepts a matching declared length", () => {
    expect(readBody(request("ab", { "content-length": "2" }))).toHaveLength(2)
  })

  it("accepts a limit of one byte and refuses a limit that is not a positive integer", () => {
    expect(readBody(request("a"), { limit: 1 })).toHaveLength(1)
    expect(() => readBody(request(null), { limit: 0 })).toThrow(
      new RangeError("The body limit must be a positive integer."),
    )
    expect(() => readBody(request(null), { limit: 1.5 })).toThrow(
      new RangeError("The body limit must be a positive integer."),
    )
  })

  it("stops on an aborted request", () => {
    const controller = new AbortController()
    controller.abort()
    expect(refusal(() => readBody({ ...request("a"), signal: controller.signal }))).toBe(
      "aborted 400: The request was aborted.",
    )
  })
})

describe("parseContentType", () => {
  it("lowercases the media type and reads a UTF-8 charset", () => {
    expect(parseContentType("Application/JSON; charset=UTF-8")).toEqual({
      mediaType: "application/json",
    })
    expect(parseContentType("application/x-www-form-urlencoded")).toEqual({
      mediaType: "application/x-www-form-urlencoded",
    })
    expect(parseContentType('application/json; charset="utf-8"')).toEqual({
      mediaType: "application/json",
    })
  })

  it("trims the media type and each parameter value", () => {
    expect(parseContentType(" application/json ; charset= utf-8 ")).toEqual({
      mediaType: "application/json",
    })
  })

  it("ignores parameters other than charset", () => {
    expect(parseContentType("application/json; q=1; profile=x")).toEqual({
      mediaType: "application/json",
    })
  })

  it("refuses any charset other than UTF-8", () => {
    expect(refusal(() => parseContentType("application/json; charset=latin1"))).toBe(
      "unsupported-media-type 415: Only UTF-8 bodies are accepted.",
    )
  })

  it("unquotes a charset only when both ends are quoted", () => {
    expect(refusal(() => parseContentType('application/json; charset="utf-8X'))).toBe(
      "unsupported-media-type 415: Only UTF-8 bodies are accepted.",
    )
    expect(refusal(() => parseContentType('application/json; charset=Xutf-8"'))).toBe(
      "unsupported-media-type 415: Only UTF-8 bodies are accepted.",
    )
    expect(refusal(() => parseContentType('application/json; charset="'))).toBe(
      "unsupported-media-type 415: Only UTF-8 bodies are accepted.",
    )
  })

  it("refuses an empty or malformed media type", () => {
    expect(refusal(() => parseContentType(""))).toBe(
      "unsupported-media-type 415: The content type is malformed.",
    )
    expect(refusal(() => parseContentType("json"))).toBe(
      "unsupported-media-type 415: The content type is malformed.",
    )
    expect(refusal(() => parseContentType("a,b/json"))).toBe(
      "unsupported-media-type 415: The content type is malformed.",
    )
    expect(refusal(() => parseContentType("application/json,x"))).toBe(
      "unsupported-media-type 415: The content type is malformed.",
    )
    expect(refusal(() => parseContentType("application/json; charset"))).toBe(
      "unsupported-media-type 415: A content-type parameter is malformed.",
    )
  })
})

describe("parseForm", () => {
  it("parses fields into a record with no prototype", () => {
    const fields = parseForm(utf8Encode("email=a%40b.example&name=J%C3%BCrgen+X&__proto__=x"))
    expect(fields["email"]).toBe("a@b.example")
    expect(fields["name"]).toBe("Jürgen X")
    expect(fields["__proto__"]).toBe("x")
    expect(Object.getPrototypeOf(fields)).toBeNull()
  })

  it("refuses a repeated field so no two parsers can disagree on which value won", () => {
    expect(refusal(() => parseForm(utf8Encode("email=a&email=b")))).toBe(
      'duplicate-field 400: The field "email" is repeated.',
    )
  })

  it("refuses more fields than the limit", () => {
    expect(refusal(() => parseForm(utf8Encode("a=1&b=2&c=3"), { maxFields: 2 }))).toBe(
      "too-many-fields 400: The form has too many fields.",
    )
    expect(Object.keys(parseForm(utf8Encode("a=1&b=2"), { maxFields: 2 }))).toEqual(["a", "b"])
  })

  it("refuses bytes that are not UTF-8", () => {
    expect(refusal(() => parseForm(Uint8Array.of(0x61, 0x3d, 0xff)))).toBe(
      "malformed-body 400: The body is not valid UTF-8.",
    )
  })

  it("treats an empty body as no fields", () => {
    expect(Object.keys(parseForm(new Uint8Array(0)))).toEqual([])
  })
})

describe("parseJsonObject", () => {
  it("parses a top-level object into a record with no prototype", () => {
    const value = parseJsonObject(
      json('{"email":"a@b.example","remember":true,"__proto__":{"x":1}}'),
    )
    expect(value["email"]).toBe("a@b.example")
    expect(value["remember"]).toBe(true)
    expect(Object.getPrototypeOf(value)).toBeNull()
    expect(Object.getPrototypeOf(value["__proto__"])).toBeNull()
    expect(({} as Record<string, unknown>)["x"]).toBeUndefined()
  })

  it("keeps null, numbers, strings and arrays as they are, and strips nested objects' prototypes", () => {
    const value = parseJsonObject(json('{"n":null,"i":1,"s":"ab","l":[1,{"k":2}]}'))
    expect(value["n"]).toBeNull()
    expect(value["i"]).toBe(1)
    expect(value["s"]).toBe("ab")
    const list = value["l"] as unknown[]
    expect(Array.isArray(list)).toBe(true)
    expect(Object.getPrototypeOf(list)).toBe(Array.prototype)
    expect(list[0]).toBe(1)
    expect(Object.getPrototypeOf(list[1])).toBeNull()
    expect(list[1]).toEqual({ k: 2 })
  })

  it("refuses a top level that is not an object", () => {
    for (const text of ["[1]", "null", '"x"', "1"]) {
      expect(refusal(() => parseJsonObject(json(text)))).toBe(
        "malformed-body 400: The JSON body must be an object.",
      )
    }
  })

  it("refuses invalid JSON and non-UTF-8 bytes", () => {
    expect(refusal(() => parseJsonObject(json('{"a":')))).toBe(
      "malformed-body 400: The body is not valid JSON.",
    )
    expect(refusal(() => parseJsonObject(json('{"\\x":1}')))).toBe(
      "malformed-body 400: The body is not valid JSON.",
    )
    expect(refusal(() => parseJsonObject(Uint8Array.of(0x7b, 0xff, 0x7d)))).toBe(
      "malformed-body 400: The body is not valid UTF-8.",
    )
  })

  it("refuses a repeated key at any depth, including one spelled with escapes", () => {
    expect(refusal(() => parseJsonObject(json('{"a":1,"a":2}')))).toBe(
      'duplicate-field 400: The key "a" is repeated.',
    )
    expect(refusal(() => parseJsonObject(json('{"a":1,"\\u0061":2}')))).toBe(
      'duplicate-field 400: The key "a" is repeated.',
    )
    expect(refusal(() => parseJsonObject(json('{"o":{"k":1,"k":2}}')))).toBe(
      'duplicate-field 400: The key "k" is repeated.',
    )
    expect(refusal(() => parseJsonObject(json('{"l":[{"k":1},{"k":1,"k":3}]}')))).toBe(
      'duplicate-field 400: The key "k" is repeated.',
    )
  })

  it("refuses a key repeated after a nested object or array has closed", () => {
    expect(refusal(() => parseJsonObject(json('{"o":{"k":1},"o":2}')))).toBe(
      'duplicate-field 400: The key "o" is repeated.',
    )
    expect(refusal(() => parseJsonObject(json('{"l":[1],"l":2}')))).toBe(
      'duplicate-field 400: The key "l" is repeated.',
    )
  })

  it("allows the same key in sibling objects and keys that only look alike", () => {
    const value = parseJsonObject(json('{"l":[{"k":1},{"k":2}],"a\\"b":1,"a":"\\"a\\",\\"a\\""}'))
    expect(value["a"]).toBe('"a","a"')
    expect(value['a"b']).toBe(1)
  })

  it("reads neither a value nor an array element as a key", () => {
    expect(parseJsonObject(json('{"a":"a"}'))["a"]).toBe("a")
    expect(parseJsonObject(json('{"a":"b","b":"a"}'))["b"]).toBe("a")
    expect(parseJsonObject(json('{"l":["x","x"]}'))["l"]).toEqual(["x", "x"])
    expect(parseJsonObject(json('{"l":[["x"],"x"],"x":1}'))["x"]).toBe(1)
  })

  it("refuses nesting deeper than the limit", () => {
    expect(refusal(() => parseJsonObject(json('{"a":{"b":{"c":1}}}'), { maxDepth: 2 }))).toBe(
      "malformed-body 400: The JSON body is nested too deeply.",
    )
    expect(parseJsonObject(json('{"a":{"b":1}}'), { maxDepth: 2 })["a"]).toEqual({ b: 1 })
    expect(refusal(() => parseJsonObject(json('{"a":[[1]]}'), { maxDepth: 2 }))).toBe(
      "malformed-body 400: The JSON body is nested too deeply.",
    )
  })

  it("refuses more top-level fields than the limit, and counts only the top level", () => {
    expect(refusal(() => parseJsonObject(json('{"a":1,"b":2,"c":3}'), { maxFields: 2 }))).toBe(
      "too-many-fields 400: The JSON body has too many fields.",
    )
    expect(Object.keys(parseJsonObject(json('{"a":1,"b":2}'), { maxFields: 2 }))).toEqual([
      "a",
      "b",
    ])
    expect(
      Object.keys(parseJsonObject(json('{"o":{"a":1,"b":2,"c":3}}'), { maxFields: 2 })),
    ).toEqual(["o"])
  })
})

describe("parseBody", () => {
  it("parses a form body", async () => {
    const parsed = await parseBody(request("code=123456", FORM))
    expect(parsed).toEqual({ kind: "form", fields: { code: "123456" } })
  })

  it("parses a JSON body", async () => {
    const parsed = await parseBody(request('{"code":"123456"}', JSON_TYPE))
    expect(parsed).toEqual({ kind: "json", fields: { code: "123456" } })
  })

  it("picks the kind by the content type, whatever order the route lists them in", async () => {
    expect(
      await parseBody(request('{"a":1}', JSON_TYPE), { accept: ["form", "json"] }),
    ).toMatchObject({ kind: "json" })
    expect(await parseBody(request("a=1", FORM), { accept: ["json", "form"] })).toMatchObject({
      kind: "form",
    })
  })

  it("returns an empty result for a request with no body and no content type", async () => {
    expect(await parseBody(request(null))).toEqual({ kind: "empty", fields: {} })
  })

  it("refuses a body without a content type, and a content type the route does not accept", async () => {
    expect(await refusalAsync(() => parseBody(request("a=1")))).toBe(
      "unsupported-media-type 415: A body was sent without a content type.",
    )
    expect(
      await refusalAsync(() => parseBody(request('{"a":1}', JSON_TYPE), { accept: ["form"] })),
    ).toBe("unsupported-media-type 415: This route does not accept that content type.")
    expect(
      await refusalAsync(() => parseBody(request("<a/>", { "content-type": "application/xml" }))),
    ).toBe("unsupported-media-type 415: This route does not accept that content type.")
  })

  it("refuses a repeated content type", async () => {
    const headers = new Headers()
    headers.append("content-type", "application/json")
    headers.append("content-type", "application/x-www-form-urlencoded")
    const req: PlainRequest = {
      method: "POST",
      url: "https://app.example/auth/x",
      headers,
      body: utf8Encode("{}"),
    }
    expect(await refusalAsync(() => parseBody(req))).toBe(
      "ambiguous-header 400: The content-type header was sent more than once.",
    )
  })

  it("passes its field and depth limits to the parser", async () => {
    expect(
      await refusalAsync(() => parseBody(request('{"a":1,"b":2}', JSON_TYPE), { maxFields: 1 })),
    ).toBe("too-many-fields 400: The JSON body has too many fields.")
    expect(
      await refusalAsync(() => parseBody(request('{"a":{"b":1}}', JSON_TYPE), { maxDepth: 1 })),
    ).toBe("malformed-body 400: The JSON body is nested too deeply.")
    expect(await refusalAsync(() => parseBody(request("a=1&b=2", FORM), { maxFields: 1 }))).toBe(
      "too-many-fields 400: The form has too many fields.",
    )
  })

  it("applies the body limit before parsing", async () => {
    expect(await refusalAsync(() => parseBody(request("a=1&b=2", FORM), { limit: 3 }))).toBe(
      "body-too-large 413: The body is over the limit.",
    )
  })
})
