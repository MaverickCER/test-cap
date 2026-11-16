import { describe, expect, it } from "vitest"
import {
  base64UrlDecode,
  base64UrlEncode,
  constantTimeEqual,
  hexEncode,
  sha256,
  utf8Decode,
  utf8Encode,
} from "../../src/core/encoding.js"

describe("base64url", () => {
  it("round-trips every byte value without padding", () => {
    const bytes = Uint8Array.from({ length: 256 }, (_, i) => i)
    const text = base64UrlEncode(bytes)
    expect(text).not.toMatch(/[+/=]/)
    expect([...base64UrlDecode(text)]).toEqual([...bytes])
  })

  it("matches the RFC 4648 test vectors (url alphabet, no padding)", () => {
    const vectors: [string, string][] = [
      ["", ""],
      ["f", "Zg"],
      ["fo", "Zm8"],
      ["foo", "Zm9v"],
      ["foob", "Zm9vYg"],
      ["fooba", "Zm9vYmE"],
      ["foobar", "Zm9vYmFy"],
    ]
    for (const [plain, encoded] of vectors) {
      expect(base64UrlEncode(utf8Encode(plain))).toBe(encoded)
      expect(utf8Decode(base64UrlDecode(encoded))).toBe(plain)
    }
  })

  it("refuses characters outside the url alphabet and impossible lengths", () => {
    expect(() => base64UrlDecode("ab+c")).toThrow(/base64url/)
    expect(() => base64UrlDecode("abc=")).toThrow(/base64url/)
    expect(() => base64UrlDecode("a")).toThrow(/base64url/)
  })
})

describe("utf8", () => {
  it("refuses malformed input instead of substituting U+FFFD", () => {
    expect(() => utf8Decode(Uint8Array.of(0xc3, 0x28))).toThrow()
  })

  it("encodes and decodes non-ASCII text", () => {
    expect(utf8Decode(utf8Encode("pässwörd 🔐"))).toBe("pässwörd 🔐")
  })
})

describe("hexEncode", () => {
  it("writes two lowercase digits per byte", () => {
    expect(hexEncode(Uint8Array.of(0, 15, 16, 255))).toBe("000f10ff")
  })
})

describe("sha256", () => {
  it("matches the FIPS 180-2 'abc' vector", async () => {
    expect(hexEncode(await sha256(utf8Encode("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )
  })
})

describe("constantTimeEqual", () => {
  it("is true only for equal bytes of equal length", () => {
    expect(constantTimeEqual(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 3))).toBe(true)
    expect(constantTimeEqual(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 4))).toBe(false)
    expect(constantTimeEqual(Uint8Array.of(9, 2, 3), Uint8Array.of(1, 2, 3))).toBe(false)
    expect(constantTimeEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2, 3))).toBe(false)
    expect(constantTimeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true)
    expect(constantTimeEqual(Uint8Array.of(1, 2, 0), Uint8Array.of(1, 2, 0))).toBe(true)
  })
})
