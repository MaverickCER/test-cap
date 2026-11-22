import { describe, expect, it } from "vitest"
import { normaliseEmail } from "../../src/core/identifier.js"

describe("email identifier normalisation (ADR 0021 §6, Open 3)", () => {
  it.each([
    ["ada@example.com", "ada@example.com"],
    ["Ada.Lovelace@Example.COM", "ada.lovelace@example.com"],
    ["a+tag@sub.example.co", "a+tag@sub.example.co"],
    ["x@a.bc", "x@a.bc"],
    ["ADA@BÜCHER.example", "ada@xn--bcher-kva.example"],
    ["ada@bücher.example", "ada@xn--bcher-kva.example"],
    // The decomposed ü (u + U+0308) composes to the same value under NFC.
    ["ada@bücher.example", "ada@xn--bcher-kva.example"],
    ["ünïcode@example.com", "ünïcode@example.com"],
    ["a@1.example", "a@1.example"],
    ["a@a-b.example", "a@a-b.example"],
  ])("normalises %s to %s", (raw, normalised) => {
    expect(normaliseEmail(raw)).toBe(normalised)
  })

  it.each([
    ["surrounding whitespace", " ada@example.com"],
    ["a trailing newline", "ada@example.com\n"],
    ["a non-breaking space", "ada @example.com"],
    ["a control character", "ada\u0000@example.com"],
    ["a C1 control character", "ada\u0085@example.com"],
    ["DEL", "ada\u007f@example.com"],
    ["a quote", '"ada"@example.com'],
    ["a comma", "a,b@example.com"],
    ["parentheses", "a(b)@example.com"],
    ["a colon", "a:b@example.com"],
    ["a semicolon", "a;b@example.com"],
    ["angle brackets", "<ada@example.com>"],
    ["square brackets", "ada@[127.0.0.1]"],
    ["a backslash", "a\\b@example.com"],
    ["no at sign", "ada.example.com"],
    ["two at signs", "a@b@example.com"],
    ["an empty local part", "@example.com"],
    ["an empty domain", "ada@"],
    ["a leading dot", ".ada@example.com"],
    ["a trailing dot", "ada.@example.com"],
    ["two dots in a row", "a..b@example.com"],
    ["a single-label domain", "ada@localhost"],
    ["an IP address", "ada@192.168.0.1"],
    ["a trailing dot in the domain", "ada@example.com."],
    ["a slash in the domain", "ada@example.com/x"],
    ["a question mark in the domain", "ada@example.com?x"],
    ["a hash in the domain", "ada@example.com#x"],
    ["a percent in the domain", "ada@ex%61mple.com"],
    ["a port", "ada@example.com:25"],
    ["a domain a URL parser refuses", "ada@exa^mple.com"],
    ["an underscore in the domain", "ada@ex_ample.com"],
    ["a label starting with a hyphen", "ada@-example.com"],
    ["a label ending with a hyphen", "ada@example-.com"],
    ["a numeric last label", "ada@example.123"],
    ["an empty label", "ada@example..com"],
  ])("refuses %s", (_name, raw) => {
    expect(normaliseEmail(raw)).toBeNull()
  })

  it("accepts a 63-character label and refuses a 64-character one", () => {
    expect(normaliseEmail(`a@${"b".repeat(63)}.example`)).toBe(`a@${"b".repeat(63)}.example`)
    expect(normaliseEmail(`a@${"b".repeat(64)}.example`)).toBeNull()
    expect(normaliseEmail(`a@example.${"c".repeat(63)}`)).toBe(`a@example.${"c".repeat(63)}`)
    expect(normaliseEmail(`a@example.${"c".repeat(64)}`)).toBeNull()
  })

  it("accepts a 64-character local part and refuses 65, counting code points", () => {
    expect(normaliseEmail(`${"a".repeat(64)}@example.com`)).not.toBeNull()
    expect(normaliseEmail(`${"a".repeat(65)}@example.com`)).toBeNull()
    expect(normaliseEmail(`${"😀".repeat(64)}@example.com`)).not.toBeNull()
  })

  it("accepts 254 code points in all and refuses 255", () => {
    const domain = `${"d".repeat(60)}.${"e".repeat(60)}.${"f".repeat(60)}.${"g".repeat(8)}`
    const fits = `${"a".repeat(254 - 1 - domain.length)}@${domain}`
    expect(fits).toHaveLength(254)
    expect(normaliseEmail(fits)).toBe(fits)
    expect(normaliseEmail(`a${fits}`)).toBeNull()
    const astral = `${"😀".repeat(254 - 1 - domain.length)}@${domain}`
    expect(normaliseEmail(astral)).toBe(astral)
  })
})
