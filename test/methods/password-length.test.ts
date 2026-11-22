import { describe, expect, it } from "vitest"
import {
  checkPasswordLength,
  codePointLength,
  normalisePassword,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_ALONE,
  PASSWORD_MIN_WITH_MFA,
} from "../../src/methods/password/rules.js"

const of = (length: number, char = "a"): string => char.repeat(length)

describe("password length (ADR 0010 §5)", () => {
  it("declares 8 within MFA, 15 alone and a 256 maximum", () => {
    expect([PASSWORD_MIN_WITH_MFA, PASSWORD_MIN_ALONE, PASSWORD_MAX_LENGTH]).toEqual([8, 15, 256])
  })

  it("needs 8 characters while multi-factor authentication is required", () => {
    expect(checkPasswordLength(normalisePassword(of(7)), { alone: false })).toBe("too-short")
    expect(checkPasswordLength(normalisePassword(of(8)), { alone: false })).toBeUndefined()
  })

  it("needs 15 characters when a password alone satisfies a requirement", () => {
    expect(checkPasswordLength(normalisePassword(of(14)), { alone: true })).toBe("too-short")
    expect(checkPasswordLength(normalisePassword(of(15)), { alone: true })).toBeUndefined()
  })

  it("accepts 256 characters and refuses 257", () => {
    expect(checkPasswordLength(normalisePassword(of(256)), { alone: false })).toBeUndefined()
    expect(checkPasswordLength(normalisePassword(of(257)), { alone: true })).toBe("too-long")
  })

  it("counts code points, not UTF-16 units", () => {
    const emoji = "\u{1F512}"
    expect(codePointLength(normalisePassword(emoji.repeat(8)))).toBe(8)
    expect(
      checkPasswordLength(normalisePassword(emoji.repeat(8)), { alone: false }),
    ).toBeUndefined()
    expect(
      checkPasswordLength(normalisePassword(emoji.repeat(256)), { alone: false }),
    ).toBeUndefined()
    expect(checkPasswordLength(normalisePassword(emoji.repeat(257)), { alone: false })).toBe(
      "too-long",
    )
  })

  it("counts the NFC form, so a decomposed character counts once", () => {
    const decomposed = "é".repeat(8)
    expect(decomposed.length).toBe(16)
    expect(normalisePassword(decomposed)).toBe("é".repeat(8))
    expect(codePointLength(normalisePassword("é".repeat(7)))).toBe(7)
    expect(checkPasswordLength(normalisePassword("é".repeat(7)), { alone: false })).toBe(
      "too-short",
    )
  })

  it("applies no composition rule", () => {
    for (const password of ["aaaaaaaa", "12345670", "        ", "ABCDEFGH"]) {
      expect(checkPasswordLength(normalisePassword(password), { alone: false })).toBeUndefined()
    }
  })
})
