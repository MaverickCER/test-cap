import { describe, expect, it } from "vitest"
import { RETURN_TO_MAX_LENGTH, safeReturnTo } from "../../src/security/redirect.js"

const ORIGIN = "https://app.example"

describe("returnTo (ADR 0026 §5)", () => {
  it.each(["/", "/account", "/a/b?x=1#top", "/%2F%2Fevil.example", "/@evil.example"])(
    "accepts the same-origin relative path %s unchanged",
    (value) => {
      expect(safeReturnTo(value, ORIGIN)).toBe(value)
    },
  )

  it.each([
    ["a protocol-relative target", "//evil.example/x"],
    ["a protocol-relative target to the app's own host", "//app.example/x"],
    ["a backslash target", "/\\evil.example"],
    ["a backslash anywhere", "/a\\b"],
    ["a tab browsers strip", "/\t/evil.example"],
    ["a newline", "/a\nb"],
    ["a space", "/a b"],
    ["a control character", "/a\u0001b"],
    ["DEL", "/a\u007fb"],
    ["an absolute URL on the app's own origin", "https://app.example/account"],
    ["an absolute URL elsewhere", "https://evil.example/"],
    ["an origin that only starts with the app's", "https://app.example.evil.example/"],
    ["javascript:", "javascript:alert(1)"],
    ["data:", "data:text/html,<script>alert(1)</script>"],
    ["a relative path without a leading slash", "account"],
    ["an empty value", ""],
  ])("refuses %s", (_name, value) => {
    expect(safeReturnTo(value, ORIGIN)).toBeNull()
  })

  it("accepts up to the length limit and refuses one character more", () => {
    const longest = `/${"a".repeat(RETURN_TO_MAX_LENGTH - 1)}`
    expect(safeReturnTo(longest, ORIGIN)).toBe(longest)
    expect(safeReturnTo(`${longest}a`, ORIGIN)).toBeNull()
  })
})
