// Attack: comparing a token, code or CSRF value leaks how many leading bytes matched. Stopped by: tokens and codes are
// looked up by hash, and the comparisons that remain (CSRF tags, TOTP codes) are constant-time (ADR 0006, 0011).
import { readFileSync } from "node:fs"
import { describe, expect, it } from "vitest"
import { constantTimeEqual } from "../../src/core/encoding.js"

describe("secret-comparison-timing", () => {
  it("compares every byte whatever the first difference", () => {
    const a = Uint8Array.from({ length: 32 }, (_, i) => i)
    let reads = 0
    const counted = new Proxy(a, {
      get(target, property) {
        if (property === "entries") {
          return function* () {
            for (const pair of target.entries()) {
              reads += 1
              yield pair
            }
          }
        }
        const value = Reflect.get(target, property) as unknown
        return typeof value === "function"
          ? (value as (...args: unknown[]) => unknown).bind(target)
          : value
      },
    })
    const firstByteDiffers = Uint8Array.from(a, (byte, i) => (i === 0 ? byte ^ 1 : byte))
    expect(constantTimeEqual(counted, firstByteDiffers)).toBe(false)
    expect(reads).toBe(32)
    expect(constantTimeEqual(a, Uint8Array.from(a))).toBe(true)
    expect(constantTimeEqual(a, a.slice(1))).toBe(false)
  })

  it("compares CSRF tags and TOTP codes with it, and looks sessions and codes up by hash", () => {
    for (const file of ["src/security/csrf.ts", "src/methods/totp/totp.ts"]) {
      expect(readFileSync(file, "utf8"), file).toMatch(/constantTimeEqual\(/)
    }
    const sessions = readFileSync("src/sessions/sessions.ts", "utf8")
    expect(sessions).toMatch(/sha256|hashToken/i)
  })
})
