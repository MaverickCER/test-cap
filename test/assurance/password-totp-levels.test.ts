// ADR 0005 §3: password alone and TOTP alone are AAL1; together they are AAL2.
import { describe, expect, it } from "vitest"
import { atLeast, levelOf } from "../../src/assurance/levels.js"
import { password, T0, totp } from "../support/evidence.js"

const at = { now: T0 }

describe("password and TOTP levels", () => {
  it("gives no level without evidence", () => {
    expect(levelOf([], at)).toBeNull()
  })

  it("makes a password alone AAL1", () => {
    expect(levelOf([password()], at)).toBe("AAL1")
  })

  it("makes TOTP alone AAL1", () => {
    expect(levelOf([totp()], at)).toBe("AAL1")
  })

  it("makes a password plus TOTP AAL2, in either order", () => {
    expect(levelOf([password(), totp()], at)).toBe("AAL2")
    expect(levelOf([totp(), password()], at)).toBe("AAL2")
  })

  it("never adds two ceremonies of the same factor into a second factor", () => {
    expect(levelOf([password(), password({ authenticatorId: "pw-2" })], at)).toBe("AAL1")
    expect(levelOf([totp(), totp({ authenticatorId: "totp-2" })], at)).toBe("AAL1")
  })

  it("orders levels", () => {
    expect(atLeast("AAL1", "AAL1")).toBe(true)
    expect(atLeast("AAL1", "AAL2")).toBe(false)
    expect(atLeast("AAL2", "AAL1")).toBe(true)
    expect(atLeast("AAL2", "AAL3")).toBe(false)
    expect(atLeast("AAL3", "AAL3")).toBe(true)
  })
})
