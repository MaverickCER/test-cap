// ADR 0005 §3: a passkey or security key without user verification is single-factor.
import { describe, expect, it } from "vitest"
import { levelOf } from "../../src/assurance/levels.js"
import { hardwareKey, passkey, password, T0, totp } from "../support/evidence.js"

const at = { now: T0 }

describe("passkey without user verification", () => {
  it("makes a passkey with user verification AAL2", () => {
    expect(levelOf([passkey()], at)).toBe("AAL2")
  })

  it("makes a passkey without user verification AAL1, whatever factors it claims", () => {
    expect(levelOf([passkey({ userVerified: false })], at)).toBe("AAL1")
    expect(
      levelOf([passkey({ userVerified: false, factors: ["possession", "knowledge"] })], at),
    ).toBe("AAL1")
    expect(levelOf([hardwareKey({ userVerified: false })], at)).toBe("AAL1")
  })

  it("counts an unverified passkey as possession only, so it adds to a password but not to TOTP", () => {
    expect(levelOf([passkey({ userVerified: false }), password()], at)).toBe("AAL2")
    expect(levelOf([passkey({ userVerified: false }), totp()], at)).toBe("AAL1")
    expect(levelOf([passkey({ userVerified: false }), totp({ userVerified: true })], at)).toBe(
      "AAL1",
    )
  })
})
