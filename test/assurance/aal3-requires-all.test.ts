// ADR 0005 §3: AAL3 needs a non-exportable key, verified attestation, user verification and phishing resistance.
import { describe, expect, it } from "vitest"
import { levelOf } from "../../src/assurance/levels.js"
import { hardwareKey, password, T0, totp } from "../support/evidence.js"

const at = { now: T0 }

describe("AAL3 requires all four conditions", () => {
  it("makes a key meeting all four AAL3", () => {
    expect(levelOf([hardwareKey()], at)).toBe("AAL3")
  })

  it("drops the level when any one condition is removed", () => {
    expect(levelOf([hardwareKey({ keyProtection: "syncable" })], at)).toBe("AAL2")
    expect(levelOf([hardwareKey({ attestationVerified: false })], at)).toBe("AAL2")
    expect(levelOf([hardwareKey({ phishingResistant: false })], at)).toBe("AAL2")
    expect(levelOf([hardwareKey({ userVerified: false })], at)).toBe("AAL1")
  })

  it("needs user verification even from evidence that claims two factors without possession", () => {
    expect(
      levelOf([hardwareKey({ factors: ["knowledge", "inherence"], userVerified: false })], at),
    ).toBe("AAL2")
  })

  it("needs two factors from the one key", () => {
    expect(levelOf([hardwareKey({ factors: ["possession"] })], at)).toBe("AAL1")
  })

  it("never gives AAL3 for attestation alone", () => {
    expect(
      levelOf([password({ attestationVerified: true }), totp({ attestationVerified: true })], at),
    ).toBe("AAL2")
    expect(
      levelOf([totp({ attestationVerified: true, keyProtection: "non-exportable" })], at),
    ).toBe("AAL1")
  })

  it("never gives AAL3 to a key whose AAL3 window has passed", () => {
    expect(levelOf([hardwareKey()], { now: T0, aal3After: T0 })).toBe("AAL2")
    expect(levelOf([hardwareKey()], { now: T0, aal3After: T0 - 1 })).toBe("AAL3")
  })
})
