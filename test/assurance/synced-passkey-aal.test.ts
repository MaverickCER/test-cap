// ADR 0005 §3 and the plan's assurance tests: a synced passkey never reaches AAL3.
import { describe, expect, it } from "vitest"
import { levelOf } from "../../src/assurance/levels.js"
import { hardwareKey, passkey, password, T0, totp } from "../support/evidence.js"

const at = { now: T0 }

describe("synced passkey", () => {
  it("stops a backup-eligible passkey at AAL2 even when attested, verified and phishing-resistant", () => {
    expect(levelOf([passkey({ attestationVerified: true })], at)).toBe("AAL2")
  })

  it("treats unknown key protection as exportable", () => {
    expect(levelOf([hardwareKey({ keyProtection: "unknown" })], at)).toBe("AAL2")
  })

  it("never reaches AAL3 by adding more evidence to a synced passkey", () => {
    expect(
      levelOf([passkey({ attestationVerified: true }), password(), totp(), passkey()], at),
    ).toBe("AAL2")
  })
})
