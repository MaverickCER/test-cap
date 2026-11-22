// ADR 0005 §4: the default requirement, used by deny by default, is AAL2.
import { describe, expect, it } from "vitest"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import { password, T0, totp } from "../support/evidence.js"
import { sessionState } from "../support/session-state.js"

describe("default requirement", () => {
  it("is AAL2 and nothing more", () => {
    const policy = defineAuthPolicy({ version: "1" })
    expect(policy.requirement("default")).toEqual({ level: "AAL2" })
    expect(policy.require(sessionState([password()]), "default", T0).outcome).toBe("step-up")
    expect(policy.require(sessionState([password(), totp()]), "default", T0).outcome).toBe("allow")
  })

  it("can be raised without a deviation", () => {
    const policy = defineAuthPolicy({ version: "1", defaultRequirement: { level: "AAL3" } })
    expect(policy.requirement("default")).toEqual({ level: "AAL3" })
    expect(policy.deviations).toEqual([])
  })

  it("keeps each named requirement as declared", () => {
    const policy = defineAuthPolicy({
      version: "1",
      requirements: { "billing.update": { level: "AAL2", phishingResistant: true } },
    })
    expect(policy.requirement("billing.update")).toEqual({ level: "AAL2", phishingResistant: true })
    expect(policy.version).toBe("1")
  })
})
