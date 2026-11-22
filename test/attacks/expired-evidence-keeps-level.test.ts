// Attack: a session keeps a level after the evidence that supported it has expired.
// Stopped by: session assurance is recomputed from the evidence still valid on every check (ADR 0005).
import { describe, expect, it } from "vitest"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import { hardwareKey, HOUR, password, T0, totp } from "../support/evidence.js"
import { sessionState } from "../support/session-state.js"

describe("expired-evidence-keeps-level", () => {
  const policy = defineAuthPolicy({
    version: "1",
    requirements: { "admin.root": { level: "AAL3" } },
  })

  it("lowers the level once the second factor's evidence expires, with no stored level to keep it", () => {
    const state = sessionState([totp({ at: T0 - 2 * HOUR }), password()], {
      lastSeenAt: T0 + 22 * HOUR - 1,
    })
    expect(policy.require(state, "default", T0 + 22 * HOUR - 1).outcome).toBe("allow")
    expect(
      policy.require({ ...state, lastSeenAt: T0 + 22 * HOUR }, "default", T0 + 22 * HOUR),
    ).toMatchObject({
      outcome: "step-up",
      missing: [{ kind: "level", level: "AAL2" }],
    })
  })

  it("lowers AAL3 to AAL2 once the key's AAL3 lifetime ends", () => {
    const state = sessionState([hardwareKey({ at: T0 - 12 * HOUR })])
    expect(policy.require(state, "admin.root", T0)).toMatchObject({ outcome: "step-up" })
    expect(policy.require(state, "default", T0)).toMatchObject({ outcome: "allow" })
  })
})
