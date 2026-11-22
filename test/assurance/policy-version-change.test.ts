// ADR 0005 §2: a session is recomputed under a new policy version from the same evidence.
import { describe, expect, it } from "vitest"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import { HOUR, MINUTE, password, T0, totp } from "../support/evidence.js"
import { sessionState } from "../support/session-state.js"

describe("policy version change", () => {
  it("recomputes the same evidence under the new policy on the next read", () => {
    const state = sessionState([password(), totp()], { lastSeenAt: T0 + 30 * MINUTE })
    const v1 = defineAuthPolicy({ version: "2026-11-01" })
    const v2 = defineAuthPolicy({ version: "2026-11-15", timeouts: { aal2AbsoluteMs: HOUR } })
    expect(v1.assurance(state, T0 + HOUR)).toMatchObject({
      level: "AAL2",
      policyVersion: "2026-11-01",
    })
    expect(v2.assurance(state, T0 + 30 * MINUTE)).toMatchObject({
      level: "AAL2",
      policyVersion: "2026-11-15",
    })
    expect(v2.assurance(state, T0 + HOUR)).toBeNull()
  })
})
