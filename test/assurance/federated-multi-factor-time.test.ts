// ADR 0005 §3: federated evidence proves its factors as of the upstream authentication, so the time a requirement's
// `multiFactorWithinMs` runs from is min(authTime, at), exactly as the issuer's maximum age is.
import { describe, expect, it } from "vitest"
import type { TrustedIssuer } from "../../src/assurance/levels.js"
import { defineAuthPolicy, type SessionState } from "../../src/assurance/policy.js"
import { MINUTE, oidc, T0 } from "../support/evidence.js"

const idp: TrustedIssuer = {
  issuer: "idp.example",
  acr: { gold: "AAL2" },
  maxAuthAgeMs: 60 * MINUTE,
}
const policy = defineAuthPolicy({
  version: "federated mfa time",
  trust: [idp],
  requirements: { export: { level: "AAL2", multiFactorWithinMs: 5 * MINUTE } },
})

/** A session whose one piece of evidence is a gold OIDC sign-in completed here at T0, upstream at `authTime`. */
function session(authTime: number): SessionState {
  return {
    subject: "acct-1",
    state: "authenticated",
    evidence: [
      oidc("idp.example", "gold", [], {
        at: T0,
        federation: { issuer: "idp.example", acr: "gold", amr: [], authTime },
      }),
    ],
    stepUps: [],
    startedAt: T0,
    lastSeenAt: T0,
  }
}

describe("the multi-factor time of federated evidence", () => {
  it("is the upstream authentication time when it came first", () => {
    const state = session(T0 - 10 * MINUTE)
    expect(policy.assurance(state, T0)?.lastMultiFactorAt).toBe(T0 - 10 * MINUTE)
    // Ten minutes since the factors were proved is past the requirement's five, though the callback was just now.
    expect(policy.require(state, "export", T0).outcome).toBe("step-up")
    expect(policy.require(state, "default", T0).outcome).toBe("allow")
  })

  it("is the local completion time when the reported upstream time is later", () => {
    const state = session(T0 + 10 * MINUTE)
    expect(policy.assurance(state, T0)?.lastMultiFactorAt).toBe(T0)
    expect(policy.require(state, "export", T0 + 5 * MINUTE - 1).outcome).toBe("allow")
  })
})
