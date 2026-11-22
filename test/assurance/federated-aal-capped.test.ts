// ADR 0005 §3: a mapped acr yields at most AAL2; a trust config that maps any value to AAL3 is refused at startup.
import { describe, expect, it } from "vitest"
import { levelOf, type TrustedIssuer } from "../../src/assurance/levels.js"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import { ConfigError } from "../../src/core/errors.js"
import { HOUR, oidc, password, T0 } from "../support/evidence.js"

const idp: TrustedIssuer = {
  issuer: "idp.example",
  acr: { silver: "AAL1", gold: "AAL2" },
  amr: { mfa: "AAL2", pwd: "AAL1" },
  maxAuthAgeMs: HOUR,
}
const at = { now: T0, trust: [idp] }

function problems(run: () => unknown): readonly string[] {
  try {
    run()
  } catch (error) {
    if (error instanceof ConfigError) return error.problems
    throw error
  }
  throw new Error("expected a ConfigError")
}

describe("federated assurance is capped at AAL2", () => {
  it("gives the mapped acr level", () => {
    expect(levelOf([oidc("idp.example", "gold")], at)).toBe("AAL2")
    expect(levelOf([oidc("idp.example", "silver")], at)).toBe("AAL1")
  })

  it("gives the highest mapped amr level when the acr is unmapped", () => {
    expect(levelOf([oidc("idp.example", null, ["pwd", "mfa"])], at)).toBe("AAL2")
    expect(levelOf([oidc("idp.example", "other", ["pwd"])], at)).toBe("AAL1")
  })

  it("ages a trusted issuer's level from the upstream authentication, not from local completion", () => {
    const trust = [{ ...idp, maxAuthAgeMs: 300_000 }]
    const upstream = (authTime: number) =>
      oidc("idp.example", "gold", [], {
        at: T0,
        federation: { issuer: "idp.example", acr: "gold", amr: [], authTime },
      })
    // The person signed in at the identity provider an hour before the callback completed here.
    expect(levelOf([upstream(T0 - HOUR)], { now: T0, trust })).toBe("AAL1")
    expect(levelOf([upstream(T0 - 300_000)], { now: T0, trust })).toBe("AAL1")
    expect(levelOf([upstream(T0 - 299_999)], { now: T0, trust })).toBe("AAL2")
    // An upstream time after local completion cannot be true; the age then runs from local completion.
    expect(levelOf([upstream(T0 + HOUR)], { now: T0 + 300_000, trust })).toBe("AAL1")
    expect(levelOf([upstream(T0 + HOUR)], { now: T0 + 299_999, trust })).toBe("AAL2")
  })

  it("does not combine federated evidence with local factors", () => {
    expect(levelOf([oidc("idp.example", "silver"), password()], at)).toBe("AAL1")
  })

  it("refuses a trust config that maps an acr or amr to AAL3, listing every problem", () => {
    const aal3 = "AAL3" as "AAL2"
    expect(
      problems(() =>
        defineAuthPolicy({
          version: "1",
          trust: [{ ...idp, acr: { platinum: aal3 }, amr: { hwk: aal3 } }],
        }),
      ),
    ).toEqual([
      'The trust config maps acr "platinum" of idp.example to AAL3; federated evidence stops at AAL2.',
      'The trust config maps amr "hwk" of idp.example to AAL3; federated evidence stops at AAL2.',
    ])
  })

  it("refuses an unknown level, a missing issuer, a bad maximum age and a duplicate issuer", () => {
    const bad = "AAL9" as "AAL2"
    expect(
      problems(() =>
        defineAuthPolicy({
          version: "1",
          trust: [
            { ...idp, acr: { x: bad } },
            { issuer: "", maxAuthAgeMs: 0 },
            { ...idp, acr: {}, amr: {} },
          ],
        }),
      ),
    ).toEqual([
      'The trust config maps acr "x" of idp.example to AAL9; federated evidence stops at AAL2.',
      "A trusted issuer needs a non-empty issuer.",
      "The maximum authentication age of  must be a whole number of at least 1 ms.",
      "The trust config names idp.example twice.",
    ])
  })
})
