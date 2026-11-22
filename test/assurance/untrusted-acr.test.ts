// ADR 0005 §3 and the plan's assurance tests: an untrusted acr never raises the level.
import { describe, expect, it } from "vitest"
import { levelOf, type TrustedIssuer } from "../../src/assurance/levels.js"
import { HOUR, oidc, password, T0 } from "../support/evidence.js"

const idp: TrustedIssuer = { issuer: "idp.example", acr: { gold: "AAL2" }, maxAuthAgeMs: HOUR }

describe("untrusted acr", () => {
  it("gives AAL1 to an issuer outside the trust config, whatever acr and amr it reports", () => {
    expect(levelOf([oidc("evil.example", "gold", ["mfa", "hwk"])], { now: T0, trust: [idp] })).toBe(
      "AAL1",
    )
    expect(levelOf([oidc("idp.example", "gold")], { now: T0 })).toBe("AAL1")
  })

  it("gives AAL1 to an unmapped acr, a missing acr, and an issuer with no amr mapping", () => {
    expect(levelOf([oidc("idp.example", "aal3")], { now: T0, trust: [idp] })).toBe("AAL1")
    expect(levelOf([oidc("idp.example", null, ["mfa"])], { now: T0, trust: [idp] })).toBe("AAL1")
  })

  it("gives AAL1 to a federated method that carries no federation details", () => {
    expect(levelOf([password({ method: "oidc" })], { now: T0, trust: [idp] })).toBe("AAL1")
    expect(
      levelOf([{ ...oidc("idp.example", "gold"), method: "saml" }], { now: T0, trust: [idp] }),
    ).toBe("AAL2")
  })

  it("never matches a missing acr against a mapping named null", () => {
    const odd: TrustedIssuer = { issuer: "idp.example", acr: { null: "AAL2" }, maxAuthAgeMs: HOUR }
    expect(levelOf([oidc("idp.example", null)], { now: T0, trust: [odd] })).toBe("AAL1")
    expect(levelOf([oidc("idp.example", "null")], { now: T0, trust: [odd] })).toBe("AAL2")
  })

  it("gives a trusted issuer's unmapped sign-in AAL1, and reads an amr-only mapping", () => {
    const amrOnly: TrustedIssuer = {
      issuer: "idp.example",
      amr: { mfa: "AAL2" },
      maxAuthAgeMs: HOUR,
    }
    expect(levelOf([oidc("idp.example", null)], { now: T0, trust: [idp] })).toBe("AAL1")
    expect(levelOf([oidc("idp.example", "gold", ["mfa"])], { now: T0, trust: [amrOnly] })).toBe(
      "AAL2",
    )
  })

  it("counts an authentication older than the issuer's maximum age as AAL1, at the exact boundary", () => {
    const trust = [idp]
    expect(levelOf([oidc("idp.example", "gold")], { now: T0 + HOUR - 1, trust })).toBe("AAL2")
    expect(levelOf([oidc("idp.example", "gold")], { now: T0 + HOUR, trust })).toBe("AAL1")
  })
})
