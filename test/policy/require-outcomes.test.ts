// ADR 0005 §7: `require` answers with exactly one of five outcomes.
import { describe, expect, it } from "vitest"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import { hardwareKey, HOUR, MINUTE, passkey, password, T0, totp } from "../support/evidence.js"
import { sessionState } from "../support/session-state.js"

const policy = defineAuthPolicy({
  version: "1",
  requirements: {
    "profile.read": { level: "AAL1" },
    "billing.update": { level: "AAL2", multiFactorWithinMs: 15 * MINUTE },
    "keys.rotate": {
      level: "AAL2",
      phishingResistant: true,
      phishingResistantWithinMs: 5 * MINUTE,
    },
    "admin.root": { level: "AAL3" },
  },
})

describe("require outcomes", () => {
  it("answers unauthenticated without a session, for an expired one, and for one with no valid evidence", () => {
    expect(policy.require(null, "default", T0)).toEqual({ outcome: "unauthenticated" })
    expect(policy.require(sessionState([password(), totp()]), "default", T0 + HOUR)).toEqual({
      outcome: "unauthenticated",
    })
    expect(
      policy.require(sessionState([password({ at: T0 - 24 * HOUR })]), "profile.read", T0),
    ).toEqual({ outcome: "unauthenticated" })
  })

  it("answers enroll for a pre-auth session and recovery-only for a recovering one, whatever it holds", () => {
    const strong = [hardwareKey()]
    expect(policy.require(sessionState(strong, { state: "pre-auth" }), "profile.read", T0)).toEqual(
      {
        outcome: "enroll",
      },
    )
    expect(
      policy.require(sessionState(strong, { state: "recovery-only" }), "profile.read", T0),
    ).toEqual({ outcome: "recovery-only" })
  })

  it("allows a session that meets the requirement, with its subject and assurance", () => {
    const result = policy.require(sessionState([password(), totp()]), "default", T0)
    expect(result).toMatchObject({
      outcome: "allow",
      subject: "acct-1",
      assurance: { level: "AAL2" },
    })
    expect(policy.require(sessionState([password()]), "profile.read", T0).outcome).toBe("allow")
    expect(policy.require(sessionState([hardwareKey()]), "admin.root", T0).outcome).toBe("allow")
  })

  it("asks a session below the level to step up to that level", () => {
    expect(policy.require(sessionState([password()]), "default", T0)).toMatchObject({
      outcome: "step-up",
      subject: "acct-1",
      missing: [{ kind: "level", level: "AAL2" }],
    })
    expect(policy.require(sessionState([passkey()]), "admin.root", T0)).toMatchObject({
      outcome: "step-up",
      missing: [{ kind: "level", level: "AAL3" }],
    })
  })

  it("asks for phishing resistance when the session has none, and for a fresh ceremony when it is stale", () => {
    expect(policy.require(sessionState([password(), totp()]), "keys.rotate", T0)).toMatchObject({
      outcome: "step-up",
      missing: [
        { kind: "phishing-resistance" },
        { kind: "fresh-phishing-resistance", withinMs: 5 * MINUTE },
      ],
    })
    const now = T0 + 5 * MINUTE
    const stale = sessionState([passkey()], { lastSeenAt: now })
    expect(policy.require(stale, "keys.rotate", now - 1).outcome).toBe("allow")
    expect(policy.require(stale, "keys.rotate", now)).toMatchObject({
      outcome: "step-up",
      missing: [{ kind: "fresh-phishing-resistance", withinMs: 5 * MINUTE }],
    })
  })

  it("asks for a fresh multi-factor ceremony at the exact boundary", () => {
    const now = T0 + 15 * MINUTE
    const state = sessionState([password(), totp()], { lastSeenAt: now })
    expect(policy.require(state, "billing.update", now - 1).outcome).toBe("allow")
    expect(policy.require(state, "billing.update", now)).toMatchObject({
      outcome: "step-up",
      missing: [{ kind: "fresh-multi-factor", withinMs: 15 * MINUTE }],
    })
  })

  it("names every missing piece at once", () => {
    expect(policy.require(sessionState([password()]), "billing.update", T0)).toMatchObject({
      missing: [
        { kind: "level", level: "AAL2" },
        { kind: "fresh-multi-factor", withinMs: 15 * MINUTE },
      ],
    })
    expect(policy.require(sessionState([password()]), "keys.rotate", T0)).toMatchObject({
      missing: [
        { kind: "level", level: "AAL2" },
        { kind: "phishing-resistance" },
        { kind: "fresh-phishing-resistance", withinMs: 5 * MINUTE },
      ],
    })
  })

  it("dates the last multi-factor and phishing-resistant ceremonies from the evidence that proves them", () => {
    const state = sessionState(
      [
        password({ at: T0 }),
        totp({ at: T0 + 10 }),
        passkey({ at: T0 + 20, userVerified: false }),
        password({ at: T0 + 30 }),
      ],
      { lastSeenAt: T0 + 30 },
    )
    expect(policy.assurance(state, T0 + 30)).toMatchObject({
      lastMultiFactorAt: T0 + 20,
      lastPhishingResistantAt: T0 + 20,
    })
    const single = sessionState(
      [password(), passkey({ userVerified: false, phishingResistant: false, at: T0 + 5 })],
      {
        lastSeenAt: T0 + 5,
      },
    )
    expect(policy.assurance(single, T0 + 5)).toMatchObject({
      lastMultiFactorAt: T0,
      lastPhishingResistantAt: null,
    })
    expect(policy.assurance(sessionState([password()]), T0)).toMatchObject({
      lastMultiFactorAt: null,
    })
  })

  it("dates multiple factors from a single strong ceremony and from trusted federation", () => {
    expect(policy.assurance(sessionState([hardwareKey({ at: T0 - 5 })]), T0)).toMatchObject({
      lastMultiFactorAt: T0 - 5,
    })
    const federated = defineAuthPolicy({
      version: "1",
      trust: [{ issuer: "idp.example", acr: { gold: "AAL2" }, maxAuthAgeMs: HOUR }],
    })
    const state = sessionState([
      {
        ...password(),
        method: "oidc",
        federation: { issuer: "idp.example", acr: "gold", amr: [], authTime: T0 },
      },
    ])
    expect(federated.assurance(state, T0)).toMatchObject({ level: "AAL2", lastMultiFactorAt: T0 })
  })

  it("never counts a federated phishing-resistance claim", () => {
    const state = sessionState([
      {
        ...passkey(),
        method: "oidc",
        federation: { issuer: "i", acr: null, amr: [], authTime: T0 },
      },
    ])
    expect(policy.assurance(state, T0)).toMatchObject({ lastPhishingResistantAt: null })
  })

  it("passes the evidence, step-up history and policy version through", () => {
    const evidence = [password(), totp()]
    const stepUps = [{ at: T0, method: "totp" as const }]
    expect(policy.assurance(sessionState(evidence, { stepUps }), T0)).toMatchObject({
      evidence,
      stepUps,
      policyVersion: "1",
    })
  })

  it("throws on a requirement id the policy does not define, never falling back", () => {
    // @ts-expect-error -- an unknown requirement id is a type error (ADR 0005 Open 2)
    expect(() => policy.require(null, "billing.delete", T0)).toThrow(
      'Unknown requirement id "billing.delete".',
    )
    // @ts-expect-error -- an inherited property name is not a requirement id
    expect(() => policy.requirement("toString")).toThrow('Unknown requirement id "toString".')
  })
})
