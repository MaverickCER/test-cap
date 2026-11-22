// Sentinels for the assurance model (ADR 0005): the level evidence supports, its recency, and the policy's checks.
// Every flow computes these, so a mutant here is covered by most of the suite; these direct checks kill it first.
import { describe, expect, it } from "vitest"
import { levelOf, recency, type TrustedIssuer } from "../../src/assurance/levels.js"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import { ConfigError } from "../../src/core/errors.js"
import {
  foreign,
  hardwareKey,
  HOUR,
  MINUTE,
  oidc,
  passkey,
  password,
  T0,
  totp,
} from "../support/evidence.js"

const NOW = { now: T0 }
const idp: TrustedIssuer = { issuer: "idp.example", acr: { gold: "AAL2" }, maxAuthAgeMs: HOUR }

/** The problems `run` is refused with; empty when it is not refused. */
function problemsOf(run: () => unknown): readonly string[] {
  try {
    run()
  } catch (error) {
    return error instanceof ConfigError ? error.problems : [String(error)]
  }
  return []
}

describe("the level evidence supports", () => {
  it("counts a possession authenticator that did not verify the person as possession alone", () => {
    expect(levelOf([passkey({ userVerified: false })], NOW)).toBe("AAL1")
    expect(levelOf([passkey()], NOW)).toBe("AAL2")
    expect(levelOf([password(), totp()], NOW)).toBe("AAL2")
    expect(levelOf([totp()], NOW)).toBe("AAL1")
    // Each proves possession only, so together they are still one factor.
    expect(levelOf([passkey({ userVerified: false }), totp()], NOW)).toBe("AAL1")
    expect(levelOf([hardwareKey({ factors: ["possession"] }), totp()], NOW)).toBe("AAL1")
  })

  it("gives AAL3 only to a two-factor hardware key completed after the AAL3 cut-off", () => {
    expect(levelOf([hardwareKey()], NOW)).toBe("AAL3")
    expect(levelOf([hardwareKey({ factors: ["possession"] })], NOW)).toBe("AAL1")
    expect(levelOf([hardwareKey()], { now: T0, aal3After: T0 })).toBe("AAL2")
    expect(levelOf([hardwareKey()], { now: T0, aal3After: T0 - 1 })).toBe("AAL3")
    expect(levelOf([hardwareKey({ userVerified: false })], NOW)).toBe("AAL1")
  })

  it("gives evidence from a method outside the list nothing, and federated evidence only what its issuer maps", () => {
    expect(levelOf([foreign("email-link")], NOW)).toBeNull()
    expect(levelOf([], NOW)).toBeNull()
    expect(levelOf([oidc("idp.example", "gold")], NOW)).toBe("AAL1")
    expect(levelOf([oidc("idp.example", "gold")], { now: T0, trust: [idp] })).toBe("AAL2")
  })

  it("dates multi-factor proof from the newest suffix that proves it, and federated proof from its authentication", () => {
    expect(recency([password({ at: T0 - MINUTE }), totp({ at: T0 })], NOW)).toEqual({
      lastMultiFactorAt: T0 - MINUTE,
      lastPhishingResistantAt: null,
    })
    expect(recency([password()], NOW)).toEqual({
      lastMultiFactorAt: null,
      lastPhishingResistantAt: null,
    })
    expect(recency([passkey({ at: T0 - MINUTE })], NOW)).toEqual({
      lastMultiFactorAt: T0 - MINUTE,
      lastPhishingResistantAt: T0 - MINUTE,
    })
    const federated = oidc("idp.example", "gold", [], {
      at: T0,
      federation: { issuer: "idp.example", acr: "gold", amr: [], authTime: T0 - MINUTE },
    })
    expect(recency([federated], { now: T0, trust: [idp] }).lastMultiFactorAt).toBe(T0 - MINUTE)
  })
})

describe("the policy", () => {
  it("lists every problem of an invalid policy at once", () => {
    expect(
      problemsOf(() =>
        defineAuthPolicy({
          version: "",
          requirements: {
            default: { level: "AAL1" },
            "Bad Id": { level: "AAL2" },
            "billing.update": { level: "AAL9" as "AAL2", multiFactorWithinMs: 0 },
            "keys.rotate": { level: "AAL2", phishingResistantWithinMs: 1.5 },
          },
          timeouts: { aal2IdleMs: 0 },
        }),
      ),
    ).toEqual([
      "The policy version must be a non-empty string.",
      'Requirement id "default" is reserved for the default requirement.',
      'Requirement id "Bad Id" must be lowercase words joined by dots, such as billing.update.',
      'Requirement "billing.update" names an unknown level "AAL9".',
      'Requirement "billing.update" has a multiFactorWithinMs that is not a whole number of at least 1 ms.',
      'Requirement "keys.rotate" has a phishingResistantWithinMs that is not a whole number of at least 1 ms.',
      "Timeout aal2IdleMs must be a whole number of at least 1 ms.",
    ])
    expect(
      problemsOf(() =>
        defineAuthPolicy({ version: "1", defaultRequirement: { level: "AAL9" as "AAL2" } }),
      ),
    ).toEqual(['Requirement "default" names an unknown level "AAL9".'])
  })

  it("accepts a whole millisecond of recency and the default limits, and reports each deviation", () => {
    const strict = defineAuthPolicy({
      version: "1",
      requirements: { "billing.update": { level: "AAL2", multiFactorWithinMs: 1 } },
      timeouts: { aal2IdleMs: HOUR },
    })
    expect(strict.deviations).toEqual([])
    const relaxed = defineAuthPolicy({
      version: "1",
      emailSignIn: true,
      defaultRequirement: { level: "AAL1" },
      timeouts: { aal2IdleMs: HOUR + 1 },
    })
    expect(relaxed.deviations).toEqual([
      {
        kind: "email-sign-in",
        detail: "Email sign-in codes and magic links are on; they add no assurance (ADR 0005).",
      },
      { kind: "default-below-aal2", detail: "The default requirement is AAL1, below AAL2." },
      {
        kind: "timeout-lengthened",
        detail: "aal2IdleMs is 3600001 ms, longer than the ADR 0006 limit of 3600000 ms.",
      },
    ])
  })

  it("ends a pre-auth session at 15 idle minutes, drops evidence from the future, and holds AAL3 only while recent", () => {
    const policy = defineAuthPolicy({ version: "1" })
    const enrolling = {
      subject: "a",
      state: "pre-auth" as const,
      evidence: [password()],
      stepUps: [],
      startedAt: T0,
      lastSeenAt: T0,
    }
    expect(policy.assurance(enrolling, T0 + 15 * MINUTE - 1)).not.toBeNull()
    expect(policy.assurance(enrolling, T0 + 15 * MINUTE)).toBeNull()
    expect(policy.require(enrolling, "default", T0 + 15 * MINUTE)).toEqual({
      outcome: "unauthenticated",
    })
    expect(policy.require(enrolling, "default", T0)).toEqual({ outcome: "enroll" })
    const signedIn = { ...enrolling, state: "authenticated" as const, evidence: [hardwareKey()] }
    expect(policy.assurance(signedIn, T0 - 1)?.level).toBeNull()
    expect(policy.assurance(signedIn, T0 + 15 * MINUTE - 1)?.level).toBe("AAL3")
    expect(policy.assurance(signedIn, T0 + 15 * MINUTE)?.level).toBe("AAL2")
  })
})
