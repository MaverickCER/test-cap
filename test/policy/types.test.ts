// ADR 0005 §3, §6, §7: the types leave no room for a level, outcome or deviation the decision does not name.
import { describe, expectTypeOf, it } from "vitest"
import type { FederatedLevel } from "../../src/assurance/levels.js"
import type {
  Deviation,
  MissingEvidence,
  Requirement,
  RequireResult,
  SessionAssurance,
  StepUpRecord,
} from "../../src/assurance/policy.js"

describe("policy types", () => {
  it("cap a trust mapping at AAL2", () => {
    expectTypeOf<FederatedLevel>().toEqualTypeOf<"AAL1" | "AAL2">()
  })

  it("name exactly five outcomes and four kinds of missing evidence", () => {
    expectTypeOf<RequireResult["outcome"]>().toEqualTypeOf<
      "allow" | "step-up" | "enroll" | "recovery-only" | "unauthenticated"
    >()
    expectTypeOf<MissingEvidence["kind"]>().toEqualTypeOf<
      "level" | "phishing-resistance" | "fresh-multi-factor" | "fresh-phishing-resistance"
    >()
  })

  it("name the three deviations", () => {
    expectTypeOf<Deviation["kind"]>().toEqualTypeOf<
      "email-sign-in" | "default-below-aal2" | "timeout-lengthened"
    >()
  })

  it("hold no stored level outside the assurance computed from evidence", () => {
    expectTypeOf<keyof Requirement>().toEqualTypeOf<
      "level" | "phishingResistant" | "multiFactorWithinMs" | "phishingResistantWithinMs"
    >()
    expectTypeOf<keyof StepUpRecord>().toEqualTypeOf<"at" | "method">()
    expectTypeOf<keyof SessionAssurance>().toEqualTypeOf<
      | "level"
      | "evidence"
      | "lastMultiFactorAt"
      | "lastPhishingResistantAt"
      | "stepUps"
      | "policyVersion"
      | "idleExpiresAt"
      | "absoluteExpiresAt"
    >()
  })
})
