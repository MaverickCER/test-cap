// ADR 0005 §6: every relaxation is a deviation the policy lists.
import { describe, expect, it } from "vitest"
import { DEFAULT_TIMEOUTS, defineAuthPolicy } from "../../src/assurance/policy.js"
import { ConfigError } from "../../src/core/errors.js"
import { HOUR, MINUTE } from "../support/evidence.js"

function problems(run: () => unknown): readonly string[] {
  try {
    run()
  } catch (error) {
    if (error instanceof ConfigError) return error.problems
    throw error
  }
  throw new Error("expected a ConfigError")
}

describe("deviations", () => {
  it("lists none for the strict defaults, and shortened limits are free", () => {
    expect(defineAuthPolicy({ version: "1" }).deviations).toEqual([])
    expect(
      defineAuthPolicy({ version: "1", emailSignIn: false, timeouts: { aal2IdleMs: MINUTE } })
        .deviations,
    ).toEqual([])
  })

  it("keeps the ADR 0006 limits as defaults", () => {
    expect(DEFAULT_TIMEOUTS).toEqual({
      aal2IdleMs: HOUR,
      aal2AbsoluteMs: 24 * HOUR,
      aal3IdleMs: 15 * MINUTE,
      aal3AbsoluteMs: 12 * HOUR,
      restrictedIdleMs: 15 * MINUTE,
      restrictedAbsoluteMs: HOUR,
    })
    expect(defineAuthPolicy({ version: "1", timeouts: { aal2IdleMs: MINUTE } }).timeouts).toEqual({
      ...DEFAULT_TIMEOUTS,
      aal2IdleMs: MINUTE,
    })
  })

  it("lists email sign-in, a default below AAL2 and every lengthened limit", () => {
    const policy = defineAuthPolicy({
      version: "1",
      emailSignIn: true,
      defaultRequirement: { level: "AAL1" },
      timeouts: { aal2IdleMs: HOUR + 1, aal3AbsoluteMs: 12 * HOUR, restrictedAbsoluteMs: 2 * HOUR },
    })
    expect(policy.deviations).toEqual([
      {
        kind: "email-sign-in",
        detail: "Email sign-in codes and magic links are on; they add no assurance (ADR 0005).",
      },
      { kind: "default-below-aal2", detail: "The default requirement is AAL1, below AAL2." },
      {
        kind: "timeout-lengthened",
        detail: "aal2IdleMs is 3600001 ms, longer than the ADR 0006 limit of 3600000 ms.",
      },
      {
        kind: "timeout-lengthened",
        detail: "restrictedAbsoluteMs is 7200000 ms, longer than the ADR 0006 limit of 3600000 ms.",
      },
    ])
  })

  it("refuses a policy it cannot run, listing every problem", () => {
    const level = "AAL4" as "AAL1"
    expect(
      problems(() =>
        defineAuthPolicy({
          version: "",
          requirements: {
            "Billing.Update": { level: "AAL2" },
            default: { level: "AAL2" },
            "a.b": { level, multiFactorWithinMs: 0, phishingResistantWithinMs: 1.5 },
          },
          defaultRequirement: { level },
          timeouts: { aal2IdleMs: -1 },
        }),
      ),
    ).toEqual([
      "The policy version must be a non-empty string.",
      'Requirement id "Billing.Update" must be lowercase words joined by dots, such as billing.update.',
      'Requirement id "default" is reserved for the default requirement.',
      'Requirement "a.b" names an unknown level "AAL4".',
      'Requirement "a.b" has a multiFactorWithinMs that is not a whole number of at least 1 ms.',
      'Requirement "a.b" has a phishingResistantWithinMs that is not a whole number of at least 1 ms.',
      'Requirement "default" names an unknown level "AAL4".',
      "Timeout aal2IdleMs must be a whole number of at least 1 ms.",
    ])
  })

  it("accepts every well-formed id and a limit of 1 ms", () => {
    expect(() =>
      defineAuthPolicy({
        version: "1",
        requirements: {
          a: { level: "AAL1", multiFactorWithinMs: 1 },
          "a-1.b-2": { level: "AAL2" },
        },
        timeouts: { aal2IdleMs: 1 },
        trust: [{ issuer: "idp.example", maxAuthAgeMs: 1 }],
      }),
    ).not.toThrow()
  })
})
