// ADR 0005 §2: `recency` finds `lastMultiFactorAt` and `lastPhishingResistantAt` in one pass over the evidence sorted
// by time (a suffix scan). This pins it against the definition it replaced, which checked every item's suffix in turn
// (quadratic): the latest time, over the items whose suffix of evidence (every item at or after it) still proves
// multiple factors, with federated evidence counting from min(authTime, at); and the latest phishing-resistant local
// ceremony. The seed is fixed, so a failure replays exactly.
import fc from "fast-check"
import { beforeAll, describe, expect, it } from "vitest"
import type { AuthenticationEvidence } from "../../src/assurance/evidence.js"
import { isLocal, levelOf, type LevelContext, recency } from "../../src/assurance/levels.js"

beforeAll(() => {
  fc.configureGlobal({ seed: 0x7e5c, numRuns: 1_000 })
})

const latest = (times: readonly number[]): number | null =>
  times.length === 0 ? null : Math.max(...times)

/** The definition `recency` replaced, exactly as policy.ts computed it before. */
function reference(evidence: readonly AuthenticationEvidence[], context: LevelContext) {
  const multiFactor = (items: readonly AuthenticationEvidence[]) => {
    const level = levelOf(items, context)
    return level === "AAL2" || level === "AAL3"
  }
  return {
    lastMultiFactorAt: latest(
      evidence
        .filter((item) => multiFactor(evidence.filter((other) => other.at >= item.at)))
        .map((item) => Math.min(item.federation?.authTime ?? item.at, item.at)),
    ),
    lastPhishingResistantAt: latest(
      evidence.filter((item) => isLocal(item) && item.phishingResistant).map((item) => item.at),
    ),
  }
}

// A small time domain around zero, so equal times (one another's suffix) are common and a time can be negative.
const at = fc.integer({ min: -3, max: 3 })
const factors = fc.subarray(["knowledge", "possession", "inherence"] as const)
const evidence: fc.Arbitrary<AuthenticationEvidence> = fc
  .record({
    method: fc.constantFrom("password", "totp", "passkey", "oidc", "saml", "email"),
    authenticatorId: fc.constantFrom("a", "b"),
    factors,
    phishingResistant: fc.boolean(),
    replayResistant: fc.boolean(),
    keyProtection: fc.constantFrom("unknown", "syncable", "non-exportable"),
    userVerified: fc.boolean(),
    attestationVerified: fc.boolean(),
    at,
    authTime: at,
    acr: fc.constantFrom("gold", "silver", null),
    amr: fc.subarray(["mfa", "pwd"]),
    issuer: fc.constantFrom("idp.example", "other.example"),
  })
  .map(({ authTime, acr, amr, issuer, ...item }) =>
    item.method === "oidc" || item.method === "saml"
      ? ({ ...item, federation: { issuer, acr, amr, authTime } } as AuthenticationEvidence)
      : (item as AuthenticationEvidence),
  )
const context: fc.Arbitrary<LevelContext> = fc.record({
  now: fc.integer({ min: -3, max: 9 }),
  aal3After: fc.constantFrom(-Infinity, -1, 1, Infinity),
  trust: fc.constant([
    {
      issuer: "idp.example",
      acr: { gold: "AAL2", silver: "AAL1" },
      amr: { mfa: "AAL2" },
      maxAuthAgeMs: 5,
    },
  ] as const),
})

describe("recency", () => {
  it("equals the per-item suffix definition on any evidence", () => {
    fc.assert(
      fc.property(fc.array(evidence, { maxLength: 12 }), context, (items, ctx) => {
        expect(recency(items, ctx)).toEqual(reference(items, ctx))
      }),
    )
  })

  it("is null for both times with no evidence", () => {
    expect(recency([], { now: 0 })).toEqual({
      lastMultiFactorAt: null,
      lastPhishingResistantAt: null,
    })
  })
})
