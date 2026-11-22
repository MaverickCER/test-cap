import type { AuthenticationEvidence } from "../../src/assurance/evidence.js"
import type { SessionState } from "../../src/assurance/policy.js"
import { T0 } from "./evidence.js"

/** An authenticated session state started and last seen at T0, unless overridden. */
export function sessionState(
  evidence: readonly AuthenticationEvidence[],
  overrides: Partial<SessionState> = {},
): SessionState {
  return {
    subject: "acct-1",
    state: "authenticated",
    evidence,
    stepUps: [],
    startedAt: T0,
    lastSeenAt: T0,
    ...overrides,
  }
}
