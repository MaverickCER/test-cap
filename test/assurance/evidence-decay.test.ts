// ADR 0005 §2 and Open 1, ADR 0006 §4: expired evidence lowers the level, at the exact boundaries.
import { describe, expect, it } from "vitest"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import { hardwareKey, HOUR, MINUTE, password, T0, totp } from "../support/evidence.js"
import { sessionState } from "../support/session-state.js"

const policy = defineAuthPolicy({ version: "1" })
const level = (state: ReturnType<typeof sessionState>, now: number) =>
  policy.assurance(state, now)?.level

describe("evidence decay", () => {
  it("drops evidence 24 hours after its ceremony, lowering the level", () => {
    const state = sessionState([totp({ at: T0 }), password({ at: T0 + HOUR })], {
      startedAt: T0 + HOUR,
      lastSeenAt: T0 + 24 * HOUR - 1,
    })
    expect(level(state, T0 + 24 * HOUR - 1)).toBe("AAL2")
    expect(level(state, T0 + 24 * HOUR)).toBe("AAL1")
  })

  it("decays AAL3 to AAL2 twelve hours after the key's ceremony", () => {
    const state = sessionState([hardwareKey()], { lastSeenAt: T0 + 12 * HOUR - 1 })
    expect(level(state, T0 + 12 * HOUR - 1)).toBe("AAL3")
    expect(level({ ...state, lastSeenAt: T0 + 12 * HOUR }, T0 + 12 * HOUR)).toBe("AAL2")
  })

  it("decays AAL3 to AAL2 after 15 minutes idle, and keeps AAL2 until an hour idle", () => {
    const state = sessionState([hardwareKey()])
    expect(level(state, T0 + 15 * MINUTE - 1)).toBe("AAL3")
    expect(level(state, T0 + 15 * MINUTE)).toBe("AAL2")
    expect(level(state, T0 + HOUR - 1)).toBe("AAL2")
  })

  it("ignores evidence dated after now", () => {
    expect(level(sessionState([password(), totp({ at: T0 + 1 })]), T0)).toBe("AAL1")
    expect(level(sessionState([password(), totp({ at: T0 })]), T0)).toBe("AAL2")
  })

  it("gives an authenticated session no level once every piece of evidence has expired", () => {
    const state = sessionState([password({ at: T0 - 24 * HOUR })])
    expect(policy.assurance(state, T0)).toMatchObject({ level: null, evidence: [] })
  })

  it("ends the session at its idle and absolute limits, from the injected time", () => {
    const state = sessionState([password(), totp()])
    expect(policy.assurance(state, T0 + HOUR - 1)).not.toBeNull()
    expect(policy.assurance(state, T0 + HOUR)).toBeNull()
    const busy = { ...state, lastSeenAt: T0 + 24 * HOUR - 1 }
    expect(policy.assurance(busy, T0 + 24 * HOUR - 1)).not.toBeNull()
    expect(policy.assurance(busy, T0 + 24 * HOUR)).toBeNull()
  })

  it("gives pre-auth and recovery-only sessions 15 minutes idle and 1 hour absolute", () => {
    for (const kind of ["pre-auth", "recovery-only"] as const) {
      const state = sessionState([password()], { state: kind })
      expect(policy.assurance(state, T0 + 15 * MINUTE - 1), kind).not.toBeNull()
      expect(policy.assurance(state, T0 + 15 * MINUTE), kind).toBeNull()
      const busy = { ...state, lastSeenAt: T0 + HOUR - 1 }
      expect(policy.assurance(busy, T0 + HOUR - 1), kind).not.toBeNull()
      expect(policy.assurance(busy, T0 + HOUR), kind).toBeNull()
    }
  })

  it("reports when the session ends", () => {
    expect(
      policy.assurance(sessionState([password()], { lastSeenAt: T0 + 5 }), T0 + 5),
    ).toMatchObject({
      idleExpiresAt: T0 + 5 + HOUR,
      absoluteExpiresAt: T0 + 24 * HOUR,
    })
    expect(policy.assurance(sessionState([password()], { state: "pre-auth" }), T0)).toMatchObject({
      idleExpiresAt: T0 + 15 * MINUTE,
      absoluteExpiresAt: T0 + HOUR,
    })
    expect(policy.assurance(sessionState([hardwareKey()]), T0)).toMatchObject({
      idleExpiresAt: T0 + HOUR,
    })
  })

  it("applies shortened timeouts from the policy", () => {
    const short = defineAuthPolicy({
      version: "1",
      timeouts: {
        aal2IdleMs: MINUTE,
        aal3IdleMs: 30_000,
        aal3AbsoluteMs: HOUR,
        aal2AbsoluteMs: 2 * HOUR,
      },
    })
    const state = sessionState([hardwareKey()])
    expect(short.assurance(state, T0 + 30_000)?.level).toBe("AAL2")
    expect(short.assurance(state, T0 + MINUTE)).toBeNull()
    expect(short.assurance({ ...state, lastSeenAt: T0 + HOUR }, T0 + HOUR)?.level).toBe("AAL2")
    expect(short.assurance({ ...state, lastSeenAt: T0 + 2 * HOUR }, T0 + 2 * HOUR)).toBeNull()
    const restricted = defineAuthPolicy({
      version: "1",
      timeouts: { restrictedIdleMs: MINUTE, restrictedAbsoluteMs: 2 * MINUTE },
    })
    const preAuth = sessionState([], { state: "pre-auth" })
    expect(restricted.assurance(preAuth, T0 + MINUTE)).toBeNull()
    expect(
      restricted.assurance({ ...preAuth, lastSeenAt: T0 + 2 * MINUTE }, T0 + 2 * MINUTE),
    ).toBeNull()
  })
})
