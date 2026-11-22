// ADR 0005 §5 and the plan's assurance tests: email codes and magic links add no level, with or without the deviation.
import { describe, expect, it } from "vitest"
import { levelOf } from "../../src/assurance/levels.js"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import { foreign, password, T0 } from "../support/evidence.js"

const at = { now: T0 }

describe("email never raises the level", () => {
  it("gives evidence from a method outside the list no level, however strong it claims to be", () => {
    for (const method of ["email", "magic-link", "email-code"]) {
      expect(levelOf([foreign(method)], at), method).toBeNull()
      expect(levelOf([password(), foreign(method)], at), method).toBe("AAL1")
    }
  })

  it("gives a recovery code no level: it moves a session to recovery-only, never to assurance (ADR 0007)", () => {
    expect(levelOf([foreign("recovery-code")], at)).toBeNull()
    expect(levelOf([password(), foreign("recovery-code")], at)).toBe("AAL1")
  })

  it("leaves every level unchanged when the email deviation is on", () => {
    const strict = defineAuthPolicy({ version: "1" })
    const relaxed = defineAuthPolicy({ version: "1", emailSignIn: true })
    const evidence = [password(), foreign("email")]
    const session = {
      subject: "acct-1",
      state: "authenticated" as const,
      evidence,
      stepUps: [],
      startedAt: T0,
      lastSeenAt: T0,
    }
    expect(relaxed.assurance(session, T0)?.level).toBe("AAL1")
    expect(relaxed.require(session, "default", T0)).toEqual(strict.require(session, "default", T0))
  })
})
