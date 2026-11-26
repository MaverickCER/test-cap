// Attack: two parallel requests rotate one session and both new tokens stay valid. Stopped by: rotation claims the
// old token once, so of parallel rotations exactly one issues a session (ADR 0002, 0006).
import { describe, expect, it } from "vitest"
import { password, totp } from "../support/evidence.js"
import { setup, TENANT } from "../support/sessions.js"

describe("session-rotation-race", () => {
  it("issues exactly one new session from parallel rotations of one token", async () => {
    const { sessions, clock } = setup()
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password({ at: clock.now() }), totp({ at: clock.now() })],
    })
    const results = await Promise.all(
      Array.from({ length: 10 }, () => sessions.rotate(TENANT, issued.token)),
    )
    expect(results.filter((result) => result !== null)).toHaveLength(1)
    expect(await sessions.read(TENANT, issued.token)).toBeNull()
  })
})
