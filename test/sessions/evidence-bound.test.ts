// ADR 0005 §2: a session keeps only the newest evidence of each (method, authenticator), and the newest step-up of
// each method, so a signed-in attacker cannot grow the session record (and the work every read does on it) by
// stepping up again and again.
import { describe, expect, it } from "vitest"
import { memoryStore } from "../../src/store/memory.js"
import type { AuthStore } from "../../src/store/port.js"
import { password, totp } from "../support/evidence.js"
import { setup, stepUp, TENANT } from "../support/sessions.js"

describe("the evidence a session keeps", () => {
  it("is at most one TOTP entry per authenticator after 1,000 verifies", async () => {
    // The memory store's transactions copy the whole store to roll back, which over 2,000 rotated records would make
    // this loop quadratic; without them each rotation is the same sequence of single operations.
    const store = Object.fromEntries(
      Object.entries(memoryStore()).filter(([name]) => name !== "transaction"),
    ) as unknown as AuthStore
    const { sessions, clock } = setup({ store })
    let { token } = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password({ at: clock.now() })],
    })
    for (let verify = 0; verify < 1_000; verify += 1) {
      clock.advance(1_000)
      const authenticatorId = verify % 2 === 0 ? "totp-1" : "totp-2"
      const issued = await stepUp(sessions, token, totp({ authenticatorId, at: clock.now() }))
      if (issued === null) throw new Error(`step-up ${verify} failed`)
      token = issued.token
    }
    clock.advance(1_000)
    const last = await stepUp(sessions, token, password({ at: clock.now() }))
    const read = await sessions.read(TENANT, last?.token ?? "")
    const evidence = read?.state.evidence ?? []
    expect(evidence.map((item) => [item.method, item.authenticatorId, item.at])).toEqual([
      ["totp", "totp-1", clock.now() - 2_000],
      ["totp", "totp-2", clock.now() - 1_000],
      ["password", "pw-1", clock.now()],
    ])
    expect(read?.state.stepUps).toEqual([
      { at: clock.now() - 1_000, method: "totp" },
      { at: clock.now(), method: "password" },
    ])
    expect(read?.assurance.level).toBe("AAL2")
  })

  it("keeps the newest entry of each authenticator, oldest first, whatever order they arrive in", async () => {
    const { sessions, clock } = setup()
    const t = clock.now()
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [
        totp({ at: t - 3 }),
        password({ at: t - 1 }),
        totp({ at: t - 2 }),
        password({ at: t - 4 }),
        totp({ authenticatorId: "totp-2", at: t - 2 }),
      ],
    })
    expect(issued.state.evidence.map((item) => [item.authenticatorId, item.at])).toEqual([
      ["totp-1", t - 2],
      ["totp-2", t - 2],
      ["pw-1", t - 1],
    ])
    const read = await sessions.read(TENANT, issued.token)
    expect(read?.state.evidence).toEqual(issued.state.evidence)
  })

  it("keeps the later of two entries of one authenticator at the same time", async () => {
    const { sessions, clock } = setup()
    const t = clock.now()
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [totp({ at: t, replayResistant: false }), totp({ at: t, replayResistant: true })],
    })
    expect(issued.state.evidence.map((item) => item.replayResistant)).toEqual([true])
  })

  it("keeps one entry of a method whose authenticators differ only by method", async () => {
    const { sessions, clock } = setup()
    const t = clock.now()
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [
        password({ authenticatorId: "x", at: t - 1 }),
        totp({ authenticatorId: "x", at: t }),
      ],
    })
    expect(issued.state.evidence.map((item) => item.method)).toEqual(["password", "totp"])
  })
})
