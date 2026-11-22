// ADR 0006 §7: a user sees and revokes their own sessions, never another user's.
import { describe, expect, it } from "vitest"
import { HOUR, MINUTE, password, T0, totp } from "../support/evidence.js"
import { setup, TENANT } from "../support/sessions.js"

describe("session list", () => {
  it("lists the caller's live sessions, marking the current one, with times and methods", async () => {
    const { sessions, clock } = setup()
    const a = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password(), totp()],
    })
    clock.advance(MINUTE)
    const b = await sessions.signIn(TENANT, null, { subject: "acct-1", evidence: [password()] })
    await sessions.signIn(TENANT, null, { subject: "acct-2", evidence: [password()] })
    const revoked = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password()],
    })
    await sessions.signOut(TENANT, revoked.token)
    expect(await sessions.list(TENANT, b.token)).toEqual([
      {
        id: a.id,
        current: false,
        state: "authenticated",
        startedAt: T0,
        lastSeenAt: T0,
        methods: ["password", "totp"],
      },
      {
        id: b.id,
        current: true,
        state: "authenticated",
        startedAt: T0 + MINUTE,
        lastSeenAt: T0 + MINUTE,
        methods: ["password"],
      },
    ])
  })

  it("leaves out sessions past their limits, and lists nothing without a valid session", async () => {
    const { sessions, clock } = setup()
    await sessions.signIn(TENANT, null, { subject: "acct-1", evidence: [password()] })
    clock.advance(HOUR)
    const fresh = await sessions.signIn(TENANT, null, { subject: "acct-1", evidence: [password()] })
    expect((await sessions.list(TENANT, fresh.token))?.map((entry) => entry.id)).toEqual([fresh.id])
    expect(await sessions.list(TENANT, null)).toBeNull()
  })

  it("revokes one of the caller's own sessions by id, never another account's", async () => {
    const { sessions } = setup()
    const mine = await sessions.signIn(TENANT, null, { subject: "acct-1", evidence: [password()] })
    const lost = await sessions.signIn(TENANT, null, { subject: "acct-1", evidence: [password()] })
    const theirs = await sessions.signIn(TENANT, null, {
      subject: "acct-2",
      evidence: [password()],
    })
    expect(await sessions.revoke(TENANT, mine.token, theirs.id)).toBe(false)
    expect(await sessions.read(TENANT, theirs.token)).not.toBeNull()
    expect(await sessions.revoke(TENANT, mine.token, lost.id)).toBe(true)
    expect(await sessions.read(TENANT, lost.token)).toBeNull()
    expect(await sessions.revoke(TENANT, mine.token, lost.id)).toBe(false)
    expect(await sessions.revoke(TENANT, null, mine.id)).toBe(false)
    expect(await sessions.read(TENANT, mine.token)).not.toBeNull()
  })
})
