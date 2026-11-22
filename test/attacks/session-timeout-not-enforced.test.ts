// Attack: a session outlives its idle or absolute limit.
// Stopped by: 1 h / 24 h at AAL2, 15 min / 12 h at AAL3, from the injected clock (ADR 0006).
import { describe, expect, it } from "vitest"
import { hardwareKey, HOUR, MINUTE, password, T0, totp } from "../support/evidence.js"
import { setup, TENANT } from "../support/sessions.js"

describe("session-timeout-not-enforced", () => {
  it("ends an AAL2 session after an hour idle, not a millisecond sooner", async () => {
    const { sessions, clock } = setup()
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password(), totp()],
    })
    clock.set(T0 + HOUR - 1)
    expect((await sessions.require(TENANT, issued.token, "default")).outcome).toBe("allow")
    clock.set(T0 + 2 * HOUR - 1)
    expect(await sessions.require(TENANT, issued.token, "default")).toEqual({
      outcome: "unauthenticated",
    })
    expect(await sessions.read(TENANT, issued.token)).toBeNull()
    expect(await sessions.rotate(TENANT, issued.token)).toBeNull()
  })

  it("ends an AAL2 session 24 hours after sign-in however active it is", async () => {
    const { sessions, clock } = setup()
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password(), totp()],
    })
    for (let step = 1; step < 48; step += 1) {
      clock.set(T0 + step * 30 * MINUTE)
      expect((await sessions.read(TENANT, issued.token))?.id, String(step)).toBe(issued.id)
    }
    clock.set(T0 + 24 * HOUR - 1)
    expect((await sessions.require(TENANT, issued.token, "default")).outcome).toBe("allow")
    clock.set(T0 + 24 * HOUR)
    expect(await sessions.require(TENANT, issued.token, "default")).toEqual({
      outcome: "unauthenticated",
    })
  })

  it("drops an AAL3 session to AAL2 after 15 minutes idle and after 12 hours", async () => {
    const { sessions, clock } = setup()
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [hardwareKey()],
    })
    clock.set(T0 + 15 * MINUTE - 1)
    expect((await sessions.require(TENANT, issued.token, "admin.root")).outcome).toBe("allow")
    clock.set(T0 + 30 * MINUTE - 1)
    expect(await sessions.require(TENANT, issued.token, "admin.root")).toMatchObject({
      outcome: "step-up",
      missing: [{ kind: "level", level: "AAL3" }],
    })
    expect((await sessions.require(TENANT, issued.token, "default")).outcome).toBe("allow")
    for (let step = 1; step <= 140; step += 1) {
      clock.set(T0 + 30 * MINUTE + step * 5 * MINUTE)
      if (clock.now() < T0 + 12 * HOUR) await sessions.read(TENANT, issued.token)
    }
    clock.set(T0 + 12 * HOUR - 1)
    expect((await sessions.require(TENANT, issued.token, "admin.root")).outcome).toBe("allow")
    clock.set(T0 + 12 * HOUR)
    expect((await sessions.require(TENANT, issued.token, "admin.root")).outcome).toBe("step-up")
  })

  it("ends a pre-auth session after 15 minutes idle", async () => {
    const { sessions, clock } = setup()
    const issued = await sessions.begin(TENANT, null, { subject: "acct-1", state: "pre-auth" })
    clock.set(T0 + 15 * MINUTE)
    expect(await sessions.require(TENANT, issued.token, "default")).toEqual({
      outcome: "unauthenticated",
    })
  })
})
