// ADR 0006 §5: a new token on every change of trust; the old token stops working at once.
import { describe, expect, it } from "vitest"
import { memoryStore } from "../../src/store/memory.js"
import type { AuthStore } from "../../src/store/port.js"
import { MINUTE, password, T0, totp, hardwareKey } from "../support/evidence.js"
import { setup, stepUp, TENANT } from "../support/sessions.js"

async function signedIn(store?: AuthStore) {
  const context = setup(store === undefined ? {} : { store })
  const issued = await context.sessions.signIn(TENANT, null, {
    subject: "acct-1",
    evidence: [password(), totp()],
  })
  return { ...context, issued }
}

describe("rotation", () => {
  it("refuses a session past its limit in every operation that loads it, with no read before", async () => {
    const { sessions, clock, issued } = await signedIn()
    clock.advance(2 * 60 * MINUTE)
    expect(await sessions.rotate(TENANT, issued.token)).toBeNull()
    expect(await sessions.credentialChanged(TENANT, issued.token)).toBeNull()
    expect(await sessions.beginStepUp(TENANT, issued.token)).toBeNull()
    expect(await sessions.list(TENANT, issued.token)).toBeNull()
    expect(await sessions.revoke(TENANT, issued.token, issued.id)).toBe(false)
  })

  it("rotates on step-up, adding the evidence and recording the step-up", async () => {
    const { sessions, clock, issued } = await signedIn()
    clock.advance(MINUTE)
    const next = await stepUp(sessions, issued.token, hardwareKey({ at: T0 + MINUTE }))
    expect(next?.token).not.toBe(issued.token)
    expect(await sessions.read(TENANT, issued.token)).toBeNull()
    expect((await sessions.read(TENANT, next?.token ?? null))?.state).toMatchObject({
      evidence: [password(), totp(), hardwareKey({ at: T0 + MINUTE })],
      stepUps: [{ at: T0 + MINUTE, method: "passkey" }],
      startedAt: T0,
      lastSeenAt: T0 + MINUTE,
    })
    expect(next?.id).not.toBe(issued.id)
  })

  it("keeps the absolute limit across a rotation inside the authenticated state", async () => {
    const { sessions, clock, issued } = await signedIn()
    clock.advance(30 * MINUTE)
    const next = await sessions.rotate(TENANT, issued.token)
    expect(next?.cookie).toContain(`Max-Age=${String(24 * 3600 - 30 * 60)};`)
  })

  it("rotates on a privilege change and on the start and end of impersonation and break-glass", async () => {
    for (const trigger of [
      "privilege-change",
      "impersonation-start",
      "impersonation-end",
      "break-glass-start",
      "break-glass-end",
    ] as const) {
      const { sessions, issued } = await signedIn()
      const sibling = await sessions.signIn(TENANT, null, {
        subject: "acct-1",
        evidence: [password(), totp()],
      })
      const next = await sessions.rotate(TENANT, issued.token)
      expect(await sessions.read(TENANT, sibling.token), trigger).not.toBeNull()
      expect(next?.token, trigger).not.toBe(issued.token)
      expect(await sessions.read(TENANT, issued.token), trigger).toBeNull()
      expect(await sessions.require(TENANT, next?.token ?? null, "default"), trigger).toMatchObject(
        {
          outcome: "allow",
        },
      )
    }
  })

  it("rotates on a credential change and revokes the account's other sessions, not another account's", async () => {
    const { sessions, issued } = await signedIn()
    const other = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password(), totp()],
    })
    const stranger = await sessions.signIn(TENANT, null, {
      subject: "acct-2",
      evidence: [password(), totp()],
    })
    const next = await sessions.credentialChanged(TENANT, issued.token)
    expect(await sessions.read(TENANT, issued.token)).toBeNull()
    expect(await sessions.read(TENANT, other.token)).toBeNull()
    expect(await sessions.read(TENANT, next?.token ?? null)).not.toBeNull()
    expect(await sessions.read(TENANT, stranger.token)).not.toBeNull()
  })

  it("rotates at the end of enrolment, carrying the pre-auth evidence into a new authenticated session", async () => {
    const { sessions, clock } = setup()
    const preAuth = await sessions.begin(TENANT, null, {
      subject: "acct-1",
      state: "pre-auth",
      evidence: [password()],
    })
    expect(preAuth.cookie).toContain("Max-Age=3600;")
    expect(await sessions.require(TENANT, preAuth.token, "default")).toEqual({ outcome: "enroll" })
    clock.advance(MINUTE)
    const done = await sessions.completeEnrolment(TENANT, preAuth.token, [
      totp({ at: T0 + MINUTE }),
    ])
    expect(await sessions.read(TENANT, preAuth.token)).toBeNull()
    expect(done?.cookie).toContain("Max-Age=86400;")
    expect(await sessions.require(TENANT, done?.token ?? null, "default")).toMatchObject({
      outcome: "allow",
    })
    expect((await sessions.read(TENANT, done?.token ?? null))?.state).toMatchObject({
      state: "authenticated",
      startedAt: T0 + MINUTE,
    })
  })

  it("ends the recovery-only session when recovery finishes, so its token carries no later trust", async () => {
    const { sessions } = setup()
    const recovering = await sessions.begin(TENANT, null, {
      subject: "acct-1",
      state: "recovery-only",
    })
    expect(await sessions.require(TENANT, recovering.token, "profile.read")).toEqual({
      outcome: "recovery-only",
    })
    expect(await sessions.endRecovery(TENANT, recovering.token)).toBe(
      "__Host-test-cap=-; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
    )
    expect(await sessions.read(TENANT, recovering.token)).toBeNull()
  })

  it("starts a pre-auth or recovery-only session with no evidence unless given, and no step-ups", async () => {
    const { sessions } = setup()
    const recovering = await sessions.begin(TENANT, null, {
      subject: "acct-1",
      state: "recovery-only",
    })
    expect((await sessions.read(TENANT, recovering.token))?.state).toMatchObject({
      evidence: [],
      stepUps: [],
    })
  })

  it("refuses a change that does not fit the session's state", async () => {
    const { sessions, issued } = await signedIn()
    expect(await sessions.completeEnrolment(TENANT, issued.token, [totp()])).toBeNull()
    const recovering = await sessions.begin(TENANT, null, {
      subject: "acct-1",
      state: "recovery-only",
    })
    expect(await sessions.beginStepUp(TENANT, recovering.token)).toBeNull()
    expect(await sessions.completeEnrolment(TENANT, recovering.token, [totp()])).toBeNull()
    expect(await sessions.read(TENANT, recovering.token)).not.toBeNull()
    expect(await sessions.read(TENANT, issued.token)).not.toBeNull()
    expect(await sessions.beginStepUp(TENANT, "x".repeat(43))).toBeNull()
  })

  it("lets only one of two concurrent rotations of one token win, even without store transactions", async () => {
    const memory = memoryStore()
    const plain: AuthStore = { ...memory }
    delete (plain as { transaction?: unknown }).transaction
    const { sessions, issued } = await signedIn(plain)
    const results = await Promise.all([
      sessions.rotate(TENANT, issued.token),
      sessions.rotate(TENANT, issued.token),
    ])
    expect(results.filter((result) => result !== null)).toHaveLength(1)
    expect(await memory.listByOwner(TENANT, "session", "acct-1")).toHaveLength(2)
  })

  it("refuses to rotate a record that changed between its read and its claim", async () => {
    const memory = memoryStore()
    let interfere = false
    const store: AuthStore = {
      ...memory,
      async get(tenant, collection, key) {
        const record = await memory.get(tenant, collection, key)
        if (interfere && record !== null) {
          interfere = false
          await memory.update(tenant, collection, key, record.version, {})
        }
        return record
      },
    }
    delete (store as { transaction?: unknown }).transaction
    const { sessions, issued } = await signedIn(store)
    interfere = true
    expect(await sessions.rotate(TENANT, issued.token)).toBeNull()
    expect(await memory.listByOwner(TENANT, "session", "acct-1")).toHaveLength(1)
  })

  it("uses the store's transaction when it has one", async () => {
    const memory = memoryStore()
    let used = 0
    const store: AuthStore = {
      ...memory,
      transaction: (fn) => {
        used += 1
        return memory.transaction(fn)
      },
    }
    const { sessions, issued } = await signedIn(store)
    used = 0
    await sessions.rotate(TENANT, issued.token)
    expect(used).toBe(1)
  })
})
