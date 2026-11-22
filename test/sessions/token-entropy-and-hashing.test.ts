// ADR 0006 §1: 256-bit tokens from the RandomSource; the store holds only the SHA-256.
import { describe, expect, it } from "vitest"
import { base64UrlEncode, hexEncode, sha256, utf8Encode } from "../../src/core/encoding.js"
import { fixedClock } from "../../src/core/clock.js"
import { createSessions } from "../../src/sessions/sessions.js"
import { memoryStore } from "../../src/store/memory.js"
import type { AuthStore } from "../../src/store/port.js"
import { password, T0, totp } from "../support/evidence.js"
import { policy, sequenceRandom, setup, TENANT } from "../support/sessions.js"

describe("session tokens", () => {
  it("draws 32 bytes from the injected random source for the token and 16 for the public id", async () => {
    const sessions = createSessions({
      store: memoryStore(),
      clock: fixedClock(T0),
      random: sequenceRandom([...Array.from({ length: 48 }, (_, i) => i)]),
      policy,
    })
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password(), totp()],
    })
    expect(issued.token).toBe(base64UrlEncode(Uint8Array.from({ length: 32 }, (_, i) => i)))
    expect(issued.id).toBe(base64UrlEncode(Uint8Array.from({ length: 16 }, (_, i) => i + 32)))
  })

  it("stores the session under the SHA-256 of the token and nowhere holds the token", async () => {
    const store = memoryStore()
    const { sessions } = setup({ store })
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password()],
    })
    const key = hexEncode(await sha256(utf8Encode(issued.token)))
    const record = await store.get(TENANT, "session", key)
    expect(record).toMatchObject({ owner: "acct-1", revokedAt: null })
    expect(JSON.stringify(record)).not.toContain(issued.token)
    const listed = await store.listByOwner(TENANT, "session", "acct-1")
    expect(listed.map((entry) => entry.key)).toEqual([key])
  })

  it("refuses to issue a token that collides with a stored one, which only a broken random source causes", async () => {
    const { sessions } = setup({ random: sequenceRandom([7]) })
    await sessions.signIn(TENANT, null, { subject: "acct-1", evidence: [password()] })
    await expect(
      sessions.signIn(TENANT, null, { subject: "acct-2", evidence: [password()] }),
    ).rejects.toThrow(
      "A new session token collided with a stored one; the random source is broken.",
    )
  })

  it("reads nothing from the store for a token that is not 43 base64url characters", async () => {
    const memory = memoryStore()
    const calls: string[] = []
    const store: AuthStore = {
      ...memory,
      get: (...args) => {
        calls.push("get")
        return memory.get(...args)
      },
      revoke: (...args) => {
        calls.push("revoke")
        return memory.revoke(...args)
      },
    }
    const { sessions } = setup({ store })
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password()],
    })
    expect(await sessions.read(TENANT, issued.token)).not.toBeNull()
    calls.length = 0
    for (const token of [
      null,
      "",
      issued.token.slice(1),
      `${issued.token}A`,
      `${issued.token.slice(1)}=`,
    ]) {
      expect(await sessions.read(TENANT, token), String(token)).toBeNull()
      expect(await sessions.signOut(TENANT, token)).toContain("Max-Age=0")
    }
    expect(calls).toEqual([])
  })
})
