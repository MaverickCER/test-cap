import { describe, expect, it, vi } from "vitest"
import { fixedClock, sequenceRandom } from "../../src/core/clock.js"
import { setPassword, signInWithPassword } from "../../src/methods/password/method.js"
import { memoryStore } from "../../src/store/memory.js"
import { testHasher } from "../support/argon2.js"

// Every test here runs argon2id behind the shared semaphore; a semaphore that stops granting slots must fail a test
// fast rather than hang the run.
vi.setConfig({ testTimeout: 6_000 })

describe("no truncation (ADR 0010 §5)", () => {
  it("verifies a password that differs only in normalisation form, and refuses one that differs in its last character", async () => {
    const deps = {
      clock: fixedClock(0),
      random: sequenceRandom([2, 7]),
      store: memoryStore(),
      hibp: "off" as const,
      hasher: testHasher,
    }
    // 256 code points in NFC; the decomposed form is longer in code points but normalises to the same string.
    const composed = `${"Å".repeat(128)}${"k".repeat(127)}Z`
    expect(
      (await setPassword(deps, { tenant: "t", accountId: "a", password: composed, alone: true }))
        .ok,
    ).toBe(true)
    const decomposed = composed.normalize("NFD")
    expect([...decomposed].length).toBeGreaterThan(256)
    const signIn = (password: string) =>
      signInWithPassword(deps, { tenant: "t", accountId: "a", password })
    expect(await signIn(decomposed)).toMatchObject({ ok: true })
    expect(await signIn(`${composed.slice(0, -1)}z`)).toEqual({ ok: false, reason: "invalid" })
    expect(await signIn(composed.slice(0, -1))).toEqual({ ok: false, reason: "invalid" })
  })
})
