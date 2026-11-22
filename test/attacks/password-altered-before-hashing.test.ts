// Attack: a password is truncated, trimmed or case-folded before hashing, so variants verify.
// Stopped by: normalised once to NFC, then hashed whole; over 256 characters refused (ADR 0010).
import { describe, expect, it, vi } from "vitest"
import { fixedClock, sequenceRandom } from "../../src/core/clock.js"
import { setPassword, signInWithPassword } from "../../src/methods/password/method.js"
import { memoryStore } from "../../src/store/memory.js"
import { testHasher } from "../support/argon2.js"

// Every test here runs argon2id behind the shared semaphore; a semaphore that stops granting slots must fail a test
// fast rather than hang the run.
vi.setConfig({ testTimeout: 6_000 })

const deps = () => ({
  clock: fixedClock(0),
  random: sequenceRandom([3, 141, 59]),
  store: memoryStore(),
  hibp: "off" as const,
  hasher: testHasher,
})

describe("password-altered-before-hashing", () => {
  it("verifies a password that differs only in normalisation form, and no other variant", async () => {
    const d = deps()
    const password = `Café ${"x".repeat(240)} Tail`
    expect((await setPassword(d, { tenant: "t", accountId: "a", password, alone: false })).ok).toBe(
      true,
    )
    const signIn = (candidate: string) =>
      signInWithPassword(d, { tenant: "t", accountId: "a", password: candidate })
    expect(await signIn(password.replace("é", "é"))).toMatchObject({ ok: true })
    for (const variant of [
      password.slice(0, -1),
      password.slice(0, 72),
      ` ${password}`,
      `${password} `,
      password.toLowerCase(),
      password.toUpperCase(),
    ]) {
      expect(await signIn(variant), JSON.stringify(variant.slice(-8))).toEqual({
        ok: false,
        reason: "invalid",
      })
    }
  })

  it("refuses over 256 characters rather than truncating them", async () => {
    const d = deps()
    expect(
      await setPassword(d, {
        tenant: "t",
        accountId: "a",
        password: "y".repeat(257),
        alone: false,
      }),
    ).toEqual({
      ok: false,
      reason: "too-long",
    })
    expect(
      await signInWithPassword(d, { tenant: "t", accountId: "a", password: "y".repeat(257) }),
    ).toEqual({
      ok: false,
      reason: "too-long",
    })
  })
})
