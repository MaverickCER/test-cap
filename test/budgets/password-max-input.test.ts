import * as hashWasm from "hash-wasm"
import { describe, expect, it, vi } from "vitest"
import { fixedClock, sequenceRandom } from "../../src/core/clock.js"
import { setPassword, signInWithPassword } from "../../src/methods/password/method.js"
import { memoryStore } from "../../src/store/memory.js"
import { testHasher } from "../support/argon2.js"

// Every test here runs argon2id behind the shared semaphore; a semaphore that stops granting slots must fail a test
// fast rather than hang the run.
vi.setConfig({ testTimeout: 6_000 })

vi.mock("hash-wasm", async (importOriginal) => {
  const original = await importOriginal<typeof import("hash-wasm")>()
  return {
    ...original,
    argon2Verify: vi.fn(original.argon2Verify),
    argon2id: vi.fn(original.argon2id),
  }
})

describe("password input is capped at 256 characters (ADR 0018 §3)", () => {
  it("refuses longer input at set and at sign-in before any argon2id runs", async () => {
    const deps = {
      clock: fixedClock(0),
      random: sequenceRandom([1]),
      store: memoryStore(),
      hibp: "off" as const,
      hasher: testHasher,
    }
    for (const length of [257, 1_000, 100_000]) {
      const password = "p".repeat(length)
      expect(
        await setPassword(deps, { tenant: "t", accountId: "a", password, alone: false }),
      ).toEqual({
        ok: false,
        reason: "too-long",
      })
      expect(await signInWithPassword(deps, { tenant: "t", accountId: "a", password })).toEqual({
        ok: false,
        reason: "too-long",
      })
    }
    expect(hashWasm.argon2id).not.toHaveBeenCalled()
    expect(hashWasm.argon2Verify).not.toHaveBeenCalled()
  })
})
