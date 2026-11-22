// Attack: a password from a breach corpus is accepted at sign-up or reset.
// Stopped by: the bundled blocklist, always on, plus the HIBP range check with padding (ADR 0010).
import { describe, expect, it, vi } from "vitest"
import { fixedClock, sequenceRandom } from "../../src/core/clock.js"
import type { HibpFetch } from "../../src/methods/password/hibp.js"
import { PASSWORD_COLLECTION, setPassword } from "../../src/methods/password/method.js"
import { memoryStore } from "../../src/store/memory.js"
import { testHasher } from "../support/argon2.js"

// Every test here runs argon2id behind the shared semaphore; a semaphore that stops granting slots must fail a test
// fast rather than hang the run.
vi.setConfig({ testTimeout: 6_000 })

// SHA-1("Tr0ub4dor&3") starts 3B9C7; the answer lists its suffix with a breach count.
async function corpusWith(password: string): Promise<HibpFetch> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-1", new TextEncoder().encode(password)),
  )
  const hex = [...digest]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase()
  return () =>
    Promise.resolve({
      ok: true,
      status: 200,
      text: () => Promise.resolve(`${hex.slice(5)}:42\r\n`),
    })
}

describe("breached-password-accepted", () => {
  it("refuses a password the breach corpus lists, and stores nothing", async () => {
    const store = memoryStore()
    const deps = {
      clock: fixedClock(0),
      random: sequenceRandom([9]),
      store,
      hibp: await corpusWith("Tr0ub4dor&3 leaked"),
      hasher: testHasher,
    }
    expect(
      await setPassword(deps, {
        tenant: "t",
        accountId: "a",
        password: "Tr0ub4dor&3 leaked",
        alone: false,
      }),
    ).toEqual({
      ok: false,
      reason: "breached",
    })
    expect(await store.get("t", PASSWORD_COLLECTION, "a")).toBeNull()
  })

  it("refuses a bundled common password even with the breach check turned off", async () => {
    const deps = {
      clock: fixedClock(0),
      random: sequenceRandom([9]),
      store: memoryStore(),
      hibp: "off" as const,
      hasher: testHasher,
    }
    expect(
      await setPassword(deps, { tenant: "t", accountId: "a", password: "iloveyou1", alone: false }),
    ).toEqual({
      ok: false,
      reason: "too-common",
    })
  })
})
