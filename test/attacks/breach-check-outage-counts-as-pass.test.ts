// Attack: HIBP is unreachable and the password is recorded as screened.
// Stopped by: the screening is recorded `indeterminate` on the authenticator and in what sign-in returns (ADR 0010).
import { describe, expect, it, vi } from "vitest"
import { fixedClock, sequenceRandom } from "../../src/core/clock.js"
import type { HibpFetch } from "../../src/methods/password/hibp.js"
import {
  PASSWORD_COLLECTION,
  setPassword,
  signInWithPassword,
} from "../../src/methods/password/method.js"
import { memoryStore } from "../../src/store/memory.js"
import { testHasher } from "../support/argon2.js"

// Every test here runs argon2id behind the shared semaphore; a semaphore that stops granting slots must fail a test
// fast rather than hang the run.
vi.setConfig({ testTimeout: 6_000 })

const down: HibpFetch = () => Promise.reject(new TypeError("getaddrinfo ENOTFOUND"))
const failing: HibpFetch = () =>
  Promise.resolve({ ok: false, status: 503, text: () => Promise.resolve("") })

describe("breach-check-outage-counts-as-pass", () => {
  it("records indeterminate, never clear, when HIBP cannot be reached or fails", async () => {
    for (const hibp of [down, failing]) {
      const store = memoryStore()
      const deps = {
        clock: fixedClock(0),
        random: sequenceRandom([5, 6]),
        store,
        hibp,
        hasher: testHasher,
      }
      const set = await setPassword(deps, {
        tenant: "t",
        accountId: "a",
        password: "a quiet harbour at dawn",
        alone: false,
      })
      expect(set).toMatchObject({ ok: true, screening: "indeterminate" })
      expect((await store.get("t", PASSWORD_COLLECTION, "a"))?.data).toMatchObject({
        screening: "indeterminate",
      })
      const signIn = await signInWithPassword(deps, {
        tenant: "t",
        accountId: "a",
        password: "a quiet harbour at dawn",
      })
      expect(signIn).toMatchObject({ ok: true, screening: "indeterminate" })
    }
  })
})
