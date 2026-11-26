// Attack: parallel sign-ins with long passwords exhaust memory and CPU.
// Stopped by: a fixed argon2id cost, a semaphore of 4 with a bounded queue, and a 256-character limit (ADR 0010, 0018).
import { describe, expect, it, vi } from "vitest"
import { fixedClock, sequenceRandom } from "../../src/core/clock.js"
import {
  ARGON2_PARAMETERS,
  type Argon2Hasher,
  createHasher,
  HASH_CONCURRENCY,
  HASH_QUEUE_LIMIT,
  hashing,
} from "../../src/methods/password/argon2.js"
import { setPassword, signInWithPassword } from "../../src/methods/password/method.js"
import { memoryStore } from "../../src/store/memory.js"
import { testHasher } from "../support/argon2.js"
import { within } from "../support/within.js"

// The burst below runs no real argon2id: an injected engine holds every computation open until the test releases it,
// so the semaphore's bound is measured exactly and the test takes milliseconds on any machine. A semaphore that stops
// granting slots must still fail a test rather than hang the run.
vi.setConfig({ testTimeout: 6_000 })

/** What the stand-in engine stores: the current cost's PHC prefix, so a sign-in never rehashes. */
const PREFIX = `$argon2id$v=19$m=${ARGON2_PARAMETERS.memoryKiB},t=${ARGON2_PARAMETERS.iterations},p=${ARGON2_PARAMETERS.parallelism}$`

/** An engine that counts the computations in flight and holds each one until `open` is called. */
function slowEngine() {
  let inFlight = 0
  let peak = 0
  let open: () => void = () => undefined
  let held: Promise<void> = Promise.resolve()
  const slow = async <T>(value: T): Promise<T> => {
    inFlight += 1
    peak = Math.max(peak, inFlight)
    await held
    inFlight -= 1
    return value
  }
  // A PHC string test-cap accepts: the real salt, and a digest that stands for the password without computing one.
  const digestOf = (password: string) =>
    password
      .replaceAll(/[^A-Za-z0-9+/]/g, "A")
      .slice(0, 43)
      .padEnd(43, "A")
  const engine: Argon2Hasher = {
    hash: ({ password, salt }) =>
      slow(
        `${PREFIX}${Buffer.from(salt).toString("base64").replace(/=+$/, "")}$${digestOf(password)}`,
      ),
    verify: (password, encoded) => slow(encoded.endsWith(`$${digestOf(password)}`)),
  }
  return {
    engine,
    get peak() {
      return peak
    },
    /** From now on, every computation waits for `open`. */
    hold() {
      held = new Promise<void>((resolve) => {
        open = resolve
      })
    },
    open: () => open(),
  }
}

describe("argon2-cost-exhaustion", () => {
  it("runs at most 4 hashes at once and refuses what the queue cannot hold", async () => {
    const slow = slowEngine()
    const store = memoryStore()
    const d = {
      clock: fixedClock(0),
      random: sequenceRandom([8, 2]),
      store,
      hibp: "off" as const,
      hasher: createHasher(ARGON2_PARAMETERS, slow.engine),
    }
    await within(
      setPassword(d, { tenant: "t", accountId: "a", password: "z".repeat(256), alone: false }),
      1_000,
    )
    slow.hold()
    const burst = HASH_CONCURRENCY + HASH_QUEUE_LIMIT + 6
    const pending = Array.from({ length: burst }, () =>
      signInWithPassword(d, { tenant: "t", accountId: "a", password: "z".repeat(256) }),
    )
    // Every request has either a slot, a place in the queue, or its refusal before any computation finishes.
    await vi.waitFor(
      () => {
        expect([hashing.active, hashing.waiting]).toEqual([HASH_CONCURRENCY, HASH_QUEUE_LIMIT])
      },
      { timeout: 1_000, interval: 1 },
    )
    slow.open()
    const results = await within(Promise.all(pending), 1_000)
    expect(slow.peak).toBe(HASH_CONCURRENCY)
    expect(results.filter((result) => result.ok)).toHaveLength(HASH_CONCURRENCY + HASH_QUEUE_LIMIT)
    expect(results.filter((result) => !result.ok)).toEqual(
      Array.from({ length: 6 }, () => ({ ok: false, reason: "busy" })),
    )
    expect([hashing.active, hashing.waiting]).toEqual([0, 0])
  })

  it("keeps the cost fixed and the input bounded", async () => {
    expect(ARGON2_PARAMETERS.memoryKiB).toBe(19_456)
    const d = {
      clock: fixedClock(0),
      random: sequenceRandom([8]),
      store: memoryStore(),
      hibp: "off" as const,
      hasher: testHasher,
    }
    expect(
      await signInWithPassword(d, { tenant: "t", accountId: "a", password: "z".repeat(10_000) }),
    ).toEqual({
      ok: false,
      reason: "too-long",
    })
  })
})
