import { argon2id } from "hash-wasm"
import { describe, expect, it, vi } from "vitest"
import { sequenceRandom } from "../../src/core/clock.js"
import { createAuth } from "../../src/core/auth.js"
import {
  ARGON2_PARAMETERS,
  argon2CostProblem,
  createHasher,
  DUMMY_HASH,
  HASH_CONCURRENCY,
  HASH_QUEUE_LIMIT,
  hashing,
} from "../../src/methods/password/argon2.js"
import { PASSWORD_COLLECTION } from "../../src/methods/password/method.js"
import { normalisePassword } from "../../src/methods/password/rules.js"
import { memoryStore } from "../../src/store/memory.js"
import type { EmailMessage } from "../../src/core/auth.js"
import {
  Browser,
  confirmEmail,
  ENV,
  hibpClear,
  inProcess,
  outboxSender,
  PASSWORD,
  TENANT,
} from "../support/auth.js"

// The one test file that runs argon2id at the ADR 0018 cost; every other test hashes at TEST_ARGON2_COST
// (test/support/argon2.ts). Every test here runs argon2id behind the shared semaphore; a semaphore that stops granting
// slots must fail a test fast rather than hang the run.
vi.setConfig({ testTimeout: 6_000 })

const SALT = Array.from({ length: 16 }, (_, i) => i + 1)

/** The hasher createAuth builds outside test mode. */
const adr0018 = createHasher()
const { needsRehash } = adr0018
const hashPassword = adr0018.hash
const verifyPasswordHash = adr0018.verify
const dummyVerify = adr0018.dummyVerify

describe("argon2id parameters (ADR 0018 §1, Open 1 and 2)", () => {
  it("declares 19 MiB, 2 iterations, parallelism 1, a 16-byte salt and a 32-byte hash", () => {
    expect(ARGON2_PARAMETERS).toEqual({
      memoryKiB: 19_456,
      iterations: 2,
      parallelism: 1,
      saltBytes: 16,
      hashBytes: 32,
    })
  })

  it("bounds hashing at 4 in flight with a queue of 32", () => {
    expect([HASH_CONCURRENCY, HASH_QUEUE_LIMIT]).toEqual([4, 32])
    expect(hashing.limit).toBe(4)
  })

  it("hashes with exactly those parameters and a salt from the random source", async () => {
    const encoded = await hashPassword(normalisePassword("correct horse"), sequenceRandom(SALT))
    const expected = await argon2id({
      password: "correct horse",
      salt: Uint8Array.from(SALT),
      memorySize: 19_456,
      iterations: 2,
      parallelism: 1,
      hashLength: 32,
      outputType: "encoded",
    })
    expect(encoded).toBe(expected)
    expect(encoded.startsWith("$argon2id$v=19$m=19456,t=2,p=1$AQIDBAUGBwgJCgsMDQ4PEA$")).toBe(true)
  })

  it("verifies the same password and nothing else", async () => {
    const encoded = await hashPassword(normalisePassword("correct horse"), sequenceRandom(SALT))
    expect(await verifyPasswordHash(normalisePassword("correct horse"), encoded)).toBe(true)
    expect(await verifyPasswordHash(normalisePassword("correct horsf"), encoded)).toBe(false)
  })

  it("keeps the dummy hash at the current parameters, so its cost matches a real check", async () => {
    expect(needsRehash(DUMMY_HASH)).toBe(false)
    expect(await dummyVerify(normalisePassword("anything"))).toBe(false)
  })

  it("asks for a rehash when any recorded parameter differs from the current ones", () => {
    const tail = "$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"
    expect(needsRehash(`$argon2id$v=19$m=19456,t=2,p=1${tail}`)).toBe(false)
    expect(needsRehash(`$argon2id$v=19$m=19455,t=2,p=1${tail}`)).toBe(true)
    expect(needsRehash(`$argon2id$v=19$m=19456,t=3,p=1${tail}`)).toBe(true)
    expect(needsRehash(`$argon2id$v=19$m=19456,t=2,p=2${tail}`)).toBe(true)
    expect(needsRehash(`$argon2i$v=19$m=19456,t=2,p=1${tail}`)).toBe(true)
    expect(needsRehash(`$argon2id$v=16$m=19456,t=2,p=1${tail}`)).toBe(true)
    expect(needsRehash(`x$argon2id$v=19$m=19456,t=2,p=1${tail}`)).toBe(true)
    expect(needsRehash(`$argon2id$v=19$m=194560,t=2,p=1${tail}`)).toBe(true)
    expect(needsRehash(`$argon2id$v=19$m=19456,t=22,p=1${tail}`)).toBe(true)
    expect(needsRehash(`$argon2id$v=19$m=19456,t=2,p=11${tail}`)).toBe(true)
    expect(needsRehash("")).toBe(true)
  })

  it("is the cost createAuth hashes at unless test mode passes its own", async () => {
    const store = memoryStore()
    const outbox: EmailMessage[] = []
    const auth = createAuth({
      store,
      env: ENV,
      hibpFetch: hibpClear,
      sendEmail: outboxSender(outbox),
    })
    const browser = new Browser(inProcess(auth))
    await browser.start()
    await browser.post("/auth/sign-up", { identifier: "ada@example.com" })
    const subject = ((await browser.get("/auth/session")).json as { session: { subject: string } })
      .session.subject
    await confirmEmail(browser, outbox)
    expect((await browser.post("/auth/password", { password: PASSWORD })).status).toBe(200)
    const record = await store.get(TENANT, PASSWORD_COLLECTION, subject)
    expect((record?.data as { hash: string }).hash).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/)
  })
})

describe("a hasher at another cost (test mode only, ADR 0018 §1)", () => {
  const cost = { memoryKiB: 8, iterations: 1, parallelism: 1 }

  it("hashes at its own cost and counts only that cost as current", async () => {
    const hasher = createHasher(cost)
    const encoded = await hasher.hash(normalisePassword("correct horse"), sequenceRandom(SALT))
    expect(encoded).toBe(
      await argon2id({
        password: "correct horse",
        salt: Uint8Array.from(SALT),
        memorySize: 8,
        iterations: 1,
        parallelism: 1,
        hashLength: 32,
        outputType: "encoded",
      }),
    )
    expect(await hasher.verify(normalisePassword("correct horse"), encoded)).toBe(true)
    expect(await hasher.verify(normalisePassword("correct horsf"), encoded)).toBe(false)
    expect(hasher.needsRehash(encoded)).toBe(false)
    expect(hasher.needsRehash(DUMMY_HASH)).toBe(true)
    expect(needsRehash(encoded)).toBe(true)
  })

  it("runs its dummy check at its own cost, against a hash nothing verifies", async () => {
    const hasher = createHasher(cost)
    expect(hasher.dummyHash).toBe(
      "$argon2id$v=19$m=8,t=1,p=1$WlpaWlpaWlpaWlpaWlpaWg$lhxJyQ2352vbiodRTI+m5puq1xV3hswYXC3vhJ2nHqg",
    )
    expect(hasher.needsRehash(hasher.dummyHash)).toBe(false)
    expect(await hasher.dummyVerify(normalisePassword("anything"))).toBe(false)
    expect(createHasher().dummyHash).toBe(DUMMY_HASH)
  })

  it("passes every computation through the one hashing semaphore", async () => {
    let release: () => void = () => undefined
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    const seen: number[] = []
    // The PHC string of SALT at `cost`, with a digest nothing computed: the hasher only holds the slot open.
    const encoded = `$argon2id$v=19$m=8,t=1,p=1$AQIDBAUGBwgJCgsMDQ4PEA$${"a".repeat(43)}`
    const hasher = createHasher(cost, {
      hash: async () => {
        seen.push(hashing.active)
        await held
        return encoded
      },
      verify: async () => {
        seen.push(hashing.active)
        await held
        return true
      },
    })
    const pending = [
      hasher.hash(normalisePassword("a"), sequenceRandom(SALT)),
      hasher.verify(normalisePassword("a"), encoded),
      hasher.dummyVerify(normalisePassword("a")),
    ]
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(hashing.active).toBe(3)
    release()
    expect(await Promise.all(pending)).toEqual([encoded, true, false])
    expect(seen).toEqual([3, 3, 3])
    expect(hashing.active).toBe(0)
  })

  it("accepts only a cost hash-wasm can compute", () => {
    expect(argon2CostProblem(cost)).toBeUndefined()
    expect(argon2CostProblem(ARGON2_PARAMETERS)).toBeUndefined()
    expect(argon2CostProblem({ memoryKiB: 16, iterations: 1, parallelism: 2 })).toBeUndefined()
    const problem =
      "argon2Cost must be whole numbers: iterations and parallelism at least 1, memoryKiB at least 8 times parallelism."
    for (const bad of [
      { memoryKiB: 7, iterations: 1, parallelism: 1 },
      { memoryKiB: 15, iterations: 1, parallelism: 2 },
      { memoryKiB: 8, iterations: 0, parallelism: 1 },
      { memoryKiB: 8, iterations: 1, parallelism: 0 },
      { memoryKiB: 8.5, iterations: 1, parallelism: 1 },
      { memoryKiB: 8, iterations: 1.5, parallelism: 1 },
      { memoryKiB: 8, iterations: 1, parallelism: 0.5 },
    ]) {
      expect(argon2CostProblem(bad), JSON.stringify(bad)).toBe(problem)
    }
  })
})
