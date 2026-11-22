import * as hashWasm from "hash-wasm"
import { beforeEach, describe, expect, it, vi } from "vitest"
import { fixedClock, randomToken, sequenceRandom } from "../../src/core/clock.js"
import { hashing } from "../../src/methods/password/argon2.js"
import type { HibpFetch } from "../../src/methods/password/hibp.js"
import {
  PASSWORD_COLLECTION,
  type PasswordDeps,
  setPassword,
  signInWithPassword,
} from "../../src/methods/password/method.js"
import { memoryStore } from "../../src/store/memory.js"
import type { JsonValue } from "../../src/store/port.js"
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

const T0 = 1_700_000_000_000
const EXPECTED_ID = randomToken(sequenceRandom([7, 1, 200, 33]))
const STRONG = "correct horse battery staple"
const clearAnswer: HibpFetch = () =>
  Promise.resolve({
    ok: true,
    status: 200,
    text: () => Promise.resolve("0018A45C4D1DEF81644B54AB7F969B88D65:0"),
  })

function deps(overrides: Partial<PasswordDeps> = {}): PasswordDeps {
  return {
    clock: fixedClock(T0),
    random: sequenceRandom([7, 1, 200, 33]),
    store: memoryStore(),
    hibp: clearAnswer,
    hasher: testHasher,
    ...overrides,
  }
}

const verifyCalls = (): unknown[] =>
  vi.mocked(hashWasm.argon2Verify).mock.calls.map(([options]) => options.hash)

beforeEach(() => {
  vi.mocked(hashWasm.argon2Verify).mockClear()
  vi.mocked(hashWasm.argon2id).mockClear()
})

describe("setPassword", () => {
  it("stores the argon2id hash, a new authenticator id and the screening result", async () => {
    const d = deps()
    const result = await setPassword(d, {
      tenant: "t",
      accountId: "acct-1",
      password: STRONG,
      alone: false,
    })
    expect(result).toEqual({ ok: true, authenticatorId: EXPECTED_ID, screening: "clear" })
    const record = await d.store.get("t", PASSWORD_COLLECTION, "acct-1")
    expect(record?.owner).toBe("acct-1")
    expect(record?.data).toEqual({
      authenticatorId: EXPECTED_ID,
      hash: expect.stringMatching(/^\$argon2id\$v=19\$m=8,t=1,p=1\$/) as unknown,
      screening: "clear",
    })
    expect(JSON.stringify(record)).not.toContain("horse")
  })

  it("refuses short, long and blocklisted passwords before hashing", async () => {
    const d = deps()
    const base = { tenant: "t", accountId: "acct-1", alone: false }
    expect(await setPassword(d, { ...base, password: "short12" })).toEqual({
      ok: false,
      reason: "too-short",
    })
    expect(await setPassword(d, { ...base, password: "a".repeat(257) })).toEqual({
      ok: false,
      reason: "too-long",
    })
    expect(await setPassword(d, { ...base, password: "Password123" })).toEqual({
      ok: false,
      reason: "too-common",
    })
    expect(
      await setPassword(d, {
        ...base,
        password: "acme-portal rocks",
        contextWords: ["ACME-Portal"],
      }),
    ).toEqual({ ok: false, reason: "too-common" })
    expect(await setPassword(d, { ...base, alone: true, password: "fourteen chars" })).toEqual({
      ok: false,
      reason: "too-short",
    })
    expect(hashWasm.argon2id).not.toHaveBeenCalled()
    expect(await d.store.get("t", PASSWORD_COLLECTION, "acct-1")).toBeNull()
  })

  it("applies no context word unless one is given", async () => {
    const d = deps({ hibp: "off" })
    expect(
      await setPassword(d, {
        tenant: "t",
        accountId: "a",
        password: "Stryker was here, honestly",
        alone: false,
      }),
    ).toMatchObject({ ok: true })
  })

  it("records an off breach check as off, and makes no request", async () => {
    const d = deps({ hibp: "off" })
    const result = await setPassword(d, {
      tenant: "t",
      accountId: "a",
      password: STRONG,
      alone: false,
    })
    expect(result).toMatchObject({ ok: true, screening: "off" })
  })

  it("replaces the password of an account that has one, under a new authenticator id", async () => {
    const d = deps({ random: sequenceRandom([1, 2, 3, 4, 5]) })
    const first = await setPassword(d, {
      tenant: "t",
      accountId: "a",
      password: STRONG,
      alone: false,
    })
    const second = await setPassword(d, {
      tenant: "t",
      accountId: "a",
      password: "a different passphrase",
      alone: false,
    })
    expect(second.ok).toBe(true)
    expect(second).not.toEqual(first)
    expect(await signInWithPassword(d, { tenant: "t", accountId: "a", password: STRONG })).toEqual({
      ok: false,
      reason: "invalid",
    })
    expect(
      await signInWithPassword(d, {
        tenant: "t",
        accountId: "a",
        password: "a different passphrase",
      }),
    ).toMatchObject({
      ok: true,
    })
  })

  it("reports a conflict when another write wins the race", async () => {
    const d = deps()
    await setPassword(d, { tenant: "t", accountId: "a", password: STRONG, alone: false })
    const store = d.store
    const racing: PasswordDeps = {
      ...d,
      store: { ...store, update: () => Promise.resolve("conflict" as const) },
    }
    expect(
      await setPassword(racing, {
        tenant: "t",
        accountId: "a",
        password: "another passphrase",
        alone: false,
      }),
    ).toEqual({
      ok: false,
      reason: "conflict",
    })
    const creating: PasswordDeps = {
      ...deps(),
      store: { ...memoryStore(), createUnique: () => Promise.resolve("exists" as const) },
    }
    expect(
      await setPassword(creating, { tenant: "t", accountId: "b", password: STRONG, alone: false }),
    ).toEqual({
      ok: false,
      reason: "conflict",
    })
  })
})

describe("signInWithPassword", () => {
  it("returns AAL1-level knowledge evidence from the injected clock, and the screening result", async () => {
    const d = deps({ hibp: "off" })
    const set = await setPassword(d, {
      tenant: "t",
      accountId: "a",
      password: STRONG,
      alone: false,
    })
    ;(d.clock as ReturnType<typeof fixedClock>).advance(5_000)
    const result = await signInWithPassword(d, { tenant: "t", accountId: "a", password: STRONG })
    expect(result).toEqual({
      ok: true,
      screening: "off",
      evidence: {
        method: "password",
        authenticatorId: set.ok ? set.authenticatorId : "",
        factors: ["knowledge"],
        phishingResistant: false,
        replayResistant: false,
        keyProtection: "unknown",
        userVerified: false,
        attestationVerified: false,
        at: T0 + 5_000,
      },
    })
  })

  it("refuses a wrong password", async () => {
    const d = deps()
    await setPassword(d, { tenant: "t", accountId: "a", password: STRONG, alone: false })
    expect(
      await signInWithPassword(d, { tenant: "t", accountId: "a", password: `${STRONG}!` }),
    ).toEqual({
      ok: false,
      reason: "invalid",
    })
  })

  it("is scoped to the tenant", async () => {
    const d = deps()
    await setPassword(d, { tenant: "t1", accountId: "a", password: STRONG, alone: false })
    expect(await signInWithPassword(d, { tenant: "t2", accountId: "a", password: STRONG })).toEqual(
      {
        ok: false,
        reason: "invalid",
      },
    )
  })

  it("runs the dummy hash for an unknown account, an account with no password and a revoked password", async () => {
    const d = deps()
    await setPassword(d, { tenant: "t", accountId: "revoked", password: STRONG, alone: false })
    await d.store.revoke("t", PASSWORD_COLLECTION, "revoked", T0)
    const realHash = (
      (await d.store.get("t", PASSWORD_COLLECTION, "revoked"))?.data as { hash: string }
    ).hash
    const broken: Record<string, JsonValue> = {
      "broken-null": null,
      "broken-array": [realHash],
      "broken-string": realHash,
      "broken-hash": { hash: 1 },
      "broken-id": { authenticatorId: 1, hash: realHash, screening: "clear" },
      "broken-hash-type": { authenticatorId: "x", hash: 1, screening: "clear" },
      "broken-screening": { authenticatorId: "x", hash: realHash, screening: "bogus" },
    }
    for (const [key, data] of Object.entries(broken)) {
      await d.store.createUnique("t", { collection: PASSWORD_COLLECTION, key, owner: key, data })
    }
    for (const accountId of [null, "nobody", "revoked", ...Object.keys(broken)]) {
      vi.mocked(hashWasm.argon2Verify).mockClear()
      expect(
        await signInWithPassword(d, { tenant: "t", accountId, password: STRONG }),
        String(accountId),
      ).toEqual({
        ok: false,
        reason: "invalid",
      })
      expect(verifyCalls(), String(accountId)).toEqual([testHasher.dummyHash])
    }
  })

  it("verifies the stored hash, not the dummy, for a known account", async () => {
    const d = deps()
    await setPassword(d, { tenant: "t", accountId: "a", password: STRONG, alone: false })
    vi.mocked(hashWasm.argon2Verify).mockClear()
    await signInWithPassword(d, { tenant: "t", accountId: "a", password: "wrong wrong wrong" })
    expect(verifyCalls()).toHaveLength(1)
    expect(verifyCalls()[0]).not.toBe(testHasher.dummyHash)
  })

  it("refuses input over 256 characters before any hash runs", async () => {
    const d = deps()
    expect(
      await signInWithPassword(d, { tenant: "t", accountId: "a", password: "a".repeat(257) }),
    ).toEqual({
      ok: false,
      reason: "too-long",
    })
    expect(hashWasm.argon2Verify).not.toHaveBeenCalled()
  })

  it("rehashes at the current cost when the stored hash used other parameters", async () => {
    const d = deps()
    const old = await hashWasm.argon2id({
      password: STRONG,
      salt: new Uint8Array(16).fill(3),
      memorySize: 8_192,
      iterations: 1,
      parallelism: 1,
      hashLength: 32,
      outputType: "encoded",
    })
    await d.store.createUnique("t", {
      collection: PASSWORD_COLLECTION,
      key: "a",
      owner: "a",
      data: { authenticatorId: "pw-1", hash: old, screening: "clear" },
    })
    const result = await signInWithPassword(d, { tenant: "t", accountId: "a", password: STRONG })
    expect(result).toMatchObject({
      ok: true,
      screening: "clear",
      evidence: { authenticatorId: "pw-1" },
    })
    const record = await d.store.get("t", PASSWORD_COLLECTION, "a")
    expect(record?.version).toBe(2)
    expect(record?.data).toEqual({
      authenticatorId: "pw-1",
      hash: expect.stringMatching(/^\$argon2id\$v=19\$m=8,t=1,p=1\$/) as unknown,
      screening: "clear",
    })
    expect(
      await signInWithPassword(d, { tenant: "t", accountId: "a", password: STRONG }),
    ).toMatchObject({ ok: true })
    expect((await d.store.get("t", PASSWORD_COLLECTION, "a"))?.version).toBe(2)
  })

  it("answers busy, for known and unknown accounts alike, when the hashing queue is full", async () => {
    const d = deps()
    await setPassword(d, { tenant: "t", accountId: "a", password: STRONG, alone: false })
    const blockers: (() => void)[] = []
    const held = Array.from({ length: hashing.limit + 32 }, () =>
      hashing.run(() => new Promise<void>((resolve) => blockers.push(resolve))),
    )
    try {
      expect(
        await signInWithPassword(d, { tenant: "t", accountId: "a", password: STRONG }),
      ).toEqual({
        ok: false,
        reason: "busy",
      })
      expect(
        await signInWithPassword(d, { tenant: "t", accountId: "nobody", password: STRONG }),
      ).toEqual({
        ok: false,
        reason: "busy",
      })
      expect(
        await setPassword(d, { tenant: "t", accountId: "b", password: STRONG, alone: false }),
      ).toEqual({
        ok: false,
        reason: "busy",
      })
    } finally {
      // Release every holder, including those that only start once an earlier one finishes.
      for (const holder of held) {
        for (const release of blockers) release()
        await new Promise((resolve) => setTimeout(resolve, 0, holder))
      }
      await Promise.all(held)
    }
  })

  it("lets a store error at set through rather than answering success", async () => {
    const d = deps({
      hibp: "off",
      hasher: testHasher,
      store: { ...memoryStore(), get: () => Promise.reject(new Error("store down")) },
    })
    await expect(
      setPassword(d, { tenant: "t", accountId: "a", password: STRONG, alone: false }),
    ).rejects.toThrow("store down")
  })

  it("lets a store error through rather than answering success", async () => {
    const d = deps({
      store: { ...memoryStore(), get: () => Promise.reject(new Error("store down")) },
    })
    await expect(
      signInWithPassword(d, { tenant: "t", accountId: "a", password: STRONG }),
    ).rejects.toThrow("store down")
  })
})
