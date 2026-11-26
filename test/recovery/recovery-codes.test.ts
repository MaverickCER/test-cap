// ADR 0007 §1 and Open 3: a set of 10 codes, each a non-secret prefix and 80 random bits, stored only as an argon2id
// hash with its own salt, shown once, single use, and a new set revokes the old one.
import { describe, expect, it } from "vitest"
import { fixedClock, systemRandom } from "../../src/core/clock.js"
import { createHasher } from "../../src/methods/password/argon2.js"
import {
  generateRecoveryCodes,
  parseRecoveryCode,
  RECOVERY_CODE_COLLECTION,
  RECOVERY_CODES_PER_SET,
  redeemRecoveryCode,
  remainingRecoveryCodes,
} from "../../src/methods/recovery/codes.js"
import { memoryStore } from "../../src/store/memory.js"
import { TEST_ARGON2_COST } from "../support/argon2.js"
import { hookedStore } from "../support/auth.js"
import { within } from "../support/within.js"

function deps() {
  return {
    store: memoryStore(),
    clock: fixedClock(1_000),
    random: systemRandom,
    hasher: createHasher(TEST_ARGON2_COST),
  }
}

const SHAPE = /^[A-Z2-7]{6}-[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$/

describe("parseRecoveryCode", () => {
  it("reads a code in any case, with spaces or hyphens, as its prefix and 16-character secret", () => {
    expect(parseRecoveryCode("abcdef-2345-6723-4567-2345")).toEqual({
      prefix: "ABCDEF",
      secret: "2345672345672345",
    })
    expect(parseRecoveryCode(" ABCDEF 2345 6723 4567 2345 ")).toEqual({
      prefix: "ABCDEF",
      secret: "2345672345672345",
    })
  })

  it.each([
    "",
    "ABCDEF-2345-6723-4567-234",
    "ABCDEF-2345-6723-4567-23451",
    "ABCDE1-2345-6723-4567-2345",
    "ABCDEF-2345-6723-4567-2345!",
  ])("refuses %j", (typed) => {
    expect(parseRecoveryCode(typed)).toBeNull()
  })
})

describe("recovery codes", () => {
  it("makes 10 distinct codes of 80 secret bits, and stores only an argon2id hash of each, under its prefix", async () => {
    const d = deps()
    const codes = (await generateRecoveryCodes(d, {
      tenant: "t",
      accountId: "acct",
    })) as readonly string[]
    expect(codes).toHaveLength(RECOVERY_CODES_PER_SET)
    expect(RECOVERY_CODES_PER_SET).toBe(10)
    expect(new Set(codes).size).toBe(10)
    for (const code of codes) {
      expect(code).toMatch(SHAPE)
      const { prefix, secret } = parseRecoveryCode(code) as { prefix: string; secret: string }
      const stored = await d.store.get("t", RECOVERY_CODE_COLLECTION, prefix)
      expect(stored?.owner).toBe("acct")
      const hash = (stored?.data as { hash: string }).hash
      expect(hash).toMatch(/^\$argon2id\$/)
      expect(JSON.stringify(stored)).not.toContain(secret)
    }
    // Each code has its own salt: two hashes never share one.
    const salts = await Promise.all(
      codes.map(async (code) => {
        const { prefix } = parseRecoveryCode(code) as { prefix: string }
        return (
          (await d.store.get("t", RECOVERY_CODE_COLLECTION, prefix))?.data as { hash: string }
        ).hash.split("$")[4]
      }),
    )
    expect(new Set(salts).size).toBe(10)
    expect(await remainingRecoveryCodes(d, { tenant: "t", accountId: "acct" })).toBe(10)
  })

  it("redeems a code once, for its own account only", async () => {
    const d = deps()
    const [code] = (await generateRecoveryCodes(d, { tenant: "t", accountId: "acct" })) as [string]
    expect(await redeemRecoveryCode(d, { tenant: "t", accountId: "other", code })).toEqual({
      ok: false,
      reason: "invalid",
    })
    expect(
      await redeemRecoveryCode(d, { tenant: "t", accountId: "acct", code: code.toLowerCase() }),
    ).toEqual({ ok: true })
    expect(await redeemRecoveryCode(d, { tenant: "t", accountId: "acct", code })).toEqual({
      ok: false,
      reason: "invalid",
    })
    expect(await remainingRecoveryCodes(d, { tenant: "t", accountId: "acct" })).toBe(9)
  })

  it("refuses a code with a right prefix and a wrong secret, an unknown account, and text that is no code", async () => {
    const d = deps()
    const [code] = (await generateRecoveryCodes(d, { tenant: "t", accountId: "acct" })) as [string]
    const wrong = `${code.slice(0, 7)}${code.slice(7, 8) === "A" ? "B" : "A"}${code.slice(8)}`
    for (const input of [
      { accountId: "acct", code: wrong },
      { accountId: null, code },
      { accountId: "acct", code: "not a code" },
    ]) {
      expect(await redeemRecoveryCode(d, { tenant: "t", ...input })).toEqual({
        ok: false,
        reason: "invalid",
      })
    }
    expect(await redeemRecoveryCode(d, { tenant: "t", accountId: "acct", code })).toEqual({
      ok: true,
    })
  })

  it("revokes every code of the old set when a new set is made", async () => {
    const d = deps()
    const old = (await generateRecoveryCodes(d, {
      tenant: "t",
      accountId: "acct",
    })) as readonly string[]
    await generateRecoveryCodes(d, { tenant: "t", accountId: "acct" })
    for (const code of old) {
      expect(await redeemRecoveryCode(d, { tenant: "t", accountId: "acct", code })).toEqual({
        ok: false,
        reason: "invalid",
      })
    }
    expect(await remainingRecoveryCodes(d, { tenant: "t", accountId: "acct" })).toBe(10)
  })

  it("keeps the old set working when the new set cannot be hashed", async () => {
    const d = deps()
    const [old] = (await generateRecoveryCodes(d, { tenant: "t", accountId: "acct" })) as [string]
    let hashes = 0
    const failing = {
      ...d.hasher,
      hash: (...args: Parameters<typeof d.hasher.hash>) => {
        hashes += 1
        return hashes > 3 ? Promise.reject(new Error("busy")) : d.hasher.hash(...args)
      },
    }
    await expect(
      within(generateRecoveryCodes({ ...d, hasher: failing }, { tenant: "t", accountId: "acct" })),
    ).rejects.toThrow("busy")
    expect(await remainingRecoveryCodes(d, { tenant: "t", accountId: "acct" })).toBe(10)
    expect(await redeemRecoveryCode(d, { tenant: "t", accountId: "acct", code: old })).toEqual({
      ok: true,
    })
  })

  it("draws exactly 80 bits for each code's secret", async () => {
    const sizes: number[] = []
    const d = {
      ...deps(),
      random: { fill: (bytes: Uint8Array) => (sizes.push(bytes.length), systemRandom.fill(bytes)) },
    }
    await generateRecoveryCodes(d, { tenant: "t", accountId: "acct" })
    // The ten secrets are drawn first, 16 base32 characters from 10 bytes each.
    expect(sizes.slice(0, RECOVERY_CODES_PER_SET)).toEqual(
      Array<number>(RECOVERY_CODES_PER_SET).fill(10),
    )
  })

  it("draws another prefix when one is already stored, and keeps the code usable", async () => {
    const d = deps()
    let first = true
    const colliding = new Proxy(d.store, {
      get(target, property, receiver) {
        const value = Reflect.get(target, property, receiver) as unknown
        if (property !== "createUnique") return value
        return (...args: unknown[]) => {
          if (first) {
            first = false
            return Promise.resolve("exists")
          }
          return (value as (...a: unknown[]) => Promise<unknown>).apply(target, args)
        }
      },
    })
    const codes = (await generateRecoveryCodes(
      { ...d, store: colliding },
      { tenant: "t", accountId: "acct" },
    )) as readonly string[]
    expect(codes).toHaveLength(RECOVERY_CODES_PER_SET)
    expect(await remainingRecoveryCodes(d, { tenant: "t", accountId: "acct" })).toBe(10)
    expect(
      await redeemRecoveryCode(d, { tenant: "t", accountId: "acct", code: codes[0] as string }),
    ).toEqual({ ok: true })
  })

  it("stops with an error after three colliding prefixes for one code, instead of drawing forever", async () => {
    const d = deps()
    let tries = 0
    const full = new Proxy(d.store, {
      get(target, property, receiver) {
        if (property === "createUnique") {
          return () => {
            tries += 1
            return Promise.resolve("exists")
          }
        }
        return Reflect.get(target, property, receiver) as unknown
      },
    })
    await expect(
      generateRecoveryCodes({ ...d, store: full }, { tenant: "t", accountId: "acct" }),
    ).rejects.toThrow(
      new Error(
        "3 recovery code prefixes in a row were already stored; the random source is broken.",
      ),
    )
    expect(tries).toBe(3)
  })

  it("refuses a code whose stored row holds no hash, without throwing", async () => {
    const d = deps()
    const [code] = (await generateRecoveryCodes(d, {
      tenant: "t",
      accountId: "acct",
    })) as readonly string[]
    const prefix = (parseRecoveryCode(code as string) as { prefix: string }).prefix
    const row = await d.store.get("t", RECOVERY_CODE_COLLECTION, prefix)
    await d.store.update("t", RECOVERY_CODE_COLLECTION, prefix, row?.version ?? 0, { data: {} })
    // The stand-in check runs, so the refusal costs the same argon2id work as a wrong code.
    const calls: string[] = []
    const counted = {
      ...d,
      hasher: {
        ...d.hasher,
        verify: (...args: Parameters<typeof d.hasher.verify>) => {
          calls.push("verify")
          return d.hasher.verify(...args)
        },
        dummyVerify: (...args: Parameters<typeof d.hasher.dummyVerify>) => {
          calls.push("dummyVerify")
          return d.hasher.dummyVerify(...args)
        },
      },
    }
    expect(
      await redeemRecoveryCode(counted, { tenant: "t", accountId: "acct", code: code as string }),
    ).toEqual({
      ok: false,
      reason: "invalid",
    })
    expect(calls).toEqual(["dummyVerify"])
  })

  it("refuses a real code when no account was resolved", async () => {
    const d = deps()
    const [code] = (await generateRecoveryCodes(d, {
      tenant: "t",
      accountId: "acct",
    })) as readonly string[]
    expect(
      await redeemRecoveryCode(d, { tenant: "t", accountId: null, code: code as string }),
    ).toEqual({
      ok: false,
      reason: "invalid",
    })
    expect(await remainingRecoveryCodes(d, { tenant: "t", accountId: "acct" })).toBe(10)
  })

  it("answers every loser of a parallel redemption as invalid", async () => {
    const d = deps()
    const [code] = (await generateRecoveryCodes(d, {
      tenant: "t",
      accountId: "acct",
    })) as readonly string[]
    const results = await Promise.all(
      Array.from({ length: 4 }, () =>
        redeemRecoveryCode(d, { tenant: "t", accountId: "acct", code: code as string }),
      ),
    )
    expect(results.filter((result) => result.ok)).toHaveLength(1)
    expect(results.filter((result) => !result.ok)).toEqual(
      Array(3).fill({ ok: false, reason: "invalid" }),
    )
  })
})

/**
 * Deps whose hasher and store record every code a request hashed and stored, shown or not, so a test can try codes no
 * reply listed. `pause(n)` holds the n-th write to a recovery collection until `release` is called.
 */
function recording() {
  const d = deps()
  const secretOf = new Map<string, string>()
  const stored: string[] = []
  const hasher = {
    ...d.hasher,
    hash: async (...args: Parameters<typeof d.hasher.hash>) => {
      const hash = await d.hasher.hash(...args)
      secretOf.set(hash, args[0])
      return hash
    },
  }
  let writes = 0
  let held: { at: number; reached: () => void; gate: Promise<void> } | null = null
  const store = hookedStore(d.store, async (operation, args) => {
    if (!["createUnique", "update", "revokeByOwner"].includes(operation)) return
    const collection =
      operation === "createUnique" ? (args[1] as { collection: string }).collection : args[1]
    if (!String(collection).startsWith("recovery-code")) return
    writes += 1
    if (operation === "createUnique") {
      const record = args[1] as { key: string; data: { hash?: string } }
      const secret = secretOf.get(String(record.data.hash))
      if (secret !== undefined) stored.push(`${record.key}${secret}`)
    }
    if (held?.at === writes) {
      held.reached()
      await held.gate
    }
  })
  return {
    deps: { ...d, store, hasher },
    plain: d,
    /** Every code hashed and stored so far, as typed. */
    stored,
    /** Holds the n-th write; resolves `reached` once the request is waiting there. */
    pause(at: number) {
      let release = (): void => undefined
      let reached = (): void => undefined
      const arrived = new Promise<void>((resolve) => {
        reached = resolve
      })
      const gate = new Promise<void>((resolve) => {
        release = resolve
      })
      held = { at, reached, gate }
      writes = 0
      return { arrived, release }
    },
  }
}

const redeems = async (d: ReturnType<typeof deps>, code: string) =>
  (await redeemRecoveryCode(d, { tenant: "t", accountId: "acct", code })).ok

describe("one live set per account", () => {
  // A write to a recovery collection: the first code, the sixth, and the eleventh (the last).
  it.each([1, 6, 11])(
    "lets exactly one of two parallel requests make a set when one pauses at its write %i",
    async (at) => {
      const r = recording()
      const old = (await generateRecoveryCodes(r.plain, { tenant: "t", accountId: "acct" })) ?? []
      const paused = r.pause(at)
      const first = generateRecoveryCodes(r.deps, { tenant: "t", accountId: "acct" })
      await within(paused.arrived)
      const second = await within(
        generateRecoveryCodes(r.plain, { tenant: "t", accountId: "acct" }),
      )
      paused.release()
      const replies = [await within(first), second]
      const listed = replies.filter((reply) => reply !== null)
      expect(listed).toHaveLength(1)
      const shown = listed[0] ?? []
      for (const code of shown) expect([code, await redeems(r.plain, code)]).toEqual([code, true])
      for (const code of [
        ...old,
        ...r.stored.filter((each) => !shown.some((s) => s.replace(/-/g, "") === each)),
      ]) {
        expect([code, await redeems(r.plain, code)]).toEqual([code, false])
      }
    },
  )

  it("answers the loser with null, never with codes that do not work", async () => {
    const r = recording()
    await generateRecoveryCodes(r.plain, { tenant: "t", accountId: "acct" })
    const paused = r.pause(11)
    const first = generateRecoveryCodes(r.deps, { tenant: "t", accountId: "acct" })
    await within(paused.arrived)
    const second = await generateRecoveryCodes(r.plain, { tenant: "t", accountId: "acct" })
    paused.release()
    expect(await within(first)).toBeNull()
    expect(second).toHaveLength(RECOVERY_CODES_PER_SET)
    expect(await remainingRecoveryCodes(r.plain, { tenant: "t", accountId: "acct" })).toBe(10)
  })

  it.each(Array.from({ length: 11 }, (_, index) => index + 1))(
    "keeps the old set as the only live one when the store fails write %i of a new set",
    async (at) => {
      const r = recording()
      const old = (await generateRecoveryCodes(r.plain, { tenant: "t", accountId: "acct" })) ?? []
      let writes = 0
      const failing = hookedStore(r.deps.store, async (operation, args) => {
        const collection =
          operation === "createUnique" ? (args[1] as { collection: string }).collection : args[1]
        if (!["createUnique", "update", "revokeByOwner"].includes(operation)) return
        if (!String(collection).startsWith("recovery-code")) return
        writes += 1
        if (writes === at) throw new Error("store down")
      })
      await expect(
        within(
          generateRecoveryCodes({ ...r.deps, store: failing }, { tenant: "t", accountId: "acct" }),
        ),
      ).rejects.toThrow("store down")
      for (const code of r.stored)
        expect([code, await redeems(r.plain, code)]).toEqual([code, false])
      expect(await remainingRecoveryCodes(r.plain, { tenant: "t", accountId: "acct" })).toBe(10)
      for (const code of old) expect([code, await redeems(r.plain, code)]).toEqual([code, true])
    },
  )

  it("refuses a code of a set that was replaced after the code was checked", async () => {
    const d = deps()
    const [code] = (await generateRecoveryCodes(d, { tenant: "t", accountId: "acct" })) as [string]
    let replaced = false
    const hasher = {
      ...d.hasher,
      verify: async (...args: Parameters<typeof d.hasher.verify>) => {
        const verified = await d.hasher.verify(...args)
        if (!replaced) {
          replaced = true
          await generateRecoveryCodes(d, { tenant: "t", accountId: "acct" })
        }
        return verified
      },
    }
    expect(
      await redeemRecoveryCode({ ...d, hasher }, { tenant: "t", accountId: "acct", code }),
    ).toEqual({
      ok: false,
      reason: "invalid",
    })
    expect(await remainingRecoveryCodes(d, { tenant: "t", accountId: "acct" })).toBe(10)
  })
})

describe("codes whose set is gone or that were revoked", () => {
  it("redeems nothing and counts nothing when the account's set record is missing", async () => {
    const d = deps()
    const codes = (await generateRecoveryCodes(d, { tenant: "t", accountId: "acct" })) ?? []
    expect(await d.store.delete("t", "recovery-code-set", "acct")).toBe(true)
    expect(await remainingRecoveryCodes(d, { tenant: "t", accountId: "acct" })).toBe(0)
    expect(
      await redeemRecoveryCode(d, { tenant: "t", accountId: "acct", code: codes[0] ?? "" }),
    ).toEqual({ ok: false, reason: "invalid" })
  })

  it("leaves a revoked code out of the count of codes left", async () => {
    const d = deps()
    const codes = (await generateRecoveryCodes(d, { tenant: "t", accountId: "acct" })) ?? []
    const prefix = parseRecoveryCode(codes[0] ?? "")?.prefix ?? ""
    expect(await d.store.revoke("t", RECOVERY_CODE_COLLECTION, prefix, 2_000)).toBe(true)
    expect(await remainingRecoveryCodes(d, { tenant: "t", accountId: "acct" })).toBe(
      RECOVERY_CODES_PER_SET - 1,
    )
  })

  it("passes on a hasher failure that is not a full queue, rather than calling it busy", async () => {
    const d = deps()
    const codes = (await generateRecoveryCodes(d, { tenant: "t", accountId: "acct" })) ?? []
    const broken = {
      ...d,
      hasher: { ...d.hasher, verify: () => Promise.reject(new Error("the hasher broke")) },
    }
    await expect(
      redeemRecoveryCode(broken, { tenant: "t", accountId: "acct", code: codes[0] ?? "" }),
    ).rejects.toThrow("the hasher broke")
  })
})
