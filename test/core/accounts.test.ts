import { describe, expect, it } from "vitest"
import {
  ACCOUNT_COLLECTION,
  accountActive,
  claimIdentifier,
  createAccount,
  hasConfirmedIdentifier,
  IDENTIFIER_COLLECTION,
  identifierValues,
  resolveConfirmed,
  UNCONFIRMED_IDENTIFIER_COLLECTION,
} from "../../src/core/accounts.js"
import { sequenceRandom, systemRandom } from "../../src/core/clock.js"
import { memoryStore } from "../../src/store/memory.js"

const T = "t1"

describe("accounts and identifiers (ADR 0021 §6)", () => {
  it("creates an active account holding its identifier unconfirmed, keyed at random", async () => {
    const store = memoryStore()
    const id = await createAccount(store, T, systemRandom, {
      identifier: "ada@example.com",
      now: 5,
    })
    expect(id).toMatch(/^[A-Za-z0-9_-]{22}$/)
    expect((await store.get(T, ACCOUNT_COLLECTION, id))?.data).toEqual({
      status: "active",
      createdAt: 5,
    })
    expect((await store.get(T, ACCOUNT_COLLECTION, id))?.owner).toBe(id)
    const [unconfirmed] = await store.listByOwner(T, UNCONFIRMED_IDENTIFIER_COLLECTION, id)
    expect(unconfirmed?.data).toEqual({ kind: "email", value: "ada@example.com" })
    expect(unconfirmed?.key).not.toBe("ada@example.com")
    expect(await accountActive(store, T, id)).toBe(true)
  })

  it("makes no uniqueness claim: two sign-ups with one address are two accounts, and neither resolves", async () => {
    const store = memoryStore()
    const first = await createAccount(store, T, systemRandom, {
      identifier: "ada@example.com",
      now: 1,
    })
    const second = await createAccount(store, T, systemRandom, {
      identifier: "ada@example.com",
      now: 2,
    })
    expect(first).not.toBe(second)
    expect(await resolveConfirmed(store, T, "ada@example.com")).toBeNull()
    expect(await store.get(T, IDENTIFIER_COLLECTION, "ada@example.com")).toBeNull()
  })

  it("resolves a confirmed identifier to its active account only", async () => {
    const store = memoryStore()
    const id = await createAccount(store, T, systemRandom, {
      identifier: "ada@example.com",
      now: 1,
    })
    await store.createUnique(T, {
      collection: IDENTIFIER_COLLECTION,
      key: "ada@example.com",
      owner: id,
      data: { account: id },
    })
    expect(await resolveConfirmed(store, T, "ada@example.com")).toBe(id)
    expect(await resolveConfirmed(store, "t2", "ada@example.com")).toBeNull()
    const account = await store.get(T, ACCOUNT_COLLECTION, id)
    await store.update(T, ACCOUNT_COLLECTION, id, account?.version ?? 0, {
      data: { status: "disabled" },
    })
    expect(await accountActive(store, T, id)).toBe(false)
    expect(await resolveConfirmed(store, T, "ada@example.com")).toBeNull()
  })

  it("resolves nothing for a revoked or malformed confirmed record, or a missing account", async () => {
    const store = memoryStore()
    const id = await createAccount(store, T, systemRandom, { identifier: "a@example.com", now: 1 })
    await store.createUnique(T, {
      collection: IDENTIFIER_COLLECTION,
      key: "a@example.com",
      owner: id,
      data: { account: id },
    })
    await store.revoke(T, IDENTIFIER_COLLECTION, "a@example.com", 2)
    expect(await resolveConfirmed(store, T, "a@example.com")).toBeNull()
    await store.createUnique(T, {
      collection: IDENTIFIER_COLLECTION,
      key: "b@example.com",
      owner: id,
      data: { account: 7 },
    })
    expect(await resolveConfirmed(store, T, "b@example.com")).toBeNull()
    await store.createUnique(T, {
      collection: IDENTIFIER_COLLECTION,
      key: "c@example.com",
      owner: null,
      data: null,
    })
    expect(await resolveConfirmed(store, T, "c@example.com")).toBeNull()
    await store.createUnique(T, {
      collection: IDENTIFIER_COLLECTION,
      key: "d@example.com",
      owner: null,
      data: { account: "gone" },
    })
    expect(await resolveConfirmed(store, T, "d@example.com")).toBeNull()
    expect(await accountActive(store, T, "gone")).toBe(false)
  })

  it("lists the identifier values an account typed, skipping a malformed record", async () => {
    const store = memoryStore()
    const id = await createAccount(store, T, systemRandom, {
      identifier: "ada@example.com",
      now: 1,
    })
    await store.createUnique(T, {
      collection: UNCONFIRMED_IDENTIFIER_COLLECTION,
      key: "x",
      owner: id,
      data: { value: 3 },
    })
    await store.createUnique(T, {
      collection: UNCONFIRMED_IDENTIFIER_COLLECTION,
      key: "y",
      owner: id,
      data: null,
    })
    expect(await identifierValues(store, T, id)).toEqual(["ada@example.com"])
  })

  it("refuses to continue when a new account id collides, which only a broken random source causes", async () => {
    const store = memoryStore()
    const random = sequenceRandom([7])
    await createAccount(store, T, random, { identifier: "a@example.com", now: 1 })
    await expect(
      createAccount(store, T, random, { identifier: "b@example.com", now: 1 }),
    ).rejects.toThrow(
      "A new account record collided with a stored one; the random source is broken.",
    )
  })

  it("holds a confirmed identifier only while its record is unrevoked, and only the account that claimed it", async () => {
    const store = memoryStore()
    expect(await hasConfirmedIdentifier(store, T, "acct-1")).toBe(false)
    expect(
      await claimIdentifier(store, T, {
        accountId: "acct-1",
        identifier: "ada@example.com",
        now: 7,
      }),
    ).toBe(true)
    expect(
      await claimIdentifier(store, T, {
        accountId: "acct-2",
        identifier: "ada@example.com",
        now: 8,
      }),
    ).toBe(false)
    expect(await hasConfirmedIdentifier(store, T, "acct-1")).toBe(true)
    expect(await hasConfirmedIdentifier(store, T, "acct-2")).toBe(false)
    await store.revoke(T, IDENTIFIER_COLLECTION, "ada@example.com", 9)
    expect(await hasConfirmedIdentifier(store, T, "acct-1")).toBe(false)
  })
})
