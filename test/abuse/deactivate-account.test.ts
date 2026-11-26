// ADR 0012 Open 15 (deprovision): disabling an account keeps its other data, records when, and retries a write that
// lost a race a bounded number of times.
import { describe, expect, it } from "vitest"
import { ACCOUNT_COLLECTION, deactivateAccount } from "../../src/core/accounts.js"
import type { AuthStore } from "../../src/store/port.js"
import { memoryStore } from "../../src/store/memory.js"

async function withAccount() {
  const store = memoryStore()
  await store.createUnique("t", {
    collection: ACCOUNT_COLLECTION,
    key: "acct",
    owner: "acct",
    data: { status: "active", createdAt: 5 },
  })
  return store
}

/** `store` with `update` answering `conflict` for the first `losses` calls; counts every call. */
function losing(store: AuthStore, losses: number) {
  const calls = { update: 0 }
  const proxy = new Proxy(store, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver) as unknown
      if (property !== "update") return value
      return (...args: unknown[]) => {
        calls.update += 1
        return calls.update <= losses
          ? Promise.resolve("conflict")
          : (value as (...a: unknown[]) => Promise<unknown>).apply(target, args)
      }
    },
  })
  return { store: proxy, calls }
}

describe("deactivateAccount", () => {
  it("marks the account disabled with the time, keeping its other fields", async () => {
    const store = await withAccount()
    expect(await deactivateAccount(store, "t", "acct", 900)).toBe(true)
    expect((await store.get("t", ACCOUNT_COLLECTION, "acct"))?.data).toEqual({
      status: "disabled",
      createdAt: 5,
      disabledAt: 900,
    })
  })

  it("resolves to false for an account that does not exist", async () => {
    expect(await deactivateAccount(memoryStore(), "t", "nobody", 900)).toBe(false)
  })

  it("retries a write another change beat, and stops once one lands", async () => {
    const { store, calls } = losing(await withAccount(), 4)
    expect(await deactivateAccount(store, "t", "acct", 900)).toBe(true)
    expect(calls.update).toBe(5)
  })

  it("throws after five lost races instead of retrying forever", async () => {
    const { store, calls } = losing(await withAccount(), 5)
    await expect(deactivateAccount(store, "t", "acct", 900)).rejects.toThrow(
      new Error("The account could not be disabled after 5 tries."),
    )
    expect(calls.update).toBe(5)
    expect((await store.get("t", ACCOUNT_COLLECTION, "acct"))?.data).toMatchObject({
      status: "active",
    })
  })
})
