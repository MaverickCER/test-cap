// The limits keep no address and no email in the app's store: every counter and block they write is named by an HMAC
// of its key under a key derived from AUTH_ENCRYPTION_KEY (ADR 0032).
import { describe, expect, it } from "vitest"
import { limitKeyName, limitStore } from "../../src/security/limit-store.js"
import { LIMIT_BLOCK_COLLECTION } from "../../src/security/store-limiter.js"
import { memoryStore } from "../../src/store/memory.js"
import { Browser, hookedStore, inProcess, testAuth } from "../support/auth.js"

/** A store that records the name of every counter and limit block the app's store is asked for. */
function recordingStore() {
  const names: string[] = []
  const store = hookedStore(memoryStore(), (operation, args) => {
    if (operation === "increment" || operation === "resetCounter") names.push(String(args[1]))
    if (["get", "update", "delete"].includes(operation) && args[1] === LIMIT_BLOCK_COLLECTION)
      names.push(String(args[2]))
    if (operation === "createUnique") {
      const record = args[1] as { collection: string; key: string }
      if (record.collection === LIMIT_BLOCK_COLLECTION) names.push(record.key)
    }
    return Promise.resolve()
  })
  return { store, names }
}

const ADDRESS = "203.0.113.77"
const EMAIL = "victim@example.com"

describe("the names the limits write to the app's store", () => {
  it("hold neither the email address typed nor the client address, after failures, a block and a mail", async () => {
    const { store, names } = recordingStore()
    const setup = testAuth({ store })
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    for (let i = 0; i < 8; i += 1) {
      await browser.post(
        "/auth/sign-in",
        { identifier: EMAIL, password: "a wrong password" },
        { clientAddress: ADDRESS },
      )
    }
    await browser.post(
      "/auth/sign-up",
      { identifier: "new@example.com", password: "a long enough password" },
      { clientAddress: ADDRESS },
    )

    expect(names.length).toBeGreaterThan(10)
    const leaked = names.filter((name) =>
      [EMAIL, "new@example.com", ADDRESS, "203.0.113"].some((secret) => name.includes(secret)),
    )
    expect(leaked).toEqual([])
  })

  it("names one key the same way every time, so a count still adds up", async () => {
    const { store, names } = recordingStore()
    const setup = testAuth({ store })
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    for (let i = 0; i < 2; i += 1) {
      await browser.post(
        "/auth/sign-in",
        { identifier: EMAIL, password: "a wrong password" },
        { clientAddress: ADDRESS },
      )
    }
    const counts = new Map<string, number>()
    for (const name of names) counts.set(name, (counts.get(name) ?? 0) + 1)
    expect(Math.max(...counts.values())).toBeGreaterThanOrEqual(2)
  })
})

describe("limitKeyName", () => {
  const key = (seed: number) => ({ id: `k${String(seed)}`, bytes: new Uint8Array(32).fill(seed) })

  it("names one key the same way under one ring key, and differently under another", async () => {
    const first = limitKeyName(key(1))
    const name = await first("throttle:client:203.0.113.77")
    expect(await first("throttle:client:203.0.113.77")).toBe(name)
    expect(await first("throttle:client:203.0.113.78")).not.toBe(name)
    expect(await limitKeyName(key(2))("throttle:client:203.0.113.77")).not.toBe(name)
  })

  it("gives a 43-character base64url name that holds nothing of the key", async () => {
    const name = await limitKeyName(key(1))("throttle:account:victim@example.com")
    expect(name).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(name).not.toContain("victim")
  })
})

describe("limitStore", () => {
  const name = (k: string) => Promise.resolve(`named(${k})`)

  it("names counters, and the keys of limit blocks, on every operation the limiter uses", async () => {
    const inner = memoryStore()
    const store = limitStore(inner, name)
    await store.increment("t", "c", 1_000, 0)
    expect((await inner.increment("t", "named(c)", 1_000, 0)).count).toBe(2)
    await store.resetCounter("t", "c")
    expect((await inner.increment("t", "named(c)", 1_000, 0)).count).toBe(1)
    const block = { collection: LIMIT_BLOCK_COLLECTION, key: "b", owner: null, data: { points: 1 } }
    expect(await store.createUnique("t", block)).toBe("created")
    expect((await inner.get("t", LIMIT_BLOCK_COLLECTION, "named(b)"))?.data).toEqual({ points: 1 })
    const read = await store.get("t", LIMIT_BLOCK_COLLECTION, "b")
    expect(
      await store.update("t", LIMIT_BLOCK_COLLECTION, "b", read?.version ?? 0, { data: 2 }),
    ).toBe("updated")
    expect(await store.delete("t", LIMIT_BLOCK_COLLECTION, "b")).toBe(true)
    expect(await inner.get("t", LIMIT_BLOCK_COLLECTION, "named(b)")).toBeNull()
  })

  it("passes the store's other properties through unchanged", () => {
    const inner = memoryStore()
    const store = limitStore(inner, name)
    expect([store.kind, store.durable]).toEqual([inner.kind, inner.durable])
  })

  it("passes every other record through unchanged", async () => {
    const inner = memoryStore()
    const store = limitStore(inner, name)
    const record = { collection: "session", key: "s", owner: "a", data: 1 }
    expect(await store.createUnique("t", record)).toBe("created")
    expect(await inner.get("t", "session", "s")).not.toBeNull()
    expect(await store.get("t", "session", "s")).not.toBeNull()
    expect(await store.listByOwner("t", "session", "a")).toHaveLength(1)
  })
})
