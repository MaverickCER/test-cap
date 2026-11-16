import { describe, expect, it } from "vitest"
import { memoryStore } from "../../src/store/memory.js"

const T = "tenant-a"

describe("memoryStore", () => {
  it("declares itself as a non-durable store, so production refuses it", () => {
    const store = memoryStore()
    expect(store.kind).toBe("memory")
    expect(store.durable).toBe(false)
  })

  it("creates a record once and reads it back with version 1 and no lifecycle times", async () => {
    const store = memoryStore()
    expect(
      await store.createUnique(T, {
        collection: "account",
        key: "a1",
        owner: null,
        data: { s: 1 },
      }),
    ).toBe("created")
    expect(await store.get(T, "account", "a1")).toEqual({
      collection: "account",
      key: "a1",
      owner: null,
      version: 1,
      expiresAt: null,
      revokedAt: null,
      consumedAt: null,
      data: { s: 1 },
    })
    expect(await store.get(T, "account", "nope")).toBeNull()
  })

  it("answers exists to a second create of the same key and keeps the first record", async () => {
    const store = memoryStore()
    await store.createUnique(T, { collection: "c", key: "k", owner: null, data: 1 })
    expect(await store.createUnique(T, { collection: "c", key: "k", owner: null, data: 2 })).toBe(
      "exists",
    )
    expect((await store.get(T, "c", "k"))?.data).toBe(1)
  })

  it("hands out copies, so a caller mutating a record changes nothing stored", async () => {
    const store = memoryStore()
    const data = { nested: { n: 1 } }
    await store.createUnique(T, { collection: "c", key: "k", owner: "o", data })
    data.nested.n = 2
    const first = await store.get(T, "c", "k")
    ;(first?.data as { nested: { n: number } }).nested.n = 3
    const [listed] = await store.listByOwner(T, "c", "o")
    ;(listed?.data as { nested: { n: number } }).nested.n = 4
    expect((await store.get(T, "c", "k"))?.data).toEqual({ nested: { n: 1 } })
  })

  it("lists by owner in creation order, only for that collection", async () => {
    const store = memoryStore()
    await store.createUnique(T, { collection: "session", key: "s1", owner: "a", data: 1 })
    await store.createUnique(T, { collection: "session", key: "s2", owner: "b", data: 2 })
    await store.createUnique(T, { collection: "session", key: "s3", owner: "a", data: 3 })
    await store.createUnique(T, { collection: "api-key", key: "k1", owner: "a", data: 4 })
    expect((await store.listByOwner(T, "session", "a")).map((r) => r.key)).toEqual(["s1", "s3"])
    expect(await store.listByOwner(T, "session", "z")).toEqual([])
  })

  it("deletes a record and reports whether one was there", async () => {
    const store = memoryStore()
    await store.createUnique(T, { collection: "c", key: "k", owner: null, data: 1 })
    expect(await store.delete(T, "c", "k")).toBe(true)
    expect(await store.delete(T, "c", "k")).toBe(false)
    expect(await store.get(T, "c", "k")).toBeNull()
  })

  it("updates data and expiry, bumping the version, and leaves the other fields alone", async () => {
    const store = memoryStore()
    await store.createUnique(T, { collection: "c", key: "k", owner: "o", expiresAt: 50, data: 1 })
    expect(await store.update(T, "c", "k", 1, { data: 2 })).toBe("updated")
    expect(await store.get(T, "c", "k")).toMatchObject({ version: 2, data: 2, expiresAt: 50 })
    expect(await store.update(T, "c", "k", 2, { expiresAt: null })).toBe("updated")
    const record = await store.get(T, "c", "k")
    expect(record).toMatchObject({ version: 3, data: 2, expiresAt: null, owner: "o" })
  })

  it("revokes once: a second revoke keeps the first time", async () => {
    const store = memoryStore()
    await store.createUnique(T, { collection: "session", key: "s", owner: "a", data: 1 })
    expect(await store.revoke(T, "session", "s", 100)).toBe(true)
    expect(await store.revoke(T, "session", "s", 200)).toBe(true)
    expect(await store.get(T, "session", "s")).toMatchObject({ revokedAt: 100, version: 2 })
    expect(await store.revoke(T, "session", "missing", 100)).toBe(false)
  })

  it("revokes an owner's records but the excepted one, bumping each version once", async () => {
    const store = memoryStore()
    for (const key of ["s1", "s2", "s3"]) {
      await store.createUnique(T, { collection: "session", key, owner: "a", data: 1 })
    }
    expect(await store.revokeByOwner(T, "session", "a", 100, { except: "s2" })).toBe(2)
    expect(await store.revokeByOwner(T, "session", "a", 200)).toBe(1)
    const records = await store.listByOwner(T, "session", "a")
    expect(records.map((r) => [r.key, r.revokedAt, r.version])).toEqual([
      ["s1", 100, 2],
      ["s2", 200, 2],
      ["s3", 100, 2],
    ])
  })

  it("consumes a record once, before its expiry, bumping its version", async () => {
    const store = memoryStore()
    await store.createUnique(T, {
      collection: "code",
      key: "c",
      owner: null,
      expiresAt: 10,
      data: 1,
    })
    await store.createUnique(T, {
      collection: "code",
      key: "late",
      owner: null,
      expiresAt: 10,
      data: 1,
    })
    expect(await store.consumeOnce(T, "code", "late", 10)).toBeNull()
    expect(await store.consumeOnce(T, "code", "c", 9)).toMatchObject({ consumedAt: 9, version: 2 })
    expect(await store.get(T, "code", "c")).toMatchObject({ consumedAt: 9, version: 2 })
    expect(await store.consumeOnce(T, "code", "c", 9)).toBeNull()
  })

  it("reads an audit stream from a sequence number, up to a limit", async () => {
    const store = memoryStore()
    expect(await store.readAudit(T, "s", 1, 10)).toEqual([])
    for (const seq of [1, 2, 3])
      expect(await store.appendAudit(T, "s", seq, { seq })).toBe("appended")
    expect(await store.readAudit(T, "s", 1, 10)).toEqual([
      { stream: "s", seq: 1, record: { seq: 1 } },
      { stream: "s", seq: 2, record: { seq: 2 } },
      { stream: "s", seq: 3, record: { seq: 3 } },
    ])
    expect((await store.readAudit(T, "s", 2, 1)).map((e) => e.seq)).toEqual([2])
    expect((await store.readAudit(T, "s", 2, 5)).map((e) => e.seq)).toEqual([2, 3])
    expect(await store.readAudit(T, "s", 4, 5)).toEqual([])
    expect(await store.readAudit(T, "other", 1, 5)).toEqual([])
  })

  it("rejects malformed arguments before touching anything", async () => {
    const store = memoryStore()
    const record = { collection: "c", key: "k", owner: null, data: 1 }
    await expect(store.createUnique("", record)).rejects.toThrow(TypeError)
    await expect(store.createUnique(T, { ...record, key: "" })).rejects.toThrow(TypeError)
    await expect(store.createUnique(T, { ...record, collection: "" })).rejects.toThrow(TypeError)
    await expect(store.createUnique(T, { ...record, owner: "" })).rejects.toThrow(TypeError)
    await expect(store.createUnique(T, { ...record, expiresAt: 1.5 })).rejects.toThrow(RangeError)
    await expect(store.increment(T, "c", 0, 0)).rejects.toThrow(RangeError)
    await expect(store.increment(T, "c", 10, Number.NaN)).rejects.toThrow(RangeError)
    await expect(store.appendAudit(T, "s", 0, {})).rejects.toThrow(RangeError)
    await expect(store.readAudit(T, "s", 1, 0)).rejects.toThrow(RangeError)
    await expect(store.update(T, "c", "k", 0, { data: 1 })).rejects.toThrow(RangeError)
    await expect(store.consumeOnce(T, "c", "k", 1.5)).rejects.toThrow(RangeError)
  })

  it("names the argument it refuses", async () => {
    const store = memoryStore()
    const record = { collection: "c", key: "k", owner: null, data: 1 }
    const name = (what: string): TypeError => new TypeError(`${what} must be a non-empty string.`)
    const whole = (what: string, min: number): RangeError =>
      new RangeError(`${what} must be a whole number of at least ${String(min)}.`)
    const refusals: [() => Promise<unknown>, Error][] = [
      [() => store.createUnique("", record), name("The tenant")],
      [() => store.get("", "c", "k"), name("The tenant")],
      [() => store.get(T, "", "k"), name("The collection")],
      [() => store.get(T, "c", ""), name("The key")],
      [() => store.listByOwner("", "c", "o"), name("The tenant")],
      [() => store.listByOwner(T, "", "o"), name("The collection")],
      [() => store.listByOwner(T, "c", ""), name("The owner")],
      [() => store.update(T, "c", "k", 0, {}), whole("The expected version", 1)],
      [() => store.update(T, "c", "k", 1, { expiresAt: -1 }), whole("expiresAt", 0)],
      [() => store.revoke(T, "c", "k", -1), whole("The revocation time", 0)],
      [() => store.revokeByOwner(T, "c", "o", -1), whole("The revocation time", 0)],
      [() => store.consumeOnce(T, "c", "k", -1), whole("The time", 0)],
      [() => store.increment("", "n", 1, 0), name("The tenant")],
      [() => store.increment(T, "", 1, 0), name("The counter")],
      [() => store.increment(T, "n", 0, 0), whole("The window", 1)],
      [() => store.increment(T, "n", 1, -1), whole("The time", 0)],
      [() => store.resetCounter("", "n"), name("The tenant")],
      [() => store.resetCounter(T, ""), name("The counter")],
      [() => store.appendAudit("", "s", 1, {}), name("The tenant")],
      [() => store.appendAudit(T, "", 1, {}), name("The stream")],
      [() => store.appendAudit(T, "s", 0, {}), whole("The sequence number", 1)],
      [
        () => store.appendAudit(T, "s", 1, Number.NaN),
        new TypeError("record is not a finite number."),
      ],
      [() => store.readAudit("", "s", 1, 1), name("The tenant")],
      [() => store.readAudit(T, "", 1, 1), name("The stream")],
      [() => store.readAudit(T, "s", 0, 1), whole("The first sequence number", 1)],
      [() => store.readAudit(T, "s", 1, 0), whole("The limit", 1)],
    ]
    for (const [run, error] of refusals) await expect(run()).rejects.toThrow(error)
  })

  it("refuses an update with a malformed expiry or data", async () => {
    const store = memoryStore()
    await store.createUnique(T, { collection: "c", key: "k", owner: null, data: 1 })
    await expect(store.update(T, "c", "k", 1, { expiresAt: 1.5 })).rejects.toThrow(RangeError)
    await expect(store.update(T, "c", "k", 1, { data: Number.NaN })).rejects.toThrow(TypeError)
    expect((await store.get(T, "c", "k"))?.version).toBe(1)
  })

  it("refuses data that is not plain JSON", async () => {
    const store = memoryStore()
    for (const data of [undefined, () => 1, Number.NaN, new Date(0), { a: undefined }, [1n]]) {
      await expect(
        store.createUnique(T, { collection: "c", key: "k", owner: null, data: data as never }),
      ).rejects.toThrow(TypeError)
    }
  })

  it("rolls a transaction back when its function throws, and commits it otherwise", async () => {
    const store = memoryStore()
    await store.createUnique(T, { collection: "session", key: "s1", owner: "a", data: 1 })
    await expect(
      store.transaction(async (tx) => {
        await tx.createUnique(T, { collection: "authenticator", key: "p1", owner: "a", data: 1 })
        await tx.revokeByOwner(T, "session", "a", 10)
        await tx.increment(T, "counter", 1000, 0)
        await tx.appendAudit(T, "stream", 1, { r: 1 })
        throw new Error("boom")
      }),
    ).rejects.toThrow("boom")
    expect(await store.get(T, "authenticator", "p1")).toBeNull()
    expect((await store.get(T, "session", "s1"))?.revokedAt).toBeNull()
    expect((await store.increment(T, "counter", 1000, 0)).count).toBe(1)
    expect(await store.appendAudit(T, "stream", 1, { r: 1 })).toBe("appended")

    expect(
      await store.transaction(async (tx) => {
        await tx.revokeByOwner(T, "session", "a", 20)
        return "done"
      }),
    ).toBe("done")
    expect((await store.get(T, "session", "s1"))?.revokedAt).toBe(20)
  })

  it("holds other callers until a transaction finishes, so none see its partial state", async () => {
    const store = memoryStore()
    let release: () => void = () => undefined
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    const running = store.transaction(async (tx) => {
      await tx.createUnique(T, { collection: "c", key: "k", owner: null, data: 1 })
      await gate
      throw new Error("abandon")
    })
    const outside = store.get(T, "c", "k")
    release()
    await expect(running).rejects.toThrow("abandon")
    expect(await outside).toBeNull()
  })
})
