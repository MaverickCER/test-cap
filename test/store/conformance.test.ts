import { describe, expect, it, vi } from "vitest"
import { runAuthStoreConformance } from "../../src/conformance/index.js"
import { memoryStore } from "../../src/store/memory.js"
import type { AuthStore, StoredRecord } from "../../src/store/port.js"

/** Yields to the event loop, which is where a read-then-write race opens up. */
const tick = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0))

/** A store that delegates to a real memory store, with selected operations replaced. */
function brokenStore(overrides: (inner: AuthStore) => Partial<AuthStore>): () => AuthStore {
  return () => {
    const inner = memoryStore()
    return { ...bind(inner), ...overrides(inner) }
  }
}

function bind(store: AuthStore): AuthStore {
  return {
    kind: "broken",
    durable: true,
    createUnique: store.createUnique.bind(store),
    get: store.get.bind(store),
    listByOwner: store.listByOwner.bind(store),
    update: store.update.bind(store),
    revoke: store.revoke.bind(store),
    revokeByOwner: store.revokeByOwner.bind(store),
    delete: store.delete.bind(store),
    consumeOnce: store.consumeOnce.bind(store),
    increment: store.increment.bind(store),
    resetCounter: store.resetCounter.bind(store),
    appendAudit: store.appendAudit.bind(store),
    readAudit: store.readAudit.bind(store),
  }
}

/** What one check reported for the store: the detail of its failure, or undefined when it passed. */
async function detailOf(createStore: () => AuthStore, id: string): Promise<string | undefined> {
  const report = await runAuthStoreConformance(createStore)
  return report.results.find((result) => result.id === id)?.detail
}

async function failedChecks(createStore: () => AuthStore): Promise<string[]> {
  const report = await runAuthStoreConformance(createStore)
  return report.results.filter((result) => !result.passed).map((result) => result.id)
}

describe("runAuthStoreConformance", () => {
  it("passes the memory store on every check, including the transaction checks", async () => {
    const report = await runAuthStoreConformance(() => memoryStore())
    expect(report.results.filter((r) => !r.passed)).toEqual([])
    expect(report.passed).toBe(true)
    expect(report.results.map((r) => r.id)).toContain("transaction-rolls-back")
  })

  it("reports the transaction checks as skipped for a store without transactions", async () => {
    const report = await runAuthStoreConformance(brokenStore(() => ({})))
    expect(report.passed).toBe(true)
    const skipped = report.results.filter((r) => r.skipped === true).map((r) => r.id)
    expect(skipped).toEqual([
      "transaction-rolls-back",
      "transaction-commits",
      "transaction-rolls-back-single-use",
      "transaction-rolls-back-operations",
      "transaction-consume-once-concurrent",
    ])
  })

  it("accepts an async factory and a custom concurrency", async () => {
    const report = await runAuthStoreConformance(async () => memoryStore(), { concurrency: 3 })
    expect(report.passed).toBe(true)
  })

  it("fails a check that never finishes, naming the timeout, and still runs every other check", async () => {
    const never = brokenStore(() => ({
      get: () => new Promise<StoredRecord | null>(() => undefined),
    }))
    const report = await runAuthStoreConformance(never, { timeoutMs: 20 })
    const hung = report.results.filter((result) => result.detail?.includes("did not finish"))
    expect(hung.length).toBeGreaterThan(0)
    expect(hung[0]?.detail).toBe("The check threw: the check did not finish within 20 ms")
    expect(report.results.length).toBe(
      (await runAuthStoreConformance(() => memoryStore())).results.length,
    )
    expect(report.results.some((result) => result.passed && result.skipped !== true)).toBe(true)
  })

  it("clears each check's timer when the check finishes, so a run leaves no timer behind", async () => {
    const timeoutMs = 123_457
    const started: unknown[] = []
    const cleared = new Set<unknown>()
    const realSet = globalThis.setTimeout
    const realClear = globalThis.clearTimeout
    const setSpy = vi.spyOn(globalThis, "setTimeout").mockImplementation(((
      handler: () => void,
      delay?: number,
    ) => {
      const handle = realSet(handler, delay)
      if (delay === timeoutMs) started.push(handle)
      return handle
    }) as typeof setTimeout)
    const clearSpy = vi.spyOn(globalThis, "clearTimeout").mockImplementation(((
      handle?: Parameters<typeof clearTimeout>[0],
    ) => {
      cleared.add(handle)
      realClear(handle)
    }) as typeof clearTimeout)
    try {
      const report = await runAuthStoreConformance(() => memoryStore(), { timeoutMs })
      expect(report.passed).toBe(true)
    } finally {
      setSpy.mockRestore()
      clearSpy.mockRestore()
    }
    expect(started.length).toBeGreaterThan(0)
    expect(started.filter((handle) => !cleared.has(handle))).toEqual([])
  })

  it("refuses a timeout that is not a whole number of milliseconds, at least 1, and runs at exactly 1", async () => {
    for (const timeoutMs of [0, 1.5, Number.NaN]) {
      await expect(
        runAuthStoreConformance(() => memoryStore(), { timeoutMs }),
        String(timeoutMs),
      ).rejects.toThrow(
        new RangeError("The timeout must be a whole number of milliseconds, at least 1."),
      )
    }
    const report = await runAuthStoreConformance(() => memoryStore(), { timeoutMs: 1 })
    expect(report.results.length).toBeGreaterThan(0)
  })

  it("refuses a concurrency below 2, which could not show a race, and runs at exactly 2", async () => {
    await expect(runAuthStoreConformance(() => memoryStore(), { concurrency: 1 })).rejects.toThrow(
      new RangeError("The concurrency must be a whole number of at least 2."),
    )
    await expect(
      runAuthStoreConformance(() => memoryStore(), { concurrency: 1.5 }),
    ).rejects.toThrow(RangeError)
    expect((await runAuthStoreConformance(() => memoryStore(), { concurrency: 2 })).passed).toBe(
      true,
    )
  })

  it("fails a consumeOnce that reads, yields, then marks consumed", async () => {
    const racy = brokenStore((inner) => ({
      async consumeOnce(tenant, collection, key, now) {
        const record = await inner.get(tenant, collection, key)
        if (record === null || record.consumedAt !== null || record.revokedAt !== null) return null
        if (record.expiresAt !== null && record.expiresAt <= now) return null
        await tick()
        await inner.consumeOnce(tenant, collection, key, now)
        return record
      },
    }))
    expect(await failedChecks(racy)).toEqual([
      "consume-once-concurrent",
      "tenant-isolation-concurrent",
    ])
  })

  it("fails a consumeOnce that ignores expiry or revocation", async () => {
    const ignoresExpiry = brokenStore((inner) => ({
      async consumeOnce(tenant, collection, key, now) {
        const record = await inner.get(tenant, collection, key)
        if (record?.expiresAt !== null && record !== undefined && record !== null) {
          await inner.update(tenant, collection, key, record.version, { expiresAt: null })
        }
        return inner.consumeOnce(tenant, collection, key, now)
      },
    }))
    expect(await failedChecks(ignoresExpiry)).toEqual([
      "create-unique-existing",
      "consume-once-expiry",
    ])
    const ignoresRevocation = brokenStore((inner) => ({
      async consumeOnce(tenant, collection, key, now) {
        const record = await inner.get(tenant, collection, key)
        if (record !== null && record.revokedAt !== null && record.consumedAt === null)
          return record
        return inner.consumeOnce(tenant, collection, key, now)
      },
    }))
    expect(await failedChecks(ignoresRevocation)).toEqual(["consume-once-revoked"])
  })

  it("fails an increment that loses concurrent updates", async () => {
    const lossy = brokenStore((inner) => {
      const counts = new Map<string, number>()
      return {
        async increment(tenant, counter, windowMs, now) {
          const id = `${tenant}/${counter}`
          const seen = counts.get(id) ?? 0
          await tick()
          counts.set(id, seen + 1)
          const real = await inner.increment(tenant, counter, windowMs, now)
          return { ...real, count: seen + 1 }
        },
      }
    })
    expect(await failedChecks(lossy)).toContain("increment-concurrent")
  })

  it("fails an increment that never starts a new window", async () => {
    const stuck = brokenStore((inner) => ({
      increment: (tenant, counter, windowMs) => inner.increment(tenant, counter, windowMs, 0),
    }))
    expect(await failedChecks(stuck)).toContain("increment-window")
  })

  it("fails a resetCounter that does nothing", async () => {
    const noReset = brokenStore(() => ({ resetCounter: async () => undefined }))
    expect(await failedChecks(noReset)).toEqual(["counter-reset", "tenant-isolation"])
  })

  it("fails a resetCounter that clears the counter in every tenant", async () => {
    const resetsAll = brokenStore((inner) => ({
      async resetCounter(_tenant, counter) {
        await inner.resetCounter("conformance-tenant-a", counter)
        await inner.resetCounter("conformance-tenant-b", counter)
      },
    }))
    const report = await runAuthStoreConformance(resetsAll)
    expect(report.results.filter((r) => !r.passed).map((r) => r.id)).toEqual(["tenant-isolation"])
    const detail = report.results.find((r) => r.id === "tenant-isolation")?.detail ?? ""
    expect(detail).toMatch(
      /^Required .*"counters":\{"a":2,"b":1\}.*; the store gave .*"counters":\{"a":1,"b":1\}/,
    )
  })

  it("fails a createUnique that checks then inserts with a yield in between", async () => {
    const racy = brokenStore((inner) => ({
      async createUnique(tenant, record) {
        if ((await inner.get(tenant, record.collection, record.key)) !== null) return "exists"
        await tick()
        await inner.delete(tenant, record.collection, record.key)
        return inner.createUnique(tenant, record)
      },
    }))
    expect(await failedChecks(racy)).toContain("create-unique-concurrent")
  })

  it("fails an appendAudit that accepts gaps or duplicates", async () => {
    const accepting = brokenStore((inner) => {
      const written: { stream: string; seq: number; record: unknown }[] = []
      return {
        async appendAudit(_tenant, stream, seq, record) {
          written.push({ stream, seq, record })
          return "appended"
        },
        readAudit: inner.readAudit.bind(inner),
      }
    })
    const failed = await failedChecks(accepting)
    expect(failed).toContain("append-audit-order")
    expect(failed).toContain("append-audit-concurrent")
  })

  it("fails a readAudit that returns entries out of order", async () => {
    const shuffled = brokenStore((inner) => ({
      readAudit: async (...args) => [...(await inner.readAudit(...args))].reverse(),
    }))
    expect(await failedChecks(shuffled)).toContain("append-audit-order")
  })

  it("fails a store whose revoke is not visible to the next read", async () => {
    const lagging = brokenStore((inner) => {
      const stale = new Map<string, StoredRecord>()
      return {
        async get(tenant, collection, key) {
          return stale.get(`${tenant}/${collection}/${key}`) ?? inner.get(tenant, collection, key)
        },
        async revoke(tenant, collection, key, at) {
          const before = await inner.get(tenant, collection, key)
          if (before !== null) stale.set(`${tenant}/${collection}/${key}`, before)
          return inner.revoke(tenant, collection, key, at)
        },
      }
    })
    expect(await failedChecks(lagging)).toContain("revoke-visible")
  })

  it("fails a revokeByOwner that ignores its exception or revokes other owners", async () => {
    const ignoresExcept = brokenStore((inner) => ({
      revokeByOwner: (tenant, collection, owner, at) =>
        inner.revokeByOwner(tenant, collection, owner, at),
    }))
    expect(await failedChecks(ignoresExcept)).toContain("revoke-by-owner")
  })

  it("fails an update that ignores the expected version", async () => {
    const blind = brokenStore((inner) => ({
      async update(tenant, collection, key, _expected, change) {
        const record = await inner.get(tenant, collection, key)
        return record === null
          ? "missing"
          : inner.update(tenant, collection, key, record.version, change)
      },
    }))
    expect(await failedChecks(blind)).toContain("update-version")
  })

  it("fails an update that checks the version, yields, then writes", async () => {
    const racy = brokenStore((inner) => ({
      async update(tenant, collection, key, expectedVersion, change) {
        const record = await inner.get(tenant, collection, key)
        if (record === null) return "missing"
        if (record.version !== expectedVersion) return "conflict"
        await tick()
        const current = await inner.get(tenant, collection, key)
        return inner.update(tenant, collection, key, current?.version ?? expectedVersion, change)
      },
    }))
    expect(await failedChecks(racy)).toEqual(["update-concurrent"])
    const report = await runAuthStoreConformance(racy, { concurrency: 2 })
    expect(report.results.find((r) => r.id === "update-concurrent")?.detail).toBe(
      'Required {"conflict":1,"data":0,"updated":1,"version":2}; ' +
        'the store gave {"conflict":0,"data":1,"updated":2,"version":3}.',
    )
  })

  it("fails a store that lets one tenant read another tenant's records", async () => {
    const leaky = brokenStore((inner) => ({
      get: (_tenant, collection, key) => inner.get("tenant-a", collection, key),
    }))
    expect(await failedChecks(leaky)).toContain("tenant-isolation")
  })

  it("fails a store that lets one tenant consume, count or audit in another tenant", async () => {
    const shared = brokenStore((inner) => ({
      consumeOnce: (_t, c, k, now) => inner.consumeOnce("tenant-a", c, k, now),
      increment: (_t, c, w, now) => inner.increment("tenant-a", c, w, now),
      readAudit: (_t, s, from, limit) => inner.readAudit("tenant-a", s, from, limit),
      listByOwner: (_t, c, o) => inner.listByOwner("tenant-a", c, o),
    }))
    expect(await failedChecks(shared)).toContain("tenant-isolation")
  })

  it("fails a store that keys records, counters and audit without the tenant", async () => {
    const tenantBlind = brokenStore((inner) => ({
      createUnique: (_t, record) => inner.createUnique("one", record),
      get: (_t, c, k) => inner.get("one", c, k),
      consumeOnce: (_t, c, k, now) => inner.consumeOnce("one", c, k, now),
      increment: (_t, c, w, now) => inner.increment("one", c, w, now),
      appendAudit: (_t, s, seq, r) => inner.appendAudit("one", s, seq, r),
    }))
    const failed = await failedChecks(tenantBlind)
    expect(failed).toContain("tenant-isolation-concurrent")
    expect(failed).toContain("tenant-isolation")
  })

  it("fails a store that returns its own stored objects", async () => {
    const aliasing = brokenStore(() => {
      const kept = new Map<string, StoredRecord>()
      return {
        async createUnique(tenant, record) {
          kept.set(`${tenant}/${record.collection}/${record.key}`, {
            collection: record.collection,
            key: record.key,
            owner: record.owner,
            version: 1,
            expiresAt: record.expiresAt ?? null,
            revokedAt: null,
            consumedAt: null,
            data: record.data,
          })
          return "created"
        },
        get: async (tenant, collection, key) => kept.get(`${tenant}/${collection}/${key}`) ?? null,
      }
    })
    expect(await failedChecks(aliasing)).toContain("returns-copies")
  })

  it("fails a delete that leaves the record readable", async () => {
    const noDelete = brokenStore(() => ({ delete: async () => true }))
    expect(await failedChecks(noDelete)).toContain("delete")
  })

  it("fails a transaction that keeps the writes of a step that threw", async () => {
    const noRollback = brokenStore((inner) => ({
      transaction: async (fn) => fn(bind(inner)),
    }))
    expect(await failedChecks(noRollback)).toEqual([
      "transaction-rolls-back",
      "transaction-rolls-back-single-use",
      "transaction-rolls-back-operations",
    ])
  })

  it("shows what a store that keeps a failed step's writes gave: the code taken, the set changed", async () => {
    const noRollback = brokenStore((inner) => ({
      transaction: async (fn) => fn(bind(inner)),
    }))
    expect(await detailOf(noRollback, "transaction-rolls-back-single-use")).toBe(
      'Required {"consumedAt":null,"outcome":"Error: rolled back","set":["old",1],"takenAgain":true}; ' +
        'the store gave {"consumedAt":0,"outcome":"Error: rolled back","set":["new",2],"takenAgain":false}.',
    )
  })

  it("shows a store that swallows the error of a step that threw", async () => {
    const swallows = brokenStore((inner) => ({
      transaction: async (fn) =>
        (inner as ReturnType<typeof memoryStore>).transaction(fn).catch(() => undefined as never),
    }))
    expect(await detailOf(swallows, "transaction-rolls-back-single-use")).toContain(
      '"outcome":"resolved"',
    )
  })

  it("reports, rather than throws on, a store that loses the records a failed step touched", async () => {
    const loses = brokenStore((inner) => ({
      transaction: async (fn) => {
        try {
          return await fn(bind(inner))
        } catch (error) {
          await inner.delete("conformance-tenant-a", "secret", "k")
          await inner.delete("conformance-tenant-a", "set", "acct")
          throw error
        }
      },
    }))
    const detail = await detailOf(loses, "transaction-rolls-back-single-use")
    expect(detail).toMatch(/^Required /)
    expect(detail).toContain('"set":["[undefined]","[undefined]"]')
  })

  it("fails a transaction that rolls back its writes but leaves the single use it took taken", async () => {
    const leaksSingleUse = brokenStore((inner) => {
      const taken = new Set<string>()
      const id = (...parts: string[]) => parts.join("/")
      return {
        async get(tenant, collection, key) {
          const record = await inner.get(tenant, collection, key)
          return record !== null && taken.has(id(tenant, collection, key))
            ? { ...record, consumedAt: record.consumedAt ?? 0 }
            : record
        },
        async consumeOnce(tenant, collection, key, now) {
          if (taken.has(id(tenant, collection, key))) return null
          return inner.consumeOnce(tenant, collection, key, now)
        },
        // The inner store is a memory store, which always has transactions.
        transaction: (fn) =>
          (inner as ReturnType<typeof memoryStore>).transaction((tx) =>
            fn({
              ...tx,
              async consumeOnce(tenant, collection, key, now) {
                const record = await tx.consumeOnce(tenant, collection, key, now)
                if (record !== null) taken.add(id(tenant, collection, key))
                return record
              },
            }),
          ),
      }
    })
    expect(await failedChecks(leaksSingleUse)).toEqual(["transaction-rolls-back-single-use"])
  })

  it("fails transactions that run side by side, each taking the same single-use record", async () => {
    const unisolated = brokenStore((inner) => ({
      transaction: async (fn) =>
        fn({
          ...bind(inner),
          async consumeOnce(tenant, collection, key, now) {
            const record = await inner.get(tenant, collection, key)
            if (record === null || record.consumedAt !== null) return null
            await tick()
            await inner.consumeOnce(tenant, collection, key, now)
            return record
          },
        }),
    }))
    expect(await failedChecks(unisolated)).toContain("transaction-consume-once-concurrent")
  })

  it("fails a transaction that drops the writes of a step that succeeded", async () => {
    const neverCommits = brokenStore(() => ({
      transaction: async (fn) => fn(bind(memoryStore())),
    }))
    expect(await failedChecks(neverCommits)).toEqual([
      "transaction-commits",
      "transaction-consume-once-concurrent",
    ])
  })

  it("passes a store that returns fields in another order", async () => {
    const reordered = brokenStore((inner) => ({
      readAudit: async (...args) =>
        (await inner.readAudit(...args)).map(({ record, seq, stream }) => ({
          record,
          seq,
          stream,
        })),
      get: async (...args) => {
        const record = await inner.get(...args)
        return record === null
          ? null
          : (Object.fromEntries(Object.entries(record).reverse()) as typeof record)
      },
    }))
    expect(await failedChecks(reordered)).toEqual([])
  })

  it("never mistakes a missing record for a null field", async () => {
    const deletesOnRollback = brokenStore((inner) => ({
      async transaction(fn) {
        try {
          return await fn(bind(inner))
        } catch (error) {
          await inner.delete("conformance-tenant-a", "authenticator", "p")
          await inner.delete("conformance-tenant-a", "session", "s")
          throw error
        }
      },
    }))
    const report = await runAuthStoreConformance(deletesOnRollback)
    const failed = report.results.find((r) => r.id === "transaction-rolls-back")
    expect(failed?.passed).toBe(false)
    expect(failed?.detail).toContain('"revokedAt":"[undefined]"')
  })

  it("fails a transaction that swallows its function's error or replaces it", async () => {
    const swallows = brokenStore((inner) => ({
      transaction: (fn) => fn(bind(inner)).catch(() => undefined as never),
    }))
    const swallowed = await runAuthStoreConformance(swallows)
    expect(swallowed.results.find((r) => r.id === "transaction-rolls-back")?.detail).toContain(
      '"outcome":"resolved"',
    )
    const replaces = brokenStore((inner) => ({
      transaction: (fn) =>
        fn(bind(inner)).catch(() => {
          throw new Error("something else")
        }),
    }))
    const replaced = await runAuthStoreConformance(replaces)
    expect(replaced.results.find((r) => r.id === "transaction-rolls-back")?.detail).toContain(
      '"outcome":"rejected with another error"',
    )
  })

  it("shows what was required and what the store gave", async () => {
    const noReset = brokenStore(() => ({ resetCounter: async () => undefined }))
    const report = await runAuthStoreConformance(noReset)
    expect(report.results.find((r) => r.id === "counter-reset")?.detail).toBe(
      "Required 1; the store gave 3.",
    )
  })

  it("reports a thrown non-Error value as text", async () => {
    const throwsString = brokenStore(() => ({
      resetCounter: () => Promise.reject("plain string"),
    }))
    const report = await runAuthStoreConformance(throwsString)
    expect(report.results.find((r) => r.id === "counter-reset")?.detail).toBe(
      "The check threw: plain string",
    )
  })

  it("passes a correct store that answers concurrent increments in a different order", async () => {
    // Counts arrive as 25..1 instead of 1..25; nothing is lost, so the store keeps the guarantee.
    const reversing = brokenStore((inner) => {
      let batch: (() => Promise<void>)[] = []
      return {
        increment: (tenant, counter, windowMs, now) =>
          new Promise((resolve, reject) => {
            if (batch.length === 0) {
              setTimeout(() => {
                const run = batch.reverse()
                batch = []
                void run.reduce((done, step) => done.then(step), Promise.resolve())
              }, 0)
            }
            batch.push(() => inner.increment(tenant, counter, windowMs, now).then(resolve, reject))
          }),
      }
    })
    expect(await failedChecks(reversing)).toEqual([])
  })

  it("reports a store that returns nothing as a mismatch on every check that reads, never as a crash", async () => {
    const empty = brokenStore(() => ({
      get: async () => null,
      listByOwner: async () => [],
      consumeOnce: async () => null,
    }))
    const report = await runAuthStoreConformance(empty)
    const details = Object.fromEntries(report.results.map((r) => [r.id, r.detail ?? "passed"]))
    for (const id of [
      "create-unique-concurrent",
      "consume-once-concurrent",
      "revoke-visible",
      "revoke-by-owner",
      "update-version",
      "update-concurrent",
      "returns-copies",
      "tenant-isolation",
      "tenant-isolation-concurrent",
    ]) {
      expect(details[id], id).toMatch(/^Required /)
    }
  })

  it("fails a store that hands out its own copy on read, even when it copied the input", async () => {
    const aliasingReads = brokenStore((inner) => {
      const kept = new Map<string, StoredRecord>()
      return {
        async get(tenant, collection, key) {
          const id = `${tenant}/${collection}/${key}`
          const record = kept.get(id) ?? (await inner.get(tenant, collection, key))
          if (record !== null) kept.set(id, record)
          return record
        },
      }
    })
    // It also serves its first read of a record forever, so later reads of changed records are stale too.
    expect(await failedChecks(aliasingReads)).toEqual([
      "update-fields",
      "returns-copies",
      "data-round-trip",
    ])
  })

  it("shows required and given values as sorted JSON, arrays included", async () => {
    const blind = brokenStore((inner) => ({
      async update(tenant, collection, key, _expected, change) {
        const record = await inner.get(tenant, collection, key)
        return record === null
          ? "missing"
          : inner.update(tenant, collection, key, record.version, change)
      },
    }))
    const report = await runAuthStoreConformance(blind)
    expect(report.results.find((r) => r.id === "update-version")?.detail).toBe(
      'Required {"data":2,"missing":"missing","right":"updated","stale":"conflict","version":2,"wrong":"conflict"}; ' +
        'the store gave {"data":2,"missing":"missing","right":"updated","stale":"updated","version":4,"wrong":"updated"}.',
    )
    const lossy = brokenStore((inner) => {
      let seen = 0
      return {
        async increment(tenant, counter, windowMs, now) {
          const before = seen
          await tick()
          seen = before + 1
          const real = await inner.increment(tenant, counter, windowMs, now)
          return { ...real, count: before + 1 }
        },
      }
    })
    const lossyReport = await runAuthStoreConformance(lossy, { concurrency: 2 })
    expect(lossyReport.results.find((r) => r.id === "increment-concurrent")?.detail).toBe(
      'Required {"counts":[1,2],"next":3}; the store gave {"counts":[1,1],"next":2}.',
    )
  })

  it("fails a concurrent append whose stored record is not the winner's", async () => {
    const wrongRecord = brokenStore((inner) => ({
      appendAudit: (tenant, stream, seq) => inner.appendAudit(tenant, stream, seq, { i: -1 }),
    }))
    expect(await failedChecks(wrongRecord)).toContain("append-audit-concurrent")
  })

  it("reports a check that throws as failed, with the error as its detail", async () => {
    const throwing = brokenStore(() => ({
      readAudit: () => Promise.reject(new Error("disk on fire")),
    }))
    const report = await runAuthStoreConformance(throwing)
    const failed = report.results.find((r) => r.id === "append-audit-order")
    expect(failed?.passed).toBe(false)
    expect(failed?.detail).toContain("disk on fire")
    expect(report.passed).toBe(false)
  })
  it("passes a memory store wrapped without changing anything, on every new check", async () => {
    expect(await failedChecks(brokenStore(() => ({})))).toEqual([])
  })

  it("fails a listByOwner that returns the newest record first", async () => {
    const newestFirst = brokenStore((inner) => ({
      listByOwner: async (...args) => [...(await inner.listByOwner(...args))].reverse(),
    }))
    expect(await failedChecks(newestFirst)).toEqual(["list-by-owner"])
    expect(await detailOf(newestFirst, "list-by-owner")).toBe(
      'Required {"consumedAt":[null,null,6,null],"keys":["s3","s1","s2","s4"],"none":[],"other":["o1"],"revokedAt":[null,5,null,null]}; ' +
        'the store gave {"consumedAt":[null,6,null,null],"keys":["s4","s2","s1","s3"],"none":[],"other":["o1"],"revokedAt":[null,null,5,null]}.',
    )
  })

  it("fails a listByOwner that sorts by key", async () => {
    const byKey = brokenStore((inner) => ({
      listByOwner: async (...args) =>
        [...(await inner.listByOwner(...args))].sort((x, y) => x.key.localeCompare(y.key)),
    }))
    expect(await failedChecks(byKey)).toEqual(["list-by-owner"])
  })

  it("fails a listByOwner that hides consumed or revoked records", async () => {
    const hidesConsumed = brokenStore((inner) => ({
      listByOwner: async (...args) =>
        (await inner.listByOwner(...args)).filter((r) => r.consumedAt === null),
    }))
    expect(await failedChecks(hidesConsumed)).toEqual(["list-by-owner"])
    expect(await detailOf(hidesConsumed, "list-by-owner")).toContain('"keys":["s3","s1","s4"]')
    const hidesRevoked = brokenStore((inner) => ({
      listByOwner: async (...args) =>
        (await inner.listByOwner(...args)).filter((r) => r.revokedAt === null),
    }))
    expect(await failedChecks(hidesRevoked)).toContain("list-by-owner")
    expect(await detailOf(hidesRevoked, "list-by-owner")).toContain('"keys":["s3","s2","s4"]')
  })

  it("fails a listByOwner that ignores the collection or the owner", async () => {
    const anyCollection = brokenStore((inner) => ({
      listByOwner: (tenant, _collection, owner) => inner.listByOwner(tenant, "session", owner),
    }))
    const all = brokenStore((inner) => ({
      listByOwner: async (tenant, collection) => [
        ...(await inner.listByOwner(tenant, collection, "a")),
        ...(await inner.listByOwner(tenant, collection, "b")),
      ],
    }))
    expect(await failedChecks(all)).toContain("list-by-owner")
    expect(await failedChecks(anyCollection)).toEqual(["list-by-owner"])
    expect(await detailOf(anyCollection, "list-by-owner")).toContain(
      '"other":["s3","s1","s2","s4"]',
    )
  })

  it("fails an update that ignores a changed or removed expiresAt", async () => {
    const ignoresExpiry = brokenStore((inner) => ({
      update: (tenant, collection, key, version, change) =>
        inner.update(
          tenant,
          collection,
          key,
          version,
          change.data === undefined ? {} : { data: change.data },
        ),
    }))
    expect(await failedChecks(ignoresExpiry)).toEqual(["update-fields"])
    expect(await detailOf(ignoresExpiry, "update-fields")).toBe(
      'Required ["updated",[2,5000,{"a":1,"b":2},"o"],"updated",[3,5000,{"c":3},"o"],"updated",[4,null,{"c":3},"o"],"updated",[5,7000,"both","o"]]; ' +
        'the store gave ["updated",[2,1000,{"a":1,"b":2},"o"],"updated",[3,1000,{"c":3},"o"],"updated",[4,1000,{"c":3},"o"],"updated",[5,1000,"both","o"]].',
    )
  })

  it("fails an update that merges data instead of replacing it, or drops fields it was not given", async () => {
    const merges = brokenStore((inner) => ({
      async update(tenant, collection, key, version, change) {
        const old = await inner.get(tenant, collection, key)
        const data =
          change.data !== undefined &&
          typeof change.data === "object" &&
          change.data !== null &&
          !Array.isArray(change.data) &&
          typeof old?.data === "object"
            ? { ...(old.data as object), ...change.data }
            : change.data
        return inner.update(
          tenant,
          collection,
          key,
          version,
          data === undefined ? change : { ...change, data },
        )
      },
    }))
    expect(await failedChecks(merges)).toContain("update-fields")
    const clearsExpiry = brokenStore((inner) => ({
      update: (tenant, collection, key, version, change) =>
        inner.update(tenant, collection, key, version, { expiresAt: null, ...change }),
    }))
    expect(await failedChecks(clearsExpiry)).toEqual(["update-fields"])
  })

  it("fails a createUnique that overwrites a consumed, revoked or expired record", async () => {
    const overwrites = (hit: (record: StoredRecord) => boolean) =>
      brokenStore((inner) => ({
        async createUnique(tenant, record) {
          const existing = await inner.get(tenant, record.collection, record.key)
          if (existing !== null && hit(existing)) {
            await inner.delete(tenant, record.collection, record.key)
          }
          return inner.createUnique(tenant, record)
        },
      }))
    const consumed = overwrites((r) => r.consumedAt !== null)
    const revoked = overwrites((r) => r.revokedAt !== null)
    const expired = overwrites((r) => r.expiresAt !== null && r.expiresAt < 10)
    for (const store of [consumed, revoked, expired]) {
      expect(await failedChecks(store)).toEqual(["create-unique-existing"])
    }
    expect(await detailOf(consumed, "create-unique-existing")).toBe(
      'Required {"again":["exists","exists","exists","exists"],"kept":[["first","live",1,null,null],["first","consumed",2,10,null],["first","revoked",2,null,20],["first","expired",1,null,null]]}; ' +
        'the store gave {"again":["exists","created","exists","exists"],"kept":[["first","live",1,null,null],["second","second",1,null,null],["first","revoked",2,null,20],["first","expired",1,null,null]]}.',
    )
    expect(await detailOf(expired, "create-unique-existing")).toContain(
      '"again":["exists","exists","exists","created"]',
    )
  })

  it("fails a createUnique that answers exists but replaces the stored record", async () => {
    const replaces = brokenStore((inner) => ({
      async createUnique(tenant, record) {
        const answer = await inner.createUnique(tenant, record)
        if (answer === "exists") {
          await inner.delete(tenant, record.collection, record.key)
          await inner.createUnique(tenant, record)
        }
        return answer
      },
    }))
    expect(await failedChecks(replaces)).toContain("create-unique-existing")
  })

  it("fails a store whose data does not come back exactly as written", async () => {
    const normalizes = brokenStore((inner) => ({
      createUnique: (tenant, record) =>
        inner.createUnique(tenant, {
          ...record,
          data: JSON.parse(
            JSON.stringify(record.data, (_k, v: unknown) =>
              typeof v === "string" ? v.normalize("NFKC") : v,
            ),
          ) as never,
        }),
    }))
    expect(await failedChecks(normalizes)).toEqual(["data-round-trip"])
    expect(await detailOf(normalizes, "data-round-trip")).toContain("the store gave")
    const truncates = brokenStore((inner) => ({
      createUnique: (tenant, record) =>
        inner.createUnique(tenant, {
          ...record,
          data: JSON.parse(
            JSON.stringify(record.data, (_k, v: unknown) =>
              typeof v === "string" ? v.slice(0, 50) : v,
            ),
          ) as never,
        }),
    }))
    expect(await failedChecks(truncates)).toEqual(["data-round-trip"])
    const singlePrecision = brokenStore((inner) => ({
      createUnique: (tenant, record) =>
        inner.createUnique(tenant, {
          ...record,
          data: JSON.parse(
            JSON.stringify(record.data, (_k, v: unknown) =>
              typeof v === "number" ? Math.fround(v) : v,
            ),
          ) as never,
        }),
    }))
    expect(await failedChecks(singlePrecision)).toEqual(["data-round-trip"])
  })

  it("fails a store whose update loses data on the way back", async () => {
    const lossyUpdate = brokenStore((inner) => ({
      update: (tenant, collection, key, version, change) =>
        inner.update(tenant, collection, key, version, {
          ...change,
          ...(change.data === undefined ? {} : { data: { stripped: true } }),
        }),
    }))
    const failed = await failedChecks(lossyUpdate)
    expect(failed).toContain("data-round-trip")
    expect(failed).toContain("update-fields")
  })

  it("fails a transaction that does not roll back increment, resetCounter, appendAudit, delete or revoke", async () => {
    // The memory store's transaction holds its lock, so a step cannot call the store itself. The mutant instead
    // replays the named operation on the store once the transaction has rolled back, which is what a store that
    // never rolled that operation back looks like afterwards.
    const outside = (
      name: "increment" | "resetCounter" | "appendAudit" | "delete" | "revoke",
    ): (() => AuthStore) =>
      brokenStore((inner) => ({
        async transaction(fn) {
          const replay: (() => Promise<unknown>)[] = []
          try {
            return await (inner as ReturnType<typeof memoryStore>).transaction((tx) =>
              fn({
                ...tx,
                [name]: (...args: unknown[]) => {
                  replay.push(() => (inner[name] as (...a: unknown[]) => Promise<unknown>)(...args))
                  return (tx[name] as (...a: unknown[]) => Promise<unknown>)(...args)
                },
              } as typeof tx),
            )
          } catch (error) {
            for (const step of replay) await step()
            throw error
          }
        },
      }))
    const expected = {
      increment: '"up":3',
      resetCounter: '"down":1',
      appendAudit:
        '"audit":[{"record":"first","seq":1,"stream":"log"},{"record":"second","seq":2,"stream":"log"}]',
      delete: '"gone":"[undefined]"',
      revoke: '"revokedAt":9',
    }
    for (const name of Object.keys(expected) as (keyof typeof expected)[]) {
      expect(await failedChecks(outside(name)), name).toEqual(["transaction-rolls-back-operations"])
      expect(await detailOf(outside(name), "transaction-rolls-back-operations"), name).toContain(
        expected[name],
      )
    }
  })
  /** Only the round-trip check writes a document with a `unicode` member. */
  const isRoundTripData = (value: unknown): boolean =>
    typeof value === "object" && value !== null && ("unicode" in value || "again" in value)

  it("pins the data the round-trip check writes, value by value", async () => {
    const written: unknown[] = []
    const spy = brokenStore((inner) => ({
      createUnique(tenant, record) {
        if (isRoundTripData(record.data)) written.push(record.data)
        return inner.createUnique(tenant, record)
      },
      update(tenant, collection, key, version, change) {
        if (isRoundTripData(change.data)) written.push(change.data)
        return inner.update(tenant, collection, key, version, change)
      },
    }))
    expect(await detailOf(spy, "data-round-trip")).toBeUndefined()
    const data = {
      unicode: ["\u{1F600}", "e\u0301", "\uFB01", "\u2028", "\u00e9", "   ", ""],
      floats: [0.1, -1.5e-7, 1e21, 123456789.12345679, Number.MAX_SAFE_INTEGER, -0.000001],
      long: "x".repeat(5_000),
      empty: { list: [], map: {} },
      flags: [null, true, false],
      nested: { a: { b: { c: [1, [2, [3]]] } } },
    }
    // Both the first write and the update's write: the update wraps the same document.
    expect(written.slice(0, 2)).toEqual([data, { again: data }])
    expect(JSON.stringify(written[0])).toBe(JSON.stringify(data))
    expect(Object.is((written[0] as typeof data).floats[1], -1.5e-7)).toBe(true)
  })

  it("reports, rather than throws on, a store that returns no record where the new checks read one", async () => {
    const empty = brokenStore((inner) => ({
      get: async () => null,
      transaction: (fn) =>
        (inner as ReturnType<typeof memoryStore>).transaction((tx) =>
          fn({ ...tx, get: async () => null }),
        ),
    }))
    const report = await runAuthStoreConformance(empty)
    const detail = (id: string): string | undefined =>
      report.results.find((r) => r.id === id)?.detail
    expect(detail("create-unique-existing")).toBe(
      'Required {"again":["exists","exists","exists","exists"],"kept":[["first","live",1,null,null],["first","consumed",2,10,null],["first","revoked",2,null,20],["first","expired",1,null,null]]}; ' +
        'the store gave {"again":["exists","exists","exists","exists"],"kept":[["[undefined]","[undefined]","[undefined]","[undefined]","[undefined]"],["[undefined]","[undefined]","[undefined]","[undefined]","[undefined]"],["[undefined]","[undefined]","[undefined]","[undefined]","[undefined]"],["[undefined]","[undefined]","[undefined]","[undefined]","[undefined]"]]}.',
    )
    expect(detail("update-fields")).toMatch(
      /the store gave \["updated",\["\[undefined\]","\[undefined\]","\[undefined\]","\[undefined\]"\],"updated",/,
    )
    expect(detail("data-round-trip")).toMatch(
      /the store gave \{"created":"\[undefined\]","updated":"\[undefined\]"\}\.$/,
    )
    expect(detail("transaction-rolls-back-operations")).toMatch(
      /^Required .*the store gave \{.*"gone":"\[undefined\]".*"revokedAt":"\[undefined\]"/,
    )
  })

  it("shows a store that swallows the error of a transaction that undid five operations", async () => {
    const swallows = brokenStore((inner) => ({
      transaction: async (fn) =>
        (inner as ReturnType<typeof memoryStore>).transaction(fn).catch(() => undefined as never),
    }))
    const detail = await detailOf(swallows, "transaction-rolls-back-operations")
    expect(detail).toBe(
      'Required {"audit":[{"record":"first","seq":1,"stream":"log"}],"down":3,"gone":"kept","outcome":"Error: rolled back","revokedAt":null,"up":2}; ' +
        'the store gave {"audit":[{"record":"first","seq":1,"stream":"log"}],"down":3,"gone":"kept","outcome":"resolved","revokedAt":null,"up":2}.',
    )
  })

  it("shows a store whose transaction resolves with nothing as an outcome that is not text", async () => {
    const vanishes = brokenStore((inner) => ({
      transaction: async (fn) => {
        await (inner as ReturnType<typeof memoryStore>).transaction(fn).catch(() => undefined)
        return undefined as never
      },
    }))
    expect(await detailOf(vanishes, "transaction-rolls-back-operations")).toContain(
      '"outcome":"resolved"',
    )
  })
})
