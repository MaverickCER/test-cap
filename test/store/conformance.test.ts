import { describe, expect, it } from "vitest"
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
    expect(skipped).toEqual(["transaction-rolls-back", "transaction-commits"])
  })

  it("accepts an async factory and a custom concurrency", async () => {
    const report = await runAuthStoreConformance(async () => memoryStore(), { concurrency: 3 })
    expect(report.passed).toBe(true)
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
    expect(await failedChecks(ignoresExpiry)).toEqual(["consume-once-expiry"])
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
    expect(await failedChecks(noReset)).toEqual(["counter-reset"])
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
    expect(await failedChecks(noRollback)).toEqual(["transaction-rolls-back"])
  })

  it("fails a transaction that drops the writes of a step that succeeded", async () => {
    const neverCommits = brokenStore(() => ({
      transaction: async (fn) => fn(bind(memoryStore())),
    }))
    expect(await failedChecks(neverCommits)).toEqual(["transaction-commits"])
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
    expect(await failedChecks(aliasingReads)).toEqual(["returns-copies"])
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
})
