// Model-based property test for the memory store (ADR 0002): random sequences of operations across two tenants are
// run against `memoryStore()` and against a few-line reference model of the port's documented semantics, and every
// result must agree. The seed is fixed, so a failure replays exactly.
import fc from "fast-check"
import { beforeAll, describe, expect, it } from "vitest"
import { memoryStore } from "../../src/store/memory.js"
import type { StoredRecord } from "../../src/store/port.js"

beforeAll(() => {
  fc.configureGlobal({ seed: 0x5f0e, numRuns: 300 })
})

const tenant = fc.constantFrom("a", "b")
const key = fc.constantFrom("k1", "k2")
const owner = fc.constantFrom("o1", "o2")
// A small time domain, so creates, expiries, consumes and windows often meet exactly at a boundary.
const time = fc.integer({ min: 0, max: 4 })

type Op =
  | {
      op: "create"
      t: string
      k: string
      owner: string | null
      expiresAt: number | null
      data: number
    }
  | { op: "get"; t: string; k: string }
  | { op: "consume"; t: string; k: string; now: number }
  | { op: "revoke"; t: string; k: string; at: number }
  | { op: "revokeByOwner"; t: string; owner: string; at: number; except: string | undefined }
  | { op: "update"; t: string; k: string; version: number; data: number }
  | { op: "delete"; t: string; k: string }
  | { op: "list"; t: string; owner: string }
  | { op: "increment"; t: string; counter: string; windowMs: number; now: number }
  | { op: "append"; t: string; seq: number }

const operation: fc.Arbitrary<Op> = fc.oneof(
  fc.record({
    op: fc.constant("create" as const),
    t: tenant,
    k: key,
    owner: fc.option(owner, { nil: null }),
    expiresAt: fc.option(time, { nil: null }),
    data: fc.integer({ min: 0, max: 9 }),
  }),
  fc.record({ op: fc.constant("get" as const), t: tenant, k: key }),
  fc.record({ op: fc.constant("consume" as const), t: tenant, k: key, now: time }),
  fc.record({ op: fc.constant("revoke" as const), t: tenant, k: key, at: time }),
  fc.record({
    op: fc.constant("revokeByOwner" as const),
    t: tenant,
    owner,
    at: time,
    except: fc.option(key, { nil: undefined }),
  }),
  fc.record({
    op: fc.constant("update" as const),
    t: tenant,
    k: key,
    version: fc.integer({ min: 1, max: 4 }),
    data: fc.integer({ min: 0, max: 9 }),
  }),
  fc.record({ op: fc.constant("delete" as const), t: tenant, k: key }),
  fc.record({ op: fc.constant("list" as const), t: tenant, owner }),
  fc.record({
    op: fc.constant("increment" as const),
    t: tenant,
    counter: fc.constantFrom("n1", "n2"),
    windowMs: fc.integer({ min: 1, max: 3 }),
    now: time,
  }),
  fc.record({ op: fc.constant("append" as const), t: tenant, seq: fc.integer({ min: 1, max: 4 }) }),
)

/** The port's documented semantics, written as plainly as possible. */
class Model {
  private readonly records = new Map<string, StoredRecord>()
  private readonly order: string[] = []
  private readonly counters = new Map<
    string,
    { count: number; windowStart: number; resetAt: number }
  >()
  private readonly lastSeq = new Map<string, number>()

  private id(t: string, k: string): string {
    return `${t}|c|${k}`
  }

  run(step: Op): unknown {
    switch (step.op) {
      case "create": {
        const id = this.id(step.t, step.k)
        if (this.records.has(id)) return "exists"
        this.records.set(id, {
          collection: "c",
          key: step.k,
          owner: step.owner,
          version: 1,
          expiresAt: step.expiresAt,
          revokedAt: null,
          consumedAt: null,
          data: step.data,
        })
        this.order.push(id)
        return "created"
      }
      case "get":
        return this.records.get(this.id(step.t, step.k)) ?? null
      case "consume": {
        const id = this.id(step.t, step.k)
        const r = this.records.get(id)
        if (r === undefined || r.consumedAt !== null || r.revokedAt !== null) return null
        if (r.expiresAt !== null && step.now >= r.expiresAt) return null
        const next = { ...r, consumedAt: step.now, version: r.version + 1 }
        this.records.set(id, next)
        return next
      }
      case "revoke": {
        const id = this.id(step.t, step.k)
        const r = this.records.get(id)
        if (r === undefined) return false
        if (r.revokedAt === null)
          this.records.set(id, { ...r, revokedAt: step.at, version: r.version + 1 })
        return true
      }
      case "revokeByOwner": {
        let count = 0
        for (const id of this.liveOrder(step.t)) {
          const r = this.records.get(id)
          if (
            r === undefined ||
            r.owner !== step.owner ||
            r.revokedAt !== null ||
            r.key === step.except
          )
            continue
          this.records.set(id, { ...r, revokedAt: step.at, version: r.version + 1 })
          count += 1
        }
        return count
      }
      case "update": {
        const id = this.id(step.t, step.k)
        const r = this.records.get(id)
        if (r === undefined) return "missing"
        if (r.version !== step.version) return "conflict"
        this.records.set(id, { ...r, data: step.data, version: r.version + 1 })
        return "updated"
      }
      case "delete": {
        const id = this.id(step.t, step.k)
        if (!this.records.has(id)) return false
        this.records.delete(id)
        this.order.splice(this.order.indexOf(id), 1)
        return true
      }
      case "list":
        return this.liveOrder(step.t)
          .map((id) => this.records.get(id))
          .filter((r): r is StoredRecord => r !== undefined && r.owner === step.owner)
      case "increment": {
        const id = `${step.t}|${step.counter}`
        const c = this.counters.get(id)
        const next =
          c === undefined || step.now >= c.resetAt
            ? { count: 1, windowStart: step.now, resetAt: step.now + step.windowMs }
            : { ...c, count: c.count + 1 }
        this.counters.set(id, next)
        return next
      }
      case "append": {
        const last = this.lastSeq.get(step.t) ?? 0
        if (step.seq <= last) return "duplicate"
        if (step.seq > last + 1) return "gap"
        this.lastSeq.set(step.t, step.seq)
        return "appended"
      }
    }
  }

  private liveOrder(t: string): string[] {
    return this.order.filter((id) => id.startsWith(`${t}|`))
  }
}

async function runStore(store: ReturnType<typeof memoryStore>, step: Op): Promise<unknown> {
  switch (step.op) {
    case "create":
      return store.createUnique(step.t, {
        collection: "c",
        key: step.k,
        owner: step.owner,
        expiresAt: step.expiresAt,
        data: step.data,
      })
    case "get":
      return store.get(step.t, "c", step.k)
    case "consume":
      return store.consumeOnce(step.t, "c", step.k, step.now)
    case "revoke":
      return store.revoke(step.t, "c", step.k, step.at)
    case "revokeByOwner":
      return store.revokeByOwner(step.t, "c", step.owner, step.at, { except: step.except })
    case "update":
      return store.update(step.t, "c", step.k, step.version, { data: step.data })
    case "delete":
      return store.delete(step.t, "c", step.k)
    case "list":
      return store.listByOwner(step.t, "c", step.owner)
    case "increment":
      return store.increment(step.t, step.counter, step.windowMs, step.now)
    case "append":
      return store.appendAudit(step.t, "s", step.seq, { seq: step.seq })
  }
}

describe("memoryStore against the reference model", () => {
  it("agrees on every result of any sequence of operations, in either tenant", async () => {
    await fc.assert(
      fc.asyncProperty(fc.array(operation, { minLength: 15, maxLength: 40 }), async (steps) => {
        const store = memoryStore()
        const model = new Model()
        for (const [index, step] of steps.entries()) {
          expect(await runStore(store, step), `step ${index}: ${JSON.stringify(step)}`).toEqual(
            model.run(step),
          )
        }
      }),
    )
  })
})
