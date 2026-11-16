/**
 * `test-cap/conformance`: proves an `AuthStore` keeps the guarantees of ADR 0002. Each guarantee is exercised by many
 * parallel calls, because a race only shows under concurrency; a store that passes sequential tests can still redeem
 * a code twice. Tenant isolation is checked on every operation.
 *
 * Each check records what the store did and compares it with what the guarantee requires; a failure shows both. The
 * kit returns structured results instead of depending on a test framework, so it runs under Vitest, `node:test`, Bun
 * and Deno alike. Each check gets a fresh store from the factory.
 */

import type { AuthStore } from "../store/port.js"

/** One check's outcome. `detail` shows what the store did against what was required. */
export interface ConformanceResult {
  /** The check's stable identifier, such as `consume-once-concurrent`. */
  readonly id: string
  /** The guarantee the check tests, as one sentence. */
  readonly title: string
  /** True when the store kept the guarantee or the check was skipped. */
  readonly passed: boolean
  /** True when the check does not apply (a store without `transaction`). */
  readonly skipped?: boolean
  /** Present only on a failure: what the guarantee required and what the store gave, or what the check threw. */
  readonly detail?: string
}

/** Every check's outcome; `passed` is true only when none failed. */
export interface ConformanceReport {
  /** True only when no check failed. */
  readonly passed: boolean
  /** One result per check, in the kit's order. */
  readonly results: readonly ConformanceResult[]
}

/** Options for a run. */
export interface ConformanceOptions {
  /** Parallel calls per race check (default 25, at least 2). */
  readonly concurrency?: number
}

const A = "conformance-tenant-a"
const B = "conformance-tenant-b"
const HOUR = 3_600_000

/** What a check observed, and what the guarantee requires it to have observed. */
interface Observation {
  readonly observed: unknown
  readonly required: unknown
}

type Transaction = NonNullable<AuthStore["transaction"]>

type Check =
  | {
      readonly id: string
      readonly title: string
      readonly kind: "plain"
      run(store: AuthStore, concurrency: number): Promise<Observation>
    }
  | {
      readonly id: string
      readonly title: string
      readonly kind: "transaction"
      run(store: AuthStore, transaction: Transaction): Promise<Observation>
    }

/**
 * JSON with object keys sorted, so a store may return fields in any order, and with `undefined` spelled out, so a
 * missing record is never mistaken for a `null` field.
 */
function canonical(value: unknown): string {
  if (value === undefined) return '"[undefined]"'
  if (value === null || typeof value !== "object") return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`
  const record = value as Record<string, unknown>
  const keys = Object.keys(record).sort()
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`
}

function parallel<T>(count: number, call: (index: number) => Promise<T>): Promise<T[]> {
  return Promise.all(Array.from({ length: count }, (_, index) => call(index)))
}

function count<T>(items: readonly T[], predicate: (item: T) => boolean): number {
  return items.filter(predicate).length
}

const CHECKS: readonly Check[] = [
  {
    id: "create-unique-concurrent",
    title: "Concurrent creates of one key: exactly one succeeds, and its data is what is stored",
    kind: "plain",
    async run(store, n) {
      const results = await parallel(n, (i) =>
        store.createUnique(A, {
          collection: "identifier",
          key: "e@x",
          owner: `acct-${i}`,
          data: { i },
        }),
      )
      const winner = results.indexOf("created")
      const stored = await store.get(A, "identifier", "e@x")
      return {
        observed: { created: count(results, (r) => r === "created"), storedData: stored?.data },
        required: { created: 1, storedData: { i: winner } },
      }
    },
  },
  {
    id: "consume-once-concurrent",
    title: "Concurrent consumeOnce of one key: exactly one gets the record, and it stays consumed",
    kind: "plain",
    async run(store, n) {
      await store.createUnique(A, {
        collection: "secret",
        key: "k",
        owner: null,
        expiresAt: HOUR,
        data: 1,
      })
      const taken = await parallel(n, () => store.consumeOnce(A, "secret", "k", 1_000))
      const winners = taken.filter((record) => record !== null)
      const again = await store.consumeOnce(A, "secret", "k", 1_001)
      return {
        observed: { winners: winners.length, consumedAt: winners[0]?.consumedAt, again },
        required: { winners: 1, consumedAt: 1_000, again: null },
      }
    },
  },
  {
    id: "consume-once-expiry",
    title: "consumeOnce refuses a record at or after its expiry and takes it just before",
    kind: "plain",
    async run(store) {
      for (const [key, expiresAt] of [
        ["at", 1_000],
        ["before", 1_000],
        ["never", null],
      ] as const) {
        await store.createUnique(A, { collection: "c", key, owner: null, expiresAt, data: 1 })
      }
      const taken = async (key: string, now: number): Promise<boolean> =>
        (await store.consumeOnce(A, "c", key, now)) !== null
      return {
        observed: {
          atExpiry: await taken("at", 1_000),
          before: await taken("before", 999),
          never: await taken("never", 10 * HOUR),
        },
        required: { atExpiry: false, before: true, never: true },
      }
    },
  },
  {
    id: "consume-once-revoked",
    title: "consumeOnce refuses a revoked record",
    kind: "plain",
    async run(store) {
      await store.createUnique(A, { collection: "c", key: "k", owner: null, data: 1 })
      await store.revoke(A, "c", "k", 5)
      return { observed: await store.consumeOnce(A, "c", "k", 6), required: null }
    },
  },
  {
    id: "increment-concurrent",
    title: "Concurrent increments of one counter: none is lost",
    kind: "plain",
    async run(store, n) {
      const states = await parallel(n, () => store.increment(A, "failures", HOUR, 1_000))
      const next = await store.increment(A, "failures", HOUR, 1_001)
      return {
        observed: { counts: states.map((s) => s.count).sort((x, y) => x - y), next: next.count },
        required: { counts: Array.from({ length: n }, (_, i) => i + 1), next: n + 1 },
      }
    },
  },
  {
    id: "increment-window",
    title: "A counter starts a new window at its reset time",
    kind: "plain",
    async run(store) {
      const observed = [
        await store.increment(A, "w", 1_000, 0),
        await store.increment(A, "w", 1_000, 999),
        await store.increment(A, "w", 1_000, 1_000),
      ]
      return {
        observed,
        required: [
          { count: 1, windowStart: 0, resetAt: 1_000 },
          { count: 2, windowStart: 0, resetAt: 1_000 },
          { count: 1, windowStart: 1_000, resetAt: 2_000 },
        ],
      }
    },
  },
  {
    id: "counter-reset",
    title: "resetCounter clears a counter",
    kind: "plain",
    async run(store) {
      await store.increment(A, "r", HOUR, 0)
      await store.increment(A, "r", HOUR, 1)
      await store.resetCounter(A, "r")
      return { observed: (await store.increment(A, "r", HOUR, 2)).count, required: 1 }
    },
  },
  {
    id: "append-audit-order",
    title: "appendAudit refuses gaps and duplicates; readAudit returns entries in order",
    kind: "plain",
    async run(store) {
      const appends: string[] = []
      for (const seq of [2, 1, 1, 3, 2])
        appends.push(await store.appendAudit(A, "stream", seq, { seq }))
      const seqs = async (from: number, limit: number): Promise<number[]> =>
        (await store.readAudit(A, "stream", from, limit)).map((entry) => entry.seq)
      return {
        observed: {
          appends,
          all: await store.readAudit(A, "stream", 1, 10),
          fromTwo: await seqs(2, 10),
          firstOnly: await seqs(1, 1),
        },
        required: {
          appends: ["gap", "appended", "duplicate", "gap", "appended"],
          all: [
            { stream: "stream", seq: 1, record: { seq: 1 } },
            { stream: "stream", seq: 2, record: { seq: 2 } },
          ],
          fromTwo: [2],
          firstOnly: [1],
        },
      }
    },
  },
  {
    id: "append-audit-concurrent",
    title: "Concurrent appends of one seq: exactly one is stored",
    kind: "plain",
    async run(store, n) {
      const results = await parallel(n, (i) => store.appendAudit(A, "race", 1, { i }))
      const stored = await store.readAudit(A, "race", 1, n)
      return {
        observed: { appended: count(results, (r) => r === "appended"), stored },
        required: {
          appended: 1,
          stored: [{ stream: "race", seq: 1, record: { i: results.indexOf("appended") } }],
        },
      }
    },
  },
  {
    id: "revoke-visible",
    title: "A revocation is visible to the very next read and is never moved",
    kind: "plain",
    async run(store) {
      await store.createUnique(A, { collection: "session", key: "s", owner: "acct", data: 1 })
      const first = await store.revoke(A, "session", "s", 50)
      const afterGet = (await store.get(A, "session", "s"))?.revokedAt
      const afterList = (await store.listByOwner(A, "session", "acct"))[0]?.revokedAt
      const second = await store.revoke(A, "session", "s", 60)
      const afterSecond = (await store.get(A, "session", "s"))?.revokedAt
      const missing = await store.revoke(A, "session", "missing", 1)
      return {
        observed: { first, afterGet, afterList, second, afterSecond, missing },
        required: {
          first: true,
          afterGet: 50,
          afterList: 50,
          second: true,
          afterSecond: 50,
          missing: false,
        },
      }
    },
  },
  {
    id: "revoke-by-owner",
    title: "revokeByOwner revokes the owner's records except the one named, and no one else's",
    kind: "plain",
    async run(store) {
      for (const [key, owner] of [
        ["s1", "a"],
        ["s2", "a"],
        ["s3", "a"],
        ["s4", "b"],
      ] as const) {
        await store.createUnique(A, { collection: "session", key, owner, data: 1 })
      }
      const revoked = await store.revokeByOwner(A, "session", "a", 7, { except: "s2" })
      const times = await Promise.all(
        ["s1", "s2", "s3", "s4"].map(
          async (key) => (await store.get(A, "session", key))?.revokedAt,
        ),
      )
      const again = await store.revokeByOwner(A, "session", "a", 8, { except: "s2" })
      return {
        observed: { revoked, times, again },
        required: { revoked: 2, times: [7, null, 7, null], again: 0 },
      }
    },
  },
  {
    id: "update-version",
    title: "update applies only at the expected version",
    kind: "plain",
    async run(store) {
      await store.createUnique(A, { collection: "c", key: "k", owner: null, data: 1 })
      // Only the right update carries data; any other update a store wrongly applies still bumps the version.
      const wrong = await store.update(A, "c", "k", 2, {})
      const right = await store.update(A, "c", "k", 1, { data: 2 })
      const stale = await store.update(A, "c", "k", 1, {})
      const missing = await store.update(A, "c", "missing", 1, {})
      const record = await store.get(A, "c", "k")
      return {
        observed: { wrong, right, stale, missing, version: record?.version, data: record?.data },
        required: {
          wrong: "conflict",
          right: "updated",
          stale: "conflict",
          missing: "missing",
          version: 2,
          data: 2,
        },
      }
    },
  },
  {
    id: "update-concurrent",
    title:
      "Concurrent updates at one expected version: exactly one applies, and its data is what is stored",
    kind: "plain",
    async run(store, n) {
      await store.createUnique(A, { collection: "c", key: "k", owner: null, data: null })
      const results = await parallel(n, (i) => store.update(A, "c", "k", 1, { data: i }))
      const record = await store.get(A, "c", "k")
      return {
        observed: {
          updated: count(results, (r) => r === "updated"),
          conflict: count(results, (r) => r === "conflict"),
          version: record?.version,
          data: record?.data,
        },
        required: { updated: 1, conflict: n - 1, version: 2, data: results.indexOf("updated") },
      }
    },
  },
  {
    id: "delete",
    title: "delete removes a record so its key can be created again",
    kind: "plain",
    async run(store) {
      await store.createUnique(A, { collection: "c", key: "k", owner: null, data: 1 })
      const first = await store.delete(A, "c", "k")
      const read = await store.get(A, "c", "k")
      const second = await store.delete(A, "c", "k")
      const recreated = await store.createUnique(A, {
        collection: "c",
        key: "k",
        owner: null,
        data: 2,
      })
      return {
        observed: { first, read, second, recreated },
        required: { first: true, read: null, second: false, recreated: "created" },
      }
    },
  },
  {
    id: "returns-copies",
    title: "The store keeps its own copies: changing an input or a result changes nothing stored",
    kind: "plain",
    async run(store) {
      const data = { nested: { n: 1 } }
      await store.createUnique(A, { collection: "c", key: "k", owner: "o", data })
      data.nested.n = 2
      const read = await store.get(A, "c", "k")
      if (read !== null) (read.data as { nested: { n: number } }).nested.n = 3
      return { observed: (await store.get(A, "c", "k"))?.data, required: { nested: { n: 1 } } }
    },
  },
  {
    id: "tenant-isolation",
    title:
      "No operation in one tenant, resetCounter included, reads or changes another tenant's records, counters or audit",
    kind: "plain",
    async run(store) {
      await store.createUnique(A, { collection: "c", key: "k", owner: "o", data: "a" })
      await store.increment(A, "n", HOUR, 0)
      await store.appendAudit(A, "s", 1, "a")
      const fromB = {
        get: await store.get(B, "c", "k"),
        listByOwner: await store.listByOwner(B, "c", "o"),
        readAudit: await store.readAudit(B, "s", 1, 10),
        consumeOnce: await store.consumeOnce(B, "c", "k", 1),
        update: await store.update(B, "c", "k", 1, {}),
        revoke: await store.revoke(B, "c", "k", 1),
        revokeByOwner: await store.revokeByOwner(B, "c", "o", 1),
        delete: await store.delete(B, "c", "k"),
        increment: (await store.increment(B, "n", HOUR, 0)).count,
        appendAudit: await store.appendAudit(B, "s", 1, "b"),
        createUnique: await store.createUnique(B, {
          collection: "c",
          key: "k",
          owner: "o",
          data: "b",
        }),
      }
      // B's counter now stands at 1. Resetting it must leave A's counter, also at 1, where it was.
      await store.resetCounter(B, "n")
      const counters = {
        a: (await store.increment(A, "n", HOUR, 0)).count,
        b: (await store.increment(B, "n", HOUR, 0)).count,
      }
      const inA = await store.get(A, "c", "k")
      const inB = await store.get(B, "c", "k")
      return {
        observed: {
          fromB,
          counters,
          inA: [inA?.data, inA?.version, inA?.revokedAt, inA?.consumedAt],
          auditA: await store.readAudit(A, "s", 1, 10),
          auditB: await store.readAudit(B, "s", 1, 10),
          dataB: inB?.data,
        },
        required: {
          fromB: {
            get: null,
            listByOwner: [],
            readAudit: [],
            consumeOnce: null,
            update: "missing",
            revoke: false,
            revokeByOwner: 0,
            delete: false,
            increment: 1,
            appendAudit: "appended",
            createUnique: "created",
          },
          counters: { a: 2, b: 1 },
          inA: ["a", 1, null, null],
          auditA: [{ stream: "s", seq: 1, record: "a" }],
          auditB: [{ stream: "s", seq: 1, record: "b" }],
          dataB: "b",
        },
      }
    },
  },
  {
    id: "tenant-isolation-concurrent",
    title:
      "Racing the same keys in two tenants at once: each tenant gets its own winner and its own count",
    kind: "plain",
    async run(store, n) {
      const both = <T>(call: (tenant: string) => Promise<T>): Promise<[T[], T[]]> =>
        Promise.all([parallel(n, () => call(A)), parallel(n, () => call(B))])
      const [createdA, createdB] = await both((tenant) =>
        store.createUnique(tenant, {
          collection: "c",
          key: "k",
          owner: null,
          expiresAt: HOUR,
          data: tenant,
        }),
      )
      const [takenA, takenB] = await both((tenant) => store.consumeOnce(tenant, "c", "k", 1))
      const [countsA, countsB] = await both((tenant) => store.increment(tenant, "n", HOUR, 0))
      const [appendsA, appendsB] = await both((tenant) => store.appendAudit(tenant, "s", 1, tenant))
      const tally = (
        created: readonly string[],
        taken: readonly unknown[],
        counts: readonly { readonly count: number }[],
        appends: readonly string[],
      ): unknown => ({
        created: count(created, (r) => r === "created"),
        taken: count(taken, (r) => r !== null),
        counts: counts.map((s) => s.count).sort((x, y) => x - y),
        appended: count(appends, (r) => r === "appended"),
      })
      const each = {
        created: 1,
        taken: 1,
        counts: Array.from({ length: n }, (_, i) => i + 1),
        appended: 1,
      }
      return {
        observed: {
          a: tally(createdA, takenA, countsA, appendsA),
          b: tally(createdB, takenB, countsB, appendsB),
          data: [(await store.get(A, "c", "k"))?.data, (await store.get(B, "c", "k"))?.data],
          audit: [await store.readAudit(A, "s", 1, n), await store.readAudit(B, "s", 1, n)],
        },
        required: {
          a: each,
          b: each,
          data: [A, B],
          audit: [[{ stream: "s", seq: 1, record: A }], [{ stream: "s", seq: 1, record: B }]],
        },
      }
    },
  },
  {
    id: "transaction-rolls-back",
    title: "A transaction whose function throws rejects with that error and leaves nothing behind",
    kind: "transaction",
    async run(store, transaction) {
      await store.createUnique(A, { collection: "session", key: "s", owner: "acct", data: 1 })
      const boom = new Error()
      const outcome = await transaction(async (tx) => {
        await tx.createUnique(A, { collection: "authenticator", key: "p", owner: "acct", data: 1 })
        await tx.revokeByOwner(A, "session", "acct", 9)
        throw boom
      }).then(
        () => "resolved",
        (error: unknown) => (error === boom ? "rejected" : "rejected with another error"),
      )
      return {
        observed: {
          outcome,
          written: await store.get(A, "authenticator", "p"),
          revokedAt: (await store.get(A, "session", "s"))?.revokedAt,
        },
        required: { outcome: "rejected", written: null, revokedAt: null },
      }
    },
  },
  {
    id: "transaction-commits",
    title: "A transaction whose function succeeds keeps every write and returns its value",
    kind: "transaction",
    async run(store, transaction) {
      const value = await transaction(async (tx) => {
        await tx.createUnique(A, { collection: "authenticator", key: "p", owner: "acct", data: 1 })
        return "committed"
      })
      return {
        observed: { value, kept: (await store.get(A, "authenticator", "p")) !== null },
        required: { value: "committed", kept: true },
      }
    },
  },
]

/** Runs every check against fresh stores from `createStore`. */
export async function runAuthStoreConformance(
  createStore: () => AuthStore | Promise<AuthStore>,
  options: ConformanceOptions = {},
): Promise<ConformanceReport> {
  const concurrency = options.concurrency ?? 25
  if (!Number.isInteger(concurrency) || concurrency < 2) {
    throw new RangeError("The concurrency must be a whole number of at least 2.")
  }
  const results: ConformanceResult[] = []
  for (const check of CHECKS) {
    const store = await createStore()
    const base = { id: check.id, title: check.title }
    let run: () => Promise<Observation>
    if (check.kind === "plain") {
      run = () => check.run(store, concurrency)
    } else if (store.transaction === undefined) {
      results.push({ ...base, passed: true, skipped: true })
      continue
    } else {
      const transaction = store.transaction.bind(store)
      run = () => check.run(store, transaction)
    }
    let detail: string | undefined
    try {
      const { observed, required } = await run()
      const got = canonical(observed)
      const want = canonical(required)
      if (got !== want) detail = `Required ${want}; the store gave ${got}.`
    } catch (error) {
      detail = `The check threw: ${error instanceof Error ? error.message : String(error)}`
    }
    results.push(
      detail === undefined ? { ...base, passed: true } : { ...base, passed: false, detail },
    )
  }
  return { passed: results.every((result) => result.passed), results }
}
