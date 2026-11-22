/**
 * `test-cap/store/memory`: the reference store, for development and tests only (ADR 0002). It passes the conformance
 * kit within one process, but it keeps nothing across restarts and nothing between processes, so it declares itself
 * non-durable and production refuses it (ADR 0026).
 *
 * Every operation runs under one lock, so each is atomic and a transaction's partial state is never visible.
 * @packageDocumentation
 */

import {
  assertJson,
  assertName,
  assertNewRecord,
  assertWhole,
  type AuditEntry,
  type AuthStore,
  type CounterState,
  type StoreOperations,
  type StoredRecord,
} from "./port.js"

interface State {
  records: Map<string, StoredRecord>
  counters: Map<string, CounterState>
  audit: Map<string, AuditEntry[]>
}

/**
 * A map key for a sequence of names. Each name is written as its length, a colon and the name, and the entries are
 * joined with commas, so no two sequences share a key whatever characters the names hold, and the key of a sequence
 * starts with the key of each of its prefixes and of nothing else.
 */
const id = (...parts: string[]): string => parts.map((part) => `${part.length}:${part}`).join()

function copy<T>(value: T): T {
  return structuredClone(value)
}

function operations(state: State): StoreOperations {
  const read = (tenant: string, collection: string, key: string): StoredRecord | undefined => {
    assertName(tenant, "The tenant")
    assertName(collection, "The collection")
    assertName(key, "The key")
    return state.records.get(id(tenant, collection, key))
  }
  const write = (tenant: string, record: StoredRecord): void => {
    state.records.set(id(tenant, record.collection, record.key), record)
  }
  // Synchronous, so `revokeByOwner` reads and writes in one step that no other call on a transaction handle can split.
  const owned = (tenant: string, collection: string, owner: string): StoredRecord[] => {
    assertName(tenant, "The tenant")
    assertName(collection, "The collection")
    assertName(owner, "The owner")
    const prefix = id(tenant, collection)
    return [...state.records.entries()]
      .filter(([key, record]) => key.startsWith(prefix) && record.owner === owner)
      .map(([, record]) => record)
  }

  return {
    async createUnique(tenant, record) {
      assertName(tenant, "The tenant")
      assertNewRecord(record)
      if (state.records.has(id(tenant, record.collection, record.key))) return "exists"
      write(tenant, {
        collection: record.collection,
        key: record.key,
        owner: record.owner,
        version: 1,
        expiresAt: record.expiresAt ?? null,
        revokedAt: null,
        consumedAt: null,
        data: copy(record.data),
      })
      return "created"
    },

    async get(tenant, collection, key) {
      const record = read(tenant, collection, key)
      return record === undefined ? null : copy(record)
    },

    async listByOwner(tenant, collection, owner) {
      return owned(tenant, collection, owner).map(copy)
    },

    async update(tenant, collection, key, expectedVersion, change) {
      assertWhole(expectedVersion, "The expected version", 1)
      if (change.data !== undefined) assertJson(change.data)
      if (change.expiresAt !== undefined && change.expiresAt !== null)
        assertWhole(change.expiresAt, "expiresAt")
      const record = read(tenant, collection, key)
      if (record === undefined) return "missing"
      if (record.version !== expectedVersion) return "conflict"
      write(tenant, {
        ...record,
        version: record.version + 1,
        ...(change.data === undefined ? {} : { data: copy(change.data) }),
        ...(change.expiresAt === undefined ? {} : { expiresAt: change.expiresAt }),
      })
      return "updated"
    },

    async revoke(tenant, collection, key, at) {
      assertWhole(at, "The revocation time")
      const record = read(tenant, collection, key)
      if (record === undefined) return false
      if (record.revokedAt === null)
        write(tenant, { ...record, revokedAt: at, version: record.version + 1 })
      return true
    },

    async revokeByOwner(tenant, collection, owner, at, options = {}) {
      assertWhole(at, "The revocation time")
      let revoked = 0
      for (const record of owned(tenant, collection, owner)) {
        if (record.revokedAt !== null || record.key === options.except) continue
        write(tenant, { ...record, revokedAt: at, version: record.version + 1 })
        revoked += 1
      }
      return revoked
    },

    async delete(tenant, collection, key) {
      if (read(tenant, collection, key) === undefined) return false
      state.records.delete(id(tenant, collection, key))
      return true
    },

    async consumeOnce(tenant, collection, key, now) {
      assertWhole(now, "The time")
      const record = read(tenant, collection, key)
      if (record === undefined || record.consumedAt !== null || record.revokedAt !== null)
        return null
      if (record.expiresAt !== null && now >= record.expiresAt) return null
      const consumed: StoredRecord = { ...record, consumedAt: now, version: record.version + 1 }
      write(tenant, consumed)
      return copy(consumed)
    },

    async increment(tenant, counter, windowMs, now) {
      assertName(tenant, "The tenant")
      assertName(counter, "The counter")
      assertWhole(windowMs, "The window", 1)
      assertWhole(now, "The time")
      const key = id(tenant, counter)
      const current = state.counters.get(key)
      const next: CounterState =
        current === undefined || now >= current.resetAt
          ? { count: 1, windowStart: now, resetAt: now + windowMs }
          : { ...current, count: current.count + 1 }
      state.counters.set(key, next)
      return { ...next }
    },

    async resetCounter(tenant, counter) {
      assertName(tenant, "The tenant")
      assertName(counter, "The counter")
      state.counters.delete(id(tenant, counter))
    },

    async appendAudit(tenant, stream, seq, record) {
      assertName(tenant, "The tenant")
      assertName(stream, "The stream")
      assertWhole(seq, "The sequence number", 1)
      assertJson(record, "record")
      const key = id(tenant, stream)
      const entries = state.audit.get(key) ?? []
      const last = entries.at(-1)?.seq ?? 0
      if (seq <= last) return "duplicate"
      if (seq > last + 1) return "gap"
      entries.push({ stream, seq, record: copy(record) })
      state.audit.set(key, entries)
      return "appended"
    },

    async readAudit(tenant, stream, fromSeq, limit) {
      assertName(tenant, "The tenant")
      assertName(stream, "The stream")
      assertWhole(fromSeq, "The first sequence number", 1)
      assertWhole(limit, "The limit", 1)
      const entries = state.audit.get(id(tenant, stream)) ?? []
      // `appendAudit` admits no gap, so the entry with sequence number s sits at index s - 1.
      const start = fromSeq - 1
      return entries.slice(start, start + limit).map(copy)
    },
  }
}

/** A promise-chain lock: callers run one at a time, in call order. */
function createLock(): <T>(fn: () => Promise<T>) => Promise<T> {
  let tail: Promise<unknown> = Promise.resolve()
  return (fn) => {
    const result = tail.then(fn)
    tail = result.catch(() => undefined)
    return result
  }
}

/** The in-memory reference store. Development and tests only. */
export function memoryStore(): AuthStore & {
  /** Runs `fn` atomically under the store's one lock; the memory store always has transactions. */
  transaction: NonNullable<AuthStore["transaction"]>
} {
  const state: State = { records: new Map(), counters: new Map(), audit: new Map() }
  const ops = operations(state)
  const exclusive = createLock()
  const locked = Object.fromEntries(
    Object.entries(ops).map(([name, op]: [string, (...args: never[]) => Promise<unknown>]) => [
      name,
      (...args: never[]) => exclusive(() => op.apply(ops, args)),
    ]),
  ) as unknown as StoreOperations

  return {
    kind: "memory",
    durable: false,
    ...locked,
    transaction(fn) {
      return exclusive(async () => {
        const snapshot = copy(state)
        try {
          return await fn(ops)
        } catch (error) {
          state.records = snapshot.records
          state.counters = snapshot.counters
          state.audit = snapshot.audit
          throw error
        }
      })
    },
  }
}
