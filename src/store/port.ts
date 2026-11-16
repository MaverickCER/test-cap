/**
 * The `AuthStore` port (ADR 0002). test-cap never opens a connection: the app supplies a store, and every guarantee
 * the flows rely on is an operation of this port, so the hard part (atomicity) is tested once, in the store, by the
 * conformance kit. Every operation is scoped to one tenant (ADR 0012).
 *
 * Records are JSON documents addressed by collection and key, with an optional owner (usually an account id) to list
 * by, a version for optimistic updates, and the three lifecycle times flows check: expiry, revocation, consumption.
 */

/** A tenant id. Single-tenant apps use one constant tenant. */
export type TenantId = string

/** Plain JSON: what a store must be able to persist and return unchanged. */
export type JsonValue =
  null | boolean | number | string | readonly JsonValue[] | { readonly [key: string]: JsonValue }

/** A record as stored. Every read returns a copy; changing it changes nothing stored. */
export interface StoredRecord {
  /** The collection the record belongs to, such as `session`. */
  readonly collection: string
  /** The record's key, unique within its tenant and collection. */
  readonly key: string
  /** Who the record belongs to, for `listByOwner` and `revokeByOwner`; `null` for none. */
  readonly owner: string | null
  /** 1 on creation, plus one on every change. */
  readonly version: number
  /** Epoch ms after which `consumeOnce` refuses the record; `null` for none. */
  readonly expiresAt: number | null
  /** When the record was revoked; `null` while it is not. Never reset once set. */
  readonly revokedAt: number | null
  /** When `consumeOnce` took the record; `null` until then. */
  readonly consumedAt: number | null
  /** The record's JSON document, as last written. */
  readonly data: JsonValue
}

/** A record to create. */
export interface NewRecord {
  /** The collection to create the record in; a non-empty string. */
  readonly collection: string
  /** The record's key, unique within its tenant and collection; a non-empty string. */
  readonly key: string
  /** Who the record belongs to, a non-empty string; `null` for none. */
  readonly owner: string | null
  /** Epoch ms after which `consumeOnce` refuses the record, a whole number; absent or `null` for none. */
  readonly expiresAt?: number | null | undefined
  /** The record's JSON document. */
  readonly data: JsonValue
}

/** The fields `update` may change. Absent fields keep their value. */
export interface RecordChange {
  /** The new JSON document, replacing the old one whole. */
  readonly data?: JsonValue
  /** The new expiry (epoch ms, a whole number), or `null` to remove it. */
  readonly expiresAt?: number | null
}

/** A fixed-window counter after an increment. */
export interface CounterState {
  /** Increments in the current window, this one included; at least 1. */
  readonly count: number
  /** When this window started (epoch ms). */
  readonly windowStart: number
  /** When the next increment starts a new window (epoch ms). */
  readonly resetAt: number
}

/** One record of an audit stream. */
export interface AuditEntry {
  /** The audit stream the entry belongs to. */
  readonly stream: string
  /** The entry's position in its stream: 1 for the first, one more for each next. */
  readonly seq: number
  /** The JSON document appended at this position. */
  readonly record: JsonValue
}

/** The operations a transaction's steps run with. */
export interface StoreOperations {
  /** Tenant-scoped uniqueness: of any number of concurrent creates of one key, exactly one gets `created`. */
  createUnique(tenant: TenantId, record: NewRecord): Promise<"created" | "exists">
  /** The record at `key` in the collection, revoked and consumed ones included; `null` when there is none. */
  get(tenant: TenantId, collection: string, key: string): Promise<StoredRecord | null>
  /** The owner's records in one collection, oldest first, revoked and consumed ones included. */
  listByOwner(tenant: TenantId, collection: string, owner: string): Promise<readonly StoredRecord[]>
  /** Optimistic update: applies only when the stored version is `expectedVersion`. */
  update(
    tenant: TenantId,
    collection: string,
    key: string,
    expectedVersion: number,
    change: RecordChange,
  ): Promise<"updated" | "conflict" | "missing">
  /**
   * Sets `revokedAt` unless already set. Once this resolves, no read returns the record unrevoked. `false` when there
   * is no such record.
   */
  revoke(tenant: TenantId, collection: string, key: string, at: number): Promise<boolean>
  /** Revokes every unrevoked record of the owner in the collection, except `except`; returns how many. */
  revokeByOwner(
    tenant: TenantId,
    collection: string,
    owner: string,
    at: number,
    options?: { readonly except?: string | undefined },
  ): Promise<number>
  /** Removes the record; `false` when there was no such record. */
  delete(tenant: TenantId, collection: string, key: string): Promise<boolean>
  /**
   * Atomic single use: takes the record if it exists, is unconsumed, unrevoked and `now < expiresAt`. Of any number of
   * concurrent calls on one key, exactly one gets the record; the rest get `null`.
   */
  consumeOnce(
    tenant: TenantId,
    collection: string,
    key: string,
    now: number,
  ): Promise<StoredRecord | null>
  /**
   * Atomic fixed-window counter: no concurrent increment is lost. A call at or after `resetAt` starts a new window at
   * `now` with a count of 1.
   */
  increment(tenant: TenantId, counter: string, windowMs: number, now: number): Promise<CounterState>
  /** Forgets the counter, so the next `increment` starts a new window with a count of 1. */
  resetCounter(tenant: TenantId, counter: string): Promise<void>
  /**
   * Appends to an audit stream. The first `seq` is 1 and each next one is the last plus one: a higher `seq` is a
   * `gap`, a used one a `duplicate`, also under concurrency (ADR 0020).
   */
  appendAudit(
    tenant: TenantId,
    stream: string,
    seq: number,
    record: JsonValue,
  ): Promise<"appended" | "gap" | "duplicate">
  /** Up to `limit` entries with `seq >= fromSeq`, in `seq` order. */
  readAudit(
    tenant: TenantId,
    stream: string,
    fromSeq: number,
    limit: number,
  ): Promise<readonly AuditEntry[]>
}

/** The handle a transaction's function receives. */
export type StoreTransaction = StoreOperations

/** The store an app gives `createAuth`. */
export interface AuthStore extends StoreOperations {
  /** A short name for messages, such as `memory` or `sql`. */
  readonly kind: string
  /** False for a store that loses state on restart or is not shared between processes; production refuses it. */
  readonly durable: boolean
  /**
   * Optional. The steps in `fn` commit together or not at all. `fn` must use the handle it receives, never the
   * outer store.
   */
  transaction?<T>(fn: (tx: StoreTransaction) => Promise<T>): Promise<T>
}

/** Throws unless `value` is a non-empty string. */
export function assertName(value: string, what: string): void {
  if (typeof value !== "string" || value === "")
    throw new TypeError(`${what} must be a non-empty string.`)
}

/** Throws unless `value` is a whole number of milliseconds (or another whole quantity) of at least `min`. */
export function assertWhole(value: number, what: string, min = 0): void {
  if (!Number.isSafeInteger(value) || value < min) {
    throw new RangeError(`${what} must be a whole number of at least ${min}.`)
  }
}

function isPlainObject(value: object): boolean {
  const prototype: unknown = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

/** Throws unless `value` is plain JSON that survives a round trip unchanged. */
export function assertJson(value: unknown, path = "data"): asserts value is JsonValue {
  if (value === null || typeof value === "boolean" || typeof value === "string") return
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError(`${path} is not a finite number.`)
    return
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertJson(item, `${path}[${index}]`))
    return
  }
  if (typeof value === "object" && isPlainObject(value)) {
    for (const [key, item] of Object.entries(value)) assertJson(item, `${path}.${key}`)
    return
  }
  throw new TypeError(`${path} is not plain JSON.`)
}

/** Validates a record to create. */
export function assertNewRecord(record: NewRecord): void {
  assertName(record.collection, "The collection")
  assertName(record.key, "The key")
  if (record.owner !== null) assertName(record.owner, "The owner")
  if (record.expiresAt !== undefined && record.expiresAt !== null)
    assertWhole(record.expiresAt, "expiresAt")
  assertJson(record.data)
}
