/**
 * `test-cap/store/memory`: the reference store, for development and tests only (ADR 0002). It passes the conformance
 * kit within one process, but it keeps nothing across restarts and nothing between processes, so it declares itself
 * non-durable and production refuses it (ADR 0026).
 *
 * Every operation runs under one lock, so each is atomic and a transaction's partial state is never visible.
 * @packageDocumentation
 */

/** One record of an audit stream. */
declare interface AuditEntry {
    /** The audit stream the entry belongs to. */
    readonly stream: string;
    /** The entry's position in its stream: 1 for the first, one more for each next. */
    readonly seq: number;
    /** The JSON document appended at this position. */
    readonly record: JsonValue;
}

/** The store an app gives `createAuth`. */
declare interface AuthStore extends StoreOperations {
    /** A short name for messages, such as `memory` or `sql`. */
    readonly kind: string;
    /** False for a store that loses state on restart or is not shared between processes; production refuses it. */
    readonly durable: boolean;
    /**
     * Optional. The steps in `fn` commit together or not at all. `fn` must use the handle it receives, never the
     * outer store.
     */
    transaction?<T>(fn: (tx: StoreTransaction) => Promise<T>): Promise<T>;
}

/** A fixed-window counter after an increment. */
declare interface CounterState {
    /** Increments in the current window, this one included; at least 1. */
    readonly count: number;
    /** When this window started (epoch ms). */
    readonly windowStart: number;
    /** When the next increment starts a new window (epoch ms). */
    readonly resetAt: number;
}

/** Plain JSON: what a store must be able to persist and return unchanged. */
declare type JsonValue = null | boolean | number | string | readonly JsonValue[] | {
    readonly [key: string]: JsonValue;
};

/** The in-memory reference store. Development and tests only. */
export declare function memoryStore(): AuthStore & {
    /** Runs `fn` atomically under the store's one lock; the memory store always has transactions. */
    transaction: NonNullable<AuthStore["transaction"]>;
};

/** A record to create. */
declare interface NewRecord {
    /** The collection to create the record in; a non-empty string. */
    readonly collection: string;
    /** The record's key, unique within its tenant and collection; a non-empty string. */
    readonly key: string;
    /** Who the record belongs to, a non-empty string; `null` for none. */
    readonly owner: string | null;
    /** Epoch ms after which `consumeOnce` refuses the record, a whole number; absent or `null` for none. */
    readonly expiresAt?: number | null | undefined;
    /** The record's JSON document. */
    readonly data: JsonValue;
}

/** The fields `update` may change. Absent fields keep their value. */
declare interface RecordChange {
    /** The new JSON document, replacing the old one whole. */
    readonly data?: JsonValue;
    /** The new expiry (epoch ms, a whole number), or `null` to remove it. */
    readonly expiresAt?: number | null;
}

/** A record as stored. Every read returns a copy; changing it changes nothing stored. */
declare interface StoredRecord {
    /** The collection the record belongs to, such as `session`. */
    readonly collection: string;
    /** The record's key, unique within its tenant and collection. */
    readonly key: string;
    /** Who the record belongs to, for `listByOwner` and `revokeByOwner`; `null` for none. */
    readonly owner: string | null;
    /** 1 on creation, plus one on every change. */
    readonly version: number;
    /** Epoch ms after which `consumeOnce` refuses the record; `null` for none. */
    readonly expiresAt: number | null;
    /** When the record was revoked; `null` while it is not. Never reset once set. */
    readonly revokedAt: number | null;
    /** When `consumeOnce` took the record; `null` until then. */
    readonly consumedAt: number | null;
    /** The record's JSON document, as last written. */
    readonly data: JsonValue;
}

/** The operations a transaction's steps run with. */
declare interface StoreOperations {
    /** Tenant-scoped uniqueness: of any number of concurrent creates of one key, exactly one gets `created`. */
    createUnique(tenant: TenantId, record: NewRecord): Promise<"created" | "exists">;
    /** The record at `key` in the collection, revoked and consumed ones included; `null` when there is none. */
    get(tenant: TenantId, collection: string, key: string): Promise<StoredRecord | null>;
    /** The owner's records in one collection, oldest first, revoked and consumed ones included. */
    listByOwner(tenant: TenantId, collection: string, owner: string): Promise<readonly StoredRecord[]>;
    /** Optimistic update: applies only when the stored version is `expectedVersion`. */
    update(tenant: TenantId, collection: string, key: string, expectedVersion: number, change: RecordChange): Promise<"updated" | "conflict" | "missing">;
    /**
     * Sets `revokedAt` unless already set. Once this resolves, no read returns the record unrevoked. `false` when there
     * is no such record.
     */
    revoke(tenant: TenantId, collection: string, key: string, at: number): Promise<boolean>;
    /** Revokes every unrevoked record of the owner in the collection, except `except`; returns how many. */
    revokeByOwner(tenant: TenantId, collection: string, owner: string, at: number, options?: {
        readonly except?: string | undefined;
    }): Promise<number>;
    /** Removes the record; `false` when there was no such record. */
    delete(tenant: TenantId, collection: string, key: string): Promise<boolean>;
    /**
     * Atomic single use: takes the record if it exists, is unconsumed, unrevoked and `now < expiresAt`. Of any number of
     * concurrent calls on one key, exactly one gets the record; the rest get `null`.
     */
    consumeOnce(tenant: TenantId, collection: string, key: string, now: number): Promise<StoredRecord | null>;
    /**
     * Atomic fixed-window counter: no concurrent increment is lost. A call at or after `resetAt` starts a new window at
     * `now` with a count of 1.
     */
    increment(tenant: TenantId, counter: string, windowMs: number, now: number): Promise<CounterState>;
    /** Forgets the counter, so the next `increment` starts a new window with a count of 1. */
    resetCounter(tenant: TenantId, counter: string): Promise<void>;
    /**
     * Appends to an audit stream. The first `seq` is 1 and each next one is the last plus one: a higher `seq` is a
     * `gap`, a used one a `duplicate`, also under concurrency (ADR 0020).
     */
    appendAudit(tenant: TenantId, stream: string, seq: number, record: JsonValue): Promise<"appended" | "gap" | "duplicate">;
    /** Up to `limit` entries with `seq >= fromSeq`, in `seq` order. */
    readAudit(tenant: TenantId, stream: string, fromSeq: number, limit: number): Promise<readonly AuditEntry[]>;
}

/** The handle a transaction's function receives. */
declare type StoreTransaction = StoreOperations;

/**
 * The `AuthStore` port (ADR 0002). test-cap never opens a connection: the app supplies a store, and every guarantee
 * the flows rely on is an operation of this port, so the hard part (atomicity) is tested once, in the store, by the
 * conformance kit. Every operation is scoped to one tenant (ADR 0012).
 *
 * Records are JSON documents addressed by collection and key, with an optional owner (usually an account id) to list
 * by, a version for optimistic updates, and the three lifecycle times flows check: expiry, revocation, consumption.
 */
/** A tenant id. Single-tenant apps use one constant tenant. */
declare type TenantId = string;

export { }
