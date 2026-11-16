/**
 * test-cap: the internal authentication package for MaverickCER apps.
 *
 * This entry holds the foundation's public contract (phase 2): the byte transport an adapter speaks, the store port an
 * app implements, the injected clock and random source, the deployment modes, and the two error types. `createAuth`
 * joins it when the first complete slice passes its gate (ADR 0004).
 * @packageDocumentation
 */

/** One record of an audit stream. */
export declare interface AuditEntry {
    /** The audit stream the entry belongs to. */
    readonly stream: string;
    /** The entry's position in its stream: 1 for the first, one more for each next. */
    readonly seq: number;
    /** The JSON document appended at this position. */
    readonly record: JsonValue;
}

/** The store an app gives `createAuth`. */
export declare interface AuthStore extends StoreOperations {
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

/**
 * The injected clock and random source (ADR 0003). Every expiry, window and time step reads a `Clock`; every token,
 * code and challenge draws from a `RandomSource`. The defaults read the system clock and Web Crypto.
 */
/** The time source every flow reads. */
export declare interface Clock {
    /** Epoch milliseconds. */
    now(): number;
}

/** A configuration test-cap refuses to start with. `problems` lists every one found, not only the first. */
export declare class ConfigError extends Error {
    /** One sentence per failed check, in the order found; never empty. */
    readonly problems: readonly string[];
    constructor(problems: readonly string[]);
}

/** Options for a run. */
export declare interface ConformanceOptions {
    /** Parallel calls per race check (default 25, at least 2). */
    readonly concurrency?: number;
}

/** Every check's outcome; `passed` is true only when none failed. */
export declare interface ConformanceReport {
    /** True only when no check failed. */
    readonly passed: boolean;
    /** One result per check, in the kit's order. */
    readonly results: readonly ConformanceResult[];
}

/** One check's outcome. `detail` shows what the store did against what was required. */
export declare interface ConformanceResult {
    /** The check's stable identifier, such as `consume-once-concurrent`. */
    readonly id: string;
    /** The guarantee the check tests, as one sentence. */
    readonly title: string;
    /** True when the store kept the guarantee or the check was skipped. */
    readonly passed: boolean;
    /** True when the check does not apply (a store without `transaction`). */
    readonly skipped?: boolean;
    /** Present only on a failure: what the guarantee required and what the store gave, or what the check threw. */
    readonly detail?: string;
}

/** A fixed-window counter after an increment. */
export declare interface CounterState {
    /** Increments in the current window, this one included; at least 1. */
    readonly count: number;
    /** When this window started (epoch ms). */
    readonly windowStart: number;
    /** When the next increment starts a new window (epoch ms). */
    readonly resetAt: number;
}

/**
 * Deployment mode and the startup checks (ADR 0026). `APP_ENV` sets the mode; a missing or unknown value is
 * production, so a mistyped variable fails safe. Production and staging refuse to start without an HTTPS origin, a
 * durable store and well-formed secrets. The checks look at presence and shape only: a key that is long and random
 * but leaked still passes.
 */
/** The deployment modes every cap shares (ADR 0022). */
export declare type DeploymentMode = "production" | "staging" | "development" | "test";

/** Plain JSON: what a store must be able to persist and return unchanged. */
export declare type JsonValue = null | boolean | number | string | readonly JsonValue[] | {
    readonly [key: string]: JsonValue;
};

/** A record to create. */
export declare interface NewRecord {
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

/**
 * The byte transport contract between adapters and the core (ADR 0003). Adapters convert their framework's request
 * into a `PlainRequest` and write the `PlainResponse` back; they parse nothing.
 */
/** A request as bytes. */
export declare interface PlainRequest {
    /** The HTTP method exactly as received, such as `POST`. */
    readonly method: string;
    /** Absolute (scheme, host, path and query) or origin-form (`/path?query`), exactly as received. */
    readonly url: string;
    /** Repeated headers keep every value. */
    readonly headers: Headers;
    /** The raw body, or `null` when there is none. */
    readonly body: Uint8Array | null;
    /** The socket's peer address. Never a forwarded header (ADR 0009). */
    readonly clientAddress?: string | undefined;
    /** Aborts when the client goes away; the core stops before its next store write. */
    readonly signal?: AbortSignal | undefined;
}

/** A response as bytes. Each `Set-Cookie` value stays separate (`headers.getSetCookie()`). */
export declare interface PlainResponse {
    /** The HTTP status code. */
    readonly status: number;
    /** The response headers; the adapter writes each `Set-Cookie` value as its own header line. */
    readonly headers: Headers;
    /** The raw body, or `null` when there is none. */
    readonly body: Uint8Array | null;
}

/**
 * The random source every token, code and challenge draws from. It must be cryptographically secure in production;
 * a predictable source makes every token guessable.
 */
export declare interface RandomSource {
    /** Fills `bytes` with random values and returns the same array. */
    fill(bytes: Uint8Array): Uint8Array;
}

/** The fields `update` may change. Absent fields keep their value. */
export declare interface RecordChange {
    /** The new JSON document, replacing the old one whole. */
    readonly data?: JsonValue;
    /** The new expiry (epoch ms, a whole number), or `null` to remove it. */
    readonly expiresAt?: number | null;
}

/** A record as stored. Every read returns a copy; changing it changes nothing stored. */
export declare interface StoredRecord {
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
export declare interface StoreOperations {
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

/** What the startup check needs to know about the store. */
export declare interface StoreTraits {
    /** The store's short name, such as `memory`, used in the refusal message. */
    readonly kind: string;
    /** False for a store that loses state on restart or is not shared between processes. */
    readonly durable: boolean;
}

/** The handle a transaction's function receives. */
export declare type StoreTransaction = StoreOperations;

/**
 * The `AuthStore` port (ADR 0002). test-cap never opens a connection: the app supplies a store, and every guarantee
 * the flows rely on is an operation of this port, so the hard part (atomicity) is tested once, in the store, by the
 * conformance kit. Every operation is scoped to one tenant (ADR 0012).
 *
 * Records are JSON documents addressed by collection and key, with an optional owner (usually an account id) to list
 * by, a version for optimistic updates, and the three lifecycle times flows check: expiry, revocation, consumption.
 */
/** A tenant id. Single-tenant apps use one constant tenant. */
export declare type TenantId = string;

/** A request refused by the transport. The message is for logs; responses carry only the code. */
export declare class TransportError extends Error {
    /** Why the request was refused; the only detail a response may carry. */
    readonly code: TransportErrorCode;
    /** The HTTP status the dispatcher answers with: 413 for `body-too-large`, 415 for `unsupported-media-type`, else 400. */
    readonly status: number;
    constructor(code: TransportErrorCode, message: string);
}

/**
 * The error model. A request the core refuses before any flow runs raises a `TransportError`, which the dispatcher
 * turns into its status code. A configuration that cannot run raises a `ConfigError` at startup, listing every problem
 * at once (ADR 0003, ADR 0026).
 */
/** Why the transport refused a request. */
export declare type TransportErrorCode = "aborted" | "ambiguous-header" | "body-too-large" | "duplicate-field" | "invalid-path" | "malformed-body" | "too-many-fields" | "unsupported-media-type";

export { }
