/**
 * `test-cap/store/sql`: the `AuthStore` port over the app's own SQL connection (ADR 0002). test-cap never opens a
 * connection and never runs DDL: the app passes a `query` function (and, for multi-step changes, a `transaction`
 * function), and applies the schema `migrations()` prints with its own migration tool.
 *
 * Every guarantee is one statement whose atomicity the database enforces through a constraint:
 * - `createUnique`: an insert that does nothing on a duplicate key;
 * - `consumeOnce`: a conditional update only the first caller matches;
 * - `increment`: an upsert that starts a new window or adds one;
 * - `appendAudit`: an insert that only happens when `seq - 1` exists, over a unique `(tenant, stream, seq)`.
 *
 * MySQL has no `RETURNING`, so its `consumeOnce` and `increment` read back the changed row inside the app's
 * transaction, which holds the row lock; the MySQL dialect therefore requires `transaction`. Values only ever travel
 * as parameters, never in the SQL text.
 */

import {
  type AuditEntry,
  type AuthStore,
  type CounterState,
  type JsonValue,
  type StoreOperations,
  type StoredRecord,
} from "./port.js"
import { validated } from "./validated.js"

/** The SQL dialects `sqlStore` writes. */
export type SqlDialect = "postgres" | "sqlite" | "mysql"

/** A value sent as a statement parameter. */
export type SqlParam = string | number | null

/** What the app's query function returns for one statement. */
export interface SqlResult {
  /** The rows a `SELECT` or a `RETURNING` clause produced; empty for any other statement. */
  readonly rows: readonly Readonly<Record<string, unknown>>[]
  /**
   * How many rows an `INSERT`, `UPDATE` or `DELETE` changed. An upsert that changed nothing must report 0 (for MySQL,
   * connect without the FOUND_ROWS flag).
   */
  readonly affectedRows: number
}

/** The app's query function: runs one statement with its parameters on the app's own connection. */
export type SqlQuery = (sql: string, params: readonly SqlParam[]) => Promise<SqlResult>

/** Runs `fn` inside one database transaction, with a `query` bound to it; commits on success, rolls back on throw. */
export type SqlTransaction = <T>(fn: (query: SqlQuery) => Promise<T>) => Promise<T>

/** Options for `sqlStore`. */
export interface SqlStoreOptions {
  /** Which SQL the store writes. */
  readonly dialect: SqlDialect
  /** Runs every statement outside a transaction. */
  readonly query: SqlQuery
  /** Required for MySQL; elsewhere it enables `AuthStore.transaction`. */
  readonly transaction?: SqlTransaction | undefined
  /** Prefix for the three table names; lowercase letters, digits and underscores (default `test_cap_`). */
  readonly tablePrefix?: string | undefined
}

const DIALECTS: ReadonlySet<string> = new Set(["postgres", "sqlite", "mysql"])
const PREFIX = /^[a-z][a-z0-9_]{0,39}$/

function checkDialect(dialect: string): void {
  if (!DIALECTS.has(dialect)) throw new TypeError(`Unknown SQL dialect "${dialect}".`)
}

function checkPrefix(prefix: string): void {
  if (!PREFIX.test(prefix)) {
    throw new TypeError(
      "The table prefix must be lowercase letters, digits and underscores, starting with a letter.",
    )
  }
}

interface Tables {
  readonly records: string
  readonly counters: string
  readonly audit: string
}

function tables(prefix: string): Tables {
  return { records: `${prefix}records`, counters: `${prefix}counters`, audit: `${prefix}audit` }
}

/** The schema for `dialect`, as SQL text the app applies with its own migration tool. */
export function migrations(
  dialect: SqlDialect,
  options: { readonly tablePrefix?: string } = {},
): string {
  checkDialect(dialect)
  const prefix = options.tablePrefix ?? "test_cap_"
  checkPrefix(prefix)
  const t = tables(prefix)
  if (dialect === "mysql") {
    const name = "VARCHAR(255) NOT NULL"
    const table = "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin"
    return [
      `CREATE TABLE IF NOT EXISTS ${t.records} (id BIGINT AUTO_INCREMENT PRIMARY KEY, tenant ${name}, collection ${name}, record_key ${name}, owner VARCHAR(255) NULL, version BIGINT NOT NULL, expires_at BIGINT NULL, revoked_at BIGINT NULL, consumed_at BIGINT NULL, data LONGTEXT NOT NULL, UNIQUE (tenant, collection, record_key), INDEX ${t.records}_owner (tenant, collection, owner)) ${table};`,
      `CREATE TABLE IF NOT EXISTS ${t.counters} (tenant ${name}, counter ${name}, hits BIGINT NOT NULL, window_start BIGINT NOT NULL, reset_at BIGINT NOT NULL, PRIMARY KEY (tenant, counter)) ${table};`,
      `CREATE TABLE IF NOT EXISTS ${t.audit} (tenant ${name}, stream ${name}, seq BIGINT NOT NULL, record LONGTEXT NOT NULL, PRIMARY KEY (tenant, stream, seq)) ${table};`,
    ].join("\n")
  }
  const id =
    dialect === "postgres"
      ? "BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY"
      : "INTEGER PRIMARY KEY AUTOINCREMENT"
  return [
    `CREATE TABLE IF NOT EXISTS ${t.records} (id ${id}, tenant TEXT NOT NULL, collection TEXT NOT NULL, record_key TEXT NOT NULL, owner TEXT NULL, version BIGINT NOT NULL, expires_at BIGINT NULL, revoked_at BIGINT NULL, consumed_at BIGINT NULL, data TEXT NOT NULL, UNIQUE (tenant, collection, record_key));`,
    `CREATE INDEX IF NOT EXISTS ${t.records}_owner ON ${t.records} (tenant, collection, owner);`,
    `CREATE TABLE IF NOT EXISTS ${t.counters} (tenant TEXT NOT NULL, counter TEXT NOT NULL, hits BIGINT NOT NULL, window_start BIGINT NOT NULL, reset_at BIGINT NOT NULL, PRIMARY KEY (tenant, counter));`,
    `CREATE TABLE IF NOT EXISTS ${t.audit} (tenant TEXT NOT NULL, stream TEXT NOT NULL, seq BIGINT NOT NULL, record TEXT NOT NULL, PRIMARY KEY (tenant, stream, seq));`,
  ].join("\n")
}

/** Rewrites `?` placeholders as `$1, $2, …` for Postgres. The SQL text here never holds a literal `?`. */
function placeholders(dialect: SqlDialect, sql: string): string {
  if (dialect !== "postgres") return sql
  let index = 0
  return sql.replace(/\?/g, () => {
    index += 1
    return `$${index}`
  })
}

function toNumber(value: unknown, column: string): number {
  const number =
    typeof value === "bigint" ? Number(value) : typeof value === "string" ? Number(value) : value
  // Number.isSafeInteger is false for anything that is not a number, so it is the whole check.
  if (!Number.isSafeInteger(number))
    throw new TypeError(`The driver returned a non-integer ${column}.`)
  return number as number
}

function toNullableNumber(value: unknown, column: string): number | null {
  return value === null || value === undefined ? null : toNumber(value, column)
}

function toText(value: unknown, column: string): string {
  if (typeof value !== "string") throw new TypeError(`The driver returned a non-text ${column}.`)
  return value
}

const COLUMNS = "collection, record_key, owner, version, expires_at, revoked_at, consumed_at, data"

function toRecord(row: Readonly<Record<string, unknown>>): StoredRecord {
  const owner = row["owner"]
  return {
    collection: toText(row["collection"], "collection"),
    key: toText(row["record_key"], "record_key"),
    owner: owner === null || owner === undefined ? null : toText(owner, "owner"),
    version: toNumber(row["version"], "version"),
    expiresAt: toNullableNumber(row["expires_at"], "expires_at"),
    revokedAt: toNullableNumber(row["revoked_at"], "revoked_at"),
    consumedAt: toNullableNumber(row["consumed_at"], "consumed_at"),
    data: JSON.parse(toText(row["data"], "data")) as JsonValue,
  }
}

function toCounter(row: Readonly<Record<string, unknown>> | undefined): CounterState {
  if (row === undefined) throw new TypeError("The counter upsert returned no row.")
  return {
    count: toNumber(row["hits"], "hits"),
    windowStart: toNumber(row["window_start"], "window_start"),
    resetAt: toNumber(row["reset_at"], "reset_at"),
  }
}

/** Runs a two-step MySQL operation atomically: in the app's transaction, or directly when already inside one. */
type Atomic = <T>(fn: (query: SqlQuery) => Promise<T>) => Promise<T>

/** A query function that rewrites placeholders for the dialect before calling `query`. */
function placed(dialect: SqlDialect, query: SqlQuery): SqlQuery {
  return (sql, params) => query(placeholders(dialect, sql), params)
}

const WHERE_KEY = "tenant = ? AND collection = ? AND record_key = ?"

/** The operations every dialect shares; Postgres and SQLite also use `consumeOnce` and `increment` from here. */
function operations(dialect: SqlDialect, t: Tables, query: SqlQuery): StoreOperations {
  const mysql = dialect === "mysql"
  const exists = async (tenant: string, collection: string, key: string): Promise<boolean> =>
    (
      await query(`SELECT 1 AS found FROM ${t.records} WHERE ${WHERE_KEY}`, [
        tenant,
        collection,
        key,
      ])
    ).rows.length > 0

  return {
    async createUnique(tenant, record) {
      const insert = `INSERT INTO ${t.records} (tenant, collection, record_key, owner, version, expires_at, revoked_at, consumed_at, data) VALUES (?, ?, ?, ?, 1, ?, NULL, NULL, ?)`
      const onConflict = mysql
        ? " ON DUPLICATE KEY UPDATE id = id"
        : " ON CONFLICT (tenant, collection, record_key) DO NOTHING"
      const result = await query(insert + onConflict, [
        tenant,
        record.collection,
        record.key,
        record.owner,
        record.expiresAt ?? null,
        JSON.stringify(record.data),
      ])
      return result.affectedRows === 1 ? "created" : "exists"
    },

    async get(tenant, collection, key) {
      const row = (
        await query(`SELECT ${COLUMNS} FROM ${t.records} WHERE ${WHERE_KEY}`, [
          tenant,
          collection,
          key,
        ])
      ).rows[0]
      return row === undefined ? null : toRecord(row)
    },

    async listByOwner(tenant, collection, owner) {
      const result = await query(
        `SELECT ${COLUMNS} FROM ${t.records} WHERE tenant = ? AND collection = ? AND owner = ? ORDER BY id`,
        [tenant, collection, owner],
      )
      return result.rows.map(toRecord)
    },

    async update(tenant, collection, key, expectedVersion, change) {
      const sets: string[] = []
      const params: SqlParam[] = []
      if (change.data !== undefined) {
        sets.push("data = ?")
        params.push(JSON.stringify(change.data))
      }
      if (change.expiresAt !== undefined) {
        sets.push("expires_at = ?")
        params.push(change.expiresAt)
      }
      sets.push("version = version + 1")
      const result = await query(
        `UPDATE ${t.records} SET ${sets.join(", ")} WHERE ${WHERE_KEY} AND version = ?`,
        [...params, tenant, collection, key, expectedVersion],
      )
      if (result.affectedRows === 1) return "updated"
      return (await exists(tenant, collection, key)) ? "conflict" : "missing"
    },

    async revoke(tenant, collection, key, at) {
      const result = await query(
        `UPDATE ${t.records} SET revoked_at = ?, version = version + 1 WHERE ${WHERE_KEY} AND revoked_at IS NULL`,
        [at, tenant, collection, key],
      )
      return result.affectedRows === 1 || (await exists(tenant, collection, key))
    },

    async revokeByOwner(tenant, collection, owner, at, options = {}) {
      const except = options.except === undefined ? "" : " AND record_key <> ?"
      const params: SqlParam[] = [at, tenant, collection, owner]
      if (options.except !== undefined) params.push(options.except)
      const result = await query(
        `UPDATE ${t.records} SET revoked_at = ?, version = version + 1 WHERE tenant = ? AND collection = ? AND owner = ? AND revoked_at IS NULL${except}`,
        params,
      )
      return result.affectedRows
    },

    async delete(tenant, collection, key) {
      return (
        (await query(`DELETE FROM ${t.records} WHERE ${WHERE_KEY}`, [tenant, collection, key]))
          .affectedRows > 0
      )
    },

    async consumeOnce(tenant, collection, key, now) {
      const row = (
        await query(
          `UPDATE ${t.records} SET consumed_at = ?, version = version + 1 WHERE ${WHERE_KEY} AND consumed_at IS NULL AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?) RETURNING ${COLUMNS}`,
          [now, tenant, collection, key, now],
        )
      ).rows[0]
      return row === undefined ? null : toRecord(row)
    },

    async increment(tenant, counter, windowMs, now) {
      const fresh = `${t.counters}.reset_at <= excluded.window_start`
      const sql = `INSERT INTO ${t.counters} (tenant, counter, hits, window_start, reset_at) VALUES (?, ?, 1, ?, ?) ON CONFLICT (tenant, counter) DO UPDATE SET hits = CASE WHEN ${fresh} THEN 1 ELSE ${t.counters}.hits + 1 END, window_start = CASE WHEN ${fresh} THEN excluded.window_start ELSE ${t.counters}.window_start END, reset_at = CASE WHEN ${fresh} THEN excluded.reset_at ELSE ${t.counters}.reset_at END RETURNING hits, window_start, reset_at`
      return toCounter((await query(sql, [tenant, counter, now, now + windowMs])).rows[0])
    },

    async resetCounter(tenant, counter) {
      await query(`DELETE FROM ${t.counters} WHERE tenant = ? AND counter = ?`, [tenant, counter])
    },

    async appendAudit(tenant, stream, seq, record) {
      const integer = mysql ? "CAST(? AS SIGNED)" : "CAST(? AS BIGINT)"
      const from = mysql ? " FROM DUAL" : ""
      const onConflict = mysql
        ? " ON DUPLICATE KEY UPDATE seq = seq"
        : " ON CONFLICT (tenant, stream, seq) DO NOTHING"
      const sql = `INSERT INTO ${t.audit} (tenant, stream, seq, record) SELECT ?, ?, ${integer}, ?${from} WHERE (${integer} = 1 AND NOT EXISTS (SELECT 1 FROM ${t.audit} WHERE tenant = ? AND stream = ?)) OR EXISTS (SELECT 1 FROM ${t.audit} WHERE tenant = ? AND stream = ? AND seq = ${integer} - 1)${onConflict}`
      const params = [
        tenant,
        stream,
        seq,
        JSON.stringify(record),
        seq,
        tenant,
        stream,
        tenant,
        stream,
        seq,
      ]
      if ((await query(sql, params)).affectedRows === 1) return "appended"
      const last = (
        await query(`SELECT MAX(seq) AS last FROM ${t.audit} WHERE tenant = ? AND stream = ?`, [
          tenant,
          stream,
        ])
      ).rows[0]?.["last"]
      return last !== null && last !== undefined && seq <= toNumber(last, "last")
        ? "duplicate"
        : "gap"
    },

    async readAudit(tenant, stream, fromSeq, limit) {
      // `limit` is a validated integer, written into the text because not every driver binds LIMIT.
      const result = await query(
        `SELECT stream, seq, record FROM ${t.audit} WHERE tenant = ? AND stream = ? AND seq >= ? ORDER BY seq LIMIT ${limit}`,
        [tenant, stream, fromSeq],
      )
      return result.rows.map((row): AuditEntry => ({
        stream: toText(row["stream"], "stream"),
        seq: toNumber(row["seq"], "seq"),
        record: JSON.parse(toText(row["record"], "record")) as JsonValue,
      }))
    },
  }
}

/**
 * MySQL's `consumeOnce` and `increment`. MySQL has no `RETURNING`, so each claims or counts with one statement and
 * reads the row back in the same transaction, which still holds the row lock the first statement took.
 */
function mysqlOperations(
  t: Tables,
  atomic: Atomic,
): Pick<StoreOperations, "consumeOnce" | "increment"> {
  return {
    async consumeOnce(tenant, collection, key, now) {
      return atomic(async (query) => {
        const claim = await query(
          `UPDATE ${t.records} SET consumed_at = ?, version = version + 1 WHERE ${WHERE_KEY} AND consumed_at IS NULL AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`,
          [now, tenant, collection, key, now],
        )
        if (claim.affectedRows !== 1) return null
        const row = (
          await query(`SELECT ${COLUMNS} FROM ${t.records} WHERE ${WHERE_KEY}`, [
            tenant,
            collection,
            key,
          ])
        ).rows[0]
        return row === undefined ? null : toRecord(row)
      })
    },

    async increment(tenant, counter, windowMs, now) {
      // MySQL applies assignments left to right, so reset_at, which every condition reads, is assigned last.
      const fresh = "reset_at <= fresh.window_start"
      return atomic(async (query) => {
        await query(
          `INSERT INTO ${t.counters} (tenant, counter, hits, window_start, reset_at) VALUES (?, ?, 1, ?, ?) AS fresh ON DUPLICATE KEY UPDATE hits = IF(${fresh}, 1, hits + 1), window_start = IF(${fresh}, fresh.window_start, window_start), reset_at = IF(${fresh}, fresh.reset_at, reset_at)`,
          [tenant, counter, now, now + windowMs],
        )
        const read = `SELECT hits, window_start, reset_at FROM ${t.counters} WHERE tenant = ? AND counter = ?`
        return toCounter((await query(read, [tenant, counter])).rows[0])
      })
    },
  }
}

/** The `AuthStore` over the app's SQL connection. */
export function sqlStore(options: SqlStoreOptions): AuthStore {
  checkDialect(options.dialect)
  const prefix = options.tablePrefix ?? "test_cap_"
  checkPrefix(prefix)
  const { dialect, transaction } = options
  const t = tables(prefix)
  if (transaction === undefined) {
    if (dialect === "mysql") {
      throw new TypeError(
        "The MySQL dialect needs a transaction function: consumeOnce and increment run two statements.",
      )
    }
    return {
      kind: "sql",
      durable: true,
      ...validated(operations(dialect, t, placed(dialect, options.query))),
    }
  }
  const build = (query: SqlQuery, atomic: Atomic): StoreOperations => {
    const base = operations(dialect, t, query)
    return validated(dialect === "mysql" ? { ...base, ...mysqlOperations(t, atomic) } : base)
  }
  return {
    kind: "sql",
    durable: true,
    ...build(placed(dialect, options.query), (fn) =>
      transaction((query) => fn(placed(dialect, query))),
    ),
    transaction: (fn) =>
      transaction((query) => {
        const inside = placed(dialect, query)
        return fn(build(inside, (step) => step(inside)))
      }),
  }
}
