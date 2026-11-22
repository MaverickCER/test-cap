/**
 * Test drivers: each turns a real database connection into the `query` and `transaction` functions `sqlStore` takes.
 * They are the same few lines an app writes, and the examples copy them.
 *
 * - SQLite: Node's built-in `node:sqlite`, a fresh in-memory database per store.
 * - Postgres: PGlite (Postgres compiled to WASM), a fresh database per store; or a real server named by
 *   TEST_CAP_POSTGRES_URL, with a fresh table prefix per store.
 * - MySQL: a real server named by TEST_CAP_MYSQL_URL (CI only), with a fresh table prefix per store.
 */

import { DatabaseSync } from "node:sqlite"
import { PGlite } from "@electric-sql/pglite"
import {
  migrations,
  sqlStore,
  type SqlQuery,
  type SqlStoreOptions,
} from "../../../src/store/sql.js"
import type { AuthStore } from "../../../src/store/port.js"

/** A promise-chain lock, so one SQLite connection runs one caller's statements at a time. */
function createLock(): <T>(fn: () => Promise<T>) => Promise<T> {
  let tail: Promise<unknown> = Promise.resolve()
  return (fn) => {
    const result = tail.then(fn)
    tail = result.catch(() => undefined)
    return result
  }
}

function statements(script: string): string[] {
  return script
    .split(";")
    .map((statement) => statement.trim())
    .filter((statement) => statement !== "")
}

/** `sqlStore` over a fresh in-memory `node:sqlite` database. */
export function sqliteStore(): AuthStore {
  const db = new DatabaseSync(":memory:")
  for (const statement of statements(migrations("sqlite"))) db.exec(statement)
  const raw: SqlQuery = async (sql, params) => {
    const statement = db.prepare(sql)
    if (/^\s*select\b|\breturning\b/i.test(sql)) {
      const rows = statement.all(...params) as Record<string, unknown>[]
      return { rows, affectedRows: rows.length }
    }
    return { rows: [], affectedRows: Number(statement.run(...params).changes) }
  }
  const exclusive = createLock()
  return sqlStore({
    dialect: "sqlite",
    query: (sql, params) => exclusive(() => raw(sql, params)),
    transaction: (fn) =>
      exclusive(async () => {
        db.exec("BEGIN IMMEDIATE")
        try {
          const result = await fn(raw)
          db.exec("COMMIT")
          return result
        } catch (error) {
          db.exec("ROLLBACK")
          throw error
        }
      }),
  })
}

function fromPglite(db: Pick<PGlite, "query">): SqlQuery {
  return async (sql, params) => {
    const result = await db.query<Record<string, unknown>>(sql, [...params])
    return { rows: result.rows, affectedRows: result.affectedRows ?? 0 }
  }
}

let pglite: Promise<PGlite> | undefined

/**
 * `sqlStore` over PGlite: one database per test run (booting the WASM build takes seconds), with fresh tables per
 * store through a table prefix, the same isolation the server stores use.
 */
export async function pgliteStore(): Promise<AuthStore> {
  pglite ??= PGlite.create()
  const db = await pglite
  const tablePrefix = freshPrefix()
  await db.exec(migrations("postgres", { tablePrefix }))
  return sqlStore({
    dialect: "postgres",
    tablePrefix,
    query: fromPglite(db),
    transaction: (fn) => db.transaction((tx) => fn(fromPglite(tx))),
  })
}

let prefixCount = 0
/** A fresh table prefix per store, so one server database serves every check. */
function freshPrefix(): string {
  prefixCount += 1
  return `tc${Date.now().toString(36)}_${prefixCount}_`
}

interface PgPool {
  query(
    sql: string,
    params?: unknown[],
  ): Promise<{ rows: Record<string, unknown>[]; rowCount: number | null }>
  connect(): Promise<{
    query(
      sql: string,
      params?: unknown[],
    ): Promise<{ rows: Record<string, unknown>[]; rowCount: number | null }>
    release(): void
  }>
}

/** `sqlStore` over a real Postgres server (CI), or `undefined` when TEST_CAP_POSTGRES_URL is unset. */
export async function postgresServerStoreFactory(): Promise<
  (() => Promise<AuthStore>) | undefined
> {
  const url = process.env["TEST_CAP_POSTGRES_URL"]
  if (url === undefined || url === "") return undefined
  const pgModule = "pg"
  const { default: pg } = (await import(pgModule)) as {
    default: { Pool: new (o: object) => PgPool }
  }
  const pool = new pg.Pool({ connectionString: url, max: 20 })
  return async () => {
    const tablePrefix = freshPrefix()
    await pool.query(migrations("postgres", { tablePrefix }))
    const options: SqlStoreOptions = {
      dialect: "postgres",
      tablePrefix,
      query: async (sql, params) => {
        const result = await pool.query(sql, [...params])
        return { rows: result.rows, affectedRows: result.rowCount ?? 0 }
      },
      transaction: async (fn) => {
        const client = await pool.connect()
        try {
          await client.query("BEGIN")
          const result = await fn(async (sql, params) => {
            const r = await client.query(sql, [...params])
            return { rows: r.rows, affectedRows: r.rowCount ?? 0 }
          })
          await client.query("COMMIT")
          return result
        } catch (error) {
          await client.query("ROLLBACK")
          throw error
        } finally {
          client.release()
        }
      },
    }
    return sqlStore(options)
  }
}

interface MysqlPool {
  query(sql: string, params?: unknown[]): Promise<[unknown, unknown]>
  getConnection(): Promise<{
    query(sql: string, params?: unknown[]): Promise<[unknown, unknown]>
    beginTransaction(): Promise<void>
    commit(): Promise<void>
    rollback(): Promise<void>
    release(): void
  }>
}

function fromMysql(run: (sql: string, params: unknown[]) => Promise<[unknown, unknown]>): SqlQuery {
  return async (sql, params) => {
    const [result] = await run(sql, [...params])
    if (Array.isArray(result))
      return { rows: result as Record<string, unknown>[], affectedRows: result.length }
    return { rows: [], affectedRows: (result as { affectedRows: number }).affectedRows }
  }
}

/**
 * `sqlStore` over a real MySQL server (CI), or `undefined` when TEST_CAP_MYSQL_URL is unset. The connection drops the
 * FOUND_ROWS flag, so an upsert that changes nothing reports 0 affected rows, as the `query` contract requires.
 */
export async function mysqlServerStoreFactory(): Promise<(() => Promise<AuthStore>) | undefined> {
  const url = process.env["TEST_CAP_MYSQL_URL"]
  if (url === undefined || url === "") return undefined
  const mysqlModule = "mysql2/promise"
  const mysql = (await import(mysqlModule)) as { createPool(o: object): MysqlPool }
  const pool = mysql.createPool({
    uri: url,
    flags: ["-FOUND_ROWS"],
    multipleStatements: true,
    connectionLimit: 20,
  })
  return async () => {
    const tablePrefix = freshPrefix()
    await pool.query(migrations("mysql", { tablePrefix }))
    return sqlStore({
      dialect: "mysql",
      tablePrefix,
      query: fromMysql((sql, params) => pool.query(sql, params)),
      transaction: async (fn) => {
        const connection = await pool.getConnection()
        try {
          await connection.beginTransaction()
          const result = await fn(fromMysql((sql, params) => connection.query(sql, params)))
          await connection.commit()
          return result
        } catch (error) {
          await connection.rollback()
          throw error
        } finally {
          connection.release()
        }
      },
    })
  }
}
