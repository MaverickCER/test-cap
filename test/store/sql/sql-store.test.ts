import { describe, expect, it } from "vitest"
import { runAuthStoreConformance } from "../../../src/conformance/index.js"
import { migrations, sqlStore, type SqlQuery } from "../../../src/store/sql.js"
import {
  mysqlServerStoreFactory,
  pgliteStore,
  postgresServerStoreFactory,
  sqliteStore,
} from "./drivers.js"

const failed = (report: Awaited<ReturnType<typeof runAuthStoreConformance>>): unknown[] =>
  report.results.filter((r) => !r.passed).map((r) => ({ id: r.id, detail: r.detail }))

describe("sqlStore conformance on real databases", () => {
  it("passes every check, transactions included, on SQLite (node:sqlite)", async () => {
    const report = await runAuthStoreConformance(sqliteStore)
    expect(failed(report)).toEqual([])
    expect(report.results.some((r) => r.skipped === true)).toBe(false)
  })

  it("passes every check, transactions included, on Postgres (PGlite)", async () => {
    const report = await runAuthStoreConformance(pgliteStore)
    expect(failed(report)).toEqual([])
    expect(report.results.some((r) => r.skipped === true)).toBe(false)
  }, 60_000)

  it("passes every check on the Postgres server named by TEST_CAP_POSTGRES_URL", async (context) => {
    const factory = await postgresServerStoreFactory()
    if (factory === undefined) return context.skip()
    expect(failed(await runAuthStoreConformance(factory))).toEqual([])
  }, 120_000)

  it("passes every check on the MySQL server named by TEST_CAP_MYSQL_URL", async (context) => {
    const factory = await mysqlServerStoreFactory()
    if (factory === undefined) return context.skip()
    expect(failed(await runAuthStoreConformance(factory))).toEqual([])
  }, 120_000)
})

/** A query function that records every statement and answers from a script. */
function recorder(answers: { rows?: Record<string, unknown>[]; affectedRows?: number }[] = []): {
  query: SqlQuery
  calls: { sql: string; params: readonly unknown[] }[]
} {
  const calls: { sql: string; params: readonly unknown[] }[] = []
  return {
    calls,
    query: async (sql, params) => {
      calls.push({ sql, params })
      const answer = answers.shift() ?? {}
      return { rows: answer.rows ?? [], affectedRows: answer.affectedRows ?? 0 }
    },
  }
}

const noTransaction = async <T>(fn: (query: SqlQuery) => Promise<T>): Promise<T> =>
  fn(async () => ({ rows: [], affectedRows: 0 }))

describe("sqlStore", () => {
  it("declares itself a durable SQL store", () => {
    const store = sqlStore({ dialect: "postgres", query: recorder().query })
    expect(store.kind).toBe("sql")
    expect(store.durable).toBe(true)
  })

  it("offers transaction only when the app supplies one", () => {
    expect(sqlStore({ dialect: "postgres", query: recorder().query }).transaction).toBeUndefined()
    expect(
      sqlStore({ dialect: "postgres", query: recorder().query, transaction: noTransaction })
        .transaction,
    ).toBeTypeOf("function")
  })

  it("requires a transaction for MySQL, whose two-step operations need one", () => {
    expect(() => sqlStore({ dialect: "mysql", query: recorder().query })).toThrow(/transaction/)
    expect(() =>
      sqlStore({ dialect: "mysql", query: recorder().query, transaction: noTransaction }),
    ).not.toThrow()
  })

  it("numbers Postgres parameters and leaves ? for SQLite and MySQL", async () => {
    const pg = recorder()
    await sqlStore({ dialect: "postgres", query: pg.query }).get("t", "c", "k")
    expect(pg.calls[0]?.sql).toMatch(/tenant = \$1 AND collection = \$2 AND record_key = \$3/)
    const lite = recorder()
    await sqlStore({ dialect: "sqlite", query: lite.query }).get("t", "c", "k")
    expect(lite.calls[0]?.sql).toMatch(/tenant = \? AND collection = \? AND record_key = \?/)
    expect(lite.calls[0]?.params).toEqual(["t", "c", "k"])
  })

  it("never puts a value into the SQL text, only into parameters", async () => {
    const hostile = "x'; DROP TABLE test_cap_records; --"
    // createUnique, listByOwner and revokeByOwner answer empty; increment needs its upserted row.
    const counterRow = { hits: 1, window_start: 0, reset_at: 1000 }
    const rec = recorder([{}, {}, {}, { rows: [counterRow] }])
    const store = sqlStore({ dialect: "sqlite", query: rec.query })
    await store.createUnique(hostile, {
      collection: hostile,
      key: hostile,
      owner: hostile,
      data: hostile,
    })
    await store.listByOwner(hostile, hostile, hostile)
    await store.revokeByOwner(hostile, hostile, hostile, 1, { except: hostile })
    await store.increment(hostile, hostile, 1000, 0)
    await store.appendAudit(hostile, hostile, 1, hostile)
    await store.readAudit(hostile, hostile, 1, 5)
    for (const call of rec.calls) expect(call.sql).not.toContain("DROP")
  })

  it("uses a custom table prefix everywhere and refuses an unsafe one", async () => {
    const rec = recorder()
    await sqlStore({ dialect: "sqlite", query: rec.query, tablePrefix: "auth_" }).get("t", "c", "k")
    expect(rec.calls[0]?.sql).toContain("FROM auth_records")
    for (const tablePrefix of ["", "Auth_", "a-b_", "1a_", "a;drop_", "a".repeat(41)]) {
      expect(
        () => sqlStore({ dialect: "sqlite", query: rec.query, tablePrefix }),
        tablePrefix,
      ).toThrow(TypeError)
    }
    expect(migrations("postgres", { tablePrefix: "auth_" })).toContain(
      "CREATE TABLE IF NOT EXISTS auth_records",
    )
    expect(() => migrations("postgres", { tablePrefix: "X" })).toThrow(TypeError)
  })

  it("reads numbers back whether a driver returns them as numbers, strings or bigints", async () => {
    const row = {
      collection: "c",
      record_key: "k",
      owner: null,
      version: "2",
      expires_at: 10n,
      revoked_at: null,
      consumed_at: 5,
      data: '{"a":1}',
    }
    const store = sqlStore({ dialect: "postgres", query: recorder([{ rows: [row] }]).query })
    expect(await store.get("t", "c", "k")).toEqual({
      collection: "c",
      key: "k",
      owner: null,
      version: 2,
      expiresAt: 10,
      revokedAt: null,
      consumedAt: 5,
      data: { a: 1 },
    })
  })

  it("refuses a row a driver returns in a shape it cannot read", async () => {
    const store = sqlStore({
      dialect: "postgres",
      query: recorder([{ rows: [{ collection: "c", record_key: "k", version: "x", data: "{}" }] }])
        .query,
    })
    await expect(store.get("t", "c", "k")).rejects.toThrow(TypeError)
  })

  it("validates arguments before sending anything", async () => {
    const rec = recorder()
    const store = sqlStore({ dialect: "sqlite", query: rec.query })
    await expect(store.get("", "c", "k")).rejects.toThrow(TypeError)
    await expect(store.readAudit("t", "s", 1, 0)).rejects.toThrow(RangeError)
    await expect(store.increment("t", "c", 0, 0)).rejects.toThrow(RangeError)
    await expect(
      store.createUnique("t", { collection: "c", key: "k", owner: null, data: Number.NaN }),
    ).rejects.toThrow(TypeError)
    expect(rec.calls).toEqual([])
  })
})

describe("migrations", () => {
  it("creates the three tables for each dialect, idempotently", () => {
    for (const dialect of ["postgres", "sqlite", "mysql"] as const) {
      const sql = migrations(dialect)
      for (const table of ["test_cap_records", "test_cap_counters", "test_cap_audit"]) {
        expect(sql, dialect).toContain(`CREATE TABLE IF NOT EXISTS ${table}`)
      }
      expect(sql).toMatch(/UNIQUE \(tenant, collection, record_key\)/)
      expect(sql).toMatch(/PRIMARY KEY \(tenant, stream, seq\)/)
    }
  })

  it("makes MySQL keys case-sensitive, so two token hashes differing in case are two keys", () => {
    expect(migrations("mysql")).toContain("COLLATE=utf8mb4_bin")
  })

  it("refuses an unknown dialect", () => {
    expect(() => migrations("oracle" as never)).toThrow(TypeError)
    expect(() => sqlStore({ dialect: "oracle" as never, query: recorder().query })).toThrow(
      TypeError,
    )
  })
})

/** A transaction function that records when it opens and closes around the statements it runs. */
function scriptedTransaction(rec: ReturnType<typeof recorder>): {
  transaction: <T>(fn: (query: SqlQuery) => Promise<T>) => Promise<T>
  log: string[]
} {
  const log: string[] = []
  return {
    log,
    transaction: async (fn) => {
      log.push("begin")
      try {
        const result = await fn(async (sql, params) => {
          log.push(sql.split(" ")[0] ?? "")
          return rec.query(sql, params)
        })
        log.push("commit")
        return result
      } catch (error) {
        log.push("rollback")
        throw error
      }
    },
  }
}

const row = {
  collection: "c",
  record_key: "k",
  owner: null,
  version: 2,
  expires_at: null,
  revoked_at: null,
  consumed_at: 7,
  data: "1",
}

describe("sqlStore on MySQL (statement logic; semantics are proven against a real server in CI)", () => {
  it("claims with an UPDATE and reads the row back inside one transaction", async () => {
    const rec = recorder([{ affectedRows: 1 }, { rows: [row] }])
    const tx = scriptedTransaction(rec)
    const store = sqlStore({
      dialect: "mysql",
      query: recorder().query,
      transaction: tx.transaction,
    })
    expect(await store.consumeOnce("t", "c", "k", 7)).toMatchObject({ key: "k", consumedAt: 7 })
    expect(tx.log).toEqual(["begin", "UPDATE", "SELECT", "commit"])
    expect(rec.calls[0]?.sql).not.toContain("RETURNING")
    expect(rec.calls[0]?.params).toEqual([7, "t", "c", "k", 7])
  })

  it("returns null without reading when the claim matched nothing, or when the row is gone", async () => {
    const lost = recorder([{ affectedRows: 0 }])
    const lostTx = scriptedTransaction(lost)
    const store = sqlStore({
      dialect: "mysql",
      query: recorder().query,
      transaction: lostTx.transaction,
    })
    expect(await store.consumeOnce("t", "c", "k", 7)).toBeNull()
    expect(lostTx.log).toEqual(["begin", "UPDATE", "commit"])
    const gone = recorder([{ affectedRows: 1 }, { rows: [] }])
    const goneStore = sqlStore({
      dialect: "mysql",
      query: recorder().query,
      transaction: scriptedTransaction(gone).transaction,
    })
    expect(await goneStore.consumeOnce("t", "c", "k", 7)).toBeNull()
  })

  it("counts with an upsert that assigns reset_at last, then reads the counter in the same transaction", async () => {
    const rec = recorder([
      { affectedRows: 1 },
      { rows: [{ hits: "3", window_start: "0", reset_at: "1000" }] },
    ])
    const tx = scriptedTransaction(rec)
    const store = sqlStore({
      dialect: "mysql",
      query: recorder().query,
      transaction: tx.transaction,
    })
    expect(await store.increment("t", "n", 1000, 5)).toEqual({
      count: 3,
      windowStart: 0,
      resetAt: 1000,
    })
    expect(tx.log).toEqual(["begin", "INSERT", "SELECT", "commit"])
    const upsert = rec.calls[0]?.sql ?? ""
    expect(upsert).toContain("ON DUPLICATE KEY UPDATE")
    expect(upsert.lastIndexOf("reset_at = IF(")).toBeGreaterThan(upsert.lastIndexOf("hits = IF("))
    expect(upsert.lastIndexOf("reset_at = IF(")).toBeGreaterThan(
      upsert.lastIndexOf("window_start = IF("),
    )
    expect(rec.calls[0]?.params).toEqual(["t", "n", 5, 1005])
  })

  it("runs a store transaction's two-step operations on the transaction's own connection, without nesting", async () => {
    const rec = recorder([{ affectedRows: 1 }, { rows: [row] }])
    const tx = scriptedTransaction(rec)
    const store = sqlStore({
      dialect: "mysql",
      query: recorder().query,
      transaction: tx.transaction,
    })
    await store.transaction?.(async (inner) => inner.consumeOnce("t", "c", "k", 7))
    expect(tx.log).toEqual(["begin", "UPDATE", "SELECT", "commit"])
  })

  it("writes MySQL's own conflict and cast syntax", async () => {
    const rec = recorder([{ affectedRows: 1 }, { affectedRows: 1 }])
    const store = sqlStore({ dialect: "mysql", query: rec.query, transaction: noTransaction })
    await store.createUnique("t", { collection: "c", key: "k", owner: null, data: 1 })
    await store.appendAudit("t", "s", 1, 1)
    expect(rec.calls[0]?.sql).toContain("ON DUPLICATE KEY UPDATE id = id")
    expect(rec.calls[1]?.sql).toContain("CAST(? AS SIGNED)")
    expect(rec.calls[1]?.sql).toContain("FROM DUAL")
    expect(rec.calls[1]?.sql).toContain("ON DUPLICATE KEY UPDATE seq = seq")
  })
})

describe("sqlStore edge paths", () => {
  it("sends an expiry update and a cleared expiry", async () => {
    const rec = recorder([{ affectedRows: 1 }, { affectedRows: 1 }])
    const store = sqlStore({ dialect: "sqlite", query: rec.query })
    expect(await store.update("t", "c", "k", 1, { expiresAt: 50 })).toBe("updated")
    expect(await store.update("t", "c", "k", 2, { expiresAt: null })).toBe("updated")
    expect(rec.calls[0]?.sql).toContain("SET expires_at = ?, version = version + 1")
    expect(rec.calls[0]?.params).toEqual([50, "t", "c", "k", 1])
    expect(rec.calls[1]?.params).toEqual([null, "t", "c", "k", 2])
    await expect(store.update("t", "c", "k", 1, { expiresAt: 1.5 })).rejects.toThrow(RangeError)
  })

  it("stores an expiry given at creation", async () => {
    const rec = recorder([{ affectedRows: 1 }])
    await sqlStore({ dialect: "sqlite", query: rec.query }).createUnique("t", {
      collection: "c",
      key: "k",
      owner: "o",
      expiresAt: 99,
      data: { a: 1 },
    })
    expect(rec.calls[0]?.params).toEqual(["t", "c", "k", "o", 99, '{"a":1}'])
  })

  it("calls an append to an empty stream at a later seq a gap", async () => {
    const rec = recorder([{ affectedRows: 0 }, { rows: [{ last: null }] }])
    expect(
      await sqlStore({ dialect: "sqlite", query: rec.query }).appendAudit("t", "s", 3, 1),
    ).toBe("gap")
  })

  it("refuses a driver that returns no counter row, or a non-text column", async () => {
    await expect(
      sqlStore({ dialect: "sqlite", query: recorder([{ rows: [] }]).query }).increment(
        "t",
        "n",
        1000,
        0,
      ),
    ).rejects.toThrow(/no row/)
    await expect(
      sqlStore({
        dialect: "sqlite",
        query: recorder([{ rows: [{ ...row, collection: 5 }] }]).query,
      }).get("t", "c", "k"),
    ).rejects.toThrow(/non-text collection/)
  })
})

describe("the SQL each dialect sends (pinned, so a change to any statement is a reviewed change)", () => {
  const counterRow = { hits: 1, window_start: 0, reset_at: 1000 }
  /** Answers that let every operation run to completion, in call order. */
  const script = (
    mysql: boolean,
  ): { rows?: Record<string, unknown>[]; affectedRows?: number }[] => [
    { affectedRows: 1 }, // createUnique
    { rows: [row] }, // get
    { rows: [row] }, // listByOwner
    { affectedRows: 1 }, // update
    { affectedRows: 0 }, // revoke: already revoked...
    { rows: [{ found: 1 }] }, // ...so it checks the record exists
    { affectedRows: 2 }, // revokeByOwner
    { affectedRows: 1 }, // delete
    ...(mysql ? [{ affectedRows: 1 }, { rows: [row] }] : [{ rows: [row] }]), // consumeOnce
    ...(mysql ? [{ affectedRows: 1 }, { rows: [counterRow] }] : [{ rows: [counterRow] }]), // increment
    { affectedRows: 1 }, // resetCounter
    { affectedRows: 0 }, // appendAudit: not inserted...
    { rows: [{ last: 4 }] }, // ...so it reads the last seq
    { rows: [{ stream: "s", seq: 4, record: "1" }] }, // readAudit
  ]

  for (const dialect of ["postgres", "sqlite", "mysql"] as const) {
    it(`for ${dialect}`, async () => {
      const rec = recorder(script(dialect === "mysql"))
      const store = sqlStore({
        dialect,
        query: rec.query,
        transaction: async (fn) => fn(rec.query),
        tablePrefix: "p_",
      })
      const results = [
        await store.createUnique("t", {
          collection: "c",
          key: "k",
          owner: "o",
          expiresAt: 9,
          data: { a: 1 },
        }),
        await store.get("t", "c", "k"),
        await store.listByOwner("t", "c", "o"),
        await store.update("t", "c", "k", 1, { data: 2, expiresAt: 3 }),
        await store.revoke("t", "c", "k", 4),
        await store.revokeByOwner("t", "c", "o", 5, { except: "k" }),
        await store.delete("t", "c", "k"),
        await store.consumeOnce("t", "c", "k", 6),
        await store.increment("t", "n", 1000, 7),
        await store.resetCounter("t", "n"),
        await store.appendAudit("t", "s", 3, { r: 1 }),
        await store.readAudit("t", "s", 2, 10),
      ]
      expect({ calls: rec.calls, results }).toMatchSnapshot()
    })
  }

  it("prints the schema for each dialect", () => {
    expect({
      postgres: migrations("postgres"),
      sqlite: migrations("sqlite"),
      mysql: migrations("mysql"),
    }).toMatchSnapshot()
  })
})

describe("reading driver values", () => {
  const read = (patch: Record<string, unknown>) =>
    sqlStore({
      dialect: "postgres",
      query: recorder([{ rows: [{ ...row, ...patch }] }]).query,
    }).get("t", "c", "k")

  it("accepts numbers, numeric strings and bigints, and reads a missing nullable column as null", async () => {
    expect(
      await read({ version: 3n, expires_at: "8", revoked_at: undefined, consumed_at: 0 }),
    ).toMatchObject({
      version: 3,
      expiresAt: 8,
      revokedAt: null,
      consumedAt: 0,
    })
    expect(await read({ owner: undefined })).toMatchObject({ owner: null })
    expect(await read({ owner: "o" })).toMatchObject({ owner: "o" })
  })

  it.each([
    ["version", { version: "x" }],
    ["version", { version: true }],
    ["version", { version: 2 ** 60 }],
    ["expires_at", { expires_at: "soon" }],
    ["revoked_at", { revoked_at: 1.5 }],
    ["consumed_at", { consumed_at: "x" }],
  ])("names %s when it is not an integer", async (column, patch) => {
    await expect(read(patch)).rejects.toThrow(
      new TypeError(`The driver returned a non-integer ${column}.`),
    )
  })

  it.each([
    ["collection", { collection: 1 }],
    ["record_key", { record_key: null }],
    ["owner", { owner: 5 }],
    ["data", { data: { a: 1 } }],
  ])("names %s when it is not text", async (column, patch) => {
    await expect(read(patch)).rejects.toThrow(
      new TypeError(`The driver returned a non-text ${column}.`),
    )
  })

  it.each(["hits", "window_start", "reset_at"])("names the counter column %s", async (column) => {
    const store = sqlStore({
      dialect: "postgres",
      query: recorder([{ rows: [{ hits: 1, window_start: 0, reset_at: 1, [column]: "x" }] }]).query,
    })
    await expect(store.increment("t", "n", 1, 0)).rejects.toThrow(
      new TypeError(`The driver returned a non-integer ${column}.`),
    )
  })

  it("names the audit columns and the last seq", async () => {
    const audit = (rows: Record<string, unknown>[]) =>
      sqlStore({ dialect: "postgres", query: recorder([{ rows }]).query }).readAudit("t", "s", 1, 1)
    await expect(audit([{ stream: 1, seq: 1, record: "1" }])).rejects.toThrow("non-text stream")
    await expect(audit([{ stream: "s", seq: "x", record: "1" }])).rejects.toThrow("non-integer seq")
    await expect(audit([{ stream: "s", seq: 1, record: 1 }])).rejects.toThrow("non-text record")
    const last = sqlStore({
      dialect: "postgres",
      query: recorder([{ affectedRows: 0 }, { rows: [{ last: "x" }] }]).query,
    })
    await expect(last.appendAudit("t", "s", 2, 1)).rejects.toThrow("non-integer last")
  })
})

describe("sqlStore results and setup", () => {
  it("reports a duplicate create as exists", async () => {
    const store = sqlStore({ dialect: "sqlite", query: recorder([{ affectedRows: 0 }]).query })
    expect(await store.createUnique("t", { collection: "c", key: "k", owner: null, data: 1 })).toBe(
      "exists",
    )
  })

  it("trusts a revocation that changed a row without a second query", async () => {
    const rec = recorder([{ affectedRows: 1 }])
    expect(await sqlStore({ dialect: "sqlite", query: rec.query }).revoke("t", "c", "k", 1)).toBe(
      true,
    )
    expect(rec.calls).toHaveLength(1)
  })

  it("is a durable SQL store with or without transactions", () => {
    const store = sqlStore({
      dialect: "postgres",
      query: recorder().query,
      transaction: noTransaction,
    })
    expect([store.kind, store.durable]).toEqual(["sql", true])
  })

  it("names the problem when the dialect or prefix is wrong", () => {
    expect(() => sqlStore({ dialect: "oracle" as never, query: recorder().query })).toThrow(
      new TypeError('Unknown SQL dialect "oracle".'),
    )
    expect(() =>
      sqlStore({ dialect: "sqlite", query: recorder().query, tablePrefix: "A" }),
    ).toThrow(
      new TypeError(
        "The table prefix must be lowercase letters, digits and underscores, starting with a letter.",
      ),
    )
    expect(() => sqlStore({ dialect: "mysql", query: recorder().query })).toThrow(
      new TypeError(
        "The MySQL dialect needs a transaction function: consumeOnce and increment run two statements.",
      ),
    )
  })
})
