# 0002: The store port names its atomic operations

## Status

Accepted (2026-11-15). Implemented in phase 2 (the `AuthStore` port, `test-cap/store/memory` and the conformance
kit), phase 3 (`test-cap/store/sql` on Postgres) and phase 6 (SQLite and MySQL).

Answers [handoff question](../../GLOSSARY.md) 2 (storage ownership).

Landed in phase 3 (internal until its gate): `sqlStore` and `migrations` for Postgres, SQLite and MySQL, with every
guarantee as one constraint-backed statement (MySQL's `consumeOnce` and `increment` as two statements inside the
app's transaction, so the MySQL dialect requires `transaction`). The full conformance kit passes on real SQLite
(`node:sqlite`) and Postgres (PGlite). Postgres 15, 16 and 17 servers and MySQL 8.4 are wired to
`TEST_CAP_POSTGRES_URL` and `TEST_CAP_MYSQL_URL` but not yet run, so the dialect claims are partly met until CI's
service jobs run them. An app that prunes audit records keeps each stream's last record, because `appendAudit`
continues from the highest stored `seq`.

Landed in phase 2: the port, `memoryStore()` and the conformance kit. The kit's checks for `consumeOnce`,
`increment`, `resetCounter`, `createUnique`, `update` (also concurrent updates at one expected version),
`appendAudit`, revoke visibility, transactions and tenant isolation (`resetCounter` included) run in one file,
`test/store/conformance.test.ts`, which also runs the kit against deliberately broken stores, at least one per check,
to prove each check catches its fault; `test/store/memory.test.ts` covers the memory store, and `test/core/mode.test.ts` the production
refusal of a non-durable store. The file names below are the original plan; the SQL rows remain for phase 3.

Planned tests:

- `test/store/conformance/consume-once.test.ts` (many concurrent consumers of one key, exactly one wins);
- `test/store/conformance/increment.test.ts` (concurrent increments lose no count; the window resets);
- `test/store/conformance/create-unique.test.ts` (concurrent enrolment of one identifier, exactly one succeeds);
- `test/store/conformance/append-audit.test.ts` (a gap or a duplicate `seq` is rejected, also under concurrency);
- `test/store/conformance/revoke-visibility.test.ts` (a read after `revoke` resolves never returns the session);
- `test/store/conformance/transaction.test.ts` (a failing step rolls back the credential change and the revocation);
- `test/store/conformance/tenant-isolation.test.ts` (a read in one tenant never returns another tenant's record);
- `test/store/memory-refused-in-production.test.ts`;
- `test/store/sql/dialects.test.ts` (the kit against Postgres 15, 16 and 17, SQLite and MySQL 8.4 in CI service
  containers);
- `test/store/sql/migrations.test.ts` (printed migrations apply cleanly to an empty database of each dialect).

The recommendations under Open are provisional defaults until the owner decides.

## Context

The handoff's storage rule was that users, credentials, sessions and recovery state go through functions the app
implements, and that a conformance kit proves an app's store keeps the guarantees. Question 2 asked whether that rule
survives Better Auth's own database adapters. ADR 0001 removed Better Auth, so the question becomes: what does the
store port promise, and how is the promise checked?

Most authentication races are store races: an OTP redeemed twice by two parallel requests, two accounts created for
one identifier, a counter that loses increments and so never throttles, a revoked session served from a lagging read.
A port of plain `get` and `put` calls leaves every one of those to the app, and the app cannot know which of its reads
need to be atomic. So the port states each guarantee as an operation, and the conformance kit tests the operation
under real concurrency.

## Decision

### 1. test-cap never opens a connection

The app supplies the store. test-cap holds no driver, no connection string and no pool. `createAuth({ store })`
receives an object that implements the `AuthStore` port.

Why: the app already owns its database, its credentials, its TLS settings and its backups. A package that opened its
own connection would duplicate all of it and add a second set of database secrets.

### 2. The port's guarantees are its operations

Records are JSON documents (`JsonValue`) addressed by tenant, collection and key. A stored record
(`StoredRecord`) carries an optional owner, a `version` that every change increments, and the times flows check:
`expiresAt`, `revokedAt` and `consumedAt`. `createUnique` takes a `NewRecord`, and `update` takes a `RecordChange`.
Every operation takes the tenant as its first argument (ADR 0012). `StoreOperations` names the operations below;
`AuthStore` adds `kind`, `durable` and the optional `transaction`, and `StoreTransaction` is the handle a transaction's
steps receive.

| Operation                                                  | Guarantee                                                                                          | Used for                                                                   |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `consumeOnce(tenant, collection, key, now)`                | Atomic single use: of any number of concurrent calls on one key, exactly one gets the record       | Email and recovery codes, WebAuthn challenges, federation transactions     |
| `increment(tenant, counter, windowMs, now)`                | Atomic counter in a fixed window, returning a `CounterState`: concurrent increments are never lost | Throttling counters and the failure ceiling (ADR 0009)                     |
| `resetCounter(tenant, counter)`                            | Clears a counter                                                                                   | A success that resets a failure count (ADR 0009)                           |
| `createUnique(tenant, record)`                             | Tenant-scoped uniqueness: of concurrent creates of one key, exactly one gets `created`             | Identifiers, authenticator ids, linked identities (ADR 0008)               |
| `update(tenant, collection, key, expectedVersion, change)` | Compare-and-set: applies only when the stored version is `expectedVersion`, else `conflict`        | The last accepted TOTP step (ADR 0027), any read-check-write on one record |
| `revoke(tenant, collection, key, at)`                      | Immediate visibility: once revoke resolves, no later read returns the record unrevoked             | Sign-out, remote revoke, delegation revoke (ADR 0006, ADR 0013)            |
| `revokeByOwner(tenant, collection, owner, at, { except })` | One operation over every unrevoked record of an owner, with the same visibility                    | Credential change, recovery, deprovision (ADR 0006, ADR 0007, ADR 0012)    |
| `get`, `listByOwner`, `delete`                             | Plain reads and removal, tenant-scoped; `listByOwner` includes revoked and consumed records        | Session lookup, the session list, cleanup                                  |
| `appendAudit(tenant, stream, seq, record)`                 | Returns `appended`, `gap` or `duplicate`: the first `seq` is 1 and each next one the last plus one | The audit chain (ADR 0020)                                                 |
| `readAudit(tenant, stream, fromSeq, limit)`                | Up to `limit` entries (`AuditEntry`) from `fromSeq`, in `seq` order                                | Verification and reports (ADR 0020)                                        |
| `transaction(fn)` (optional)                               | The steps inside `fn` commit together or not at all                                                | A credential change plus revoking the account's other sessions             |

Why: naming the guarantee in the operation puts the hard part (atomicity) where it can be tested once, in the store,
instead of in every flow. A flow that needs single use calls `consumeOnce`; it never reads, checks and deletes.

### 3. `store/memory` is for development only

`test-cap/store/memory` (`memoryStore()`) passes the conformance kit within one process. Every store declares a
`durable` trait, and the memory store's is `false`. Production and staging refuse to start with any store whose
`durable` is `false` (ADR 0026), so the refusal follows the trait, not the store's name.

Why: memory loses every session and every counter on restart and is not shared between processes, so throttling and
single use would hold per process only.

### 4. `store/sql` implements every guarantee as a single statement backed by a constraint

`sqlStore({ dialect, query, transaction? })`, where `dialect` is a `SqlDialect` (`postgres`, `sqlite` or `mysql`), runs
over the app's own `query(sql, params)` function and its optional
`transaction` function. Each guarantee is one statement whose atomicity the database enforces:

- `consumeOnce`: a conditional `UPDATE … RETURNING` (or `DELETE … RETURNING`) that only the first caller matches;
- `increment` and `createUnique`: `INSERT … ON CONFLICT`, over a unique key;
- `appendAudit`: an insert over a unique `(stream, seq)` constraint plus a check that `seq - 1` exists.

No guarantee depends on a read followed by a write in application code. MySQL 8.4 has neither `RETURNING` nor
`ON CONFLICT`; see Open.

Why: a single statement over a constraint is atomic in every supported database without locks, isolation-level
settings or retries in test-cap, and it is the same statement whether the app uses `pg`, `mysql2`, `better-sqlite3`
or an ORM's raw query.

Override: an app may bring its own store (an ORM, a key-value database) if it passes the conformance kit.

### 5. Migrations are printed, not run

`store/sql` ships the schema for each dialect as SQL text, returned by `migrations(dialect)`. test-cap prints it; the
app applies it with its own migration tool. test-cap never runs DDL.

Why: section 1. Running migrations needs a connection with DDL rights, which test-cap must not hold.

### 6. The conformance kit runs real concurrency against real databases

`test-cap/conformance` is a set of tests an app runs against its own store. `runAuthStoreConformance(createStore,
options)` returns a `ConformanceReport` holding one `ConformanceResult` per check, instead of depending on a test
framework, so it runs under Vitest, `node:test`, Bun and Deno alike; `ConformanceOptions` sets how many parallel calls
each race check makes. Each guarantee in section 2 is exercised
by many parallel calls, not by sequential calls that only look concurrent, and tenant isolation is checked on every
operation. CI runs the kit against `store/memory`, and against `store/sql` on Postgres 15, 16 and 17, SQLite and MySQL
8.4 as service containers.

Why: a race only shows up under concurrency. A store that passes sequential tests can still redeem a code twice.

## Consequences

- Every flow is written against named guarantees, so the attack tests for redemption races and lost counters
  (`test/attacks/redemption-race.test.ts`) test the flow and the store together.
- test-cap maintains SQL for three dialects, and the migrations that go with them.
- An app that uses an ORM passes its raw-query function; nothing in test-cap depends on the ORM.
- A custom store is possible, and the kit is the one way to show that it is safe.

## Limits

- **The kit tests the store it is given, not the deployment.** An app that sends reads to a lagging replica breaks
  revocation visibility after the kit passed against the primary. The docs say that every `AuthStore` read must go to
  the primary.
- **Without `transaction`, a credential change and the revocation are two writes.** A crash between them leaves one
  done; see Open for the order.
- **SQLite concurrency is one writer at a time.** The kit's concurrent calls on SQLite prove the guarantees hold, not
  that they scale.
- **Encryption at rest, backups and retention of the database** are the app's. test-cap encrypts the values it must
  (OTP secrets, ADR 0027) and hashes the ones it can (session tokens, codes), and nothing else.

## Open

1. **MySQL 8.4 lacks `RETURNING` and `ON CONFLICT`.** The plan names those statements for every dialect.
   Recommendation: keep "one statement backed by a constraint" and write it per dialect: `INSERT … ON DUPLICATE KEY
UPDATE` for `increment` and `createUnique`, and for `consumeOnce` a conditional `UPDATE` whose affected-row count
   picks the single winner, followed by a read of the row it claimed. This needs the app's `query` function to return
   the affected-row count for MySQL, so the `query` contract carries it.
2. **Order of writes without `transaction`.** Recommendation: revoke the account's other sessions first, then change
   the credential. A crash in between signs people out but never leaves an attacker's session alive with a credential
   the owner has replaced.
3. **How migrations are printed.** Recommendation: an exported function that returns the SQL text for a dialect, plus
   a documented one-line command that prints it, so no bin script is needed.
