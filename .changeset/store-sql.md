---
"test-cap": minor
---

Add the SQL store's option types (`SqlDialect`, `SqlParam`, `SqlQuery`, `SqlResult`, `SqlStoreOptions`,
`SqlTransaction`). The store itself stays internal until CI runs it against real Postgres and MySQL servers, planned
for phase 6. Its tests run it on SQLite (`node:sqlite`) and Postgres (PGlite).
