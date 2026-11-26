---
"test-cap": minor
---

test-cap's store conformance tests have five more checks:

- `list-by-owner`: oldest first, with revoked and consumed records included;
- `update-fields`;
- `create-unique-existing`;
- `data-round-trip`;
- `transaction-rolls-back-operations`: `increment`, `resetCounter`, `appendAudit`, `delete` and `revoke` roll back.

A store that listed newest first used to pass, and then refused a valid email code. A new `timeoutMs` option, 30 seconds
by default, fails a check that never finishes. A store that deadlocks is then reported instead of hanging the run.
