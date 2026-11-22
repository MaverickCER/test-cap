---
"test-cap": minor
---

Revoke a session when a read finds it past its idle or absolute limit (ADR 0006 §4). A clock that later jumps
backwards can then not give it the rest of its window again. The read answers unauthenticated even when that revoke
fails, and the next read tries again.
