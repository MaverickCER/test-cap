---
"test-cap": minor
---

Add the `test-cap/tanstack-start` entry, tested on TanStack Start 1.169.5. `tanstackStartMiddleware(auth, { public })`
is the server function of a global request middleware. It protects every route and server function call at the
default requirement unless its path is listed as public, and puts the subject in `context.auth`.
`tanstackStartAuth(auth)` serves the `/auth/$` server route through its `handlers`. Its `require` and `session` let a
server function check a requirement itself.

Add the `test-cap/store/memory` entry. Its `memoryStore()` is the development and test store; production and staging
refuse it.
