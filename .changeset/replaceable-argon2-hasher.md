---
"test-cap": minor
---

Add `argon2Hasher`, so an app can replace the argon2id computation with its own `Argon2Hasher` (ADR 0031). test-cap
still checks what any hasher returns: a hash that is not the argon2id PHC string of the salt and cost it asked for
throws, a stored hash in another format fails to verify, and only `true` from `verify` is a match. Where the runtime
cannot compile WebAssembly, such as Cloudflare Workers, argon2id runs on `@noble/hashes` (pinned to 2.4.0, a new
dependency) and `onDiagnostic` reports `argon2-fallback` once. Both write the same PHC string, so a hash made by one
verifies with the other.
