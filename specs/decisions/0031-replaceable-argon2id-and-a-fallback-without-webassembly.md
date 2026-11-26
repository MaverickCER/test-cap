# 0031: A replaceable argon2id, and a fallback where WebAssembly cannot compile

## Status

Accepted (2026-11-24), on the owner's rules that every default can be replaced and that an existing package is used
where it meets the bar ([ADR 0030](0030-use-existing-libraries-for-limits-and-client-addresses.md)). Implemented in
phase 4. Amends [ADR 0018](0018-budgets.md) §1 and the "workerd is probed, not in CI" limit of ADR 0030. Pinned by:

- `test/methods/password-hasher.test.ts`
- `test/methods/password-hasher-fallback.test.ts`
- `test/core/dist-reach.test.ts`
- `test/cross-runtime/journey.mjs`, run on Node, Bun and Deno by `test/cross-runtime/run.mjs` and on workerd by
  `test/cross-runtime/workers.mjs`

## Context

test-cap hashed passwords with `hash-wasm` alone, and an app could not swap it. On 2026-11-21 the universal-baseline
probe ran argon2id on four runtimes. `hash-wasm` passed on Node, Bun and Deno and failed on Cloudflare Workers:
`WebAssembly.compile(): Wasm code generation disallowed by embedder`. Workers refuse to compile WebAssembly from bytes
at runtime, which is how `hash-wasm` loads. `@noble/hashes` 2.4.0 ran argon2id at the OWASP cost on all four, in 207
to 299 ms.

## Decision

### 1. The app can replace the hasher

`createAuth` takes `argon2Hasher`, an `Argon2Hasher` with `hash` and `verify`. The default stays argon2id at the ADR
0018 cost. Whatever hasher runs, test-cap keeps the fixed cost, the salt, the semaphore and the dummy hash, and it
refuses what it can check:

- a `hash` result that is not the argon2id PHC string of the salt and cost it asked for;
- a stored hash in any other format, which fails to verify without reaching the hasher;
- any answer from `verify` other than `true`, which is not a match.

### 2. `@noble/hashes` runs where WebAssembly cannot compile

When `hash-wasm` throws a `CompileError`, the hasher switches to `@noble/hashes` for the rest of the process and
reports `argon2-fallback` once through `onDiagnostic`. Any other error is thrown as before. The fallback writes the
same PHC string, so a hash made by either verifies with the other. `@noble/hashes` is pinned to 2.4.0 and loaded by
`import("@noble/hashes/argon2.js")` only when the fallback starts, so nothing else in the package loads.

### 3. The sign-in journey runs on every runtime test-cap names

`test/cross-runtime/journey.mjs` signs up, confirms the email code, sets a password, enrols TOTP, signs out, refuses
a wrong password, signs in and steps up, through `fetchAuth` and the memory store at the test cost. The
`cross-runtime` CI job runs it on Node, Bun and Deno, and on workerd through wrangler 4.129.0 with `nodejs_compat`.
test-cap needs that flag on Workers, because forwarded-parse imports Node's `util`. Cloudflare turns it on by default
from compatibility date 2026-08-04, so ADR 0030's probe of 2026-11-21, dated 2026-09-01, ran with it on as well, and
its "no `nodejs_compat` flag" is corrected here.

## Alternatives considered

| Alternative                      | Why it lost                                                                    |
| -------------------------------- | ------------------------------------------------------------------------------ |
| `@noble/hashes` everywhere       | About 4 times slower than WebAssembly on Node (3,472 ms against 786 ms a hash) |
| Precompiled `WebAssembly.Module` | Needs a bundler rule in every app; Workers accept it only as a bundled import  |
| A Workers-only entry             | A second entry to keep, and an app that moves runtimes must change its import  |
| Leave Workers unsupported        | Breaks the owner's rule that each capability runs on every runtime it names    |

## Consequences

- An app can bring a native argon2id, a hardware module or a hosted hasher, and test-cap still checks its output.
- A stored hash in an unknown format now fails to verify. Before, `hash-wasm` threw.
- test-cap depends on `@noble/hashes` too. Like the other dependencies, it sits outside the size budget (ADR 0018).
- On Workers, each hash spends 200 to 300 ms of CPU at the OWASP cost. The app checks that its plan allows it.

## Limits

- The checks cannot prove a replaced hasher computes argon2id correctly. They catch a wrong format or a wrong
  parameter, not a wrong digest.
- CI fetches wrangler with `npx` at a pinned version, outside the lockfile, so its own dependencies are not locked.
