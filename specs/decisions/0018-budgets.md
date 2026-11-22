# 0018: Budgets

## Status

Accepted (2026-11-15), with the numbers open (see Open). The fixed argon2id cost, the concurrency semaphore and the
256-character input limit are implemented in phase 3; the latency and bundle-size budgets are set and checked in
phase 9. Answers [handoff question](../../GLOSSARY.md) 18.

Planned tests:

- `test/budgets/argon2-parameters.test.ts` (the parameters in use equal the declared ones)
- `test/budgets/argon2-semaphore.test.ts` (no more hashes run at once than the limit, under concurrent load)
- `test/budgets/password-max-input.test.ts` (input over 256 characters is refused before hashing)
- `test/budgets/bundle-size.test.ts` (each entry within its gzip budget)
- `benchmarks/performance-runtime/suite.mjs` entries for password sign-in, TOTP verification and `auth.require`
  (phase 3), and passkey verification (planned, phase 5)

The recommendations under Open are provisional defaults until the owner decides.

## Context

The handoff asked for login latency targets and a bundle-size budget per entry point. Two kinds of cost matter.

**Latency.** Most of test-cap's work is cheap: parsing, a few store calls, an HMAC. One step is expensive on purpose:
argon2id password hashing, which is made slow and memory-hungry so a stolen hash is costly to crack. Its cost is also
an attack surface: an attacker who can make the server hash many long passwords at once can exhaust memory or CPU.

**Bundle size.** The browser entries (`test-cap/client`, `test-cap/forms`, `test-cap/react` and the default pages'
hashed assets) are downloaded by every visitor. The server entries matter less, but a passkey-only app should not
carry SAML ([ADR 0004](0004-package-entries-and-capability-gates.md)).

What the repository already measures. internal-package-contract's benchmarks run each function over a ladder of input
sizes, gate the measured big-O against the documented one and the overhead as a ratio to a bare baseline, and set no
threshold on a raw time, because times are not comparable between machines (`benchmarks/README.md`). They record
each bundle file's bytes and gzip bytes; size is gated separately by the `Size` check (below).

What `hash-wasm` 4.13.0 argon2id costs, measured on 2026-11-15 on an Apple M3 with Node 22.23.2 (median of 10 after
a warm-up, 32-byte output):

| Parameters (memory, iterations, parallelism) | Median time |
| -------------------------------------------- | ----------- |
| 19 MiB, 2, 1                                 | 37.5 ms     |
| 46 MiB, 1, 1                                 | 47.6 ms     |
| 64 MiB, 3, 1                                 | 189.3 ms    |
| 64 MiB, 3, 4                                 | 190.4 ms    |

Two observations follow. Parallelism above 1 buys nothing, because `hash-wasm` computes the lanes on one thread.
And four hashes started together at 19 MiB, 2, 1 took 147.6 ms in total: concurrent hashes share one thread, so each
waits for the others and latency grows with the number in flight. The event loop stayed responsive (its largest gap
was 2.5 ms), so other requests are delayed by CPU contention, not blocked outright.

## Decision

### 1. argon2id runs at a fixed cost

Memory, iterations and parallelism are fixed constants in the password module. Each stored hash records the
parameters it was made with, so a later change of constants never makes an old hash unverifiable.

Why: a cost an app can lower is a cost an app will lower to make tests faster, and then ship. A fixed cost makes the
latency of password sign-in predictable and the strength of stored hashes known.

Override: in `test` mode only, `createAuth`'s `argon2Cost` sets another cost, so a test suite does not spend the full
cost on every sign-in. Any other mode refuses to start with it, the same rule as a custom `Clock` or `RandomSource`
([ADR 0026](0026-strict-defaults-and-deployment-mode.md) §4). The cost a test passes still goes through the semaphore
(§2) and the dummy hash runs at it, so a test sees the same flow. test-cap's own tests hash at the smallest cost
hash-wasm accepts; one test file keeps the full 19 MiB, 2 passes, parallelism 1 and checks that `createAuth` uses it
when no cost is passed.

### 2. A concurrency semaphore bounds hashing

At most a fixed number of argon2id computations run at once per process; further requests wait. The dummy hash run for
an unknown account ([ADR 0009](0009-abuse-and-proxy-trust.md)) goes through the same semaphore, so waiting reveals
nothing about whether an account exists.

Why: without a bound, a burst of sign-in attempts makes every hash slower and multiplies memory use. The measurement
above shows hashes do not run in parallel anyway, so the bound costs no throughput.

### 3. Password input is capped at 256 characters

A password longer than 256 characters is refused before it reaches the hash. NIST requires a maximum of at least 64;
256 leaves room for passphrases.

Why: the cap removes very long inputs as a way to make each hash more expensive.

### 4. Budgets are checked at release, per entry

Phase 9 sets a latency budget for each sign-in method and a gzip size budget for each `exports` entry, and the release
verification checks them. Latency is judged the way the repository already judges it (big-O and overhead ratio
through the benchmark suite) plus the argon2id parameter test above; bundle size is gated by
the contract's `Size` check over `ci/size-budgets.mjs`, one budget per `exports` entry, and
`test/budgets/size-budgets.test.ts` fails when an entry has no budget. Each entry is measured together with every
`dist/` chunk it imports, since an entry file may only re-export from shared chunks; a library it imports by package
name is a dependency and is left out. The default pages' assets are measured as `auth.handle` serves them. Since
2026-11-16 the server entries carry their first measurement plus 10 percent and the page assets the fixed 15 KiB of
Open 4.

Why: the plan puts "size and benchmark budgets" in release verification. Gating size inside test-cap closes the one
gap the shared benchmarks leave.

## Consequences

- Password sign-in costs one argon2id hash plus store round trips; every other method is dominated by store and
  network time.
- A sign-in burst is queued, not amplified. Under heavy load password sign-in slows first, and the throttle
  ([ADR 0009](0009-abuse-and-proxy-trust.md)) limits how much load one source can add.
- A size regression in a browser entry fails the release, not just a report.

## Limits

- Latency depends on the app's store, network and hardware. test-cap's budgets cover its own work, not a whole
  request.
- The measurements above come from one machine and one runtime. Bun and Deno, and CI runners, will differ;
  [ADR 0023](0023-runtime-support-per-capability.md) covers runtime support.
- The semaphore is per process. An app running many processes multiplies the total hashing capacity and memory.
- No budget covers the first load of WASM for `hash-wasm`; it is measured once in phase 9.

## Open

1. **argon2id parameters.** The plan fixes the cost but not its values. Recommendation: memory 19 MiB (19,456 KiB),
   2 iterations, parallelism 1, the minimum configuration in OWASP's Password Storage Cheat Sheet: about 38 ms per
   hash on the machine above. Parallelism stays 1, since `hash-wasm` gains nothing from more.
2. **Semaphore limit and queue.** Recommendation: 4 hashes in flight per process (about 150 ms worst case at the
   parameters above), with a bounded queue; a request that cannot queue gets the same throttled reply as
   [ADR 0009](0009-abuse-and-proxy-trust.md), with a wait time, so the reply does not differ for known and unknown
   accounts.
3. **Latency budgets.** Recommendation: record, in the release report, the server-side time of each sign-in method
   on the CI runner, excluding store and network, and fail the release when password sign-in exceeds 250 ms or any
   other method exceeds 50 ms there. Per pull request, rely on the contract's ratio and big-O gates, since raw times
   are not comparable between machines.
4. **Bundle-size budgets.** Recommendation, gzip, measured over `dist/`: `test-cap/client` 8 KiB, `test-cap/forms`
   6 KiB, `test-cap/react` 12 KiB excluding React, the default pages' hashed assets 15 KiB in total. Each server
   entry gets its first measured size plus 10 percent, fixed in phase 9, and the core entry must not grow when SAML or
   the audit trail is added.
5. **Moving old hashes to new parameters.** Recommendation: when the constants change, rehash a password at its next
   successful sign-in, when the plaintext is available.
