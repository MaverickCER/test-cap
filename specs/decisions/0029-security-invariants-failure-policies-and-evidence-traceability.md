# 0029: Security invariants, failure policies and evidence traceability

## Status

Accepted (2026-11-16). Written during phase 3; the owner has not reviewed it yet, and the recommendations under Open
are provisional defaults until the owner decides. Governs [security-invariants.md](../security-invariants.md) and
[dependency-failures.md](../dependency-failures.md). Pinned by:

- `test/docs/security-invariants.test.ts`
- `test/docs/attack-catalogue.test.ts`
- `test/failure/store.test.ts`
- `test/failure/email.test.ts`
- `test/failure/hibp.test.ts`
- `test/failure/clock.test.ts`
- `test/failure/random.test.ts`
- `test/failure/keys.test.ts`
- `test/failure/events.test.ts`

## Context

The attack catalogue proves that each listed attack is stopped, one test per attack. It does not say which property
each test defends, so it cannot answer the questions a reviewer or an agent asks first: what does test-cap guarantee
whatever adapter, store or framework is used, where in the code is that enforced, and what proves the proof itself
bites? Success metric 13 asks for that answer as a registry of security invariants with complete traceability.

The catalogue also says little about the things test-cap depends on but does not control. A store outage, a mail
outage, a clock jump or a missing key each has a right answer, and the wrong one opens an account. Success metric 16
asks that every external dependency have an explicit failure policy and verified behaviour.

Before this decision, `fail-open-on-error` covered one case (a store read during `require`). Building the failure
matrix for every store call of every phase 3 flow found one fail-open path (F-1 in dependency-failures.md) that no
existing test reached.

## Decision

### 1. Security invariants are a governing spec

[security-invariants.md](../security-invariants.md) lists every framework-independent property test-cap keeps. Each
invariant has a stable `INV-` id and states its property, its enforcement points (exported functions in core
modules, never an adapter), its attack-catalogue ids, its threat-model flows, its positive and negative tests by file
and exact name, the source files whose cold mutation is its evidence, and its limitations. Its status is `tested`,
`partial (phase N)` or `planned (phase N)`.

Why core and not adapters: an adapter converts bytes (ADR 0003, ADR 0024). A property an adapter enforced would hold
for one framework only, and the next adapter could drop it.

### 2. The chain is checked, in both directions

`test/docs/security-invariants.test.ts` enforces the chain attack → threat → invariant → enforcement point → test →
assertion → evidence. Every `tested` catalogue row names an invariant in a new Invariant column, and the column must
equal the registry; every attack an invariant names exists and is cited by one of its flows; every enforcement point
is an export that exists outside `src/adapters/`; every named test exists with that exact name; every enforcement
file is listed as mutation evidence. A `planned` invariant names only planned attacks and the phase that builds it.

Mutation evidence is the existing `Mutation` check: 100% cold on every merged change, so the listed files' tests are
proven to bite whenever they are merged. The registry names the files; the check is the evidence.

### 3. Every dependency has a failure policy, and fail closed is the default

[dependency-failures.md](../dependency-failures.md) gives each dependency phase 3 uses (the store, email delivery,
HIBP, the clock, the random source, key material and the event sink) a section stating its expected failures, its
policy, what is unavailable while it fails, what a reply may expose, recovery, operator diagnostics, and audit and
event implications. A failing dependency never produces an authentication, a higher level or a silent downgrade. A
degraded mode is allowed only where the dependency cannot change an outcome (mail and events, handed off without
waiting) or where the degradation is recorded on the result (HIBP's `indeterminate`).

### 4. Failure injection proves each policy

`test/failure/` injects faults into each dependency. For the store, every call of every phase 3 flow is failed in
turn, with and without store transactions where a session change takes several steps, and each operation is also
failed by a synchronous throw, a timeout and a call that never settles. Each flow's list of store calls is pinned, so
a flow that starts calling something new fails until its failure cases cover it.

### 5. A finding is fixed or stated, never hidden

A failure test that shows an opening is either fixed in the same change, with the test that pins the fix, or recorded
under Findings in dependency-failures.md with what remains and who decides. The three findings so far are fixed, F-1
and L-1 with a stated residual (see Open). A credential change whose rotation fails revokes every session of the
account (F-1, ADR 0006 §7). An email code's attempts count over its whole life, so a failed kill write buys no fresh
guesses (F-2, ADR 0009 Open 1). A read that finds a session expired revokes it, so a backward clock jump cannot
revive it (L-1, ADR 0006 §4).

## Consequences

- A new attack row that reaches `tested` must name an invariant; a new invariant must name its proof. A reviewer can
  go from any guarantee to its code and its tests in one step.
- The registry and the policies are read by agents as well as people, so their claims stay as narrow as their tests.
- Each future phase adds its own dependencies (identity providers in phase 5, the audit store in phase 8) as policy
  sections with failure tests, and flips its planned invariants.
- The failure matrix adds about 300 fast tests, which run in the mutation of every file they cover.

## Limits

- The failure tests use the memory store with injected faults. Persistence under real SQL concurrency, transaction
  failure and restarts is phase 6's work (success metric 15).
- The invariants are what test-cap enforces in its own code. A route the app never hands to an adapter, a public path
  the app lists and a relaxed policy are the app's.

## Open

1. **F-1 residual.** When the store fails both the rotation and the fallback revoke, the account's other sessions
   stay until an operator revokes them. Recommendation: confirm the TOTP authenticator and rotate the session in one
   store transaction when the store has one.
2. **L-1 residual.** A backward clock jump still revives a session that expired with no read to find it, and one whose
   every revoke failed. Recommendation: none yet; an operator revokes such sessions with `auth.admin.revoke`.
