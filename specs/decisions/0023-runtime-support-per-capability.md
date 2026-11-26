# 0023: Runtime support per capability

## Status

Accepted (2026-11-15). Implemented in phase 6 (Bun and Deno CI) and verified in phase 9 (the cross-runtime matrix over
the release build). The `cross-runtime` CI job runs `test/cross-runtime/run.mjs` over the built `dist/` on Node 22 and
24, Bun 1.3.14 and Deno 2.9.4, and `test/cross-runtime/coverage.test.ts` makes its coverage grow with every value the
package exports. Pinned by:

- `test/cross-runtime/core.test.ts`
- `test/cross-runtime/passwords.test.ts`
- `test/cross-runtime/passkeys.test.ts`
- `test/cross-runtime/oidc.test.ts`
- `test/cross-runtime/audit.test.ts`
- `test/cross-runtime/saml-node-only.test.ts`
- `test/docs/runtime-table.test.ts`
- `test/supply-chain/simplewebauthn-floor.test.ts`

The recommendations under Open are provisional defaults until the owner decides.

Amended 2026-11-24: none of the eight "Pinned by" files above exists yet, and the section 1 table says more than CI
runs. What CI runs today is `test/cross-runtime/run.mjs` and `test/cross-runtime/journey.mjs` (a sign-in journey
through `test-cap/fetch`) on Node 22 and 24, Bun 1.3.14 and Deno 2.9.4, and `test/cross-runtime/workers.mjs` on
Cloudflare workerd ([ADR 0031](0031-replaceable-argon2id-and-a-fallback-without-webassembly.md)). The table and its
pinning tests follow in phase 6.

## Context

Owner requirement 6 asks for Node, Bun and Deno. A single "runs everywhere" line would over-claim: test-cap's
capabilities sit on different libraries, and those libraries support different runtimes. The review triage adopted
"runtime support is stated per capability".

The facts (research note, "Libraries" and "Platform"):

- Node's floor is 22; Node 20 reached end of life on 2026-04-30.
- Ed25519 and AES-GCM in the global `crypto.subtle` were tested locally on Node 22.23, Bun 1.3.14 and Deno 2.9.4.
- `@simplewebauthn/server` officially supports Node 22+ and Deno 2.4+, with pure-JS dependencies and no `node:`
  imports. It does not claim Bun.
- `hash-wasm` is the only argon2id found that runs on Node, Bun and Deno with no native build.
- `@node-saml/node-saml` depends on Node.
- Next.js 16's `proxy` runs on Node only.

env-cap already proves runtime support this way: tests run the built `dist/` under each runtime in CI.

## Decision

### 1. Support is stated per capability, and every claimed cell is a CI job over `dist/`

| Capability                                 | Node 22/24 | Bun         | Deno        | Edge (Next proxy excluded) |
| ------------------------------------------ | ---------- | ----------- | ----------- | -------------------------- |
| Core, sessions, policy, TOTP, forms, pages | CI         | CI          | CI          | not claimed                |
| Passwords (`hash-wasm`)                    | CI         | CI          | CI          | not claimed                |
| Passkeys (`@simplewebauthn/server`)        | CI         | CI (ours)   | CI          | not claimed                |
| OIDC (`oauth4webapi`)                      | CI         | CI          | CI          | not claimed                |
| Audit (Ed25519 / HMAC, Web Crypto)         | CI         | CI          | CI          | not claimed                |
| SAML (`@node-saml/node-saml`)              | CI         | unsupported | unsupported | unsupported                |

"CI" means a required CI job runs that capability's tests against the built `dist/` on that runtime: Node through
Vitest, Bun through `bun test`, Deno through `deno test`. "CI (ours)" marks a cell the library itself does not claim
and only test-cap's CI covers. "Not claimed" means nothing is promised either way. "Unsupported" means it is known not
to work.

Why: the build that ships is the build that is tested, so a source-only pass cannot hide a bundling fault. A cell says
exactly what has been run, and nothing more.

Override: none. An app may run a capability where the table does not claim it, on its own evidence.

### 2. A cell is evidence for the library version it ran

Each "CI" cell holds for the library version the lockfile pins. The passkeys row in particular pins
`@simplewebauthn/server` to a release past the fixes of 2026-09-13 for GHSA-6hxq-p678-4hr2 (attestation chain not
anchored), GHSA-2g3p-m8c9-hhwh (CRL cache poisoning) and GHSA-j3h4-m3m2-7p7j (SSRF through attestation certificates).
Bun is not claimed upstream, so for that cell test-cap's own CI is the only evidence, and a library upgrade re-runs it
before the cell stays "CI".

Why: a runtime claim about a vulnerable version is a claim nobody should rely on, and a cell no upstream vouches for
needs its own proof on every upgrade.

Override: none.

### 3. Edge runtimes are not claimed

No capability claims an edge runtime. The Next.js `proxy` is excluded from the column because it runs on Node in
Next.js 16.

Why: no CI job runs an edge runtime, and edge hosts limit CPU time in ways an argon2id hash with fixed cost may exceed.
A claim with no job behind it is the over-claim this decision exists to avoid.

### 4. SAML is Node only

The SAML entry runs on Node only. [ADR 0028](0028-saml-library-and-its-own-gate.md) owns the rest of SAML.

Why: its library depends on Node, and no Bun or Deno job proves otherwise.

### 5. How a cell changes

A cell moves up (to "CI") only in the pull request that adds a required CI job exercising that capability over `dist/`
on that runtime. A cell moves down in the same pull request that removes or weakens such a job. A docs test compares
the table in the README with the CI matrix and fails when they disagree.

Why: the table is a projection of the CI matrix. Tying each edit to the job that justifies it keeps the two from
drifting.

## Consequences

- An app on Bun or Deno knows exactly which capabilities it can rely on.
- Every capability added later adds a row, and its capability gate includes its runtime jobs.
- CI time grows with each runtime and capability; ADR 0018 owns the budget.

## Limits

- **A passing job is evidence for the versions it ran**, not for every release of that runtime.
- **The table covers test-cap's code, not the app's.** The app's database driver and framework have their own runtime
  support.
- **Adapters are not rows.** The plan's table lists capabilities, not the five adapters
  ([ADR 0024](0024-adapters-and-deny-by-default.md)); see Open 1.

## Open

1. **Adapter rows.** Express and Nest are Node frameworks; the `fetch` adapter is runtime-neutral; TanStack Start and
   Next.js depend on their hosts. Recommendation: add one row per adapter, claiming only the runtimes the adapter
   conformance suite runs on.
2. **Bun and Deno version floors.** The plan names Node's floor only. Recommendation: Bun 1.3 and Deno 2.4 (the
   SimpleWebAuthn floor), raised whenever CI moves past them.
3. **What loading SAML on Bun or Deno does.** Recommendation: the SAML entry checks for Node when it is created and
   throws a named error that points to this ADR, rather than failing deep inside a dependency.
