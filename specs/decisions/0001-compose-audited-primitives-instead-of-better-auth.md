# 0001: Compose audited primitives instead of wrapping Better Auth

## Status

Accepted (2026-11-15). Owner decision. Implemented in phase 1 (this record and the attack catalogue) and pinned from
phase 4 onwards, as each advisory class gains its negative test.

Answers handoff question 1 (Better Auth). It also removes the premise of questions 2 and 3, which assumed Better
Auth's database adapters and its web `Request` handler; ADR 0002 and ADR 0003 answer them on their own terms.

Planned tests:

- `test/docs/better-auth-advisories-covered.test.ts` (each of the 49 advisory ids appears in the attack catalogue,
  with a test or a "not applicable" reason);
- the ten attack tests named in section 3;
- `test/core/injected-clock-and-random.test.ts` (no call to the global clock or random source outside the defaults
  ADR 0003 names);
- `test/docs/attack-catalogue-has-tests.test.ts` (an entry without a test fails the build).

## Context

The handoff described the package as "a better auth wrapper" and asked whether that meant wrapping the Better Auth
library (question 1). The owner answered on 2026-11-15: compose audited primitives; do not wrap the Better Auth
library.

The research note (`Dev/auth-cap-design/research-2026-11-15.md`) and its primary-source companion
(`Dev/auth-cap-design/research-raw-2026-11-15.md`, which wins where the two differ) record what an evaluation of
Better Auth found:

| Concern                | Finding                                                                                          |
| ---------------------- | ------------------------------------------------------------------------------------------------ |
| Ownership and version  | Version 1.7.25; owned by Vercel since 2026-07-07.                                                |
| Security track record  | 49 repository advisories from 2024-12-30 to 2026-11-03, 4 rated critical by the repository.      |
| Where they cluster     | SSO, SCIM, OAuth and OTP; 25 of the 49 were published on two days (2026-05-31 and 2026-11-03).   |
| Patching               | Only the latest version is patched.                                                              |
| Testability            | About 180 calls to `Date.now()` / `new Date()` with no clock option; randomness from the global. |
| Storage and HTTP shape | Its own database adapters (Kysely, Prisma, Drizzle) and a handler on the web `Request`.          |

Two of test-cap's requirements cannot be met through a wrapper. Every flow must be deterministic under test, so that
mutation testing can kill time- and randomness-dependent mutants, which needs an injectable clock and random source
(ADR 0003). The core must never open a database connection (ADR 0002). A wrapper would also inherit a release stream
where a fix arrives only in the newest version, and an API whose shape leaks into test-cap's.

## Decision

### 1. test-cap composes primitives; Better Auth is not a dependency

test-cap writes the flows, sessions, assurance model, policy, events and audit itself, and delegates every protocol
and every cryptographic operation to an established library or to Web Crypto:

| Work                        | Delegated to                                           |
| --------------------------- | ------------------------------------------------------ |
| OIDC relying party          | `oauth4webapi` 3.8 (OpenID-certified, no dependencies) |
| WebAuthn                    | `@simplewebauthn/server` 14.1 and `/browser`           |
| Password hashing            | `hash-wasm` 4.13 argon2id                              |
| SAML 2.0 SP                 | `@node-saml/node-saml` 5.2 (ADR 0028)                  |
| HMAC, AES-GCM, Ed25519, SHA | Web Crypto `crypto.subtle` (ADR 0027 for OTP)          |

Better Auth does not appear in `dependencies`, `peerDependencies` or `devDependencies`.

Why: the owner chose it, and the evaluation supports it. A wrapper's security is bounded by the wrapped library's, and
Better Auth's advisory rate, latest-only patching and fixed clock all work against the deterministic, evidence-backed
package test-cap must be. Each primitive above is narrow, has a public test suite or certification, and accepts the
inputs test-cap needs to control (`oauth4webapi`'s `clockSkew`, a caller-supplied WebAuthn challenge).

### 2. The alternative the handoff asked for is this composition

Question 1 asked for an alternative if wrapping were rejected. The alternative is section 1: the primitives above,
joined by test-cap's own core. No other framework (Auth.js, Lucia's successor guidance, a hosted provider) is wrapped
either; the positioning survey is not part of the build (ADR 0019).

Why: the primitives are the parts where hand-written code is most dangerous, and they are available separately. The
parts left to test-cap (flow order, session state, policy) are the ones its tests can pin.

### 3. Better Auth's advisory classes become attack tests

Every one of Better Auth's 49 advisories becomes an entry in `specs/attack-catalogue.md`. The catalogue owns the
entries; this section fixes the rule and the source. The classes the plan names, with the advisories behind them:

| Class                                                         | Advisories (GHSA)                                    | Negative test                                      |
| ------------------------------------------------------------- | ---------------------------------------------------- | -------------------------------------------------- |
| Second factor bypassed through a session cache                | `xg6x-h9c9-2m83`                                     | `test/attacks/session-cache-2fa-bypass.test.ts`    |
| OAuth `state` usable as a magic-link token                    | `965c-763c-88jm`                                     | `test/attacks/oauth-state-reuse.test.ts`           |
| Pre-account hijack through magic link or email OTP            | `qq9h-g4jm-xgf3`                                     | `test/attacks/pre-account-hijack.test.ts`          |
| OIDC identity auto-linked to an unverified email              | `g38m-r43w-p2q7`, `9hm7-xhfp-cx58`                   | `test/attacks/auto-link-unverified-email.test.ts`  |
| Rate limit bypassed by rotating IPv6 addresses                | `p6v2-xcpg-h6xw`                                     | `test/attacks/ipv6-rate-limit-bypass.test.ts`      |
| Race on an OTP's attempt limit                                | `2f9c-7xj7-gh55`                                     | `test/attacks/otp-redemption-race.test.ts`         |
| Double-slash path past route checks and rate limits           | `x732-6j76-qmhm`                                     | `test/attacks/double-slash-path.test.ts`           |
| Open redirect                                                 | `8jhw-6pjj-8723`, `hjpm-7mrm-26w8`, `36rg-gfq2-3h56` | `test/attacks/open-redirect.test.ts`               |
| Passkey accepted without user verification or from any origin | `gv75-j3v8-3crm`                                     | `test/attacks/passkey-uv-and-origin.test.ts`       |
| Revoked session still valid through a cache                   | `fvxx-76fc-893x`                                     | `test/attacks/revoked-session-still-valid.test.ts` |

The other applicable advisories also get entries and tests: `9x4v-xfq5-m8x5`, `vp58-j275-797x`, `99h5-pjcv-gr6v`,
`4vcf-q4xf-f48m`, `wmjr-v86c-m9jj`, `569q-mpph-wgww`, `wxw3-q3m9-c3jr`, `5rr4-8452-hf4v`, `gv74-j8m3-fg5f`,
`86j7-9j95-vpqj`, `2vg6-77g8-24mp`, `prpr-5gj3-qqhg`, `8c5h-wx78-2cfg`, `mx9r-x6ww-qjw9`, `r4xp-prcw-77qf`,
`44jh-23m7-hpcf`, `48c2-w96j-mv3m` and `hwq2-v29r-p69r`.

Eighteen advisories concern parts test-cap does not have: an OAuth authorization server, billing, organisation
invites, a SCIM server, Expo and Electron integrations, and phone numbers. Their entries say "not applicable" and
why, so the catalogue still accounts for all 49.

Why: test-cap's glue code (sessions, linking, throttling, recovery) is exactly where those advisories occurred. Turning
each class into a test is the cheapest way to learn from a library test-cap does not use.

## Consequences

- test-cap owns the code where most authentication bugs live: flow order, session handling, linking and throttling.
  Its defences are the attack catalogue, the conformance kits, fuzzing and cold mutation testing, and they are only as
  good as the catalogue is complete.
- No Better Auth API shape, plugin model or database adapter constrains test-cap's public API. ADR 0002 and ADR 0003
  define the store and HTTP surfaces from scratch.
- A new Better Auth advisory is a prompt to add a catalogue entry, not a dependency update.
- test-cap carries the maintenance of every flow itself, for every runtime it claims (ADR 0023).

## Limits

- **test-cap's own code has no outside review.** It is internal, has no external pen test (owner decision) and makes
  no public security claim. The free review apps on the public repository and the tests in section 3 are the review
  it gets.
- **One protocol is hand-written in part.** Oslo is deprecated, so HOTP and TOTP truncation and counting are written
  in test-cap on top of Web Crypto HMAC and checked against the RFC 4226 and RFC 6238 vectors. This only partly meets
  the owner's requirement "never hand-write protocols or cryptography"; ADR 0027 records it.
- **The catalogue covers known classes.** It cannot cover a class nobody has published yet.
- **The library list is pinned to versions checked on 2026-11-15.** Each phase re-reads its library's advisories
  before relying on it (research note, preamble).
