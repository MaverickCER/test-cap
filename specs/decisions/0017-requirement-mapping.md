# 0017: Requirement mapping

## Status

Accepted (2026-11-15). `specs/requirements.md` is written in phase 1; its docs test lands with the first test code in
phase 2, and every later phase updates the rows its capabilities change. Answers
[handoff question](../../GLOSSARY.md) 17.

Planned tests:

- `test/docs/design-traceability.test.ts` (its requirement-mapping checks)
- `test/docs/no-public-security-claims.test.ts` (owned by [ADR 0019](0019-internal-use-disclosure-and-distribution.md))

The recommendations under Open are provisional defaults until the owner decides.

## Context

Two outside documents describe what good authentication does. OWASP ASVS 5.0.0 lists verification requirements by
chapter; the ones that bear on test-cap are V6 Authentication (47), V7 Session Management (19), V9 Self-contained
Tokens (7), V10 OAuth and OIDC (36) and V16 Security Logging and Error Handling (17). NIST SP 800-63B-4 states what a
verifier SHALL and SHOULD do at each assurance level.

A reader of test-cap's design wants to know, for each of those statements, whether test-cap does it, does part of it,
or leaves it to someone else, and how they can check. The handoff asked for that record and called it what it is:
engineering traceability, not a compliance claim. test-cap is internal and makes no public security claims
([ADR 0019](0019-internal-use-disclosure-and-distribution.md)).

A word clash needs settling first. In test-cap, a **requirement** is a named rule in the policy, such as
`billing.update` (see `GLOSSARY.md`). The statements in ASVS and NIST are called **ASVS requirements** and **NIST
statements** here and in `specs/requirements.md`, never bare "requirements".

## Decision

### 1. One row per outside statement, with one of four statuses

`specs/requirements.md` has one row for every ASVS requirement in V6, V7, V9, V10 and V16, and one for every NIST
800-63B-4 statement that applies to a verifier offering the methods test-cap ships (plus the 800-63A-4 §3.8
confirmation-code statements email confirmation relies on). Each row gives:

- the identifier (ASVS 5.0.0 id, or 800-63B-4 section and statement);
- a short paraphrase;
- a status, one of four:
  - **met by design**: the design meets the statement, and the planned test will prove it;
  - **partly met**: part of it is met, and the row states the gap;
  - **not applicable**: it concerns something test-cap does not do, and the row says why;
  - **out of scope**: it is real but belongs to another owner (the app, access-cap or secure-cap), whom the row names;
- the ADR that owns the design element and the tests under `test/` that pin it, or `none:` with the reason no
  test-cap test can exist.

`specs/requirements.md` defines the four in the same words and is the copy a reader uses.

A row whose capability has not passed its gate keeps its status and names its planned test path. Its status says what
the design does; the gate (ADR 0004) says whether the code exists yet, so the row needs no separate "planned" marker.

Why: a fixed shape makes the record checkable by a test and readable in one pass. Four statuses separate "not ours to
do" (not applicable) from "someone else's to do" (out of scope), which three would merge.

### 2. Gaps the plan already names

Some rows are settled by the plan and are recorded as such, for example:

| Statement                                                                     | Status         | Why                                                                                                                                                                                                                                                |
| ----------------------------------------------------------------------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| NIST: OTP secrets protected by access controls                                | met by design  | test-cap encrypts them too ([ADR 0027](0027-otp-on-web-crypto-and-encrypted-secrets.md)), a stricter choice than NIST asks                                                                                                                         |
| NIST: email not used for out-of-band auth                                     | partly met     | met while email sign-in is off, the default; turned on, it is a reported deviation that adds no assurance ([ADR 0005](0005-policy-and-evidence-based-assurance.md), [ADR 0021](0021-excluded-methods-and-emails-role.md))                          |
| NIST: no syncable authenticator at AAL3                                       | met by design  | a synced passkey stops at AAL2 ([ADR 0005](0005-policy-and-evidence-based-assurance.md))                                                                                                                                                           |
| ASVS V10 rows for an authorization server, resource server or OpenID Provider | not applicable | test-cap is only an OIDC relying party; generic OAuth 2.0 sign-in is a stated gap                                                                                                                                                                  |
| ASVS V9 rows on issuing self-contained tokens                                 | not applicable | sessions are opaque ([ADR 0006](0006-sessions-and-cookies.md)); delegations depend on [ADR 0013](0013-human-machine-and-delegation-separation.md), Open 2                                                                                          |
| ASVS V9 rows on validating received tokens                                    | met by design  | every ID token's signature is verified with `validateApplicationLevelSignature` against a per-issuer algorithm allowlist, because `oauth4webapi` alone skips it for token-endpoint responses ([ADR 0016](0016-protocol-conformance.md), section 7) |
| Breached-password screening                                                   | met by design  | the bundled blocklist always runs; an unreachable HIBP is recorded `indeterminate`, never a pass, and reported ([ADR 0010](0010-passwords-and-breach-screening.md))                                                                                |

Why: these follow from decisions already made; the mapping records them rather than revisiting them.

### 3. Traceability, in "maps to" language

The file and every row use "maps to" language: a row says which design element a statement maps to and which test
will pin it. The file's opening states that it is engineering traceability for internal readers.

Why: a status in this file is test-cap's own reading of a statement, checked by test-cap's own tests. Nobody outside
has verified it, and calling it compliance would be a claim the evidence does not support.

### 4. A docs test keeps it honest

`test/docs/design-traceability.test.ts` fails when:

- an ASVS chapter's row count differs from the pinned count;
- a row has a status other than the four;
- a row names neither a test path under `test/` nor a `none:` reason;
- a row cites an ADR that does not exist.

Planned additions, as capabilities pass their gates ([ADR 0004](0004-package-entries-and-capability-gates.md)): a
partly met row must state a gap and an out-of-scope row an owner, and a row whose capability is in `exports` must name
a test file that exists.

The wording rule of section 3 is checked by `test/docs/no-public-security-claims.test.ts`
([ADR 0019](0019-internal-use-disclosure-and-distribution.md)).

Why: a mapping nobody checks drifts within a release. A failing test turns drift into a red pull request.

## Consequences

- A reader can go from any ASVS or NIST statement to the design element and the test, or to the reason it is not
  covered.
- Every partly met row is a visible, named gap rather than a quiet one.
- Changing a capability means updating its rows in the same pull request, or the docs test fails.

## Limits

- The statuses are test-cap's own judgement. No outside party has reviewed them.
- The mapping covers the five ASVS chapters and the 800-63B-4 statements named above. Other ASVS chapters (for
  example V3 Web Frontend Security or V5 File Handling) and other NIST volumes are not mapped; parts of them are
  secure-cap's or the app's.
- A met-by-design row means a design element and a passing test exist. It does not mean the test covers every way the
  statement could be violated.

## Open

1. **The ASVS id list the test checks against.** Recommendation: pin the ASVS 5.0.0 machine-readable release (its
   JSON export) under `test/fixtures/`, so the test checks against the published list rather than a hand-typed one.
