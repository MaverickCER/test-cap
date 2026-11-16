# 0017: Requirement mapping

## Status

Accepted (2026-11-15). `specs/requirements.md` is written in phase 1; its docs test lands with the first test code in
phase 2, and every later phase updates the rows its capabilities change. Answers handoff question 17.

Planned tests:

- `test/docs/requirements-mapping.test.ts`
- `test/docs/no-public-security-claims.test.ts` (owned by [ADR 0019](0019-internal-use-disclosure-and-distribution.md))

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

### 1. One row per outside statement, with one of three statuses

`specs/requirements.md` has one row for every ASVS requirement in V6, V7, V9, V10 and V16, and one for every NIST
800-63B-4 statement that applies to a verifier offering the methods test-cap ships (plus the 800-63A-4 §3.8
confirmation-code statements email confirmation relies on). Each row gives:

- the identifier (ASVS 5.0.0 id, or 800-63B-4 section and statement);
- a short paraphrase;
- a status: **met**, **partly met** or **out of scope**;
- for met and partly met, the design element that does it (an ADR and, where it applies, a flow id) and the tests
  under `test/` that pin it;
- for partly met, the gap, in one sentence;
- for out of scope, the reason and, where there is one, who owns it (the app, access-cap or secure-cap).

Why: a fixed shape makes the record checkable by a test and readable in one pass. Three statuses are enough to be
honest and few enough to apply consistently.

### 2. Gaps the plan already names

Some rows are settled by the plan and are recorded as such, for example:

| Statement                                      | Status       | Why                                                                                                                                                       |
| ---------------------------------------------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| NIST: OTP secrets protected by access controls | met          | test-cap encrypts them too ([ADR 0027](0027-otp-on-web-crypto-and-encrypted-secrets.md)), a stricter choice than NIST asks                                |
| NIST: email not used for out-of-band auth      | met          | email never raises assurance ([ADR 0005](0005-policy-and-evidence-based-assurance.md), [ADR 0021](0021-excluded-methods-and-emails-role.md))              |
| NIST: no syncable authenticator at AAL3        | met          | a synced passkey stops at AAL2 ([ADR 0005](0005-policy-and-evidence-based-assurance.md))                                                                  |
| ASVS V10 rows on generic OAuth 2.0 sign-in     | out of scope | generic OAuth 2.0 sign-in is a stated gap; OIDC covers federation                                                                                         |
| ASVS V9 rows on issuing self-contained tokens  | out of scope | sessions are opaque ([ADR 0006](0006-sessions-and-cookies.md)); delegations depend on [ADR 0013](0013-human-machine-and-delegation-separation.md), Open 2 |
| ASVS V9 rows on validating received tokens     | met          | OIDC ID tokens are validated through `oauth4webapi` ([ADR 0005](0005-policy-and-evidence-based-assurance.md), [ADR 0016](0016-protocol-conformance.md))   |
| Breached-password screening                    | partly met   | the HIBP check can be `indeterminate` when unreachable ([ADR 0010](0010-passwords-and-breach-screening.md))                                               |

Why: these follow from decisions already made; the mapping records them rather than revisiting them.

### 3. Traceability, never a compliance claim

The file and every row use "maps to" language. It never says test-cap complies with, is certified against or passes
ASVS or NIST. The file's opening states that it is engineering traceability for internal readers.

Why: a status in this file is test-cap's own reading of a statement, checked by test-cap's own tests. Nobody outside
has verified it, and calling it compliance would be a claim the evidence does not support.

### 4. A docs test keeps it honest

`test/docs/requirements-mapping.test.ts` fails when:

- an ASVS id from the five chapters is missing or appears twice;
- a row has a status other than the three;
- a partly met row has no gap, or an out-of-scope row has no reason;
- a met or partly met row names no test, or names a test file that does not exist once its capability has passed its
  gate ([ADR 0004](0004-package-entries-and-capability-gates.md));
- a row cites an ADR that does not exist.

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
- A met row means a design element and a passing test exist. It does not mean the test covers every way the
  statement could be violated.

## Open

1. **Rows for capabilities not yet built.** Phase 1 writes the mapping before any test exists. Recommendation: a row
   whose capability has not passed its gate shows its target status prefixed "planned" (for example "planned: met"),
   and the docs test only demands existing test files once the capability is in `exports`.
2. **The ASVS id list the test checks against.** Recommendation: pin the ASVS 5.0.0 machine-readable release (its
   JSON export) under `test/fixtures/`, so the test checks against the published list rather than a hand-typed one.
