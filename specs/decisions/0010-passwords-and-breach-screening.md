# 0010: Passwords: length, blocklist and breach screening

## Status

Accepted (2026-11-15). Implemented in phase 3 (passwords in the first complete slice); the policy report line lands
with the policy report in phase 8. Answers handoff question 10.

Planned tests:

- `test/methods/password-blocklist.test.ts`
- `test/methods/password-hibp-request.test.ts`
- `test/methods/password-hibp-unreachable.test.ts`
- `test/report/hibp-deviation.test.ts`
- `test/attacks/breached-password-accepted.test.ts`

## Context

NIST SP 800-63B-4 requires a verifier to compare a new password against a blocklist of commonly used, expected or
compromised values. A small list bundled with the package catches the most common choices. It cannot know about the
billions of passwords exposed in breaches; only a breach corpus can.

Have I Been Pwned (HIBP) offers that corpus through a free range API with no key. The caller sends the first 5 hex
characters of a password's SHA-1 and receives every suffix that shares the prefix, with a count for each. The server
never sees the password or its full hash. The request is `GET https://api.pwnedpasswords.com/range/{prefix}`. Sending
the header `Add-Padding: true` pads every response to between 800 and 1,000 rows, with the padding rows carrying a
count of 0, so an observer of the encrypted traffic cannot tell which prefix was asked from the response length. HIBP
states no rate limit for this API.

The check still has two costs. It sends a hash prefix and the server's address to a third party each time someone
sets a password. And it depends on a service test-cap does not run, which can be slow or unreachable. The handoff
asked whether the check is opt-in or opt-out, what happens when the service is unreachable, and what the privacy note
says.

The rule for an answer test-cap cannot prove either way is **indeterminate** (see `GLOSSARY.md`): it is reported as
such and never counted as a pass.

## Decision

### 1. The bundled blocklist is always on

Every password that is set (sign-up in F01, reset in F09, and a password change) is checked against a blocklist that
ships inside the package. A match rejects the password with a field error that says the password is too common.

Why: NIST requires a blocklist, and a bundled list needs no network, so it works in every deployment mode and every
runtime.

Override: none. The blocklist cannot be turned off.

### 2. The HIBP range check is on by default, with padding

When a password is set, test-cap also asks the HIBP range API, sending only the 5-character SHA-1 prefix and the
`Add-Padding: true` header. A suffix match rejects the password with the same field error as a blocklist match. The
host is fixed in code; no configuration names another one.

Why: the bundled list is small by necessity; the breach corpus is what catches a password that is uncommon yet already
leaked. Padding removes the response-size side channel at no cost.

Override: turning HIBP off is one declared line in the policy. It is a deviation
([ADR 0026](0026-strict-defaults-and-deployment-mode.md)): the policy report lists it, and the bundled blocklist keeps
running.

### 3. An unreachable HIBP is indeterminate, never a pass

When HIBP cannot be reached, times out or answers with an error, the screening result is recorded as `indeterminate`
on the password authenticator, and the evidence its ceremonies produce carries that result. Sign-up continues on the
bundled list alone. The policy report states how screening is configured and that an unreachable service yields
`indeterminate`.

Why: blocking every sign-up because a third party is down would make HIBP an availability dependency of the app.
Recording the gap keeps the claim honest: test-cap never says a password was screened against the breach corpus when
it was not.

Override: none. An app that wants sign-up to stop when HIBP is down has no switch for it in the plan.

### 4. The privacy note

The docs and the policy report carry this note: when a password is set, test-cap sends the first 5 hex characters of
its SHA-1 to `api.pwnedpasswords.com`, with padding. HIBP learns the server's address and when passwords are set, never
the password or its full hash. Turning the check off stops all traffic to HIBP.

### 5. Length, and how it is counted

A password is at least 8 characters while the policy requires multi-factor authentication for every route that
accepts it, and at least 15 when a deviation lets a password alone satisfy a requirement (800-63B-4 §3.1.1.2). The
maximum accepted is 256 characters, which also bounds the argon2id input ([ADR 0018](0018-budgets.md)). Length counts
Unicode code points after NFC normalisation. A password is verified exactly as received: never truncated, never
case-folded, and with no composition rules.

Why: NIST sets both minimums and counts each code point as one character; the 256 ceiling exceeds NIST's 64 while
keeping the hashing cost bounded. This ADR owns every password-verifier rule, so length lives beside the blocklist it
filters.

Override: the minimums can be raised, never lowered. A password-only requirement is itself a reported deviation.

Planned tests: `test/methods/password-length.test.ts`, `test/methods/password-no-truncation.test.ts`.

## Consequences

- A password is screened in two layers, and the evidence says which ones ran.
- A deployment with no outbound internet access still signs people up; its policy report shows the screening as
  `indeterminate`, or HIBP as turned off if the app declares it.
- The HIBP call sits on the sign-up and password-change path, so its timeout counts against the latency budget
  ([ADR 0018](0018-budgets.md)).
- The fetch used for HIBP is injectable like the clock and random source, so tests never reach the real service.

## Limits

- Screening runs when a password is set. A password that was clean at sign-up and appears in a breach later is not
  caught by this decision.
- The bundled list is only as good as its source and size; both are open (see Open).
- HIBP's own availability, accuracy and retention are outside test-cap's control.

## Open

1. **Bundled list source and size.** The plan names "the bundled list" but not its source. Recommendation: a list of the
   most common passwords from a source whose licence allows redistribution, filtered to the minimum length test-cap
   accepts, sized to fit the server entry's bundle budget ([ADR 0018](0018-budgets.md)), plus context-specific words
   built at run time (the `APP_SYSTEM_ID` value and the account identifier).
2. **Re-screening an indeterminate result.** The plan records `indeterminate` but does not say whether it is ever
   resolved. Recommendation: re-check at the next successful password sign-in, when the plaintext is available again;
   on a match, put the session in the recovery state and require a new password.
3. **HIBP timeout and match threshold.** Recommendation: a 1.5-second timeout, after which the result is
   `indeterminate`, and rejection on any occurrence count above zero. A matching suffix with a count of 0 is a padding
   row and is never a match; a planned case in `test/methods/password-hibp-request.test.ts` pins that.
