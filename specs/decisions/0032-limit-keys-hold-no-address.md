# 0032: The limits keep no email address or client address in the app's store

## Status

Accepted (2026-11-24). Implemented in phase 4. Applies to every limit of [ADR 0009](0009-abuse-and-proxy-trust.md) and
[ADR 0030](0030-use-existing-libraries-for-limits-and-client-addresses.md), and amends ADR 0030's Consequences: the
counter names it gives (`throttle:client:<key>` and the rest) are now the keys behind HMAC names. Pinned by:

- `test/security/limit-keys-pseudonymous.test.ts`
- `test/topology/client-address.test.ts`, which reads each counted key back through `test/support/limit-keys.ts`

## Context

The limits count per identifier, per client and per pair, so their keys hold what a person typed and where they came
from: `throttle:account:<email>`, `throttle:client:<address>`, `rate:…|<address>`, `stuffing:<address>`, the mail
limits' `address:<email>`, and the refusal events' keys. Each key became a counter or block record in the app's own
database. That includes the addresses an attacker sprays and the ones a person mistypes, for accounts that do not
exist. A database dump or a support query could read them back.

## Decision

`createAuth` gives every limit a view of the app's store in which each counter, and the key of each limit block, is
named by HMAC-SHA-256 of its key. The HMAC key is derived by HKDF from the current `AUTH_ENCRYPTION_KEY`, with the
label `limit-keys`, so it is apart from every other use of the ring. The name is the unpadded base64url digest, 43
characters.

- The same key always gets the same name, so counts add up and blocks are found again.
- Every other record passes through unchanged.
- An app's own limiter, given through `rateLimit.limiter` or `emailLimit.limiter`, receives the plain key, as its
  library expects. What it keeps is the app's choice.

## Alternatives considered

| Alternative                          | Why it lost                                                                        |
| ------------------------------------ | ---------------------------------------------------------------------------------- |
| Plain SHA-256 of the key             | An IPv4 address or a common email address is found again by hashing guesses        |
| A key option on `createStoreLimiter` | Six call sites to thread it through, and an app's own use would skip it by default |
| Keep plain keys, document a purge    | The rows are readable for as long as they exist                                    |

## Consequences

- A counter or block in the store says nothing about whom it counts without `AUTH_ENCRYPTION_KEY`.
- Rotating `AUTH_ENCRYPTION_KEY` renames every limit key, so each count starts again from zero. That includes each
  authenticator's count toward the failure ceiling, which has no window. A rotation is rare and made by the operator.
- Development and test without `AUTH_ENCRYPTION_KEY` use the key generated for the process, so counts start again at
  each start.

## Limits

- The names are pseudonymous, not anonymous: whoever holds `AUTH_ENCRYPTION_KEY` can test a guessed key against them.
- Expired counters and blocks stay in the store until the app deletes them. The `AuthStore` port has no sweep. An app
  deletes counters whose reset time has passed and `rate-limit-block` records whose expiry has passed.
