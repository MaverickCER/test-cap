# 0006: Server-side sessions and their cookies

## Status

Accepted (2026-11-15). Implemented in phase 3 (sessions, the `__Host-test-cap` cookie, timeouts, rotation, sign-out,
session list and remote revoke), phase 5 (the federation transaction cookie for OIDC) and phase 8 (its SameSite=None
form for SAML's POST binding).

Answers [handoff question](../../GLOSSARY.md) 6 (sessions).

Planned tests:

- `test/sessions/token-entropy-and-hashing.test.ts` (256-bit tokens from the `RandomSource`; the store holds only the
  SHA-256);
- `test/sessions/cookie-attributes.test.ts` (`__Host-test-cap` with Secure, HttpOnly, SameSite=Lax, `Path=/`, no
  Domain);
- `test/sessions/timeouts.test.ts` (idle and absolute limits at AAL2 and AAL3, on both sides of each boundary);
- `test/sessions/rotation.test.ts` (a new token on each trigger of section 5, including the end of enrolment and of the
  recovery-only state; the old token stops working);
- `test/sessions/revocation-immediate.test.ts` (sign-out and remote revoke take effect on the next request);
- `test/sessions/session-list.test.ts` (a user sees and revokes their own sessions, never another user's);
- `test/sessions/credential-change-revokes-others.test.ts`;
- `test/sessions/tx-cookie.test.ts` (`__Host-test-cap-tx` holds only a random id, lasts 10 minutes, and its
  transaction is consumed once);
- `test/attacks/session-fixation.test.ts` (a token the client chose is never accepted);
- `test/attacks/session-cache-skips-mfa.test.ts` and `test/attacks/cached-session-survives-revocation.test.ts`;
- `test/attacks/cookie-tossing.test.ts` (a cookie set by a sibling subdomain cannot replace the session cookie);
- `test/attacks/redemption-race.test.ts` (a federation transaction cannot be completed twice).

The recommendations under Open are provisional defaults until the owner decides.

## Context

Question 6 asked for server-side sessions or signed tokens and the revocation each allows, cookie attributes,
rotation on privilege change, concurrent session limits, and device listing with remote sign-out.

Better Auth's advisories show where sessions fail: a second factor bypassed through a session cache
(`xg6x-h9c9-2m83`), revoked sessions that stayed valid through secondary storage or a cookie cache (`fvxx-76fc-893x`),
and a forged multi-session cookie that revoked arbitrary sessions (`wmjr-v86c-m9jj`). Each one is a session whose
state lived somewhere other than the one authoritative record.

NIST SP 800-63B-4 sets the timeouts: at AAL2 the overall limit SHOULD be at most 24 hours and inactivity at most 1
hour (§2.2.3); at AAL3 the overall limit SHALL be at most 12 hours and inactivity SHOULD be at most 15 minutes
(§2.3.3).

## Decision

### 1. Sessions are server-side, with opaque tokens stored as hashes

A session is a record in the store. The client holds a 256-bit token drawn from the injected `RandomSource` (ADR
0003); the store holds only its SHA-256. Each request looks the session up by the hash of the presented token. The
token carries no data.

Why: a server-side record can be revoked at once, and an opaque token cannot be forged or read. Storing only the hash
means a copy of the database holds no usable token. A 256-bit random token needs no slow hash: it cannot be guessed.

### 2. The session cookie is `__Host-test-cap`

Attributes: `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain`. Its value is the token and nothing else.

Why: the `__Host-` prefix requires `Secure`, `Path=/` and no `Domain`, so a sibling subdomain cannot set or overwrite
it (cookie tossing). `HttpOnly` and `SameSite=Lax` are test-cap's choices beyond what the prefix requires: script
cannot read the token, and the cookie is not sent on a cross-site POST, which backs the CSRF checks of ADR 0011.

### 3. Federation round trips use the `__Host-test-cap-tx` cookie

A federation transaction is a single-use, server-side record holding the `state`, nonce, PKCE S256 verifier and, for
SAML, `InResponseTo`. The browser is bound to it by `__Host-test-cap-tx`, which holds only a random id, lasts 10
minutes, and is consumed with `consumeOnce` (ADR 0002) when the response returns.

For SAML's POST binding the cookie is `SameSite=None`, because a cookie set with an explicit `SameSite=Lax` is not sent
on a cross-site POST. That is the only place test-cap sets `SameSite=None`. OIDC uses `response_mode=query`, a
top-level GET, which a Lax cookie survives; see Open for which attributes it uses.

Why: binding the round trip to a server record, not to values in the cookie, means a stolen or replayed `state` is
useless once consumed, and an OAuth `state` can never double as another kind of token (ADR 0001, `965c-763c-88jm`).
Keeping the relaxed SameSite on a separate, short-lived cookie that holds no session means it never weakens the
session cookie.

### 4. Timeouts follow the session's assurance

| Session assurance | Idle   | Absolute |
| ----------------- | ------ | -------- |
| AAL2              | 1 h    | 24 h     |
| AAL3              | 15 min | 12 h     |

Every request checks both limits against the injected `Clock`. The cookie never outlives the absolute limit; the
server record is authoritative. A read that finds a session past either limit revokes its record, so a clock that
later jumps backwards cannot give the session the rest of its window again. The read answers `unauthenticated`
whether or not that revoke lands; a failed revoke is tried again by the next read that finds the session
(`test/failure/clock.test.ts`, finding L-1 in [dependency-failures.md](../dependency-failures.md#findings)).

Why: these are the 800-63B-4 limits quoted above. Using them as defaults means the policy report has nothing to
explain for an app that keeps them. An expiry read from the clock alone is only as final as the clock; a revoked
record stays ended whatever the clock does next.

Override: an app may shorten any limit. Lengthening one is a deviation, listed in the policy report (ADR 0005).

### 5. Tokens rotate on every change of trust

A new token is issued, and the old one revoked, on every change of trust:

- sign-in;
- the end of enrolment, when a pre-auth session becomes authenticated;
- the end of the recovery-only state (under ADR 0007 Open 5 that state ends the session instead, which also leaves no
  recovery-only token carrying later trust);
- step-up;
- a credential change (section 7);
- a privilege change;
- the start and the end of impersonation or break-glass (ADR 0014).

A token the client presents that the store did not issue is never adopted.

Why: rotation is the defence against session fixation. A token known before a change of trust must not carry the
trust gained after it.

### 6. Nothing skips revocation or the assurance check

`auth.session(req)` returns a `SessionInfo` or `null`. Every `auth.session`, `auth.require` and dispatcher request
reads the session from the store and recomputes its
assurance (ADR 0005). There is no cookie cache, no signed session snapshot and no in-process cache that answers in its
place. Revocation is visible on the next request because the store guarantees it (ADR 0002).

Why: every session advisory cited above came from a cache that answered for the store. One store read per request is
the price.

### 7. People can see and end their sessions

A user can list their own sessions and revoke any of them (`<Sessions/>`, flow F14). Signing out revokes the server
record and clears the cookie. A credential change (as the glossary defines it) rotates this session and revokes the
account's other sessions, in one `transaction` where the store offers it (ADR 0002).

Why: remote sign-out is how a person recovers from a lost device without an administrator. Revoking other sessions on
a credential change is how a person who changed their password because of a compromise actually removes the attacker.

## Consequences

- Every authenticated request costs one store read, and an authoritative answer.
- Revocation, step-up and decay all act on the next request, with no expiry window to wait out.
- A database dump yields no session tokens.
- Apps on several subdomains cannot share the session cookie; each origin signs in on its own.

## Limits

- **Session timeouts below AAL2 are not set.** The default requirement is AAL2, but a deviation can allow AAL1
  sessions, and the pre-auth and recovery states need limits too. See Open.
- **No concurrent session limit.** The plan sets none; see Open.
- **The session list shows what is recorded.** Recording IP address and user agent is opt-in,
  so without it the list shows times, methods and assurance only.
- **Privilege changes test-cap cannot see.** test-cap sees changes to assurance, credentials and impersonation. A role
  change made in access-cap or the app reaches test-cap only if the app says so; see Open.
- **Token theft from the device.** An attacker who reads the cookie from a compromised device holds the session until
  it expires or is revoked. test-cap does not bind sessions to a device key.

## Open

1. **Which cookie binds an OIDC transaction.** The plan says `__Host-test-cap-tx` "exists only for SAML's POST
   binding", yet lists OIDC's `state`, nonce and PKCE among what it binds, and the glossary defines it for "one OIDC or
   SAML round trip". Recommendation: one name, `__Host-test-cap-tx`, for both protocols; `SameSite=Lax` for OIDC and
   `SameSite=None` only on a SAML transaction. The plan's "exists only for SAML's POST binding" then reads as "the
   relaxed SameSite exists only for it".
2. **Timeouts for AAL1, pre-auth and recovery-only sessions.** Recommendation: an AAL1 session (only possible through a
   deviation) keeps AAL2's limits; pre-auth and recovery-only sessions last 15 minutes idle and 1 hour absolute.
3. **Concurrent session limits.** Recommendation: none by default; an optional per-account cap that revokes the
   oldest session when exceeded, with a security event.
4. **Privilege changes made outside test-cap.** Recommendation: an `auth.rotate(req)` call the app (or access-cap's
   integration) makes after a role change, so the rotation trigger "privilege change" has an entry point.
5. **Grace period after rotation.** Recommendation: none. The old token stops working at once, and a client with
   parallel requests in flight retries once with the new cookie.
