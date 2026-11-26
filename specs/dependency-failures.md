# Dependency failure policies

test-cap relies on things it does not control: the app's store, its mail sender, the HIBP breach API, the clock, the
random source, the key material, the app's event sink, a proxy in front of the app, and the counter of each limit. A
failure policy says what happens when one of them fails: what fails, whether test-cap fails closed or runs in a narrow
degraded mode, what stops working, what a reply may reveal, how service comes back, what an operator sees, and what the
events record. [ADR 0029](decisions/0029-security-invariants-failure-policies-and-evidence-traceability.md) makes this
file a governing spec; [security-invariants.md](security-invariants.md) holds the invariants these policies protect,
chiefly `INV-FAIL-CLOSED`. Terms follow the [glossary](../GLOSSARY.md). This file does not yet cover the app's
`challengeHook`, a `Throttle` or `StuffingDetector` the app supplies, or the argon2id fallback. Its store flows leave
out recovery-code redemption and deprovisioning.

The rule under every policy: **a failing dependency never produces an authentication, a higher level or a silent
downgrade.** Fail closed is the default. A degraded mode is allowed only where the dependency cannot change an
outcome (mail and events), or where the degradation is recorded on the result (HIBP's `indeterminate`).

The failure-injection tests under `test/failure/` prove each policy with the memory store and injected faults. They
cover phase 3's flows: password sign-in, sign-up, email confirmation, TOTP enrolment and verification, step-up, the
session read, sign-out and revocation, and phase 4's request limiter (`test/failure/rate-limit.test.ts`). Persistence under real SQL concurrency, transaction failure and restarts is
phase 6's work (success metric 15): it runs these guarantees against the supported SQL stores on real databases, and
until then the SQL store is held to the conformance kit (`test/store/conformance.test.ts`) and the PGlite runs in
`test/store/sql/sql-store.test.ts`.

This is an internal design document. It records tested behaviour under the conditions the tests set up; it is not
an availability promise.

## How a docs test enforces this file

`test/docs/security-invariants.test.ts` fails when any of these is false:

- Every dependency section below states all eight parts: expected failures, policy, what is unavailable while it
  fails, what is safe to expose, recovery, operator diagnostics, audit and events, and tests. The policy starts with
  "Fail closed." or "Degraded.".
- Every test a section names exists and contains that test name, and every file under `test/failure/` is named here.
- The store's call table equals the flows `test/failure/store.test.ts` runs, call for call.

## Summary

| Dependency                    | Policy                                  | Unavailable while it fails                                                   |
| ----------------------------- | --------------------------------------- | ---------------------------------------------------------------------------- |
| The store (SQL and memory)    | Fail closed                             | Everything that reads or writes a session, an account or a credential        |
| Email delivery                | Degraded: the reply never waits on mail | Receiving a confirmation code, so confirming an address                      |
| HIBP                          | Degraded and recorded `indeterminate`   | Breach screening of new passwords; the bundled blocklist still runs          |
| The clock                     | Fail closed                             | Sessions, codes, tokens and challenges, early, when the clock jumps forwards |
| The random source             | Fail closed                             | Every flow that issues a token, code, secret or id                           |
| Key material                  | Fail closed                             | TOTP seeds, email codes and CSRF tokens made under a key no longer held      |
| The event sink                | Degraded: outcomes never wait on events | The app's copy of the events while the sink fails                            |
| A proxy in front of the app   | Fail closed                             | State-changing requests whose `Origin` and `Sec-Fetch-Site` were stripped    |
| The request limiter's counter | Fail closed                             | Every request to `/auth`, pages and assets included                          |

## The store (SQL and memory)

- **Expected failures:** a refused or dropped connection, a statement timeout, a deadlock or serialization error, a
  pool that is exhausted, a disk that is full, a driver call that throws before it returns a promise, a call that never
  settles, and a store that answers `conflict`, `exists`, `false` or `null` because another request won a race.
- **Policy:** Fail closed. Every store call is awaited, so an error at any point of a flow ends the request: a route
  answers the fixed `500 {"error":"internal"}` with no session cookie, deny by default answers the same 500, and
  `auth.require` and `auth.session` reject. A store that answers "no" (a conflict, a used challenge, a taken key) is
  read as a refusal. Multi-step session changes run in the store's transaction when it has one; without one, the old
  session is claimed before the new one is written, so a failure between steps never leaves the old token and a new
  one both working. A credential change whose rotation fails revokes every session of the account (finding F-1, fixed).
  Two writes are allowed to fail without ending the request. One is the revoke of a session a read found past its
  limit: that read answers `unauthenticated` either way, and the next read that finds the session tries the revoke
  again (L-1). The other marks a refusal's event as emitted (ADR 0009 §8): the refusal stands, and the event is
  emitted, so a store failure can only repeat an event.
- **Unavailable while it fails:** sign-up, email confirmation, password setting, sign-in, TOTP enrolment and
  verification, step-up, the session read, the session list, sign-out, remote revoke and `auth.admin.revoke`, and every
  route behind deny by default. Public paths still pass.
- **Safe to expose:** the fixed 500 body `{"error":"internal"}`, the same for every cause. The driver's error, the
  query, the record and the configuration never reach the reply (`secret-in-response`).
- **Recovery:** none needed inside test-cap: it holds no state between requests, so the first request after the store
  returns works. A person repeats the action: a sign-out or revoke answered 500 did not happen, and a retry does it. A
  TOTP code consumed by a request that failed later is spent; the next code works. An email code consumed by a request
  that failed later is spent; a resend issues a new one.
- **Operator diagnostics:** test-cap does not log. The app's driver or store wrapper sees and logs the error; the
  app's monitoring sees the rate of 500s on `/auth/*` and on protected routes. A request that hangs is bounded only by
  the driver's own timeout, which the app sets.
- **Audit and events:** a request that fails before its outcome emits no success event, and every event reports
  only what was stored: a Logon success is emitted only after its session was written. One event can precede a
  failure: a TOTP confirmation's Enable MFA Factors is reported once the authenticator is stored, before the session
  rotates, so a 500 can follow it; the authenticator is then stored, and after F-1 no session of the account stands.
- **Tests:**
  - `test/failure/store.test.ts`: "%s calls exactly the documented store operations"
  - `test/failure/store.test.ts`: "$name: a rejected $op (call $call) answers 500 and grants nothing"
  - `test/failure/store.test.ts`: "$name without store transactions: a rejected $op (call $call) answers 500 and grants nothing"
  - `test/failure/store.test.ts`: "$name: a $op that fails by $mode answers 500 and grants nothing"
  - `test/failure/store.test.ts`: "$name: a $op that never answers leaves the request pending, with nothing issued"
  - `test/failure/store.test.ts`: "rejects auth.require and auth.session, never answering, when %s fails"
  - `test/failure/store.test.ts`: "answers deny by default with the fixed 500, never letting the request through, when %s fails"
  - `test/failure/store.test.ts`: "refuses the step-up when the challenge's single use reports it already taken"
  - `test/failure/store.test.ts`: "never answers a sign-out whose revoke failed as signed out, and a retry revokes"
  - `test/failure/store.test.ts`: "rejects auth.admin.revoke when the store fails, and revokes on a retry"
  - `test/failure/store.test.ts`: "leaves no session of the account standing once the authenticator is confirmed and $op (call $call) fails, transactions: $transactional"
  - `test/failure/store.test.ts`: "refuses the right code for the rest of the code's life, even though the kill write failed"
  - `test/failure/store.test.ts`: "gives the old code no fresh guesses when a resend fails to revoke it, and a resend that works starts a new count"
  - `test/abuse/refusal-events.test.ts`: "still emit, and the refusal still stands, when the store cannot record that one was sent"

### Store calls per flow

The failure tests inject a fault into every call below, one at a time: a rejection at every call, with and without
store transactions for the three flows whose session change takes several steps, and a synchronous throw, a timeout
and a call that never settles at the first call of each operation. A flow that starts calling something else fails
its test until this table and its failure cases grow. Since phase 4 every session lookup also reads the account's
status (a `get`), and every guessed secret goes through the throttle: its blocks are read (`get`), each attempt is
counted on the account's keys (`increment`), and a success clears them (`resetCounter`, `delete`), as does the
authenticator's failure ceiling. Every request to `/auth` starts with the request limiter's `increment`, so a flow of
two requests, such as step-up's start and its ceremony, has two.

| Flow                                  | Store calls, in order                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| password sign-in                      | `increment`, `get`, `get`, `get`, `get`, `get`, `get`, `increment`, `increment`, `get`, `get`, `resetCounter`, `delete`, `resetCounter`, `delete`, `resetCounter`, `delete`, `resetCounter`, `delete`, `resetCounter`, `delete`, `listByOwner`, `revoke`, `createUnique`, `get`                                                                                                                                                            |
| email confirmation                    | `increment`, `get`, `get`, `update`, `listByOwner`, `listByOwner`, `increment`, `consumeOnce`, `createUnique`                                                                                                                                                                                                                                                                                                                              |
| TOTP verification                     | `increment`, `get`, `get`, `update`, `get`, `listByOwner`, `get`, `get`, `get`, `increment`, `increment`, `listByOwner`, `get`, `update`, `resetCounter`, `delete`, `resetCounter`, `delete`, `resetCounter`, `delete`, `resetCounter`, `delete`, `resetCounter`, `delete`, `get`, `get`, `createUnique`, `get`, `get`, `get`, `consumeOnce`, `get`, `get`, `update`, `createUnique`, `revoke`                                             |
| step-up                               | `increment`, `get`, `get`, `update`, `get`, `get`, `createUnique`, `increment`, `get`, `get`, `update`, `get`, `get`, `listByOwner`, `get`, `get`, `get`, `increment`, `increment`, `listByOwner`, `get`, `update`, `resetCounter`, `delete`, `resetCounter`, `delete`, `resetCounter`, `delete`, `resetCounter`, `delete`, `resetCounter`, `delete`, `get`, `get`, `get`, `consumeOnce`, `get`, `get`, `update`, `createUnique`, `revoke` |
| session read                          | `increment`, `get`, `get`, `update`                                                                                                                                                                                                                                                                                                                                                                                                        |
| password sign-in with rehash          | `increment`, `get`, `get`, `get`, `get`, `get`, `get`, `increment`, `increment`, `get`, `get`, `resetCounter`, `delete`, `update`, `resetCounter`, `delete`, `resetCounter`, `delete`, `resetCounter`, `delete`, `resetCounter`, `delete`, `listByOwner`, `createUnique`, `get`                                                                                                                                                            |
| sign-up                               | `increment`, `createUnique`, `createUnique`, `increment`, `increment`, `increment`, `revokeByOwner`, `resetCounter`, `delete`, `createUnique`, `createUnique`                                                                                                                                                                                                                                                                              |
| TOTP enrolment by a signed-in account | `increment`, `get`, `get`, `update`, `get`, `get`, `update`, `get`, `get`, `update`, `createUnique`, `revoke`, `revokeByOwner`                                                                                                                                                                                                                                                                                                             |
| sign-out                              | `increment`, `get`, `get`, `update`, `revoke`                                                                                                                                                                                                                                                                                                                                                                                              |

## Email delivery

- **Expected failures:** the app's `sendEmail` throws, rejects, never settles, or resolves while the provider later
  drops or bounces the message.
- **Policy:** Degraded. test-cap hands the message to `sendEmail` without waiting and ignores its result, so a mail
  outage changes no reply, no status and no timing. Nothing is confirmed without the code, and email adds no evidence, so an outage cannot raise anything.
- **Unavailable while it fails:** the person receives no confirmation code, so the address cannot be confirmed and
  the account stays in the pre-auth state.
- **Safe to expose:** nothing about delivery: the sign-up and resend replies are the same whether the mail went out
  or not. The resend reply's `retryAfterMs` is the send limit's wait, not a delivery status.
- **Recovery:** once the sender works again, a resend (one a minute, five an hour per address) mails a new code with
  a new attempt count, and the old one stops working. A send the sender lost still counts against the send limits, so an outage cannot be
  used to flood an inbox later.
- **Operator diagnostics:** the app's `sendEmail` sees every failure; test-cap neither logs nor reports it, so the
  app logs its own sender's errors and its provider's bounces.
- **Audit and events:** sign-up emits its User Management Create whatever the mail does; no event reports a send or
  a lost send.
- **Tests:**
  - `test/failure/email.test.ts`: "that %s: sign-up still answers at once and the session stays enrolling"
  - `test/failure/email.test.ts`: "that %s: a resend still answers at once with the wait, and confirms nothing"
  - `test/failure/email.test.ts`: "recovers by a resend once the sender works again, and the new code confirms the address"
  - `test/failure/email.test.ts`: "counts a send the sender lost against the send limits, so an outage cannot be used to flood later"

## HIBP

- **Expected failures:** the API is unreachable, answers an error status or a rate limit, answers a body that is not
  a range, or answers after the 1.5-second timeout.
- **Policy:** Degraded. A new password is still checked for length and against the bundled blocklist, and is stored
  with the screening `indeterminate`, never `clear` (ADR 0010 §3). An answer later than 1.5 seconds is abandoned and
  its request aborted. Sign-in never calls HIBP, so an outage changes no sign-in.
- **Unavailable while it fails:** breach screening of passwords set during the outage.
- **Safe to expose:** nothing: setting a password answers the same whether HIBP answered or not. A refusal names
  only `too-common` or `breached`, and `breached` only when HIBP answered.
- **Recovery:** automatic for new passwords. A password stored as `indeterminate` stays so; the policy report that
  lists such passwords, so the app can ask for a change, arrives in phase 8.
- **Operator diagnostics:** the screening result is stored on each password record (`indeterminate`). The app's
  `hibpFetch` sees each failure and can log it.
- **Audit and events:** the Enable MFA Factors event for the password is emitted as usual; the screening result is
  on the record, not in the event.
- **Tests:**
  - `test/failure/hibp.test.ts`: "that %s: the password is stored as indeterminate, never clear, and the session stays enrolling"
  - `test/failure/hibp.test.ts`: "still refuses a bundled common password while HIBP is down"
  - `test/failure/hibp.test.ts`: "is never called by sign-in, so an outage changes no sign-in"
  - `test/methods/password-hibp-unreachable.test.ts`: "is indeterminate when the request does not answer within the timeout, and aborts it"

## The clock

- **Expected failures:** outside test mode the clock is the system clock, since `createAuth` refuses a custom one
  (ADR 0026 §4), so its failure is a jump: forwards, or backwards after an NTP correction or a restored snapshot.
- **Policy:** Fail closed. A forward jump ends sessions at their idle and absolute limits, and expires synchronizer
  tokens, step-up challenges and codes early; the TOTP code the person's app shows no longer matches. A backward jump
  makes every piece of evidence dated after the new time count for nothing, so a session answers `unauthenticated`,
  and refuses every TOTP code at or before the last accepted step. A read that finds a session past its idle or
  absolute limit revokes it in the store, so a later backward jump cannot give it the rest of its window again (L-1,
  fixed). If that revoke fails, the read still answers `unauthenticated` and the next read tries again. Two cases stay
  open: a session no request presented between its expiry and the backward jump was never found expired, so it is not
  revoked; and a session whose every revoke failed before the jump is revived like it.
- **Unavailable while it fails:** after a forward jump, every session, code, token and challenge older than its
  limit by the new time; after a backward jump, every session whose evidence is in the new future, and TOTP until the
  clock passes the last accepted step.
- **Safe to expose:** the ordinary replies: `unauthenticated`, `invalid-code`, `csrf`, `invalid-challenge`. Nothing
  names the clock.
- **Recovery:** correct the clock. Sessions ended by a forward jump and then read are revoked, so they stay ended
  when the clock is corrected, and the person signs in again. An operator who must end the sessions in the two open
  cases revokes them with `auth.admin.revoke`.
- **Operator diagnostics:** a burst of `unauthenticated`, `invalid-code` and `csrf` replies across all accounts at
  once. Every event carries its time from the same clock, so events show the jump.
- **Audit and events:** event times follow the clock, jumps included.
- **Tests:**
  - `test/failure/clock.test.ts`: "counts evidence dated after the new time for nothing, so an AAL2 session answers unauthenticated"
  - `test/failure/clock.test.ts`: "refuses the code of every TOTP step at or before the last one accepted"
  - `test/failure/clock.test.ts`: "revokes a session a read finds past its $limit limit, so a jump back cannot revive it (L-1, fixed)"
  - `test/failure/clock.test.ts`: "answers unauthenticated when the revoke of a session found expired fails by %s, and the next read revokes it"
  - `test/failure/clock.test.ts`: "ends the session at once when the jump passes its idle limit"
  - `test/failure/clock.test.ts`: "refuses the code the person's app shows for the real time"
  - `test/failure/clock.test.ts`: "expires the synchronizer token, so a state-changing request is refused"
  - `test/failure/clock.test.ts`: "expires a step-up challenge past its 10 minutes, adding no evidence"

## The random source

- **Expected failures:** outside test mode the source is Web Crypto, since `createAuth` refuses a custom one
  (ADR 0026 §4), so its failures are an exception from `getRandomValues` or a platform that repeats its output.
- **Policy:** Fail closed. A source that throws ends the request with the fixed 500. A source that repeats makes a
  new token collide with a stored one; `createUnique` reports the collision and the request ends with the fixed 500,
  so the token is never handed out and no browser gets another's session. A digit draw that keeps rejecting bytes
  gives up after 64 rounds instead of looping.
- **Unavailable while it fails:** every flow that issues a session token, session id, code, challenge, TOTP secret,
  IV, salt, account id or CSRF pre-session value.
- **Safe to expose:** the fixed 500 body.
- **Recovery:** none inside test-cap; the next request after the platform recovers works.
- **Operator diagnostics:** the rate of 500s on `/auth/*`; the thrown error names "the random source is broken" for a
  collision, but stays inside the process.
- **Audit and events:** no success event is emitted for a request that failed before its session was written.
- **Tests:**
  - `test/failure/random.test.ts`: "that throws: sign-in answers 500 and hands out no token"
  - `test/failure/random.test.ts`: "that repeats itself: the sign-in whose token collides answers 500, and the first session stays its own"
  - `test/failure/random.test.ts`: "that only yields bytes the digit draw rejects: sign-up answers 500, sends nothing and issues no session"
  - `test/sentinel/create-auth.test.ts`: "accepts a custom clock and random source only in test mode"

## Key material

- **Expected failures:** a key id removed from `AUTH_ENCRYPTION_KEY` or `AUTH_CSRF_KEY` before everything under it
  was re-sealed or expired, a key id whose bytes were replaced, a ring in the wrong order, and, outside production and
  staging, a restart that generates a new key because none is configured. A malformed, short, repeated or published
  example key is refused at startup (`INV-STRICT-DEFAULTS`).
- **Policy:** Fail closed. A TOTP seed under a key the ring no longer holds, or under other bytes with the same id,
  does not open, and its code is refused as a wrong one. An email code keyed under such a key does not redeem. A
  synchronizer token signed under such a key is refused as `csrf`.
- **Unavailable while it fails:** TOTP for every authenticator sealed under the missing key, so those accounts cannot
  reach AAL2 with it; confirmation codes issued under it; the synchronizer tokens browsers hold (they fetch new ones
  from `GET /auth/session`).
- **Safe to expose:** only the ordinary refusals: `invalid-code` and `csrf`. Nothing names a key id.
- **Recovery:** put the old key back in the ring after the new one. A TOTP verification under the ring re-seals the
  seed under the current key, after which the old key can leave; a TOTP authenticator that never verifies again keeps
  needing it. An account whose seed's key is gone needs recovery, which arrives in phase 4 (saved codes) and phase 5
  (email).
- **Operator diagnostics:** a rise in `invalid-code` from accounts whose authenticator records name the removed key
  id (each sealed seed stores its key id). test-cap reports no key error, because a missing key and a wrong code must
  look the same from outside.
- **Audit and events:** the failed verification emits its ordinary failed Logon; no event names a key.
- **Tests:**
  - `test/failure/keys.test.ts`: "is refused as a wrong code when %s, adding no evidence"
  - `test/failure/keys.test.ts`: "opens again once the old key is back after the new one, and is then sealed under the new one"
  - `test/failure/keys.test.ts`: "with %s, answers %s"
  - `test/failure/keys.test.ts`: "refuses every seed and code sealed before a restart, since the restart generates another"
  - `test/security/csrf.test.ts`: "keeps verifying under a previous key still in the ring, and stops once it is removed"

## The event sink

- **Expected failures:** the app's `onEvent` throws, rejects, never settles, or loses events downstream.
- **Policy:** Degraded. test-cap hands every event to the sink without waiting, and a sink error is caught, so a
  failing sink changes no outcome, no status and no timing (ADR 0015 §3). The event is lost to the app; the
  authentication decision is not affected either way.
- **Unavailable while it fails:** the app's copy of the security events. The opt-in audit trail, with its own
  sequence and gap detection, arrives in phase 8 (ADR 0020).
- **Safe to expose:** nothing: replies do not depend on the sink.
- **Recovery:** events emitted during the outage are not replayed. The audit trail of phase 8 is the record that
  detects such gaps.
- **Operator diagnostics:** the app's sink sees its own errors; a gap in the event stream is the sign.
- **Audit and events:** this dependency is the event path; until phase 8 there is no second record.
- **Tests:**
  - `test/failure/events.test.ts`: "that %s: the second factor still answers at once with the level it proved"
  - `test/failure/events.test.ts`: "that %s: a wrong code is still refused"
  - `test/sentinel/create-auth.test.ts`: "keeps the outcome when the event sink throws"

## A proxy in front of the app

- **Expected failures:** a load balancer, CDN or gateway the app did not declare sends every request from its own
  address; a declared one stops setting its forwarding header, or sets one the app did not name; a proxy strips
  `Origin` and `Sec-Fetch-Site`, or rewrites `Origin` to `null`, so a browser's state-changing request carries
  neither; a gateway strips a path prefix the app did not set as `publicBasePath`.
- **Policy:** Fail closed. The client address is the socket's peer unless the app declared the peer a proxy (ADR
  0009 §5), so an undeclared proxy makes every client behind it one client to the throttle: guessing is slowed more,
  never less. A state-changing request with no site `Origin` and no `Sec-Fetch-Site: same-origin` is refused with
  `403 csrf`; `Origin: null` passes only with `Sec-Fetch-Site: same-origin`. Links, redirects and email URLs are built
  from `APP_ORIGIN` and `publicBasePath`, never from the request, so a missing prefix sends people to pages the gateway
  does not serve, and no header can redirect them elsewhere.
- **Unavailable while it fails:** with an undeclared proxy, clients behind it share one throttle key, so one client's
  failures slow the others. With stripped origin headers, sign-in, sign-up, sign-out and every other `POST` under
  `/auth/`. With a missing `publicBasePath`, the default pages' links and redirects.
- **Safe to expose:** the refusal is the fixed `403 {"error":"csrf"}`; the throttle's reply is the usual `429` with
  `Retry-After`. Neither names the proxy, the header or the address test-cap used.
- **Recovery:** the operator declares the proxy (`trustedProxies`: addresses, CIDR ranges or a `platform()` preset),
  makes the proxy pass `Origin` and `Sec-Fetch-Site` through unchanged, or sets `publicBasePath`. `createAuth` reads
  these once, so the change takes effect when the app starts again.
- **Operator diagnostics:** the `onDiagnostic` hook is told once per `Auth`: `forwarded-header-ignored` names the
  header and the peer when a forwarding header arrives from a peer that is not a declared proxy, and
  `origin-unverifiable` says a state-changing request carried neither header. The app decides whether to log them.
- **Audit and events:** a refused request emits the route's failure event with the detail `csrf`. A throttled attempt
  emits the usual failed event with the detail `rate-limited`.
- **Tests:**
  - `test/topology/urls-and-csrf.test.ts`: "refuses Origin null with no Sec-Fetch-Site, and tells the operator once"
  - `test/topology/urls-and-csrf.test.ts`: "passes Origin null when Sec-Fetch-Site says same-origin, as a no-referrer page sends it"
  - `test/topology/client-address.test.ts`: "an untrusted peer's header is ignored"
  - `test/topology/configuration.test.ts`: "name the header and the peer"
  - `test/topology/configuration.test.ts`: "follow the proxy list createAuth read, so a later change to the list waits for a restart"
  - `test/topology/urls-and-csrf.test.ts`: "redirects a form post, and links its email, under the prefix and APP_ORIGIN"

## The request limiter's counter

- **Expected failures:** the store's `increment` throws, rejects, times out or never settles when the default
  limiter counts a request; a rate-limiter-flexible limiter of the app's rejects with an error, times out or never
  settles; a rule function the app wrote throws or
  returns something that is not a rule.
- **Policy:** Fail closed. The count is the first store call of every request to `/auth`, and it is awaited, so a
  count that throws or rejects ends the request with the fixed `500 {"error":"internal"}` before its route runs: no
  account, session, mail or event comes of it. A count that never settles leaves the request pending, with nothing done,
  until the store's driver or the app's limiter times it out; test-cap sets no timeout of its own. Failing open would let a client flood sign-up for as long as the store, or the app's limiter,
  stayed down.
- **Unavailable while it fails:** every request to `/auth`, the default pages and their assets included, even those
  that touch no other store call. With the store down, those routes could not sign anyone in anyway.
- **Safe to expose:** the fixed 500 body, the same for every cause; nothing names the limiter, the key or the rule.
- **Recovery:** none needed inside test-cap: the next request after the counter works again is counted and answered.
- **Operator diagnostics:** the app's store wrapper or its own limiter sees the error; the app's monitoring sees
  the rate of 500s on `/auth/*`.
- **Audit and events:** a request that fails at its count emits no event, as it never reached its route.
- **Tests:**
  - `test/failure/rate-limit.test.ts`: "ends sign-up with the fixed 500 before an account exists when the store's increment fails"
  - `test/failure/rate-limit.test.ts`: "ends a request, and a page, with the fixed 500 when the app's limiter fails"
  - `test/failure/rate-limit.test.ts`: "leaves a request pending, with nothing created, when the counter never answers"
  - `test/failure/rate-limit.test.ts`: "lets requests through again once the counter works"
  - `test/security/rate-limit.test.ts`: "refuses a rule function's answer that is not a rule, so a broken rule fails closed"

## Findings

The failure tests found these. Each is stated with what was observed, what changed and what remains.

| Id  | Finding                                                                                                                                                                                                                                                                                                                                           | State                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| F-1 | Fail-open. Confirming a TOTP authenticator from a signed-in session stores it, then rotates the session and revokes the account's other sessions. A store failure in the rotation, or a rotation that found the session already claimed, left the new authenticator in place and every other session of the account working, behind a 500 or 401. | Fixed: when the rotation fails or returns nothing, the dispatcher revokes every session of the account (`afterCredentialChange`, ADR 0006 §7). Pinned by the "leaves no session of the account standing" tests in `test/failure/store.test.ts`. Residual: if the store also fails that revoke, the other sessions stay until an operator calls `auth.admin.revoke`. Committing the authenticator and the rotation in one transaction would close it; that needs the TOTP method to take the transaction handle, and awaits the owner.                                             |
| F-2 | Degraded, not open. When the store failed the write that kills an email code at its fifth wrong attempt, the code stayed live. Attempts were counted per 15-minute window, so the next window allowed five more guesses on the same code while the pre-auth session lasted (one hour at most).                                                    | Fixed: attempts count per code over the code's whole life (ADR 0009 Open 1, ADR 0021 §2). The counter's window is the code's 24 hours, starting at the first attempt, so the count alone refuses a sixth attempt until the code has expired, whether or not the kill write landed. A resend resets the count only after it has revoked the codes before it, so a resend whose revoke fails leaves the old code under its old count. Pinned by "refuses the right code for the rest of the code's life" and "gives the old code no fresh guesses" in `test/failure/store.test.ts`. |
| L-1 | Limitation. A clock that jumped backwards gave an expired session the rest of its window again, because expiry was read from the clock on every request and a session found expired stayed unrevoked in the store.                                                                                                                                | Fixed: a read that finds a session past its idle or absolute limit revokes it (ADR 0006 §4). A failed revoke still answers `unauthenticated`, and the next read tries again. Pinned by the "revokes a session a read finds past its" and "answers unauthenticated when the revoke of a session found expired fails" tests in `test/failure/clock.test.ts`. Residual: a session no request presented between its expiry and the jump, or whose every revoke failed, is revived; an operator revokes it with `auth.admin.revoke`.                                                   |
