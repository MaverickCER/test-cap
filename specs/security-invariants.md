# Security invariants

A security invariant is a property test-cap keeps whatever framework, adapter, store or provider sits around it. This
file is the registry: each invariant's property, the core function that enforces it, the attacks it stops, the
threat-model flows those attacks belong to, the tests that prove it holds and fails when broken, the source files
whose cold mutation shows those tests bite, and what it does not cover. [ADR 0029](decisions/0029-security-invariants-failure-policies-and-evidence-traceability.md)
makes this file a governing spec. Terms follow the [glossary](../GLOSSARY.md).

Each invariant closes one chain:

```text
attack (attack-catalogue.md) → threat (threat-model.md flow) → invariant (here) → enforcement point (src/)
  → test (positive and negative) → assertion (the named test) → evidence (cold mutation of the enforcement files)
```

This is an internal design document. It records what is enforced and tested, under the conditions the tests set up.
It is not a pen test and makes no compliance claim.

## How a docs test enforces this file

`test/docs/security-invariants.test.ts` reads every invariant below and fails when any of these is false:

- **Ids are stable and unique.** Each id is `INV-` and upper-case words. An id is never renamed or reused. The index
  table and the sections name the same ids, once each.
- **Status is honest.** Status is `tested`, `partial (phase N)` or `planned (phase N)`. `tested` means every part of
  the property phase 3 promises is enforced and tested; `partial` means the part this phase builds is, and phase N
  builds the rest; `planned` means nothing is built yet. A `tested` invariant names at least one `tested` attack. A
  `planned` invariant names only `planned` attacks. The phase of a `partial` or `planned` invariant is the latest
  phase among its `planned` attacks.
- **Every attack traces both ways.** Each attack id exists in the catalogue. Each catalogue row's Invariant cell
  names exactly the invariants that list it, every `tested` row names at least one, and a `not applicable` row names
  none. Each attack is cited by at least one of the invariant's flows in the threat model, and each listed flow cites
  at least one of its attacks.
- **Enforcement is in the core and exists.** A `tested` or `partial` invariant names enforcement points as
  `` `src/<file>.ts` `<export>` ``. Each file exists outside `src/adapters/`, and the module exports that name. The
  prose after the export says which step inside it enforces the property.
- **Tests exist and say what is named.** A `tested` or `partial` invariant names at least one positive and one
  negative test as `` `test/<file>.test.ts`: "<test name>" ``. Each file exists and contains that name exactly.
- **Mutation evidence covers enforcement.** Every enforcement file is listed under mutation evidence, and every
  listed file exists.

A phase that changes an invariant changes its section, its catalogue rows and its tests in the same pull request.

## Index

| Id                          | Status            | Property                                                                      |
| --------------------------- | ----------------- | ----------------------------------------------------------------------------- |
| `INV-AUTH-BYPASS`           | tested            | No adapter path reaches a protected route or an auth route without the core   |
| `INV-SESSION-IDENTITY`      | tested            | Only an issued token names a session, and no client input changes it          |
| `INV-ASSURANCE-EVIDENCE`    | tested            | Assurance rises only with new evidence from a ceremony bound to this session  |
| `INV-REVOCATION`            | tested            | A revoked session is refused on the next request, and a failed revoke says so |
| `INV-EXPIRY`                | tested            | Nothing is accepted at or after its expiry, measured on the server's clock    |
| `INV-RECOVERY-NO-ELEVATION` | partial (phase 4) | Recovery never raises assurance                                               |
| `INV-SUBJECT-KINDS`         | partial (phase 8) | People, services and agents stay distinct subjects                            |
| `INV-FAIL-CLOSED`           | tested            | A failing dependency never yields `allow`, a session or a higher level        |
| `INV-ORIGIN`                | tested            | Every origin and absolute URL comes from `APP_ORIGIN`                         |
| `INV-ONE-TIME-SECRETS`      | tested            | A one-time secret works once, for its own purpose, account and address        |
| `INV-SECRETS-AT-REST`       | tested            | No reply carries a secret, and nothing stored is usable as it stands          |
| `INV-PASSWORD-INTEGRITY`    | tested            | A password is screened when set and verified whole                            |
| `INV-NO-ENUMERATION`        | tested            | Replies and timing do not say whether an account exists                       |
| `INV-BROWSER-BOUNDARY`      | tested            | Another site cannot drive, frame or cache an auth route                       |
| `INV-BOUNDED-WORK`          | tested            | No request makes test-cap do unbounded work or send unbounded mail            |
| `INV-STRICT-DEFAULTS`       | tested            | A deployment that is not explicitly development or test starts only when safe |
| `INV-IDENTIFIER-PROOF`      | tested            | Only a proven identifier finds an account                                     |
| `INV-DELEGATION-CEILING`    | planned (phase 8) | A delegation never exceeds what its issuing session could do                  |
| `INV-IMPERSONATION`         | planned (phase 8) | Impersonation needs explicit authorization and leaves a trace on every event  |
| `INV-BREAK-GLASS`           | planned (phase 8) | Break-glass cannot skip its own authorization, time limit or review           |

## Invariants

### INV-AUTH-BYPASS: no adapter path skips the core

- **Status:** tested
- **Property:** Every request an adapter sees is decided by the core: a path under `/auth/` goes to the dispatcher,
  whose checks run in one order for every route, and any other path passes only when it is public or its session
  meets the default requirement. The core reads the raw path, refuses an ambiguous one, and reads the body bytes
  itself under each route's declared fields. An adapter converts bytes and has no branch of its own that could allow
  a request.
- **Enforcement:** `src/core/auth.ts` `createAuth` (its `gate`, which every adapter's deny by default calls),
  `src/core/dispatcher.ts` `createDispatcher` (its `dispatch` and `checkPost`), `src/transport/path.ts`
  `matchAuthPath`, `src/core/public-paths.ts` `compilePublicPaths`, `src/transport/body.ts` `parseBody`
- **Attacks:** `deny-by-default-bypass`, `double-slash-path-bypass`, `adapter-core-parsing-differential`,
  `upstream-body-parser-changes-core-view`, `next-proxy-treated-as-protection`, `mass-assignment-server-owned-fields`
- **Flows:** F01, F22
- **Positive tests:**
  - `test/adapters/express.test.ts`: "runs sign-up to an AAL2 session, then opens a protected route with req.auth set"
  - `test/adapters/public-paths.test.ts`: "matches an exact entry only, so / is the root and nothing else"
- **Negative tests:**
  - `test/attacks/deny-by-default-bypass.test.ts`: "lets only the listed public paths through"
  - `test/attacks/double-slash-path-bypass.test.ts`: "refuses %s with a 400, reaching neither a route nor a ceremony"
  - `test/attacks/adapter-core-parsing-differential.test.ts`: "hands the core the same method, path, header values and body bytes through every adapter"
  - `test/attacks/upstream-body-parser-changes-core-view.test.ts`: "refuses a middleware that sets req.body without reading the stream, never trusting it"
  - `test/attacks/next-proxy-treated-as-protection.test.ts`: "a forged session cookie passes the proxy, and the server helper refuses it"
  - `test/attacks/mass-assignment-server-owned-fields.test.ts`: "refuses the same in a form body"
- **Mutation evidence:** `src/core/auth.ts`, `src/core/dispatcher.ts`, `src/transport/path.ts`,
  `src/core/public-paths.ts`, `src/transport/body.ts`
- **Limitations:** A route the app mounts before the adapter, or outside the framework middleware's reach, is never
  seen and so never protected. The app's public list is configuration test-cap cannot judge. The Next.js `proxy` is
  for early redirects only; the server helpers are the protection. The NestJS adapter arrives in phase 4.

### INV-SESSION-IDENTITY: only an issued token names a session

- **Status:** tested
- **Property:** The account a request acts as comes only from the session record found by the SHA-256 of a token
  test-cap issued. No header, body field, session id or hash in a cookie names a session, and a cookie sent twice
  names none. A token the client presents at sign-in or sign-up is revoked, never adopted. Evidence from a step-up
  lands only on the session that opened the challenge.
- **Enforcement:** `src/sessions/sessions.ts` `createSessions` (its `load`, which reads by the token's hash, and
  `signIn`, `begin` and `stepUp`), `src/sessions/sessions.ts` `readSessionToken`, `src/transport/cookies.ts`
  `readCookie`
- **Attacks:** `forged-cookie-names-other-session`, `session-fixation`, `step-up-bound-to-other-session`,
  `cookie-tossing`, `session-rotation-race`
- **Flows:** F01, F02, F11, F12, F13, F14
- **Positive tests:**
  - `test/sessions/token-entropy-and-hashing.test.ts`: "stores the session under the SHA-256 of the token and nowhere holds the token"
  - `test/core/sign-in-and-step-up.test.ts`: "adds TOTP evidence under the session's own challenge and rotates the token"
- **Negative tests:**
  - `test/attacks/session-fixation.test.ts`: "never adopts a token the client chose"
  - `test/attacks/forged-cookie-names-other-session.test.ts`: "signs out nothing when the cookie carries another session's id or hash instead of its token"
  - `test/attacks/step-up-bound-to-other-session.test.ts`: "refuses a challenge another session asked for, and leaves it usable by its own session"
  - `test/sessions/cookie-attributes.test.ts`: "reads the token by its exact name, and reads nothing when the name arrives twice"
- **Mutation evidence:** `src/sessions/sessions.ts`, `src/transport/cookies.ts`
- **Limitations:** A token copied off the person's device is a valid bearer token: sessions are not bound to a
  device key (threat model, "What test-cap does not defend against"). The `cookie-tossing` and
  `session-rotation-race` attack tests arrive in phase 4.

### INV-ASSURANCE-EVIDENCE: assurance rises only with new evidence

- **Status:** tested
- **Property:** A session's level is computed on every read from the evidence still valid; nothing stores a level.
  Evidence enters a session only from a ceremony that succeeded in the same request: sign-in, the end of enrolment, or
  a step-up through a challenge this session opened. Email confirmation, an unconfirmed TOTP secret, a failed
  ceremony and a repeated one add nothing. A pre-auth session answers `enroll`, never `allow`, whatever it holds.
- **Enforcement:** `src/assurance/policy.ts` `defineAuthPolicy` (its `assurance` and `require`),
  `src/assurance/levels.ts` `levelOf`, `src/sessions/sessions.ts` `createSessions` (its `stepUp` and
  `completeEnrolment`), `src/methods/totp/method.ts` `verifyTotp`
- **Attacks:** `session-cache-skips-mfa`, `assurance-downgrade`, `totp-unconfirmed-enrolment-counts`,
  `alternate-path-skips-second-factor`, `email-raises-assurance`
- **Flows:** F02, F03, F04, F06, F08, F09, F10, F13, F14, F15, F16
- **Positive tests:**
  - `test/policy/require-outcomes.test.ts`: "allows a session that meets the requirement, with its subject and assurance"
  - `test/core/sign-in-and-step-up.test.ts`: "raises a password session to AAL2 and rotates its token"
- **Negative tests:**
  - `test/attacks/session-cache-skips-mfa.test.ts`: "keeps answering step-up for a password-only session however often it is read"
  - `test/attacks/session-cache-skips-mfa.test.ts`: "answers enroll, not allow, for a session that has not finished enrolling MFA"
  - `test/attacks/assurance-downgrade.test.ts`: "keeps step-up when the step-up itself uses a weaker method"
  - `test/attacks/totp-unconfirmed-enrolment-counts.test.ts`: "produces no evidence from an unconfirmed secret, even with a correct code"
  - `test/assurance/email-never-raises.test.ts`: "leaves every level unchanged when the email deviation is on"
  - `test/policy/types.test.ts`: "hold no stored level outside the assurance computed from evidence"
  - `test/core/email-confirmation.test.ts`: "answers enroll to every requirement after sign-up, after the confirmation and after the password"
- **Mutation evidence:** `src/assurance/policy.ts`, `src/assurance/levels.ts`, `src/sessions/sessions.ts`,
  `src/methods/totp/method.ts`
- **Limitations:** Phase 3 produces password and TOTP evidence only; the passkey and federation mappings arrive in
  phase 5. The levels map to NIST SP 800-63B-4 and are computed only from evidence the server holds; they are not a
  certification. `alternate-path-skips-second-factor` is tested in phase 4 and `email-raises-assurance` in phase 5.

### INV-REVOCATION: a revoked session is refused at once

- **Status:** tested
- **Property:** Once a revocation resolves (sign-out, a remote revoke, `auth.admin.revoke`, or the old token of a
  rotation), the next request with that token is refused: every request reads the session record from the store, and
  there is no cache. A revocation that fails is answered as a failure, never as done. A credential change rotates the
  session and revokes the account's other sessions; when that rotation fails or finds its session gone, every
  session of the account is revoked instead (finding F-1 in
  [dependency-failures.md](dependency-failures.md#findings)).
- **Enforcement:** `src/sessions/sessions.ts` `createSessions` (its `load`, `signOut`, `revoke` and
  `credentialChanged`), `src/core/dispatcher.ts` `createDispatcher` (its `revokeAll` and `afterCredentialChange`),
  `src/store/memory.ts` `memoryStore` (its `revoke` and `revokeByOwner`), `src/store/sql.ts` `sqlStore`
- **Attacks:** `cached-session-survives-revocation`, `sign-out-leaves-session-valid`, `session-fixation`,
  `sessions-survive-credential-change`, `bulk-revoke-race-misses-session`, `deleted-account-sessions-survive`
- **Flows:** F01, F02, F03, F05, F09, F14, F19
- **Positive tests:**
  - `test/sessions/revocation-immediate.test.ts`: "answers unauthenticated on the request after sign-out, remote revoke or a store revoke"
  - `test/sessions/rotation.test.ts`: "rotates on a credential change and revokes the account's other sessions, not another account's"
- **Negative tests:**
  - `test/attacks/cached-session-survives-revocation.test.ts`: "refuses a revoked session on the very next request, after it had just been allowed"
  - `test/attacks/cached-session-survives-revocation.test.ts`: "lets a revoked token mint nothing: no rotation, step-up, credential change, list or revoke"
  - `test/attacks/sign-out-leaves-session-valid.test.ts`: "revokes the session in the store and clears the cookie"
  - `test/failure/store.test.ts`: "never answers a sign-out whose revoke failed as signed out, and a retry revokes"
  - `test/failure/store.test.ts`: "leaves no session of the account standing when the rotation finds its session already claimed"
- **Mutation evidence:** `src/sessions/sessions.ts`, `src/core/dispatcher.ts`, `src/store/memory.ts`,
  `src/store/sql.ts`
- **Limitations:** Revoke-all under concurrent writes, deprovision and the credential-change attack test arrive in
  phase 4. The SQL store's revocation under real database concurrency is phase 6's persistence work (success metric
  15). When the store fails the credential change's rotation and then its fallback revoke too, the other sessions
  stay until an operator revokes them (F-1, residual).

### INV-EXPIRY: nothing is accepted after it expires

- **Status:** tested
- **Property:** No session, piece of evidence, step-up challenge, email code, unconfirmed TOTP enrolment or
  synchronizer token is accepted at or after its expiry. Every expiry is measured on the injected server clock;
  nothing in a request supplies the time. A read that finds a session past its idle or absolute limit revokes it, so
  a clock that later jumps backwards cannot revive it.
- **Enforcement:** `src/assurance/policy.ts` `defineAuthPolicy` (its `assurance`, which applies the idle and
  absolute limits and drops expired evidence), `src/sessions/sessions.ts` `createSessions` (its `read`, which revokes
  a session found expired), `src/store/memory.ts` `memoryStore` (its `consumeOnce`, which honours
  `expiresAt`), `src/security/csrf.ts` `createCsrfTokens` (its `verify`), `src/methods/totp/totp.ts` `findStep`,
  `src/methods/totp/method.ts` `confirmTotpEnrolment`
- **Attacks:** `session-timeout-not-enforced`, `expired-evidence-keeps-level`, `totp-client-supplied-time`
- **Flows:** F04, F13, F14
- **Positive tests:**
  - `test/core/email-confirmation.test.ts`: "refuses a code at the end of its 24 hours, and takes it a moment before"
  - `test/security/csrf.test.ts`: "expires after an hour, to the millisecond"
- **Negative tests:**
  - `test/attacks/session-timeout-not-enforced.test.ts`: "ends an AAL2 session after an hour idle, not a millisecond sooner"
  - `test/attacks/session-timeout-not-enforced.test.ts`: "ends an AAL2 session 24 hours after sign-in however active it is"
  - `test/attacks/expired-evidence-keeps-level.test.ts`: "lowers the level once the second factor's evidence expires, with no stored level to keep it"
  - `test/attacks/totp-client-supplied-time.test.ts`: "ignores any time field in the input and checks against the server clock"
  - `test/attacks/step-up-bound-to-other-session.test.ts`: "uses each challenge once, and never after 10 minutes"
  - `test/failure/clock.test.ts`: "ends the session at once when the jump passes its idle limit"
  - `test/failure/clock.test.ts`: "revokes a session a read finds past its $limit limit, so a jump back cannot revive it (L-1, fixed)"
- **Mutation evidence:** `src/assurance/policy.ts`, `src/sessions/sessions.ts`, `src/store/memory.ts`,
  `src/security/csrf.ts`, `src/methods/totp/totp.ts`, `src/methods/totp/method.ts`, `src/core/email.ts`
- **Limitations:** A clock that jumps backwards still revives a session that expired unread, since no read found it
  expired, and one whose every revoke failed ([dependency-failures.md](dependency-failures.md#the-clock), L-1).
  The SQL store's `consumeOnce` honours `expiresAt` as the conformance kit checks; its behaviour on a real database
  under load is phase 6's. No startup check refuses an expired key.

### INV-RECOVERY-NO-ELEVATION: recovery never raises assurance

- **Status:** partial (phase 4)
- **Property:** A recovery-only session holds no assurance: it answers `recovery-only` to every requirement whatever
  evidence it carries, a recovery code gives no level, and the session is revoked when recovery finishes, so its token
  carries no later trust. Phase 3 builds the state, its outcome and its end. Redeeming a saved recovery code (F07)
  arrives in phase 4, and email recovery (F09) in phase 5; until then no route starts a recovery-only session.
- **Enforcement:** `src/assurance/policy.ts` `defineAuthPolicy` (its `require`, which answers `recovery-only` before
  reading any level), `src/assurance/levels.ts` `levelOf` (no level for a recovery code), `src/sessions/sessions.ts`
  `createSessions` (its `begin` and `endRecovery`)
- **Attacks:** `recovery-below-account-level`, `outstanding-codes-survive-recovery`, `session-fixation`
- **Flows:** F01, F02, F07, F09, F14
- **Positive tests:**
  - `test/sessions/rotation.test.ts`: "starts a pre-auth or recovery-only session with no evidence unless given, and no step-ups"
- **Negative tests:**
  - `test/policy/require-outcomes.test.ts`: "answers enroll for a pre-auth session and recovery-only for a recovering one, whatever it holds"
  - `test/assurance/email-never-raises.test.ts`: "gives a recovery code no level: it moves a session to recovery-only, never to assurance (ADR 0007)"
  - `test/attacks/session-fixation.test.ts`: "stops a recovery-only token working once recovery ends"
  - `test/sessions/rotation.test.ts`: "ends the recovery-only session when recovery finishes, so its token carries no later trust"
  - `test/core/sign-in-and-step-up.test.ts`: "needs a signed-in session, and a good returnTo"
- **Mutation evidence:** `src/assurance/policy.ts`, `src/assurance/levels.ts`, `src/sessions/sessions.ts`
- **Limitations:** The recovery flows themselves, and the attack tests that a recovery yields no more than the
  account's proven evidence, arrive in phases 4 and 5. A compromised mailbox reaches the recovery-only state by
  design (threat model O6).

### INV-SUBJECT-KINDS: people, services and agents stay distinct

- **Status:** partial (phase 8)
- **Property:** A person (`user`), a service using an API key (`service`) and an agent acting through a delegation
  (`agent`) are different subjects. A service or agent never carries a person's session assurance, and a requirement
  written for people is never met by either. Phase 3 has people only: every session belongs to a `user`, `require`
  answers only for sessions, and every event names its subject's kind. The type separation is `EventSubject.kind`
  (`"user" | "service" | "agent"`) on events, with no kind on `SessionState` because only people hold sessions. API
  keys (F15) and delegations (F16) arrive in phase 8, in `src/machine/` and `src/delegation/` (ADR 0013).
- **Enforcement:** `src/ocsf/events.ts` `authenticationEvent` (it records `subject_kind`), `src/core/dispatcher.ts`
  `createDispatcher` (every event it reports names a `user`), `src/sessions/sessions.ts` `createSessions` (sessions
  only for people)
- **Attacks:** `service-subject-satisfies-human-requirement`, `delegation-borrows-human-assurance`
- **Flows:** F15, F16
- **Positive tests:**
  - `test/ocsf/events.test.ts`: "names service and agent subjects"
- **Negative tests:**
  - `test/events/subject-kind.test.ts`: "names a user as the subject of every event sign-up, enrolment, sign-in, step-up and sign-out report"
- **Mutation evidence:** `src/ocsf/events.ts`, `src/core/dispatcher.ts`, `src/sessions/sessions.ts`
- **Limitations:** Until phase 8 nothing issues a `service` or `agent` subject, so the property is held by absence;
  the tests that a service or agent cannot meet a person's requirement arrive with them.

### INV-FAIL-CLOSED: a failing dependency opens nothing

- **Status:** tested
- **Property:** An error from a dependency (the store, the random source, a library, the app's mail sender, HIBP or
  the event sink) never yields `allow`, a session or a higher level. A route that throws answers the fixed 500 with no
  detail; deny by default answers the fixed 500; `auth.require` and `auth.session` reject. Dependencies whose failure
  must not change an outcome (mail and events) are handed their work without waiting, and an HIBP failure is
  `indeterminate`, never `clear`. [dependency-failures.md](dependency-failures.md) gives each dependency's policy.
- **Enforcement:** `src/core/dispatcher.ts` `failure` and `createDispatcher` (its `handle`), `src/core/auth.ts`
  `createAuth` (its `gate`), `src/methods/password/hibp.ts` `screenWithHibp`, `src/ocsf/events.ts` `deliver`
- **Attacks:** `fail-open-on-error`, `breach-check-outage-counts-as-pass`, `secret-in-response`
- **Flows:** F01, F14, F21, F22
- **Positive tests:**
  - `test/failure/store.test.ts`: "%s calls exactly the documented store operations"
- **Negative tests:**
  - `test/attacks/fail-open-on-error.test.ts`: "rejects, never allows, when the store fails to read or to record activity"
  - `test/failure/store.test.ts`: "$name: a rejected $op (call $call) answers 500 and grants nothing"
  - `test/failure/store.test.ts`: "$name: a $op that fails by $mode answers 500 and grants nothing"
  - `test/attacks/secret-in-response.test.ts`: "answers a store failure with a bare 500 that carries none of the error"
  - `test/adapters/next-surfaces.test.ts`: "lets a store failure reach the caller as an error, never as allow"
  - `test/failure/random.test.ts`: "that throws: sign-in answers 500 and hands out no token"
- **Mutation evidence:** `src/core/dispatcher.ts`, `src/core/auth.ts`, `src/methods/password/hibp.ts`,
  `src/ocsf/events.ts`, `src/core/email.ts`
- **Limitations:** An app that calls `auth.require` must treat a rejection as a refusal; every supported framework
  turns an unhandled rejection into a 500. A store call that never settles holds its request open: test-cap sets no
  timeout of its own, and the app's driver timeout bounds it. F-1's residual is in
  [dependency-failures.md](dependency-failures.md#findings). One store write is allowed to fail without ending the
  request: the revoke of a session found expired, whose read answers `unauthenticated` either way.

### INV-ORIGIN: every origin comes from configuration

- **Status:** tested
- **Property:** Every absolute URL test-cap builds and every origin it compares comes from `APP_ORIGIN`, checked at
  startup. The `Host` header and the request URL never choose one. A `returnTo` navigates only to a same-origin
  relative path, checked after URL parsing.
- **Enforcement:** `src/security/redirect.ts` `safeReturnTo`, `src/security/csrf.ts` `sameOrigin`,
  `src/core/mode.ts` `originProblem`, `src/core/email.ts` `sendConfirmation` (its link)
- **Attacks:** `host-header-poisoning`, `open-redirect-protocol-relative`, `open-redirect-origin-prefix`,
  `open-redirect-scheme`, `email-link-redirect`
- **Flows:** F02, F08, F09, F12, F21, F22
- **Positive tests:**
  - `test/attacks/open-redirect-protocol-relative.test.ts`: "redirects to a same-origin path as given"
- **Negative tests:**
  - `test/attacks/host-header-poisoning.test.ts`: "builds the confirmation email's link on APP_ORIGIN, whatever Host and URL the sign-up came with"
  - `test/attacks/open-redirect-origin-prefix.test.ts`: "compares Origin exactly, so a prefix origin cannot post"
  - `test/attacks/open-redirect-scheme.test.ts`: "refuses returnTo %j on every route that takes one"
  - `test/attacks/email-link-redirect.test.ts`: "links only to the confirmation page, whatever returnTo the sign-up asked for"
  - `test/security/csrf.test.ts`: "never reads Host"
- **Mutation evidence:** `src/security/redirect.ts`, `src/security/csrf.ts`, `src/core/mode.ts`, `src/core/email.ts`
- **Limitations:** The app's own links and redirects are the app's. A wrong `APP_ORIGIN` is refused only when it is
  malformed or not https where https is required.

### INV-ONE-TIME-SECRETS: a one-time secret works once, for its own purpose

- **Status:** tested
- **Property:** A one-time secret is accepted at most once, and only for the purpose, account and address it was
  issued to. A TOTP time step is accepted once per authenticator, through a
  compare-and-set on the last step. An email code is redeemed once through `consumeOnce`, keyed by an HMAC over its
  purpose, account, address and code, and only within its attempt limit: every attempt counts with the atomic
  `increment` before the code is checked, over the code's whole life, so the count refuses a sixth attempt even when
  the write that kills the code failed. A step-up challenge is consumed once, only by the session that opened it.
- **Enforcement:** `src/methods/totp/method.ts` `verifyTotp`, `src/core/email.ts` `redeemConfirmation`,
  `src/sessions/sessions.ts` `createSessions` (its `stepUp`), `src/store/memory.ts` `memoryStore` (its
  `consumeOnce` and `increment`)
- **Attacks:** `totp-code-replay`, `email-code-brute-force`, `step-up-bound-to-other-session`,
  `one-time-secret-cross-purpose`, `otp-attempt-limit-race`, `totp-brute-force`
- **Flows:** F04, F07, F08, F09, F10, F13
- **Positive tests:**
  - `test/core/email-confirmation.test.ts`: "confirms the address: the account now resolves by it, an Update event says so, and nothing else changes"
- **Negative tests:**
  - `test/attacks/totp-code-replay.test.ts`: "refuses the same code a second time within its step"
  - `test/attacks/totp-code-replay.test.ts`: "lets exactly one of many concurrent requests with the same code succeed"
  - `test/attacks/email-code-brute-force.test.ts`: "counts parallel guesses one by one, so a burst checks no more codes than the limit"
  - `test/core/email-confirmation.test.ts`: "is single use"
  - `test/failure/store.test.ts`: "refuses the right code for the rest of the code's life, even though the kill write failed"
  - `test/core/email-confirmation.test.ts`: "refuses a code issued to another account, even for the same address"
  - `test/attacks/step-up-bound-to-other-session.test.ts`: "uses each challenge once, and never after 10 minutes"
- **Mutation evidence:** `src/methods/totp/method.ts`, `src/core/email.ts`, `src/sessions/sessions.ts`,
  `src/store/memory.ts`
- **Limitations:** TOTP throttles and the race and
  cross-purpose attack tests arrive in phase 4; the SQL store under real concurrency in phase 6.

### INV-SECRETS-AT-REST: no secret leaves, and nothing stored is usable as it stands

- **Status:** tested
- **Property:** No reply carries a key, a configuration value or a submitted secret, and an error answers a fixed
  body. Nothing the store holds can be used as it stands: session tokens are stored as their SHA-256, email codes as
  an HMAC key under `AUTH_ENCRYPTION_KEY`, TOTP seeds sealed with AES-GCM under a key held outside the store and bound
  to their tenant, account, authenticator and key id, and passwords as argon2id hashes.
- **Enforcement:** `src/methods/totp/secret-box.ts` `sealSecret` and `openSecret`, `src/sessions/sessions.ts`
  `createSessions` (it stores only the token's hash), `src/core/email.ts` `sendConfirmation` (it stores only the
  HMAC key), `src/security/headers.ts` `errorResponse`, `src/core/dispatcher.ts` `failure`
- **Attacks:** `secret-in-response`, `totp-secret-read-at-rest`, `totp-key-rotation-confusion`,
  `secret-in-security-event`, `weak-secret-generation`
- **Flows:** F02, F03, F04, F07, F08, F09, F14, F20, F21, F22
- **Positive tests:**
  - `test/crypto/key-rotation.test.ts`: "opens a secret sealed under an older key while that key stays in the ring"
- **Negative tests:**
  - `test/attacks/secret-in-response.test.ts`: "never puts a key, the configuration or a submitted secret in any reply"
  - `test/attacks/totp-secret-read-at-rest.test.ts`: "stores no form of the seed a dump could read"
  - `test/attacks/totp-secret-read-at-rest.test.ts`: "cannot be opened without the key, or with another key under the same id"
  - `test/attacks/totp-key-rotation-confusion.test.ts`: "refuses a ciphertext swapped in from another account's row"
  - `test/sessions/token-entropy-and-hashing.test.ts`: "stores the session under the SHA-256 of the token and nowhere holds the token"
  - `test/core/email-confirmation.test.ts`: "stores only a keyed hash of the code, for 24 hours (email-code-storage.test.ts checks the key)"
- **Mutation evidence:** `src/methods/totp/secret-box.ts`, `src/sessions/sessions.ts`, `src/core/email.ts`,
  `src/security/headers.ts`, `src/core/dispatcher.ts`
- **Limitations:** Anyone holding the database and `AUTH_ENCRYPTION_KEY` holds every seed (threat model, attacker
  with database write and keys). The `secret-in-security-event` and `weak-secret-generation` rows are still
  `planned`: their attack tests are not written yet.

### INV-PASSWORD-INTEGRITY: a password is screened when set and verified whole

- **Status:** tested
- **Property:** A password is normalised once to NFC and hashed whole with argon2id at a fixed cost: never
  truncated, trimmed or case-folded, and refused over 256 characters. A new password must pass the length rule and
  the bundled blocklist, and the HIBP range check when HIBP answers. An HIBP outage is recorded `indeterminate`,
  never `clear`.
- **Enforcement:** `src/methods/password/method.ts` `setPassword` and `signInWithPassword`,
  `src/methods/password/rules.ts` `normalisePassword` and `isBlocklisted`, `src/methods/password/hibp.ts`
  `screenWithHibp`
- **Attacks:** `breached-password-accepted`, `breach-check-outage-counts-as-pass`, `password-altered-before-hashing`
- **Flows:** F01, F02, F09
- **Positive tests:**
  - `test/attacks/password-altered-before-hashing.test.ts`: "verifies a password that differs only in normalisation form, and no other variant"
- **Negative tests:**
  - `test/attacks/breached-password-accepted.test.ts`: "refuses a password the breach corpus lists, and stores nothing"
  - `test/attacks/breach-check-outage-counts-as-pass.test.ts`: "records indeterminate, never clear, when HIBP cannot be reached or fails"
  - `test/attacks/password-altered-before-hashing.test.ts`: "refuses over 256 characters rather than truncating them"
  - `test/failure/hibp.test.ts`: "still refuses a bundled common password while HIBP is down"
- **Mutation evidence:** `src/methods/password/method.ts`, `src/methods/password/rules.ts`,
  `src/methods/password/hibp.ts`, `src/methods/password/blocklist.ts`, `src/methods/password/argon2.ts`
- **Limitations:** The HIBP range check sends a 5-character hash prefix to a third party. A password stored while
  HIBP was down is accepted with `indeterminate` screening; the policy report that lists such passwords arrives in
  phase 8.

### INV-NO-ENUMERATION: replies do not reveal accounts

- **Status:** tested
- **Property:** Sign-up and sign-in give one reply, byte for byte, whether or not the account exists, is confirmed,
  has a password or is disabled, and a failed sign-in takes the same argon2id work whenever no stored hash is
  verified.
- **Enforcement:** `src/core/dispatcher.ts` `createDispatcher` (its `sign-up` and `sign-in` routes),
  `src/methods/password/method.ts` `signInWithPassword` (its dummy verify)
- **Attacks:** `user-enumeration-responses`, `user-enumeration-timing`
- **Flows:** F01, F02, F09, F21
- **Positive tests:**
  - `test/core/sign-in-and-step-up.test.ts`: "issues an AAL1 session that the default requirement still steps up"
- **Negative tests:**
  - `test/attacks/user-enumeration-responses.test.ts`: "gives sign-in one reply, byte for byte, for every way the account can be missing or wrong"
  - `test/attacks/user-enumeration-responses.test.ts`: "gives sign-up one reply for a new address and one an account already holds"
  - `test/attacks/user-enumeration-timing.test.ts`: "takes as long to refuse a missing account, or one with no password, as a wrong password"
- **Mutation evidence:** `src/core/dispatcher.ts`, `src/methods/password/method.ts`, `src/methods/password/argon2.ts`
- **Limitations:** Timing is measured on the test machine, within the tolerance its test states. Throttles, whose
  replies must also stay uniform, arrive in phase 4.

### INV-BROWSER-BOUNDARY: another site cannot drive, frame or cache an auth route

- **Status:** tested
- **Property:** A state-changing auth route runs only for a request from `APP_ORIGIN` carrying a synchronizer token
  bound to this browser's own session or pre-session. Every auth reply forbids framing and shared caching, and every
  cookie test-cap sets is `__Host-`, Secure and HttpOnly.
- **Enforcement:** `src/core/dispatcher.ts` `createDispatcher` (its `checkPost`), `src/security/csrf.ts`
  `createCsrfTokens` and `sameOrigin`, `src/security/headers.ts` `jsonResponse` and `errorResponse`,
  `src/transport/cookies.ts` `serializeCookie`
- **Attacks:** `csrf-state-changing-route`, `login-csrf`, `clickjacking`, `auth-response-cached`, `https-downgrade`
- **Flows:** F02, F11, F14, F21, F22
- **Positive tests:**
  - `test/attacks/login-csrf.test.ts`: "signs in a browser whose own form carries its own token"
  - `test/core/dispatcher-pipeline.test.ts`: "accepts the token in the header with Origin, or in the body with Sec-Fetch-Site"
- **Negative tests:**
  - `test/attacks/csrf-state-changing-route.test.ts`: "leaves the victim signed in after a forged sign-out"
  - `test/attacks/csrf-state-changing-route.test.ts`: "refuses a token bound to another session of the same account"
  - `test/attacks/login-csrf.test.ts`: "refuses a cross-site sign-in post, even carrying a token the attacker fetched for themselves"
  - `test/attacks/clickjacking.test.ts`: "forbids framing on every reply, with the rest of the strict policy"
  - `test/attacks/auth-response-cached.test.ts`: "marks every reply no-store: successes, refusals, errors and deny by default"
  - `test/attacks/https-downgrade.test.ts`: "marks every cookie Secure, whatever its other attributes"
- **Mutation evidence:** `src/core/dispatcher.ts`, `src/security/csrf.ts`, `src/security/headers.ts`,
  `src/transport/cookies.ts`
- **Limitations:** CSRF and XSS in the app's own routes are the app's and secure-cap's (ADR 0011).

### INV-BOUNDED-WORK: no request makes unbounded work

- **Status:** tested
- **Property:** A body is capped before it is parsed, with depth and field limits. argon2id runs at a fixed cost,
  behind a semaphore with a bounded queue, on at most 256 characters. Confirmation mail is counted per address and
  per IP address or IPv6 /64 before it is sent. An account holds at most 5 confirmed TOTP authenticators and one
  pending enrolment, and a session keeps only the newest evidence of each authenticator.
- **Enforcement:** `src/transport/body.ts` `readBody`, `parseForm` and `parseJsonObject`,
  `src/methods/password/semaphore.ts` `createSemaphore`, `src/methods/password/argon2.ts` `createHasher`,
  `src/core/email.ts` `sendConfirmation`, `src/methods/totp/method.ts` `totpEnrolmentAllowed`
- **Attacks:** `request-parser-resource-exhaustion`, `argon2-cost-exhaustion`, `email-send-flooding`,
  `totp-authenticator-flood`
- **Flows:** F01, F02, F03, F04, F08, F09, F10, F22
- **Positive tests:**
  - `test/transport/body.test.ts`: "accepts a body exactly at the limit and refuses one byte more"
- **Negative tests:**
  - `test/attacks/request-parser-resource-exhaustion.test.ts`: "refuses an oversized body before parsing it"
  - `test/attacks/argon2-cost-exhaustion.test.ts`: "runs at most 4 hashes at once and refuses what the queue cannot hold"
  - `test/attacks/email-send-flooding.test.ts`: "sends at most 20 an hour from one IP address, across addresses"
  - `test/attacks/totp-authenticator-flood.test.ts`: "answers a sixth enrolment, by the API or the page, with 409 too-many-authenticators"
  - `test/sessions/evidence-bound.test.ts`: "is at most one TOTP entry per authenticator after 1,000 verifies"
- **Mutation evidence:** `src/transport/body.ts`, `src/methods/password/semaphore.ts`,
  `src/methods/password/argon2.ts`, `src/core/email.ts`, `src/methods/totp/method.ts`, `src/sessions/sessions.ts`
- **Limitations:** Volumetric denial of service is out of scope (threat model). Sign-in throttles arrive in phase 4.

### INV-STRICT-DEFAULTS: only a safe deployment starts

- **Status:** tested
- **Property:** A missing, empty or unknown `APP_ENV` runs as production. Production and staging refuse to start
  without an https `APP_ORIGIN`, a durable store, both keys (neither a published example) and the system clock and
  Web Crypto random source.
- **Enforcement:** `src/core/mode.ts` `checkReadiness` and `resolveDeploymentMode`, `src/core/auth.ts` `createAuth`
- **Attacks:** `production-runs-with-dev-defaults`, `missing-or-default-secret`, `https-downgrade`
- **Flows:** F14, F22
- **Positive tests:**
  - `test/core/create-auth.test.ts`: "starts in production with an https origin, a durable store and both keys"
- **Negative tests:**
  - `test/attacks/production-runs-with-dev-defaults.test.ts`: "refuses the development setup once the mode falls back to production"
  - `test/attacks/missing-or-default-secret.test.ts`: "refuses a missing key in production at both layers"
  - `test/attacks/https-downgrade.test.ts`: "refuses to start production or staging on an http origin, loopback included"
  - `test/core/create-auth.test.ts`: "accepts a custom clock and random source only in test mode"
- **Mutation evidence:** `src/core/mode.ts`, `src/core/auth.ts`
- **Limitations:** An expired key is not refused at startup. A developer can still relax the policy; the policy
  lists every deviation (ADR 0005 §6).

### INV-IDENTIFIER-PROOF: only a proven identifier finds an account

- **Status:** tested
- **Property:** Only an identifier whose emailed code was redeemed resolves to an account, and it resolves to one
  account per tenant. An unconfirmed sign-up holds no claim on the address and never leaves the pre-auth state.
  Confirmation proves control of a mailbox and adds no evidence.
- **Enforcement:** `src/core/accounts.ts` `resolveConfirmed`, `claimIdentifier` and `createAccount`,
  `src/core/email.ts` `redeemConfirmation`, `src/core/identifier.ts` `normaliseEmail`
- **Attacks:** `pre-account-hijack`, `unverified-identifier-trusted`, `identifier-normalisation-collision`,
  `concurrent-enrolment-collision`
- **Flows:** F01, F05, F08, F09, F11
- **Positive tests:**
  - `test/attacks/unverified-identifier-trusted.test.ts`: "resolves the address only once its code is redeemed"
- **Negative tests:**
  - `test/attacks/pre-account-hijack.test.ts`: "gives the attacker's unconfirmed sign-up no claim, no password and no way past enrolment"
  - `test/attacks/pre-account-hijack.test.ts`: "does not let the victim's code confirm the attacker's account"
  - `test/attacks/unverified-identifier-trusted.test.ts`: "gives an account holding only an unconfirmed address and a valid password the unknown-account reply"
  - `test/core/accounts.test.ts`: "makes no uniqueness claim: two sign-ups with one address are two accounts, and neither resolves"
- **Mutation evidence:** `src/core/accounts.ts`, `src/core/email.ts`, `src/core/identifier.ts`
- **Limitations:** A compromised mailbox confirms the address (threat model). The normalisation-collision and
  concurrent-enrolment attack tests arrive in phase 4.

### INV-DELEGATION-CEILING: a delegation never exceeds its issuer

- **Status:** planned (phase 8)
- **Property:** A delegation carries at most the scopes its issuing session granted, never the person's session
  assurance, and cannot issue a further delegation. It ends at its expiry, at revocation and when its person is
  deprovisioned, and only its issuing person can approve, change or revoke it.
- **Enforcement:** planned in `src/delegation/` (ADR 0013 §4, §5)
- **Attacks:** `delegation-scope-escalation`, `delegation-borrows-human-assurance`, `delegation-outlives-grant`,
  `idor-delegation`, `delegation-consent-confusion`
- **Flows:** F16, F19
- **Limitations:** Nothing is built yet.

### INV-IMPERSONATION: impersonation is authorized and traced

- **Status:** planned (phase 8)
- **Property:** Impersonation starts only from a fresh AAL2 or higher admin session with a reason and a time limit,
  ends at that limit, never carries into a new session, blocks credential changes, and is flagged on every event it
  causes.
- **Enforcement:** planned in `src/admin/` (ADR 0014)
- **Attacks:** `impersonation-without-fresh-admin-session`, `impersonation-exceeds-grant`,
  `impersonation-changes-credentials`, `privileged-session-unflagged-in-events`
- **Flows:** F17, F18
- **Limitations:** Nothing is built yet. Phase 3's session rotation already runs on the start and end of
  impersonation (`test/sessions/rotation.test.ts`), but nothing starts one.

### INV-BREAK-GLASS: break-glass keeps its own authorization and review

- **Status:** planned (phase 8)
- **Property:** Break-glass access needs a reason, ends at its time limit, blocks credential changes, is flagged on
  every event it causes and is listed for review. It works outside the normal requirements, never outside its own.
- **Enforcement:** planned in `src/admin/` (ADR 0014)
- **Attacks:** `break-glass-exceeds-grant`, `privileged-session-unflagged-in-events`,
  `impersonation-changes-credentials`
- **Flows:** F17, F18
- **Limitations:** Nothing is built yet.
