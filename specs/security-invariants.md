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
| `INV-RECOVERY-NO-ELEVATION` | partial (phase 5) | Recovery never raises assurance                                               |
| `INV-SUBJECT-KINDS`         | partial (phase 8) | People, services and agents stay distinct subjects                            |
| `INV-FAIL-CLOSED`           | tested            | A failing dependency never yields `allow`, a session or a higher level        |
| `INV-ORIGIN`                | tested            | Every origin and absolute URL comes from `APP_ORIGIN`                         |
| `INV-ONE-TIME-SECRETS`      | tested            | A one-time secret works once, for its own purpose, account and address        |
| `INV-SECRETS-AT-REST`       | tested            | No reply carries a secret, and nothing stored is usable as it stands          |
| `INV-PASSWORD-INTEGRITY`    | tested            | A password is screened when set and verified whole                            |
| `INV-NO-ENUMERATION`        | tested            | Replies and timing do not say whether an account exists                       |
| `INV-BROWSER-BOUNDARY`      | tested            | Another site cannot drive, frame or cache an auth route                       |
| `INV-BOUNDED-WORK`          | tested            | No request makes test-cap do unbounded work or send unbounded mail            |
| `INV-GUESS-THROTTLE`        | tested            | Guessing a secret is slowed and capped, and never locks the account           |
| `INV-REQUEST-LIMIT`         | tested            | Every request is counted per client before its route runs                     |
| `INV-CLIENT-ADDRESS`        | tested            | The client address comes from the socket or a proxy the app declared          |
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
  for early redirects only; the server helpers are the protection. The NestJS adapter follows phase 4.

### INV-SESSION-IDENTITY: only an issued token names a session

- **Status:** tested
- **Property:** The account a request acts as comes only from the session record found by the SHA-256 of a token
  test-cap issued, in the tenant the app configured. No header, body field, session id or hash in a cookie names a
  session, no signed value stands in for a token, and a cookie sent twice names none. A session id names another
  session only to its own account. A token the client presents at sign-in or sign-up is revoked, never adopted. Evidence from a step-up
  lands only on the session that opened the challenge.
- **Enforcement:** `src/sessions/sessions.ts` `createSessions` (its `load`, which reads by the token's hash, and
  `signIn`, `begin` and `stepUp`), `src/sessions/sessions.ts` `readSessionToken`, `src/transport/cookies.ts`
  `readCookie`
- **Attacks:** `forged-cookie-names-other-session`, `session-fixation`, `step-up-bound-to-other-session`,
  `cookie-tossing`, `session-rotation-race`, `signing-oracle-key-reuse`, `idor-session-revoke`, `cross-tenant-reference`
- **Flows:** F01, F02, F11, F12, F13, F14
- **Positive tests:**
  - `test/sessions/token-entropy-and-hashing.test.ts`: "stores the session under the SHA-256 of the token and nowhere holds the token"
  - `test/core/sign-in-and-step-up.test.ts`: "adds TOTP evidence under the session's own challenge and rotates the token"
- **Negative tests:**
  - `test/attacks/session-fixation.test.ts`: "never adopts a token the client chose"
  - `test/attacks/forged-cookie-names-other-session.test.ts`: "signs out nothing when the cookie carries another session's id or hash instead of its token"
  - `test/attacks/step-up-bound-to-other-session.test.ts`: "refuses a challenge another session asked for, and leaves it usable by its own session"
  - `test/sessions/cookie-attributes.test.ts`: "reads the token by its exact name, and reads nothing when the name arrives twice"
  - `test/attacks/cookie-tossing.test.ts`: "treats a tossed second session cookie as no session, rather than picking one"
  - `test/attacks/session-rotation-race.test.ts`: "issues exactly one new session from parallel rotations of one token"
  - `test/attacks/signing-oracle-key-reuse.test.ts`: "issues a session token that is a random reference, which no CSRF token can stand in for"
  - `test/attacks/idor-session-revoke.test.ts`: "refuses to revoke another account's session, which stays signed in"
  - `test/attacks/cross-tenant-reference.test.ts`: "does not let a session or an account of one tenant act in another tenant over the same store"
- **Mutation evidence:** `src/sessions/sessions.ts`, `src/transport/cookies.ts`
- **Limitations:** A token copied off the person's device is a valid bearer token: sessions are not bound to a
  device key (threat model, "What test-cap does not defend against").

### INV-ASSURANCE-EVIDENCE: assurance rises only with new evidence

- **Status:** tested
- **Property:** A session's level is computed on every read from the evidence still valid; nothing stores a level.
  Evidence enters a session only from a ceremony that succeeded in the same request: sign-in, the end of enrolment, or
  a step-up through a challenge this session opened. Email confirmation, an unconfirmed TOTP secret, a failed
  ceremony and a repeated one add nothing. A pre-auth session answers `enroll`, never `allow`, whatever it holds. A
  credential change needs a multi-factor ceremony in the last 15 minutes, whatever the session's level (ADR 0005 §8).
- **Enforcement:** `src/assurance/policy.ts` `defineAuthPolicy` (its `assurance` and `require`),
  `src/assurance/levels.ts` `levelOf`, `src/sessions/sessions.ts` `createSessions` (its `stepUp` and
  `completeEnrolment`), `src/methods/totp/method.ts` `verifyTotp`, `src/core/dispatcher.ts` `createDispatcher` (its
  `recentlyVerified`, before every credential change)
- **Attacks:** `session-cache-skips-mfa`, `assurance-downgrade`, `totp-unconfirmed-enrolment-counts`,
  `alternate-path-skips-second-factor`, `email-raises-assurance`, `sensitive-change-without-reauth`
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
  - `test/attacks/alternate-path-skips-second-factor.test.ts`: "gives a password-only session no session list, no recovery codes, no new authenticator and no access"
  - `test/attacks/sensitive-change-without-reauth.test.ts`: "refuses a new authenticator and new recovery codes on a session whose last multi-factor ceremony is stale"
- **Mutation evidence:** `src/assurance/policy.ts`, `src/assurance/levels.ts`, `src/sessions/sessions.ts`,
  `src/methods/totp/method.ts`, `src/core/dispatcher.ts`
- **Limitations:** Phase 3 produces password and TOTP evidence only; the passkey and federation mappings arrive in
  phase 5. The levels map to NIST SP 800-63B-4 and are computed only from evidence the server holds; they are not a
  certification. `email-raises-assurance` is tested in phase 5, with email sign-in.

### INV-REVOCATION: a revoked session is refused at once

- **Status:** tested
- **Property:** Once a revocation resolves (sign-out, a remote revoke, `auth.admin.revoke`, or the old token of a
  rotation), the next request with that token is refused: every request reads the session record from the store, and
  there is no cache. A revocation that fails is answered as a failure, never as done. A credential change rotates the
  session and revokes the account's other sessions; when that rotation fails or finds its session gone, every
  session of the account is revoked instead (finding F-1 in
  [dependency-failures.md](dependency-failures.md#findings)). A deprovisioned account is disabled before its sessions
  are revoked: every session read checks the account's status, so none of its sessions, ceremonies or recoveries
  works even while the revoke is still running.
- **Enforcement:** `src/sessions/sessions.ts` `createSessions` (its `load`, `signOut`, `revoke` and
  `credentialChanged`), `src/core/dispatcher.ts` `createDispatcher` (its `revokeAll` and `afterCredentialChange`),
  `src/store/memory.ts` `memoryStore` (its `revoke` and `revokeByOwner`), `src/store/sql.ts` `sqlStore`,
  `src/core/accounts.ts` `accountActive` and `deactivateAccount`
- **Attacks:** `cached-session-survives-revocation`, `sign-out-leaves-session-valid`, `session-fixation`,
  `sessions-survive-credential-change`, `bulk-revoke-race-misses-session`, `deleted-account-sessions-survive`,
  `deprovisioned-account-signs-in`
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
  - `test/attacks/sessions-survive-credential-change.test.ts`: "revokes every session when the account is recovered and the password replaced"
  - `test/attacks/sessions-survive-credential-change.test.ts`: "revokes a session whose sign-in checked the old password while the owner replaced it"
  - `test/attacks/bulk-revoke-race-misses-session.test.ts`: "revokes every session the account holds, in one operation"
  - `test/attacks/bulk-revoke-race-misses-session.test.ts`: "revokes a session written while the revocation is already running"
  - `test/attacks/deleted-account-sessions-survive.test.ts`: "refuses a session of a disabled account even before it is revoked"
  - `test/attacks/deprovisioned-account-signs-in.test.ts`: "refuses the right password of a deprovisioned account, with the reply any wrong one gets"
- **Mutation evidence:** `src/sessions/sessions.ts`, `src/core/dispatcher.ts`, `src/store/memory.ts`,
  `src/store/sql.ts`, `src/core/accounts.ts`
- **Limitations:** The SQL store's revocation under real database concurrency is phase 6's persistence work (success metric
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

- **Status:** partial (phase 5)
- **Property:** A recovery-only session holds no assurance: it answers `recovery-only` to every requirement whatever
  evidence it carries, a recovery code gives no level, and the session is revoked when recovery finishes, so its token
  carries no later trust. Redeeming a saved recovery code (F07, built in phase 4) starts that state, revokes the
  account's other sessions, and allows only replacing authenticators; the level comes only from signing in again.
  Email recovery (F09) arrives in phase 5.
- **Enforcement:** `src/assurance/policy.ts` `defineAuthPolicy` (its `require`, which answers `recovery-only` before
  reading any level), `src/assurance/levels.ts` `levelOf` (no level for a recovery code), `src/sessions/sessions.ts`
  `createSessions` (its `begin` and `endRecovery`), `src/core/dispatcher.ts` `createDispatcher` (its `recovery` route,
  which begins a recovery-only session and adds no evidence)
- **Attacks:** `recovery-below-account-level`, `outstanding-codes-survive-recovery`, `session-fixation`
- **Flows:** F01, F02, F07, F09, F14
- **Positive tests:**
  - `test/sessions/rotation.test.ts`: "starts a pre-auth or recovery-only session with no evidence unless given, and no step-ups"
  - `test/recovery/recovery-flow.test.ts`: "lets the session replace the password and enrol TOTP, still with no level"
- **Negative tests:**
  - `test/policy/require-outcomes.test.ts`: "answers enroll for a pre-auth session and recovery-only for a recovering one, whatever it holds"
  - `test/assurance/email-never-raises.test.ts`: "gives a recovery code no level: it moves a session to recovery-only, never to assurance (ADR 0007)"
  - `test/attacks/session-fixation.test.ts`: "stops a recovery-only token working once recovery ends"
  - `test/sessions/rotation.test.ts`: "ends the recovery-only session when recovery finishes, so its token carries no later trust"
  - `test/core/sign-in-and-step-up.test.ts`: "needs a signed-in session, and a good returnTo"
  - `test/attacks/recovery-below-account-level.test.ts`: "leaves a recovered AAL2 account's session with no level and no access to what needs one"
  - `test/recovery/recovery-flow.test.ts`: "answers recovery-only for every requirement, so the session reaches nothing protected"
- **Mutation evidence:** `src/assurance/policy.ts`, `src/assurance/levels.ts`, `src/sessions/sessions.ts`,
  `src/core/dispatcher.ts`
- **Limitations:** Email recovery, and the test that an emailed code issued before a completed recovery no longer
  works (`outstanding-codes-survive-recovery`), arrive in phase 5. A compromised mailbox reaches the recovery-only
  state by design (threat model O6).

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
  the write that kills the code failed. An app may lower the limit below 5, never raise or remove it. A step-up challenge is consumed once, only by the session that opened it. A
  saved recovery code is consumed once through `consumeOnce`, and only for the account whose row it names.
- **Enforcement:** `src/methods/totp/method.ts` `verifyTotp`, `src/core/email.ts` `redeemConfirmation`,
  `src/sessions/sessions.ts` `createSessions` (its `stepUp`), `src/store/memory.ts` `memoryStore` (its
  `consumeOnce` and `increment`), `src/methods/recovery/codes.ts` `redeemRecoveryCode`
- **Attacks:** `totp-code-replay`, `email-code-brute-force`, `step-up-bound-to-other-session`,
  `one-time-secret-cross-purpose`, `otp-attempt-limit-race`, `totp-brute-force`, `redemption-race`
- **Flows:** F04, F07, F08, F09, F10, F13
- **Positive tests:**
  - `test/core/email-confirmation.test.ts`: "confirms the address: the account now resolves by it, an Update event says so, and nothing else changes"
- **Negative tests:**
  - `test/abuse/mail-and-stuffing-options.test.ts`: "can be neither raised above 5 nor turned off, and says why"
  - `test/attacks/totp-code-replay.test.ts`: "refuses the same code a second time within its step"
  - `test/attacks/totp-code-replay.test.ts`: "lets exactly one of many concurrent requests with the same code succeed"
  - `test/attacks/email-code-brute-force.test.ts`: "counts parallel guesses one by one, so a burst checks no more codes than the limit"
  - `test/core/email-confirmation.test.ts`: "is single use"
  - `test/failure/store.test.ts`: "refuses the right code for the rest of the code's life, even though the kill write failed"
  - `test/core/email-confirmation.test.ts`: "refuses a code issued to another account, even for the same address"
  - `test/attacks/step-up-bound-to-other-session.test.ts`: "uses each challenge once, and never after 10 minutes"
  - `test/attacks/redemption-race.test.ts`: "lets exactly one of twenty parallel redemptions of one code succeed"
  - `test/attacks/one-time-secret-cross-purpose.test.ts`: "refuses one account's recovery code for another account, and as a TOTP code"
- **Mutation evidence:** `src/methods/totp/method.ts`, `src/core/email.ts`, `src/sessions/sessions.ts`,
  `src/store/memory.ts`, `src/methods/recovery/codes.ts`
- **Limitations:** The SQL store under real concurrency is phase 6's work.

### INV-SECRETS-AT-REST: no secret leaves, and nothing stored is usable as it stands

- **Status:** tested
- **Property:** No reply carries a key, a configuration value or a submitted secret, and an error answers a fixed
  body. Nothing the store holds can be used as it stands: session tokens are stored as their SHA-256, email codes as
  an HMAC key under `AUTH_ENCRYPTION_KEY`, TOTP seeds sealed with AES-GCM under a key held outside the store and bound
  to their tenant, account, authenticator and key id, and passwords and saved recovery codes as argon2id hashes, each
  with its own salt. Secrets that must be compared, not looked up, are compared in constant time.
- **Enforcement:** `src/methods/totp/secret-box.ts` `sealSecret` and `openSecret`, `src/sessions/sessions.ts`
  `createSessions` (it stores only the token's hash), `src/core/email.ts` `sendConfirmation` (it stores only the
  HMAC key), `src/security/headers.ts` `errorResponse`, `src/core/dispatcher.ts` `failure`,
  `src/methods/recovery/codes.ts` `generateRecoveryCodes`, `src/core/encoding.ts` `constantTimeEqual`
- **Attacks:** `secret-in-response`, `totp-secret-read-at-rest`, `totp-key-rotation-confusion`,
  `secret-in-security-event`, `weak-secret-generation`, `recovery-code-weak-storage`, `secret-comparison-timing`
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
  - `test/attacks/recovery-code-weak-storage.test.ts`: "stores nothing but an argon2id hash at the production cost, never the secret"
  - `test/attacks/secret-comparison-timing.test.ts`: "compares every byte whatever the first difference"
- **Mutation evidence:** `src/methods/totp/secret-box.ts`, `src/sessions/sessions.ts`, `src/core/email.ts`,
  `src/security/headers.ts`, `src/core/dispatcher.ts`, `src/methods/recovery/codes.ts`, `src/core/encoding.ts`
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
  - `test/abuse/counter-keys.test.ts`: "throttles an address no account holds exactly as one an account holds"
- **Mutation evidence:** `src/core/dispatcher.ts`, `src/methods/password/method.ts`, `src/methods/password/argon2.ts`
- **Limitations:** Timing is measured on the test machine, within the tolerance its test states.

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
  per IP address or IPv6 /64 before it is sent; an app may change those limits, and production and staging refuse to
  start with them off. An account holds at most 5 confirmed TOTP authenticators and one
  pending enrolment, and a session keeps only the newest evidence of each authenticator.
- **Enforcement:** `src/transport/body.ts` `readBody`, `parseForm` and `parseJsonObject`,
  `src/methods/password/semaphore.ts` `createSemaphore`, `src/methods/password/argon2.ts` `createHasher`,
  `src/core/email.ts` `sendConfirmation`, `src/methods/totp/method.ts` `totpEnrolmentAllowed`, `src/core/auth.ts`
  `createAuth` (its startup check of `emailLimit`)
- **Attacks:** `request-parser-resource-exhaustion`, `argon2-cost-exhaustion`, `email-send-flooding`,
  `totp-authenticator-flood`
- **Flows:** F01, F02, F03, F04, F08, F09, F10, F22
- **Positive tests:**
  - `test/transport/body.test.ts`: "accepts a body exactly at the limit and refuses one byte more"
- **Negative tests:**
  - `test/attacks/request-parser-resource-exhaustion.test.ts`: "refuses an oversized body before parsing it"
  - `test/attacks/argon2-cost-exhaustion.test.ts`: "runs at most 4 hashes at once and refuses what the queue cannot hold"
  - `test/attacks/email-send-flooding.test.ts`: "sends at most 20 an hour from one IP address, across addresses"
  - `test/abuse/mail-and-stuffing-options.test.ts`: "refuse emailLimit: false in production and staging, naming inbox flooding"
  - `test/attacks/totp-authenticator-flood.test.ts`: "answers a sixth enrolment, by the API or the page, with 409 too-many-authenticators"
  - `test/sessions/evidence-bound.test.ts`: "is at most one TOTP entry per authenticator after 1,000 verifies"
- **Mutation evidence:** `src/transport/body.ts`, `src/methods/password/semaphore.ts`,
  `src/methods/password/argon2.ts`, `src/core/email.ts`, `src/methods/totp/method.ts`, `src/sessions/sessions.ts`,
  `src/core/auth.ts`
- **Limitations:** Volumetric denial of service is out of scope (threat model). The throttle (`INV-GUESS-THROTTLE`)
  slows guessing, and the request limit (`INV-REQUEST-LIMIT`) bounds each client's requests; neither bounds a flood
  spread across many clients.

### INV-GUESS-THROTTLE: guessing is slowed and capped, never a lockout

- **Status:** tested
- **Property:** Every password, TOTP code and saved recovery code is checked only after the throttle lets the
  attempt through. Attempts count on the typed identifier (a signed-in session's TOTP check and step-up on its
  account's address, so every flow of one account shares the count), on the identifier and client, and on the client
  (an IPv4 address or an IPv6 /64); past 5 free failures in 15 minutes each key is blocked for a wait that doubles to 15
  minutes, and a parallel burst gets one attempt, not one each. Failures never disable an account: an authenticator
  stops after 100 consecutive failures, the account's others keep working, and recovery replaces it. A TOTP code that
  one of the account's authenticators takes counts a failure on none of them. A client that
  fails across many accounts is sent to the app's challenge, or loses its free attempts. Production and staging refuse
  to start with the throttle or the stuffing detector off, and no deployment can raise the ceiling above 100; an app
  may lower it, or put its own throttle or detector in place of the default.
- **Enforcement:** `src/security/throttle.ts` `createThrottle` (its `attempt`, which counts and reserves before any
  check), `src/security/ceiling.ts` `createFailureCeiling`, `src/security/stuffing.ts` `createStuffingDetector`,
  `src/core/dispatcher.ts` `createDispatcher` (its `throttled` wrapper around every guessable ceremony),
  `src/core/auth.ts` `createAuth` (its startup checks of `throttle` and `failureCeiling`)
- **Attacks:** `throttle-counter-race`, `credential-stuffing`, `password-brute-force`, `lockout-denial-of-service`,
  `recovery-code-brute-force`, `ipv6-rotation-throttle-bypass`
- **Flows:** F02, F04, F07
- **Positive tests:**
  - `test/abuse/throttle.test.ts`: "lets an untouched subject try now"
  - `test/attacks/lockout-denial-of-service.test.ts`: "never disables the account: once the throttle's wait ends, the owner signs in"
- **Negative tests:**
  - `test/abuse/throttle.test.ts`: "lets six attempts through, then blocks for the delay and lets the subject try once it ends"
  - `test/attacks/throttle-counter-race.test.ts`: "counts every one of a burst of parallel failures from one client"
  - `test/attacks/password-brute-force.test.ts`: "doubles the wait for each guess past the free ones, whatever address the guesses come from"
  - `test/attacks/credential-stuffing.test.ts`: "sends a client that failed on many accounts to the app's challenge, even with a working pair"
  - `test/attacks/recovery-code-brute-force.test.ts`: "throttles recovery guesses on the account, from any address"
  - `test/abuse/failure-ceiling.test.ts`: "refuses even the right password after 100 consecutive failures, with the same reply as a wrong one"
  - `test/methods/totp.test.ts`: "counts no failure on the account's other authenticators when one of them takes the code"
  - `test/abuse/sign-in-paths.test.ts`: "is the one a session's password step-up uses, so the two flows share one budget"
  - `test/abuse/limit-options.test.ts`: "is refused in production and staging, citing NIST SP 800-63B"
  - `test/abuse/limit-options.test.ts`: "cannot be raised above 100, citing NIST SP 800-63B"
  - `test/abuse/mail-and-stuffing-options.test.ts`: "refuses stuffing: false in production and staging"
- **Mutation evidence:** `src/security/throttle.ts`, `src/security/ceiling.ts`, `src/security/stuffing.ts`,
  `src/core/dispatcher.ts`, `src/core/auth.ts`
- **Limitations:** A throttle slows guessing; it does not stop a distributed attack that stays under every key's
  threshold, which is the challenge hook's job, and the hook is only as strong as the app's challenge. Anyone who knows
  an identifier can drive its password to the failure ceiling (ADR 0009, Consequences).

### INV-REQUEST-LIMIT: every request is counted per client before its route runs

- **Status:** tested
- **Property:** Every request the dispatcher answers is counted per client (an IPv4 address or an IPv6 /64) with the
  store's atomic `increment`, under the route its raw path names, before anything else runs. Over its rule, it
  answers `429 rate-limited` and runs nothing; sign-up is refused before an account exists. A parallel burst gets the
  rule's count and no more, and no spelling of a path counts under one rule while running another route. Each rule
  can be changed, replaced or turned off by the app; a counter that fails ends the request with a 500.
- **Enforcement:** `src/security/rate-limit.ts` `createRequestLimits` (its `check`, which picks the route's rule),
  `src/security/store-limiter.ts` `createStoreLimiter` (its `_upsert`, one atomic `increment` per request),
  `src/core/dispatcher.ts` `createDispatcher` (its `limitIdOf` and `overLimit`, before any route runs)
- **Attacks:** `sign-up-flooding`, `request-flooding`, `limiter-path-bypass`
- **Flows:** F01, F02, F22
- **Positive tests:**
  - `test/abuse/request-limit.test.ts`: "count each client on its own"
  - `test/security/store-limiter.test.ts`: "allows points in a window, then refuses with the wait, counted on the injected clock"
- **Negative tests:**
  - `test/attacks/sign-up-flooding.test.ts`: "refuses the 21st sign-up from one client in an hour before any account row exists"
  - `test/attacks/request-flooding.test.ts`: "lets through exactly the rule's count of a parallel burst from one client"
  - `test/attacks/request-flooding.test.ts`: "counts every address of one IPv6 /64 as one client, in any spelling"
  - `test/attacks/limiter-path-bypass.test.ts`: "never runs the sign-in route for another spelling of its path, before or after the budget is spent"
  - `test/failure/rate-limit.test.ts`: "ends sign-up with the fixed 500 before an account exists when the store's increment fails"
  - `test/abuse/client-address-required.test.ts`: "is refused with the fixed 500 before it is counted or run, and the operator is told once"
  - `test/abuse/client-address-required.test.ts`: "refuses to start in production and staging, naming the fix"
- **Mutation evidence:** `src/security/rate-limit.ts`, `src/security/store-limiter.ts`, `src/core/dispatcher.ts`
- **Limitations:** The window is fixed, so a client can make up to twice a rule's count across a window boundary. A
  request with no client address is not counted in development and test, or with `requireClientAddress: false`;
  production and staging refuse it (ADR 0009 §8). An app that sets `rateLimit: false`, or a rule to
  `false`, takes that limit on itself. A flood spread across many clients stays under every client's rule.

### INV-CLIENT-ADDRESS: the client address comes from the socket or a declared proxy

- **Status:** tested
- **Property:** The address the throttle counts is the socket's peer, unless the app declared that peer a proxy, by
  address, CIDR range or platform preset. Then exactly one header is read, the one the app or its preset names, and
  only from that peer, except under the `vercel`, `fly` and `netlify` presets, which have no peer to check: every
  request reaches the app through the platform's edge. No other forwarding header is ever read. An IPv4 address and its IPv4-mapped IPv6 form are one
  client, and an IPv6 client is its /64.
- **Enforcement:** `src/core/proxy-trust.ts` `resolveClient`, `src/core/client-address.ts` `clientKey`
- **Attacks:** `spoofed-forwarded-for`, `ipv6-rotation-throttle-bypass`
- **Flows:** F02, F22
- **Positive tests:**
  - `test/abuse/client-address.test.ts`: "reads the right-most address that is not a trusted proxy"
- **Negative tests:**
  - `test/attacks/spoofed-forwarded-for.test.ts`: "still counts every attempt against the real socket when the client forges the header"
  - `test/attacks/spoofed-forwarded-for.test.ts`: "reads only the header the app named, so a forged copy of the other one changes nothing"
  - `test/attacks/spoofed-forwarded-for.test.ts`: "counts a client that prepends its own Forwarded elements, well-formed or not, under the address its proxy appended"
  - `test/attacks/ipv6-rotation-throttle-bypass.test.ts`: "counts every address of one /64 as one client"
- **Mutation evidence:** `src/core/proxy-trust.ts`, `src/core/client-address.ts`
- **Limitations:** The platform presets follow the vendors' documentation and are tested in simulation only
  (`test/topology/`); a platform's shared address ranges do not prove a request came through the app's own account
  (ADR 0009 §5, Limits).

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
  - `test/attacks/identifier-normalisation-collision.test.ts`: "signs in to the one account whichever spelling is typed, and refuses a padded one"
  - `test/attacks/concurrent-enrolment-collision.test.ts`: "lets exactly one of many accounts confirming one address in parallel claim it"
- **Mutation evidence:** `src/core/accounts.ts`, `src/core/email.ts`, `src/core/identifier.ts`
- **Limitations:** A compromised mailbox confirms the address (threat model).

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
