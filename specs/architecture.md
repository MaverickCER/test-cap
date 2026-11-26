# Architecture

test-cap is an internal authentication package. It has one framework-free core, thin adapters for each server
framework, stores the app supplies, and an interface layer built on one form model. This document is the map. Each
decision it relies on lives in an ADR under [decisions/](decisions/). Each flow's threats live in
[threat-model.md](threat-model.md). This file names them rather than repeating them. Terms are defined in the
[glossary](../GLOSSARY.md). A recommendation under any document's Open heading is a provisional default until the
owner decides.

The map covers the full nine-phase design. The modules table marks what is built so far. Everything else is planned,
with its phase.

## The shape

```text
 react · forms · pages · client ─┐            ┌─ stores: memory (dev) · sql (Postgres, SQLite, MySQL)
                                 ▼            ▼
 adapters ─ bytes ─► core: auth.handle(PlainRequest) → PlainResponse ─► human · machine · delegation ─► libraries
 express · nest · next · tanstack-start · fetch      assurance · sessions · security · events · audit
```

Three rules hold the shape together:

1. **All logic is in the core.** Parsing, validation, ceremonies, sessions, assurance, events and audit run in one
   place (ADR 0003). The core runs on Web Crypto and standard globals, with the clock and random source injected.
2. **Edges only convert.** An adapter turns its framework's request into bytes and the core's response back
   (ADR 0003, ADR 0024). A store turns named atomic operations into the app's own queries (ADR 0002).
3. **Assurance is computed, never declared.** Ceremonies produce evidence; the session's level is computed from the
   evidence still valid (ADR 0005).

## Modules

| Module (source)    | Entry                    | Holds                                                                 | ADR              | State                                                            |
| ------------------ | ------------------------ | --------------------------------------------------------------------- | ---------------- | ---------------------------------------------------------------- |
| `src/core/`        | `test-cap`               | `createAuth`, dispatcher, config, deployment mode, error model        | 0003, 0026       | built                                                            |
| `src/transport/`   | `test-cap`               | byte parsing: content type, body limit, forms, JSON, cookies, headers | 0003             | built                                                            |
| `src/assurance/`   | `test-cap`               | evidence, session assurance, decay, `require`                         | 0005             | built                                                            |
| `src/sessions/`    | `test-cap`               | tokens, cookies, rotation, revocation, expiry                         | 0006             | built                                                            |
| `src/security/`    | `test-cap`               | CSRF, origin, headers, CSP, redirects, throttling, request limits     | 0009, 0011       | built                                                            |
| `src/methods/*`    | `test-cap`, method gates | password, TOTP, passkeys, recovery, email, OIDC                       | 0007, 0010, 0027 | password, TOTP, recovery codes built; the rest phase 5           |
| `src/machine/`     | `test-cap/machine`       | API keys and the `service` subject                                    | 0013             | planned (phase 8)                                                |
| `src/delegation/`  | `test-cap/delegation`    | delegations and the `agent` subject                                   | 0013             | planned (phase 8)                                                |
| `src/admin/`       | `test-cap`               | revoke, deprovision, impersonate, break-glass                         | 0012, 0014       | `revoke`, `deprovision` built (in `src/core/`); the rest planned |
| `src/ocsf/`        | `test-cap`               | security event types and builders                                     | 0015             | built                                                            |
| `src/audit/`       | `test-cap/audit`         | audit records, chain, checkpoints, verification, reports              | 0020             | planned (phase 8)                                                |
| `src/report/`      | `test-cap/report`        | the policy report                                                     | 0005, 0017       | planned (phase 8)                                                |
| `src/env/`         | `test-cap/env`           | the env-cap contract                                                  | 0022             | built, not exported                                              |
| `src/store/`       | `test-cap/store/*`       | the `AuthStore` port, memory store, SQL store, migrations             | 0002             | built; memory exported; SQL export planned (phase 6)             |
| `src/conformance/` | `test-cap/conformance`   | the store conformance kit                                             | 0002             | built, not exported                                              |
| `src/adapters/*`   | `test-cap/<framework>`   | express, nest, next, tanstack-start, fetch                            | 0024             | built and exported, but Nest in progress (after phase 4)         |
| `src/client/`      | `test-cap/client`        | the browser API and passkey ceremonies                                | 0025             | planned (phase 7)                                                |
| `src/forms/`       | `test-cap/forms`         | the framework-free form model                                         | 0025             | built; types on `test-cap`; own entry planned (phase 7)          |
| `src/react/`       | `test-cap/react`         | the React components                                                  | 0025             | planned (phase 7)                                                |
| `src/pages/`       | `test-cap` (served)      | server-rendered default pages and hashed assets                       | 0025             | built                                                            |
| `src/saml/`        | `test-cap/saml`          | SAML 2.0 service provider                                             | 0028             | planned (phase 8)                                                |

A module's entry is added to `package.json` `exports` only when its capability gate passes (ADR 0004). A built module
whose entry is not exported exists in source and tests only.

## Public types

Every public type names the ADR that owns its shape. A docs test fails when a row names an ADR that does not exist.
It also fails when a name the main entry exports is missing from this table.

| Type or function                                                                                                            | Entry                     | ADR  |
| --------------------------------------------------------------------------------------------------------------------------- | ------------------------- | ---- |
| `createAuth(config): Auth`                                                                                                  | `test-cap`                | 0003 |
| `AuthConfig`                                                                                                                | `test-cap`                | 0026 |
| `Argon2Hasher`                                                                                                              | `test-cap`                | 0031 |
| `Auth` (`handle`, `session`, `require`, `admin`)                                                                            | `test-cap`                | 0003 |
| `AuthAdmin`                                                                                                                 | `test-cap`                | 0012 |
| `PlainRequest`, `PlainResponse`                                                                                             | `test-cap`                | 0003 |
| `Clock`, `RandomSource`                                                                                                     | `test-cap`                | 0003 |
| `TransportError`, `ConfigError`                                                                                             | `test-cap`                | 0003 |
| `TransportErrorCode`                                                                                                        | `test-cap`                | 0003 |
| `FixedClock`, `fixedClock`, `sequenceRandom`                                                                                | `test-cap`                | 0003 |
| `DeploymentMode`                                                                                                            | `test-cap`                | 0026 |
| `StoreTraits`                                                                                                               | `test-cap`                | 0002 |
| `RingKey`                                                                                                                   | `test-cap`                | 0022 |
| `AuthenticationEvidence`, `KeyProtection`                                                                                   | `test-cap`                | 0005 |
| `AuthenticationMethod`, `Factor`                                                                                            | `test-cap`                | 0005 |
| `SessionAssurance`, `AssuranceLevel`                                                                                        | `test-cap`                | 0005 |
| `RequireResult` (`allow`, `step-up`, `enroll`, `recovery-only`, `unauthenticated`)                                          | `test-cap`                | 0005 |
| `defineAuthPolicy`, `AuthPolicy`, `Requirement`, `Deviation`                                                                | `test-cap`                | 0005 |
| `AuthPolicyInput`, `SessionTimeouts`, `SessionState`, `SessionKind`                                                         | `test-cap`                | 0005 |
| `MissingEvidence`, `StepUpRecord`, `FederatedLevel`                                                                         | `test-cap`                | 0005 |
| `SessionInfo`                                                                                                               | `test-cap`                | 0006 |
| `Subject`, `UserSubject`, `ServiceSubject`, `AgentSubject`                                                                  | `test-cap`                | 0013 |
| `Impersonator`, `BreakGlassGrant`                                                                                           | `test-cap`                | 0014 |
| `TrustConfig`, `TrustedIssuer`                                                                                              | `test-cap`                | 0005 |
| `ThrottleConfig`, `StuffingConfig`, `TrustedProxies`, `ForwardedHeader`, `ChallengeHook`                                    | `test-cap`                | 0009 |
| `platform`, `PlatformName`, `PlatformTrust`, `AuthDiagnostic`                                                               | `test-cap`                | 0009 |
| `Throttle`, `ThrottleSubject`, `ThrottleSecret`, `createStoreLimiter`, `StoreLimiterOptions`, `RateRule`, `RateLimiterLike` | `test-cap`                | 0030 |
| `RateLimitConfig`, `RateLimitRouteId`, `RateRuleSetting`, `LimiterFactory`, `LimiterOptions`                                | `test-cap`                | 0030 |
| `EmailLimitConfig`, `StuffingDetector`                                                                                      | `test-cap`                | 0009 |
| `BreachedPasswordConfig`                                                                                                    | `test-cap`                | 0010 |
| `HibpFetch`, `HibpResponse`                                                                                                 | `test-cap`                | 0010 |
| `Argon2Cost`                                                                                                                | `test-cap`                | 0018 |
| `SendEmail`, `EmailMessage`                                                                                                 | `test-cap`                | 0021 |
| `TenantId`, `TenantConfig`                                                                                                  | `test-cap`                | 0012 |
| `SecurityEvent`, `EventSink`                                                                                                | `test-cap`                | 0015 |
| `AuthenticationEvent`, `UserManagementEvent`, their inputs and parts                                                        | `test-cap`                | 0015 |
| `AuthenticationActivity`, `AuthenticationInput`, `UserManagementActivity`, `UserManagementInput`                            | `test-cap`                | 0015 |
| `EventInput`, `EventSubject`, `FactorKind`, `Outcome`, `SessionRef`, `TestCapFacts`                                         | `test-cap`                | 0015 |
| `OcsfActor`, `OcsfAuthFactor`, `OcsfBaseEvent`, `OcsfMetadata`, `OcsfProduct`                                               | `test-cap`                | 0015 |
| `OcsfService`, `OcsfSession`, `OcsfUnmapped`, `OcsfUser`                                                                    | `test-cap`                | 0015 |
| `AuthStore`, `StoreTransaction`                                                                                             | `test-cap`                | 0002 |
| `StoredRecord`, `NewRecord`, `JsonValue`                                                                                    | `test-cap`                | 0002 |
| `ConformanceReport`, `ConformanceResult`                                                                                    | `test-cap`                | 0002 |
| `StoreOperations`, `RecordChange`, `CounterState`, `AuditEntry`                                                             | `test-cap`                | 0002 |
| `SqlDialect`, `SqlParam`, `SqlQuery`, `SqlResult`, `SqlStoreOptions`, `SqlTransaction`                                      | `test-cap`                | 0002 |
| `ConformanceOptions`                                                                                                        | `test-cap`                | 0002 |
| `memoryStore()`                                                                                                             | `test-cap/store/memory`   | 0002 |
| `sqlStore(options)`, `SqlDialect`, `migrations(dialect)`                                                                    | `test-cap/store/sql`      | 0002 |
| `runAuthStoreConformance(createStore)`                                                                                      | `test-cap/conformance`    | 0002 |
| `ApiKey`, `issueApiKey`                                                                                                     | `test-cap/machine`        | 0013 |
| `Delegation`, `issueDelegation`                                                                                             | `test-cap/delegation`     | 0013 |
| `AuditRecord`, `AuditSink`, `Checkpoint`, `verifyAudit`, `AuditVerification`                                                | `test-cap/audit`          | 0020 |
| `sessionTimeline`, `accessReport`                                                                                           | `test-cap/audit`          | 0020 |
| `PolicyReport`, `renderPolicyReport`                                                                                        | `test-cap/report`         | 0005 |
| `testCapEnv`, `testCapAuditEnv`, `testCapSamlEnv` (the env-cap contracts)                                                   | `test-cap/env`            | 0022 |
| `expressAuth(auth, options)`                                                                                                | `test-cap/express`        | 0024 |
| `ExpressAuthOptions`, `ExpressAuthInfo`, `ExpressAuthMiddleware`, `ExpressLike*`                                            | `test-cap/express`        | 0024 |
| `TestCapModule`, `AuthGuard`, `@Public()`, `@RequireAuth()`                                                                 | `test-cap/nest`           | 0024 |
| `nextAuthHandler`, `nextServerAuth`, `nextProxy`                                                                            | `test-cap/next`           | 0024 |
| `NextAuthHandlers`, `NextRouteHandler`, `NextServerAuth`, `NextServerAuthOptions`                                           | `test-cap/next`           | 0024 |
| `NextHeaders`, `NextProxy`, `NextProxyOptions`, `NextAuthHandlerOptions`                                                    | `test-cap/next`           | 0024 |
| `tanstackStartAuth`, `tanstackStartMiddleware`                                                                              | `test-cap/tanstack-start` | 0024 |
| `TanstackStartAuth`, `TanstackStartAuthInfo`, `TanstackStartContext`, `TanstackStartAuthOptions`                            | `test-cap/tanstack-start` | 0024 |
| `TanstackStartMiddleware*`, `TanstackStartRouteHandler*`                                                                    | `test-cap/tanstack-start` | 0024 |
| `withAuth(auth, handler, options)`                                                                                          | `test-cap/fetch`          | 0024 |
| `fetchAuth(auth, options)`                                                                                                  | `test-cap/fetch`          | 0024 |
| `FetchAuthInfo`, `FetchHandler`, `FetchAuthOptions`, `WithAuthOptions`                                                      | `test-cap/fetch`          | 0024 |
| `ClientAddress`                                                                                                             | `test-cap/fetch`          | 0009 |
| `createAuthClient`                                                                                                          | `test-cap/client`         | 0025 |
| `FormId`, `FormModel`, `FormOptions`, `FieldList`, `FieldState`, `FieldLength`, `FieldPattern`                              | `test-cap`                | 0025 |
| `FlowOutcome`, `Messages`                                                                                                   | `test-cap`                | 0025 |
| `PageAssets`, `PageContext`, `PageLink`, `PageAsset`, `PageAssetSet`                                                        | `test-cap`                | 0025 |
| `FormModel`, `FieldState`, `Messages`                                                                                       | `test-cap/forms`          | 0025 |
| `SignInForm`, `SignUpForm`, `RecoverForm`, `MfaChallenge`, `PasskeyEnroll`                                                  | `test-cap/react`          | 0025 |
| `TotpEnroll`, `RecoveryCodes`, `Sessions`, `StepUp`                                                                         | `test-cap/react`          | 0025 |
| `samlProvider(options)`                                                                                                     | `test-cap/saml`           | 0028 |

The table is the full design. Six entries exist today: `test-cap`, `test-cap/express`, `test-cap/fetch`,
`test-cap/next`, `test-cap/tanstack-start` and `test-cap/store/memory`. A `test-cap` row is public only once
`src/index.ts` exports it; the other rows arrive with their phase. Names are provisional until their phase lands; a
rename updates this table in the same pull request.

## Core API

`createAuth(config)` returns `auth`:

- `auth.handle(req: PlainRequest): Promise<PlainResponse | null>` serves every `/auth/*` route, the default pages and
  the hashed assets. It answers `null` for a path outside them, so the adapter passes the request on (ADR 0003,
  Open 4). This is what adapters call.
- `auth.session(req)` returns the current `SessionInfo` or `null`, after revocation and expiry are checked against
  the store; no cached answer skips that check (ADR 0006).
- `auth.require(req, requirementId)` returns a `RequireResult` (ADR 0005):
  - `allow`, with the subject;
  - `step-up`, with the evidence that is missing;
  - `enroll`, when the session is in the pre-auth state;
  - `recovery-only`, when the session came from recovery and may only restore authenticators (recovery: phase 4);
  - `unauthenticated`.
- `auth.admin` holds `revoke` today. `deprovision` is planned (threat model O15 proposes phase 4); `impersonate` and
  `breakGlass` are planned for phase 8 (ADR 0012, ADR 0014).

The config names the store, the email sender, the HIBP `fetch`, the event sink, the policy (which holds the trust
config) and the environment. For tests it also takes the clock, the random source and an argon2id cost. Production
refuses to start without an HTTPS origin, a durable store and both keys (ADR 0026).

## Routes the dispatcher serves

| Route group                                                    | Flow     | Phase |
| -------------------------------------------------------------- | -------- | ----- |
| `GET /auth/session`                                            | F14      | 3     |
| sign-up, email confirmation and resend                         | F01, F08 | 3     |
| password sign-in                                               | F02      | 3     |
| TOTP enrol, confirm, verify                                    | F03, F04 | 3     |
| passkey registration and authentication (options, verify)      | F05, F06 | 5     |
| recovery codes (issue, redeem), email recovery, password reset | F07, F09 | 4, 5  |
| email sign-in (opt-in)                                         | F10      | 5     |
| OIDC start and callback                                        | F11      | 5     |
| SAML start, ACS and metadata                                   | F12      | 8     |
| step-up                                                        | F13      | 3     |
| sign-out, session list, remote revoke                          | F14      | 3     |
| default pages and `/auth/assets/*`                             | F21      | 3, 7  |

Every route is counted per client against its request limit before it runs (ADR 0009 §8).

API keys (F15), delegations (F16), impersonation (F17), break-glass (F18) and deprovisioning (F19) are server calls,
not routes, and no request limit counts them. Audit (F20) is a library the app calls.

## Data model

Logical records, each scoped to a tenant (ADR 0012). Records written only by a planned flow arrive with that flow. The
SQL store keeps every record in three generic tables (ADR 0002).

| Record                 | Key fields                                                                                   | Written by    |
| ---------------------- | -------------------------------------------------------------------------------------------- | ------------- |
| account                | id, tenant, status, created, deprovisioned                                                   | F01, F19      |
| identifier             | account, kind (email), value (normalised), verified at; unique per tenant                    | F01, F08      |
| authenticator          | account, method, public data, encrypted secret and key id, key protection, failures, created | F03, F05, F07 |
| linked identity        | account, issuer, subject; unique per tenant and issuer                                       | F11, F12      |
| session                | token hash (SHA-256), subject, evidence, state, idle and absolute expiry, revoked at         | F02–F18       |
| one-time secret        | purpose, hash, expiry, consumed at (consumed through `consumeOnce`)                          | F07–F11       |
| counter                | key, window, count (through `increment`)                                                     | F02–F12       |
| federation transaction | id, state, nonce, PKCE verifier, `InResponseTo`, expiry, consumed at                         | F11, F12      |
| API key                | hash, scopes, expiry, owner                                                                  | F15           |
| delegation             | token hash, issuing session, agent, scopes, expiry, revoked at                               | F16           |
| audit record           | stream, sequence number, key id, canonical JSON, chain MAC; unique (stream, sequence)        | F20           |

## Flows

Each flow lists what it produces. The threats and the design element stopping each are in
[threat-model.md](threat-model.md) under the same id.

- **F01 Sign-up.** Identifier first; the account starts in the pre-auth state, and email confirmation (F08) comes
  next. No requirement allows the account until it enrols a password plus TOTP; passkeys arrive in phase 5. Produces
  a User Management event (Create).
- **F02 Password sign-in.** argon2id verify under a fixed cost and a concurrency limit, with a dummy hash whenever no
  stored password hash is verified. Evidence: one factor, AAL1. Failures are throttled (ADR 0009, phase 4).
- **F03 TOTP enrolment.** Secret generated by the injected random source, shown once, stored AES-GCM encrypted
  (ADR 0027), confirmed by one valid code before it counts.
- **F04 TOTP verification.** RFC 6238 over Web Crypto HMAC; a time step already used is rejected. With a password,
  the session reaches AAL2.
- **F05 Passkey registration (planned, phase 5).** `@simplewebauthn/server` with a caller-supplied challenge, UV required. Attestation is
  verified when roots are configured; it alone never establishes AAL3 (ADR 0005).
- **F06 Passkey authentication (planned, phase 5).** UV required; origin and RP ID checked; counter and backup flags recorded as key
  protection. AAL2 and phishing-resistant; AAL3 only with all ADR 0005 conditions.
- **F07 Recovery codes.** 80-bit codes, hashed, each consumed once. Redeeming one yields the recovery-only state, never
  more than the account's proven evidence (ADR 0007).
- **F08 Email confirmation.** At least 6 digits, at most 24 hours, single use. Confirms an address; never raises
  assurance (ADR 0021).
- **F09 Email recovery and password reset (planned, phase 5).** Same code rules as F08; leads to the recovery-only
  state. Completing it revokes the account's other sessions and outstanding emailed codes. The recovery-only session
  then ends, and the person signs in with the new authenticators (ADR 0007, Open 5).
- **F10 Email sign-in (opt-in) (planned, phase 5).** A declared deviation; cannot satisfy AAL2 (ADR 0021).
- **F11 OIDC sign-in and linking (planned, phase 5).** `oauth4webapi`, state, nonce, PKCE S256,
  `response_mode=query`, issuer allowlist; AAL1 unless the trust config maps the issuer's `acr`/`amr` (ADR 0005,
  ADR 0008).
- **F12 SAML sign-in (planned, phase 8).** Node only, behind its own gate (ADR 0028). The POST binding uses the
  federation transaction cookie (ADR 0006).
- **F13 Step-up.** Runs a ceremony inside a session (password or TOTP in phase 3); the new evidence is added and the
  token rotates.
- **F14 Session lifecycle.** Opaque token, stored as a hash, rotated on every change of trust (ADR 0006, section 5).
  Idle and absolute limits per level; list and remote revoke (ADR 0006).
- **F15 API keys (planned, phase 8).** Hashed, scoped, mandatory expiry; a `service` subject with no assurance level
  (ADR 0013).
- **F16 Delegations (planned, phase 8).** Issued from a session, short-lived, scoped, revocable; an `agent` subject
  with `actingFor` (ADR 0013).
- **F17 Impersonation (planned, phase 8).** A fresh AAL2+ admin session, a reason and a time limit; flagged on every
  event; credential changes blocked (ADR 0014).
- **F18 Break-glass (planned, phase 8).** As F17, outside the normal requirements, listed for review (ADR 0014).
- **F19 Deprovision (planned; threat model O15 proposes phase 4).** The hook a SCIM server calls. It marks the
  account disabled, so no ceremony produces evidence for it. It revokes every session and delegation (ADR 0012).
- **F20 Audit (planned, phase 8).** The app records activity; records are chained and checkpointed; `verifyAudit`
  checks them (ADR 0020).
- **F21 Default pages.** Server-rendered from the form model; progressive enhancement; strict CSP with no inline
  script; hashed assets cached as immutable (ADR 0025). The client and React parts are planned (phase 7).
- **F22 Adapter transport.** Bytes in, bytes out; deny by default; the core's view cannot be changed by an app body
  parser (ADR 0003, ADR 0024).

## The UX contract

Every form in the default pages keeps one tested set of promises. For example, a field's error replaces its help
text, and global errors sit in the row above the submit button. The React components (phase 7) will keep the same
set.
ADR 0025 owns the list and the test for each point.

## Security invariants and failure policies

The properties the core keeps whatever surrounds it are in [security-invariants.md](security-invariants.md). Each
names its enforcement point, the attacks it stops and its proof. What happens when a dependency fails is in
[dependency-failures.md](dependency-failures.md). Both are governing specs
([ADR 0029](decisions/0029-security-invariants-failure-policies-and-evidence-traceability.md)), and two of their rules
shape the code:

1. **Invariants live in the core.** Each is enforced by a core module's export, never by an adapter, so a new adapter
   cannot drop one.
2. **Dependencies fail closed.** An error from the store, the random source, a key or a library never reaches
   `allow`. It ends the request with the fixed 500, or rejects `auth.require`. Only mail, events and HIBP run
   degraded, and only in ways that cannot raise anything.

## Runtime support

Support is stated per capability, and a cell counts only once a CI job runs it over the built `dist/`. The table lives
in [ADR 0023](decisions/0023-runtime-support-per-capability.md), section 1, and only there. Today the `cross-runtime`
job runs the built package on Node 22 and 24, Bun 1.3.14, Deno 2.9.4 and Cloudflare workerd: checks of the exported
values, then a sign-in journey through `test-cap/fetch` (`test/cross-runtime/journey.mjs`). The per-capability matrix is
planned for phase 6; until then, ADR 0023's table says more than CI runs, as its dated note records.

## Stated gaps

test-cap does not cover these:

- generic OAuth 2.0 sign-in;
- a SCIM server (the deprovision hook is planned);
- mTLS and workload identity;
- SAML outside Node;
- components for Vue, Svelte and Solid (the form model imports no framework).

The access-cap subject shape, the shared OCSF types and the shared env fixture are test-cap's proposals until
access-cap's design lands.
