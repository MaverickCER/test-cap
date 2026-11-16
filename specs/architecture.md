# Architecture

test-cap is an internal authentication package: one framework-free core, thin adapters for each server framework,
stores the app supplies, and an interface layer built on one form model. This document is the map. Each decision it
relies on lives in an ADR under [decisions/](decisions/), and each flow's threats live in
[threat-model.md](threat-model.md); this file names them rather than repeating them. Terms are defined in the
[glossary](../GLOSSARY.md).

## The shape

```text
 react · forms · pages · client ─┐            ┌─ stores: memory (dev) · sql (Postgres, SQLite, MySQL)
                                 ▼            ▼
 adapters ─ bytes ─► core: auth.handle(PlainRequest) → PlainResponse ─► human · machine · delegation ─► libraries
 express · nest · next · tanstack-start · fetch      assurance · sessions · security · events · audit
```

Three rules hold the shape together:

1. **All logic is in the core.** Parsing, validation, ceremonies, sessions, assurance, events and audit run in one
   place, on Web Crypto and standard globals, with the clock and random source injected (ADR 0003).
2. **Edges only convert.** An adapter turns its framework's request into bytes and the core's response back
   (ADR 0003, ADR 0024). A store turns named atomic operations into the app's own queries (ADR 0002).
3. **Assurance is computed, never declared.** Ceremonies produce evidence; the session's level is computed from the
   evidence still valid (ADR 0005).

## Modules

| Module (source)    | Entry                    | Holds                                                                 | ADR              |
| ------------------ | ------------------------ | --------------------------------------------------------------------- | ---------------- |
| `src/core/`        | `test-cap`               | `createAuth`, dispatcher, config, deployment mode, error model        | 0003, 0026       |
| `src/transport/`   | `test-cap`               | byte parsing: content type, body limit, forms, JSON, cookies, headers | 0003             |
| `src/assurance/`   | `test-cap`               | evidence, session assurance, decay, `require`                         | 0005             |
| `src/sessions/`    | `test-cap`               | tokens, cookies, rotation, revocation, expiry                         | 0006             |
| `src/security/`    | `test-cap`               | CSRF, origin, headers, CSP, redirects, throttling, proxy trust        | 0009, 0011       |
| `src/methods/*`    | `test-cap`, method gates | password, TOTP, passkeys, recovery, email, OIDC                       | 0007, 0010, 0027 |
| `src/machine/`     | `test-cap/machine`       | API keys and the `service` subject                                    | 0013             |
| `src/delegation/`  | `test-cap/delegation`    | delegations and the `agent` subject                                   | 0013             |
| `src/admin/`       | `test-cap`               | revoke, deprovision, impersonate, break-glass                         | 0012, 0014       |
| `src/ocsf/`        | `test-cap`               | security event types and builders                                     | 0015             |
| `src/audit/`       | `test-cap/audit`         | audit records, chain, checkpoints, verification, reports              | 0020             |
| `src/report/`      | `test-cap/report`        | the policy report                                                     | 0005, 0017       |
| `src/env/`         | `test-cap/env`           | the env-cap contract                                                  | 0022             |
| `src/store/`       | `test-cap/store/*`       | the `AuthStore` port, memory store, SQL store, migrations             | 0002             |
| `src/conformance/` | `test-cap/conformance`   | the store conformance kit                                             | 0002             |
| `src/adapters/*`   | `test-cap/<framework>`   | express, nest, next, tanstack-start, fetch                            | 0024             |
| `src/client/`      | `test-cap/client`        | the browser API and passkey ceremonies                                | 0025             |
| `src/forms/`       | `test-cap/forms`         | the framework-free form model                                         | 0025             |
| `src/react/`       | `test-cap/react`         | the React components                                                  | 0025             |
| `src/pages/`       | `test-cap` (served)      | server-rendered default pages and hashed assets                       | 0025             |
| `src/saml/`        | `test-cap/saml`          | SAML 2.0 service provider                                             | 0028             |

A module's entry is added to `package.json` `exports` only when its capability gate passes (ADR 0004). Until then it
exists in source and tests only.

## Public types

Every public type names the ADR that owns its shape. A docs test fails when a row names an ADR that does not exist,
and from phase 2 on, when an exported type is missing from this table.

| Type or function                                                                   | Entry                     | ADR  |
| ---------------------------------------------------------------------------------- | ------------------------- | ---- |
| `createAuth(config): Auth`                                                         | `test-cap`                | 0003 |
| `AuthConfig`                                                                       | `test-cap`                | 0026 |
| `Auth` (`handle`, `session`, `require`, `admin`)                                   | `test-cap`                | 0003 |
| `PlainRequest`, `PlainResponse`                                                    | `test-cap`                | 0003 |
| `Clock`, `RandomSource`                                                            | `test-cap`                | 0003 |
| `DeploymentMode`                                                                   | `test-cap`                | 0026 |
| `AuthenticationEvidence`, `KeyProtection`                                          | `test-cap`                | 0005 |
| `SessionAssurance`, `AssuranceLevel`                                               | `test-cap`                | 0005 |
| `RequireResult` (`allow`, `step-up`, `enroll`, `recovery-only`, `unauthenticated`) | `test-cap`                | 0005 |
| `defineAuthPolicy`, `AuthPolicy`, `Requirement`, `Deviation`                       | `test-cap`                | 0005 |
| `SessionInfo`                                                                      | `test-cap`                | 0006 |
| `Subject`, `UserSubject`, `ServiceSubject`, `AgentSubject`                         | `test-cap`                | 0013 |
| `Impersonator`, `BreakGlassGrant`                                                  | `test-cap`                | 0014 |
| `TrustConfig`, `TrustedIssuer`                                                     | `test-cap`                | 0008 |
| `ThrottleConfig`, `TrustedProxies`, `ChallengeHook`                                | `test-cap`                | 0009 |
| `BreachedPasswordConfig`                                                           | `test-cap`                | 0010 |
| `SendEmail`, `EmailMessage`                                                        | `test-cap`                | 0021 |
| `TenantId`, `TenantConfig`                                                         | `test-cap`                | 0012 |
| `SecurityEvent`, `EventSink`                                                       | `test-cap`                | 0015 |
| `AuthStore`, `StoreTransaction`                                                    | `test-cap`                | 0002 |
| `memoryStore()`                                                                    | `test-cap/store/memory`   | 0002 |
| `sqlStore(options)`, `SqlDialect`, `migrations(dialect)`                           | `test-cap/store/sql`      | 0002 |
| `runAuthStoreConformance(createStore)`                                             | `test-cap/conformance`    | 0002 |
| `ApiKey`, `issueApiKey`                                                            | `test-cap/machine`        | 0013 |
| `Delegation`, `issueDelegation`                                                    | `test-cap/delegation`     | 0013 |
| `AuditRecord`, `AuditSink`, `Checkpoint`, `verifyAudit`, `AuditVerification`       | `test-cap/audit`          | 0020 |
| `sessionTimeline`, `accessReport`                                                  | `test-cap/audit`          | 0020 |
| `PolicyReport`, `renderPolicyReport`                                               | `test-cap/report`         | 0005 |
| `env`, the env-cap schema                                                          | `test-cap/env`            | 0022 |
| `expressAuth(auth, options)`                                                       | `test-cap/express`        | 0024 |
| `TestCapModule`, `AuthGuard`, `@Public()`, `@RequireAuth()`                        | `test-cap/nest`           | 0024 |
| `nextAuthHandler`, `nextServerAuth`, `nextProxy`                                   | `test-cap/next`           | 0024 |
| `tanstackStartAuth`, `tanstackStartMiddleware`                                     | `test-cap/tanstack-start` | 0024 |
| `withAuth(auth, handler, options)`                                                 | `test-cap/fetch`          | 0024 |
| `createAuthClient`                                                                 | `test-cap/client`         | 0025 |
| `FormModel`, `FieldState`, `Messages`                                              | `test-cap/forms`          | 0025 |
| `SignInForm`, `SignUpForm`, `RecoverForm`, `MfaChallenge`, `PasskeyEnroll`         | `test-cap/react`          | 0025 |
| `TotpEnroll`, `RecoveryCodes`, `Sessions`, `StepUp`                                | `test-cap/react`          | 0025 |
| `samlProvider(options)`                                                            | `test-cap/saml`           | 0028 |

Names are provisional until their phase lands; a rename updates this table in the same pull request.

## Core API

`createAuth(config)` returns `auth`:

- `auth.handle(req: PlainRequest): Promise<PlainResponse>` serves every `/auth/*` route, the default pages and the
  hashed assets. This is what adapters call (ADR 0003).
- `auth.session(req)` returns the current `SessionInfo` or `null`, after revocation and expiry are checked against
  the store; no cached answer skips that check (ADR 0006).
- `auth.require(req, requirementId)` returns a `RequireResult` (ADR 0005):
  - `allow`, with the subject;
  - `step-up`, with the evidence that is missing;
  - `enroll`, when the session is in the pre-auth state;
  - `recovery-only`, when the session came from recovery and may only restore authenticators;
  - `unauthenticated`.
- `auth.admin` holds `revoke`, `deprovision`, `impersonate` and `breakGlass` (ADR 0012, ADR 0014).

The config names the store, the email sender, the event sink, the policy, the trust config, the env contract (or plain
values) and, for tests, the clock and random source. Production refuses to start without an HTTPS origin, a real
store and every secret (ADR 0026).

## Routes the dispatcher serves

| Route group                                                    | Flow     | Phase |
| -------------------------------------------------------------- | -------- | ----- |
| `GET /auth/session`                                            | F14      | 3     |
| sign-up, email confirmation                                    | F01, F08 | 3, 5  |
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

API keys (F15), delegations (F16), impersonation (F17), break-glass (F18) and deprovisioning (F19) are server calls,
not routes. Audit (F20) is a library the app calls.

## Data model

Logical records, each scoped to a tenant (ADR 0012). The SQL store's tables and constraints follow these in phase 3
(ADR 0002).

| Record                 | Key fields                                                                                   | Written by    |
| ---------------------- | -------------------------------------------------------------------------------------------- | ------------- |
| account                | id, tenant, status, created, deprovisioned                                                   | F01, F19      |
| identifier             | account, kind (email), value (normalised), verified at; unique per tenant                    | F01, F08      |
| authenticator          | account, method, public data, encrypted secret and key id, key protection, failures, created | F03, F05, F07 |
| linked identity        | account, issuer, subject; unique per tenant and issuer                                       | F11, F12      |
| session                | token hash (SHA-256), subject, session assurance, idle and absolute expiry, revoked at       | F02–F18       |
| one-time secret        | purpose, hash, expiry, consumed at (consumed through `consumeOnce`)                          | F07–F11       |
| counter                | key, window, count (through `increment`)                                                     | F02–F12       |
| federation transaction | id, state, nonce, PKCE verifier, `InResponseTo`, expiry, consumed at                         | F11, F12      |
| API key                | hash, scopes, expiry, owner                                                                  | F15           |
| delegation             | token hash, issuing session, agent, scopes, expiry, revoked at                               | F16           |
| audit record           | stream, sequence number, key id, canonical JSON, chain MAC; unique (stream, sequence)        | F20           |

## Flows

Each flow lists what it produces. The threats and the design element stopping each are in
[threat-model.md](threat-model.md) under the same id.

- **F01 Sign-up.** Identifier first; the account starts in the pre-auth state; email confirmation (F08) runs
  alongside; the account must enrol a passkey, or a password plus TOTP, before any requirement allows it. Produces
  an Account Change event (Create).
- **F02 Password sign-in.** argon2id verify under a fixed cost and a concurrency limit, with a dummy hash for unknown
  accounts. Evidence: one factor, AAL1. Throttled per ADR 0009.
- **F03 TOTP enrolment.** Secret generated by the injected random source, shown once, stored AES-GCM encrypted
  (ADR 0027), confirmed by one valid code before it counts.
- **F04 TOTP verification.** RFC 6238 over Web Crypto HMAC; a time step already used is rejected. With a password,
  the session reaches AAL2.
- **F05 Passkey registration.** `@simplewebauthn/server` with a caller-supplied challenge, UV required. Attestation is
  verified when roots are configured; it alone never establishes AAL3 (ADR 0005).
- **F06 Passkey authentication.** UV required; origin and RP ID checked; counter and backup flags recorded as key
  protection. AAL2 and phishing-resistant; AAL3 only with all ADR 0005 conditions.
- **F07 Recovery codes.** 80-bit codes, hashed, each consumed once. Redeeming one yields the recovery-only state, never
  more than the account's proven evidence (ADR 0007).
- **F08 Email confirmation.** At least 6 digits, at most 24 hours, single use. Confirms an address; never raises
  assurance (ADR 0021).
- **F09 Email recovery and password reset.** Same code rules as F08; leads to the recovery-only state; credential
  changes rotate the session and revoke the others (ADR 0007, ADR 0006).
- **F10 Email sign-in (opt-in).** A declared deviation; cannot satisfy AAL2 (ADR 0021).
- **F11 OIDC sign-in and linking.** `oauth4webapi`, state, nonce, PKCE S256, `response_mode=query`, issuer
  allowlist; AAL1 unless the trust config maps the issuer's `acr`/`amr` (ADR 0005, ADR 0008).
- **F12 SAML sign-in.** Node only, last phase, behind its own gate (ADR 0028); the POST binding uses the federation
  transaction cookie (ADR 0006).
- **F13 Step-up.** Runs any ceremony inside a session; the new evidence is added and the token rotates.
- **F14 Session lifecycle.** Opaque token, stored as a hash, rotated on sign-in, step-up, privilege change and
  impersonation; idle and absolute limits per level; list and remote revoke (ADR 0006).
- **F15 API keys.** Hashed, scoped, mandatory expiry; a `service` subject with no assurance level (ADR 0013).
- **F16 Delegations.** Issued from a session, short-lived, scoped, revocable; an `agent` subject with `actingFor`
  (ADR 0013).
- **F17 Impersonation.** A fresh AAL2+ admin session, a reason and a time limit; flagged on every event; credential
  changes blocked (ADR 0014).
- **F18 Break-glass.** As F17, outside the normal requirements, listed for review (ADR 0014).
- **F19 Deprovision.** The hook a SCIM server calls: disables the account and revokes every session and delegation
  (ADR 0012).
- **F20 Audit.** The app records activity; records are chained and checkpointed; `verifyAudit` checks them
  (ADR 0020).
- **F21 Default pages.** Server-rendered from the form model; progressive enhancement; strict CSP with no inline
  script; hashed assets cached immutably (ADR 0025).
- **F22 Adapter transport.** Bytes in, bytes out; deny by default; the core's view cannot be changed by an app body
  parser (ADR 0003, ADR 0024).

## The UX contract

Every form, in the React components and the default pages, keeps one tested set of promises: a field's error replaces
its help text, global errors sit in the row above the submit button, and the rest. ADR 0025 owns the list and the test
for each point.

## Runtime support

Per capability, from CI over the built `dist/` (ADR 0023):

| Capability                                 | Node 22/24 | Bun         | Deno        | Edge        |
| ------------------------------------------ | ---------- | ----------- | ----------- | ----------- |
| Core, sessions, policy, TOTP, forms, pages | CI         | CI          | CI          | not claimed |
| Passwords (`hash-wasm`)                    | CI         | CI          | CI          | not claimed |
| Passkeys (`@simplewebauthn/server`)        | CI         | CI          | CI          | not claimed |
| OIDC (`oauth4webapi`)                      | CI         | CI          | CI          | not claimed |
| Audit (Ed25519, HMAC on Web Crypto)        | CI         | CI          | CI          | not claimed |
| SAML (`@node-saml/node-saml`)              | CI         | unsupported | unsupported | unsupported |

## Stated gaps

Generic OAuth 2.0 sign-in, a SCIM server (the deprovision hook ships), mTLS and workload identity, SAML outside Node,
and components for Vue, Svelte and Solid (the form model is ready for them). The access-cap subject shape, the shared
OCSF types and the shared env fixture are test-cap's proposals until access-cap's design lands.
