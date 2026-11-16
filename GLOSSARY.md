# Glossary

The terms test-cap's API, specs and decision records use. Each term means one thing everywhere. The first group keeps
apart words that are often used loosely for the same idea; the order of that group is the order in which a sign-in
uses them.

## Signing in

**Method.** A way of signing in that test-cap offers, such as passwords, TOTP, passkeys or OIDC. A method is
configuration, not proof: turning a method on gives no one any assurance.

**Authenticator.** Something a person has, knows or is, registered to their account: one passkey, one TOTP secret, one
password. A person can hold several authenticators of the same method. Attempt limits are counted per authenticator.

**Factor.** The kind of proof an authenticator gives: something you know (a password), something you have (a device
holding a key or an OTP secret) or something you are (a biometric that unlocks a device). A passkey used with user
verification proves two factors at once.

**Ceremony.** One run of a method from start to finish: the options sent to the browser, the person's response, and the
verification. A ceremony either produces evidence or fails. Registration ceremonies enrol an authenticator;
authentication ceremonies prove possession of one.

**Evidence** (`AuthenticationEvidence`). What one successful ceremony proves, recorded as data: the method, the factors,
whether it is phishing-resistant and replay-resistant, the key protection (`non-exportable`, `syncable` or
`unknown`), whether user verification happened, when, and for federation the issuer and the upstream `acr` and `amr`.
Evidence expires.

**Assurance level** (AAL). The NIST SP 800-63B-4 level, AAL1, AAL2 or AAL3, that a set of evidence supports. test-cap
computes it from evidence; no method and no configuration declares it.

**Session assurance** (`SessionAssurance`). The assurance a session holds right now: the level computed from the
evidence still valid, the evidence itself, the time of the last multi-factor and the last phishing-resistant
ceremony, the step-up history, the policy version, and the idle and absolute expiry. It decays when evidence expires.

**One-time secret.** A single-use code, link token or challenge bound to a purpose, an account and an identifier,
redeemed with `consumeOnce`.

**Step-up.** A ceremony run inside an existing session to raise its session assurance, because a requirement asks for
more than the session holds.

**Step-up pending.** The session state after a requirement answered `step-up` and before the missing evidence
arrives.

**Requirement** (requirement id). A named rule in the policy, such as `billing.update`, that says what session
assurance a route or operation needs. `auth.require(req, requirementId)` checks one. Requirement ids belong to test-cap;
an app or access-cap maps its own capability ids to them.

**Email sign-in.** The opt-in method (a code or magic link sent to a confirmed address). It is a deviation, produces no
evidence and adds no assurance.

**ASVS requirement** and **NIST statement.** An item of OWASP ASVS 5.0.0 or NIST SP 800-63B-4 that
`specs/requirements.md` maps. Named apart from **requirement**, which always means a policy rule id here.

**Screening result.** `pass`, `fail` or `indeterminate`: the outcome of the blocklist and breached-password checks,
recorded on a password authenticator.

**Scope.** A named permission an API key or delegation carries. test-cap requires and carries scopes; what a scope
allows is access-cap's or the app's decision.

**Deviation.** A line in the policy that relaxes a strict default, for example turning on email sign-in. Every deviation
is listed in the policy report. A deviation never raises what evidence is worth.

**Indeterminate.** The answer when test-cap cannot prove something either way, for example a breached-password check
whose service could not be reached. Indeterminate is reported as such and never counted as a pass.

## Who is signed in

**Subject.** Who a request acts as. Three kinds: `user` (a person, carrying session assurance), `service` (an API key,
carrying scopes and no assurance level) and `agent` (a delegation, acting for a user, carrying its own scopes and
never the user's assurance).

**Impersonator.** An administrator acting as another user. Recorded on the subject and on every event while it lasts.

**Break-glass.** Emergency access by an administrator, outside the normal requirements, with a reason and a time limit.
Flagged on every event and listed for review.

**Delegation.** A short-lived, scoped, revocable grant that a user's session issues to an agent. The agent subject it
produces carries `actingFor`.

**Pre-auth state.** A session that has proven an identifier but has not finished enrolling the authenticators the
policy requires. It can only enrol; `auth.require` answers `enroll`.

**Recovery-only state.** A session that redeemed a saved recovery code or an emailed recovery code. It holds no
assurance and can only replace authenticators; `auth.require` answers `recovery-only`. It ends once the change is
made.

**Recovery code.** Two kinds. A saved recovery code is 80-bit, shown once and stored as a salted argon2id hash. An
issued recovery code is at least 6 digits, sent by email, valid at most 24 hours and single use; 800-63B-4 §3.1.3.1
says such a code is not an authentication process. test-cap treats neither kind as evidence (ADR 0007).

**Credential change.** Setting or changing a password; adding or removing a passkey, security key, TOTP secret or set
of recovery codes; changing the confirmed email address; linking or unlinking a federated identity. It rotates the
session and revokes the account's other sessions (ADR 0006).

**Linked identity.** A federated identity, issuer plus `sub` for OIDC or IdP plus persistent NameID for SAML, bound to
one account in one tenant.

**Enforced SSO.** A tenant setting under which sign-in starts only at the tenant's identity provider.

**Deprovision.** The admin call (F19) a SCIM server or the app makes to mark an account disabled and revoke its
sessions and delegations (ADR 0012). A disabled account produces no evidence in any ceremony.

**Tenant.** An isolated group of accounts, such as one customer organisation. Every stored record and every store
operation is scoped to one tenant.

**System.** The application an account signs in to, named by `APP_SYSTEM_ID`. Audit records and events name the system.

## How it runs

**Core.** The framework-free part of test-cap that holds all logic: parsing, validation, ceremonies, sessions,
assurance, events and audit. It uses only Web Crypto and standard globals.

**Transport contract.** The byte-level boundary between an adapter and the core: `PlainRequest` (method, URL, headers,
body bytes, client address, abort signal) in, `PlainResponse` (status, headers, body) out. The core does all parsing.

**Dispatcher.** `auth.handle(req)`: the core's single entry for every `/auth/*` route, the default pages and their
hashed assets.

**Adapter.** A small module that converts one framework's request and response to and from the transport contract,
and can deny every route by default. It contains no authentication logic.

**Deny by default.** An adapter mode where every route needs the default requirement (AAL2) unless it is listed as
public.

**Deployment mode.** The value of `APP_ENV`. When it is missing or unknown, test-cap runs as production and refuses to
start without an HTTPS origin, a real store and every secret.

**Store.** The app-supplied persistence behind the `AuthStore` port. test-cap never opens a database connection.

**Atomic operation.** A store operation whose guarantee is part of its name: `consumeOnce` (single use, even under
concurrency), `increment` (a counter in a time window), `createUnique` (tenant-scoped uniqueness), `update` with an
expected version (compare-and-set) and `appendAudit` (rejects a gap or a duplicate sequence number). ADR 0002 owns the
full list.

**Conformance kit.** `test-cap/conformance`: tests an app runs against its own store to prove the atomic operations and
tenant isolation hold under real concurrency.

**Trust config.** The explicit list of federation issuers test-cap accepts, with each issuer's `acr` and `amr` mapping
and maximum authentication age. A mapping names AAL1 or AAL2, never AAL3. An issuer or context outside it never raises
assurance.

**`returnTo`.** The path a person returns to after signing in. Accepted only as a same-origin relative path.

**Federation transaction.** The single-use, server-side record (state, nonce, PKCE verifier, `InResponseTo`) that one
OIDC or SAML round trip is bound to, referenced by the short-lived `__Host-test-cap-tx` cookie: SameSite=Lax for
OIDC, SameSite=None only for SAML's POST binding.

**Rotation.** Issuing a new session token and revoking the old one when trust changes. ADR 0006 section 5 owns the list
of triggers.

**Throttle.** A delay on further attempts against a counter key after failures. It never disables an account.

**Failure ceiling.** 100 consecutive failures, after which one authenticator stops accepting attempts until the
account proves itself another way. The account stays usable.

**Credential-stuffing detector** and **challenge hook.** The detector spots failures spread across many accounts; the
hook is the app-supplied function (Turnstile, hCaptcha or the app's own) it escalates to.

**Client address** and **trusted proxies.** The client address is the socket peer in `PlainRequest.clientAddress`.
`X-Forwarded-For` is read only when that peer is in the declared `trustedProxies` list.

**Clock** and **random source.** The injected time and cryptographically secure randomness every flow uses, so tests
are deterministic. `oauth4webapi` and `@simplewebauthn/server` also read the system clock internally; ADR 0003 states
that limit.

**Public path.** A route listed in an adapter's `public` option and so exempt from deny by default. It matches only a
clean raw path, exactly or through an explicit wildcard such as `/blog/*`, and never after normalisation; an ambiguous
path is refused with a 400 before any match (ADR 0003, ADR 0024).

**Server helper.** In Next.js, test-cap's authoritative session and requirement check, called in route handlers,
server functions and the data-access layer. `proxy` only redirects early and is never the protection.

**Capability gate.** The tests a capability (a method, an adapter, the audit trail) must pass before it is added to
`package.json` `exports`.

## Interface

**Default pages.** Server-rendered sign-in, sign-up, recovery and account pages that `auth.handle` serves. They work
without JavaScript for password and email flows and load hashed client assets under a strict CSP.

**Form model.** `test-cap/forms`: a framework-free description of a form's fields, validation, help and error text,
submit state and focus target. The React components and the default pages are both built on it.

**UX contract.** The tested promises every form keeps: a field's error replaces its help text, global errors sit in
the row above the submit button, labels, `autocomplete` values, focus after a failed submit, and the rest. ADR 0025
owns the list.

## Evidence after the fact

**Security event.** An OCSF 1.9.0 record (Authentication 3002 or Account Change 3001) that test-cap always emits to the
app's `onEvent` sink. Storing events is the app's job. Events never contain a secret, a code or a full token.

**Audit trail.** The opt-in `test-cap/audit` record of who signed in to which system, when, at what level, and what
the app recorded during the session. Separate from security events.

**Audit record.** One entry in the audit trail: system, tenant, sequence number, key id and content, serialised as RFC
8785 canonical JSON. An **activity record** is one the app writes with `audit.record`; the others are session facts
test-cap writes.

**Audit stream.** One numbered sequence of audit records, one per system and tenant. `appendAudit(tenant, stream, seq,
record)` keeps it free of gaps and duplicates.

**Audit chain.** The audit records linked by HMAC-SHA-256 under the **chain key** `AUTH_AUDIT_KEY`, so a change to any
record breaks every link after it. The **chain head** is the latest link.

**Key ring.** The current key plus older keys kept only to decrypt or verify. Each ciphertext and audit record stores
the **key id** of the key that produced it.

**Retention** and **legal hold.** Retention is the per-tenant period after which audit records may be removed, always
as a whole prefix ending at an exported checkpoint. A legal hold suspends removal.

**Checkpoint.** An Ed25519 signature, under `AUTH_AUDIT_SIGNING_KEY`, over the chain head and its sequence number,
exported by the app to storage outside the database. Verification detects tampering back to the last exported
checkpoint.

**Open item** and **provisional default.** An open item is a question the plan leaves unsettled, listed under a
document's `## Open` heading with a recommendation. The recommendation is a provisional default: the build follows it
until the owner decides.

**Handoff question.** One of the 19 questions in the design handoff of 2026-11-15 (`Dev/AUTH_CAP_HANDOFF_2026-11-15.md`,
kept outside this repository). ADRs 0001 to 0019 each answer the question with their own number.

**Policy report.** The JSON and Markdown report `test-cap/report` produces from the policy: requirements, how
assurance is computed, timeouts checked against 800-63B-4, and every deviation.

**Attack catalogue.** `specs/attack-catalogue.md`: each attack test-cap is designed against, the design element that
stops it, and the negative test in `test/attacks/` that proves it.
