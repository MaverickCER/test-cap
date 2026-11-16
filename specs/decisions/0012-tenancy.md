# 0012: Tenancy

## Status

Accepted (2026-11-15). Tenant scoping of the store port and the isolation tests of the conformance kit are
implemented in phase 2; per-tenant OIDC configuration and enforced SSO in phase 5; per-tenant SAML configuration and
the deprovision hook in phase 8. Answers [handoff question](../../GLOSSARY.md) 12.

Planned tests:

- `test/store/conformance/tenant-isolation.test.ts` (shared with [ADR 0002](0002-store-port-and-atomic-operations.md);
  part of `test-cap/conformance`)
- `test/attacks/cross-tenant-store-read.test.ts`
- `test/attacks/cross-tenant-reference.test.ts`
- `test/attacks/cross-tenant-issuer-accepted.test.ts`
- `test/tenancy/enforced-sso.test.ts`
- `test/tenancy/deprovision-revokes.test.ts`
- `test/tenancy/deprovision-disables-account.test.ts` (after deprovision, no ceremony produces evidence and no session
  answers `allow`)
- `test/attacks/deprovisioned-account-signs-in.test.ts`
- `test/attacks/deleted-account-sessions-survive.test.ts`

The recommendations under Open are provisional defaults until the owner decides.

## Context

A **tenant** (see `GLOSSARY.md`) is an isolated group of accounts, such as one customer organisation. Apps that sell
to organisations need three things from authentication: one tenant's data never reaches another, each tenant can bring
its own identity provider (IdP), and a tenant can require that its people sign in only through that IdP. They also
need a way to cut off a person the organisation has removed.

The store is the app's ([ADR 0002](0002-store-port-and-atomic-operations.md)), so test-cap cannot rely on database
permissions it never sees. Isolation has to hold in the operations test-cap calls, and the app has to be able to prove
its own store keeps it.

Better Auth's advisories show what goes wrong: any organisation member registering an SSO provider, personal
providers signing in another provider's users, and stale sessions after a user is deleted. Each becomes an attack test
in the catalogue.

## Decision

### 1. Every record and every store operation is scoped to one tenant

Every record test-cap stores (account, authenticator, session, recovery state, federation transaction, API key,
delegation, audit record) carries its tenant, a `TenantId`. Every `AuthStore` operation takes the tenant as its first
argument, and `createUnique` enforces uniqueness within a tenant, so the same identifier can exist in two tenants as two
unrelated accounts. A session belongs to one tenant, and `auth.require` never answers `allow` for a request in another.

Why: an operation that cannot express "which tenant" cannot be checked for leaking across tenants. Putting the
tenant in the port's signatures makes a missing scope a type error rather than a review finding.

### 2. The conformance kit checks isolation

`test-cap/conformance` (the **conformance kit**) includes tenant-isolation tests: under real concurrency, no read,
`consumeOnce`, `increment`, `createUnique` or `appendAudit` in one tenant sees or changes another tenant's records. The
kit runs against the memory store and, in CI, against Postgres 15, 16 and 17, SQLite and MySQL 8.4.

Why: the store is app code. The kit is how an app proves its store keeps the guarantee test-cap assumes, the same way
it proves the atomic operations ([ADR 0002](0002-store-port-and-atomic-operations.md)).

### 3. IdP configuration is per tenant

Each tenant has its own OIDC issuers and SAML IdPs, declared in its `TenantConfig` and each entered in the **trust
config** for that tenant with its `acr`
/ `amr` mapping and maximum authentication age ([ADR 0005](0005-policy-and-evidence-based-assurance.md)). An assertion
or ID token is accepted only in the tenant whose configuration names its issuer. A user never supplies a discovery URL,
and private and link-local addresses are blocked ([ADR 0026](0026-strict-defaults-and-deployment-mode.md)).

Why: an IdP trusted by one customer has no standing in another. Binding issuers to tenants closes the "provider signs
in another provider's users" class.

Override: the app declares each tenant's IdPs. Who may change that declaration is an authorization question for the
app or access-cap.

### 4. A tenant can enforce SSO

A tenant can declare SSO as required. For its accounts, sign-in starts only at the tenant's IdP, and the other
sign-in methods are refused. The policy report lists every tenant with enforced SSO.

Why: an organisation that runs its own IdP wants removals and policies there to be final, which is only true when
local sign-in cannot route around it.

Override: enforced SSO is off unless a tenant declares it.

### 5. Deprovisioning is a hook, not a SCIM server

test-cap ships a `deprovision` admin call (flow F19). Called for an account, it:

1. marks the account `disabled`;
2. revokes every session of that account with immediate visibility (`revokeByOwner`,
   [ADR 0002](0002-store-port-and-atomic-operations.md));
3. revokes the delegations issued from them ([ADR 0013](0013-human-machine-and-delegation-separation.md));
4. emits a security event ([ADR 0015](0015-security-events.md), Account Change Disable).

Every ceremony reads the account's status before it produces any evidence, and a disabled account produces none:
password, TOTP, passkey, OIDC, SAML and recovery alike fail with the same reply as a wrong credential (ADR 0009). Every
session read checks the status too, so a session that escaped revocation still answers `unauthenticated`. An app wires
it to whatever tells it a person has left: a SCIM endpoint of its own, an IdP webhook or an admin page.

Why: the plan leaves a SCIM server out of the first build as a stated gap. The hook is the part every deprovisioning
source needs, and it is small enough to verify. Revoking sessions alone would leave the account able to sign in again
the next minute through a passkey or a linked identity; the `disabled` status is what makes the removal stick.

## Consequences

- An app with one customer runs as one tenant and never sees tenancy in its quick start; an app with many passes the
  tenant through without changing how methods, sessions or events work.
- Events and audit records name the tenant, and audit retention is set per tenant
  ([ADR 0020](0020-audit-integrity-model.md)).
- A tenant-isolation bug in an app's store shows up as a failing conformance kit test, not in production.

## Limits

- test-cap isolates what it stores. Isolation of the app's own data is the app's, and authorization across tenants
  is access-cap's.
- There is no SCIM server; the plan records it as a gap. Provisioning (creating accounts from an IdP) is not covered.
- A disabled account cannot be re-enabled in the first build except by the app changing the record; see Open 5.
- The conformance kit proves isolation for the operations it exercises, against the store the app runs it on. It
  does not prove the app always passes the right tenant.

## Open

1. **Cross-tenant administrators.** The plan does not settle whether an administrator from one tenant (for example the
   app owner's support staff) may act in another. Recommendation: no session ever spans tenants. A platform
   administrator acts in another tenant only through impersonation or break-glass
   ([ADR 0014](0014-impersonation-and-break-glass.md)), and every event of that session names both the administrator's
   home tenant and the target tenant. Which administrators may do so is an authorization decision for access-cap.
2. **Resolving the tenant of a request.** The plan does not say how test-cap learns the tenant (subdomain, path,
   identifier domain). Recommendation: an app-supplied resolver from `PlainRequest` to a tenant id, with a single
   default tenant when the app supplies none, so the quick start stays unchanged.
3. **Enforced SSO and the AAL2 default.** An IdP outside the trust config, or without an `acr` mapping, yields AAL1,
   which cannot meet the default AAL2 requirement. Recommendation: under enforced SSO, sign-in must start at the IdP,
   but a local passkey may still be used for step-up; the policy report flags any enforced-SSO tenant whose IdP cannot
   reach AAL2 on its own.
4. **Deprovisioning and API keys.** Whether `deprovision` also revokes API keys the account created depends on who owns
   an API key, which [ADR 0013](0013-human-machine-and-delegation-separation.md) leaves open. Recommendation: yes,
   revoke them in the same call.
5. **Re-enabling a disabled account.** Recommendation: an admin `enable` call that needs a fresh AAL2 administrator
   session (as ADR 0014 section 1), emits Account Change Enable, and restores sign-in without restoring any revoked
   session or delegation.
