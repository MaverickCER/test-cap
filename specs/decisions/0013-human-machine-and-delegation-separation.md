# 0013: Human, machine and delegation separation

## Status

Accepted (2026-11-15). Implemented in phase 8 (`test-cap/machine` and `test-cap/delegation`). Answers handoff
question 13.

Planned tests:

- `test/machine/api-key-hash-only.test.ts`
- `test/machine/api-key-expiry-required.test.ts`
- `test/machine/api-key-scopes-required.test.ts`
- `test/assurance/service-subject-no-aal.test.ts`
- `test/assurance/agent-never-borrows-aal.test.ts`
- `test/delegation/lifetime-and-revocation.test.ts`
- `test/attacks/delegation-scope-escalation.test.ts`
- `test/attacks/api-key-created-without-session.test.ts`

## Context

Three kinds of caller reach an app: a person in a browser, a program calling an API, and an AI agent working for a
person. They prove different things. A person runs **ceremonies** that produce **evidence**, and test-cap computes an
**assurance level** from it ([ADR 0005](0005-policy-and-evidence-based-assurance.md)). A program holds a secret it was
given; nothing about it maps to a NIST level. An agent acts on a person's instruction but is not that person.

The usual failure is to treat all three as one: an API key that counts as a signed-in user, or an agent that inherits
everything its user's session can do, including its AAL2. Better Auth's advisories include unauthenticated API-key
creation, which this design turns into an attack test.

The **subject** (see `GLOSSARY.md`) is who a request acts as. access-cap consumes it to decide permissions, so its
shape has to keep the three apart.

## Decision

### 1. Three subject kinds

- `user`: a person, carrying `SessionAssurance`.
- `service`: an API key, carrying scopes and no assurance level.
- `agent`: a delegation, carrying `actingFor` (the user it acts for) and its own scopes, and no assurance level of its
  own or borrowed.

Every subject also names its tenant ([ADR 0012](0012-tenancy.md)).

Why: a consumer that branches on the kind cannot mistake one for another. access-cap can intersect an agent's scopes
with its user's permissions because both are present and separate.

### 2. API keys: hashed, expiring, scoped

An API key is a random secret shown once when it is created. The store keeps only its hash, never the key itself.
Every key has an expiry and at least one scope; creating a key without either fails. Creating a key needs a signed-in
`user` session. A request presenting a valid, unexpired key yields a `service` subject.

Why: a hash in the store means a database leak yields no usable key. A mandatory expiry bounds how long a leaked key
works. Mandatory scopes stop a key from being a master key by default.

Override: the app chooses each key's scopes and expiry within these rules.

### 3. A service subject carries no AAL

No requirement that asks for an assurance level is ever met by a `service` subject. A route reachable by API key
must say so in its requirement.

Why: AAL describes how a person proved who they are. A key proves possession of a bearer secret and nothing about
who holds it. Giving it a level would let a leaked key pass for a signed-in person.

### 4. Delegations: short-lived, scoped, revocable, issued from a session

A **delegation** is issued from a `user` session to an agent. It has a short lifetime, a set of scopes and can be
revoked at any time, with the same immediate visibility as a session revoke
([ADR 0002](0002-store-port-and-atomic-operations.md)). A request carrying a valid delegation yields an `agent` subject
whose `actingFor` names the user. Deprovisioning the user revokes their delegations ([ADR 0012](0012-tenancy.md)).

Why: an agent needs enough authority to do a task, for as long as the task takes, and the person needs a way to stop
it.

Override: the user (through the app) chooses the scopes and lifetime within the limits the policy sets.

### 5. An agent never borrows the human's assurance

The `agent` subject has no `SessionAssurance`. A requirement that asks for AAL2 is not met by an agent even when the
issuing session held AAL3. A step-up never happens on an agent's behalf.

Why: the session's assurance proves the person was present at a moment. An agent acting later, possibly on
instructions the person never saw, has not proven that. Borrowing the level would let prompt injection reach what
step-up protects.

## Consequences

- An API endpoint for machines and an endpoint for people are declared differently, and deny by default
  ([ADR 0024](0024-adapters-and-deny-by-default.md)) never lets an API key through an AAL2 route by accident.
- access-cap receives three distinguishable subject kinds and can gate an agent's tool calls by intersecting its scopes
  with its user's permissions.
- Security events name the subject kind, so a reviewer can tell a person's action from a program's or an agent's
  ([ADR 0015](0015-security-events.md)).

## Limits

- OAuth 2.0 client credentials, mTLS and workload identity are not in the first build; the plan lists mTLS and
  workload identity as gaps.
- An API key is a bearer secret. test-cap cannot tell who presents it; a leaked key works until it expires or is
  revoked.
- test-cap enforces that scopes exist and are carried; what a scope permits is access-cap's or the app's decision.
- An agent's actions are attributed to the agent subject and its `actingFor` user. test-cap cannot tell whether the
  user wanted a particular action.

## Open

1. **How a requirement admits machine and agent subjects.** The plan says a service carries no AAL but not how a route
   accepts one. Recommendation: a requirement lists the subject kinds it admits and the scopes each needs, and the
   default requirement admits `user` only.
2. **Delegation credential format.** The plan does not fix it. Recommendation: an opaque 256-bit token stored only as
   its SHA-256, like a session token ([ADR 0006](0006-sessions-and-cookies.md)), so revocation is visible at once and no
   self-contained token needs ASVS V9 handling.
3. **Lifetime limits.** "Mandatory expiry" and "short-lived" have no numbers in the plan. Recommendation: API keys at
   most 365 days, default 90; delegations at most 1 hour, default 15 minutes; both reported in the policy report.
4. **Who may issue a delegation.** Recommendation: the issuing session must meet the default requirement (AAL2), and
   the delegation's scopes may not exceed what the app allows that user to delegate.
5. **API key ownership.** Whether a key belongs to the user who created it or to the tenant decides what happens when
   that user is deprovisioned ([ADR 0012](0012-tenancy.md), Open 4). Recommendation: record the creating user and tenant
   on every key and revoke the user's keys on deprovision.
