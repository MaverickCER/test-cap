# 0005: Policy and the evidence-based assurance model

## Status

Accepted (2026-11-15). Implemented in phase 3 (evidence, session assurance, the level rules for password and TOTP,
`defineAuthPolicy` and `auth.require`), phase 5 (the rules for passkeys, email and OIDC) and phase 8 (the policy
report that recomputes and checks them).

Answers [handoff question](../../GLOSSARY.md) 5 (policy model).

Planned tests:

- `test/assurance/password-totp-levels.test.ts` (password alone and TOTP alone are AAL1; together they are AAL2);
- `test/assurance/passkey-without-uv.test.ts` (a passkey without user verification is single-factor);
- `test/assurance/synced-passkey-aal.test.ts` (a synced passkey never reaches AAL3);
- `test/assurance/aal3-requires-all.test.ts` (each of the four AAL3 conditions removed in turn drops the level;
  attestation alone never gives AAL3);
- `test/assurance/email-never-raises.test.ts` (email codes and magic links add no level, with or without the
  deviation);
- `test/assurance/federated-aal-capped.test.ts` (a mapped `acr` yields at most AAL2; a trust config that maps any
  value to AAL3 is refused at startup);
- `test/assurance/untrusted-acr.test.ts` (an issuer outside the trust config, or an unmapped `acr`, never raises the
  level; an authentication older than the issuer's maximum age counts as AAL1);
- `test/assurance/evidence-decay.test.ts` (expired evidence lowers the level);
- `test/assurance/policy-version-change.test.ts` (a session is recomputed under a new policy version);
- `test/policy/require-outcomes.test.ts` (each of the five outcomes, and nothing else);
- `test/policy/default-requirement-aal2.test.ts`;
- `test/policy/deviations-reported.test.ts` (every relaxation appears in the policy report);
- `test/report/recomputes-assurance.test.ts` (the report's levels match the model's for every rule above).

The recommendations under Open are provisional defaults until the owner decides.

## Context

The handoff asked how a route declares its assurance level, how methods map to levels, how step-up is reported, and
how declarations link to access-cap's capabilities (question 5). Its starting design let a developer declare "which
methods count toward which assurance level".

A review of the plan rejected that last idea: assurance is computed from validated evidence, never declared by a
method. A method is configuration (GLOSSARY); what a ceremony proved is evidence. If configuration could declare a
level, one line could make a synced passkey AAL3 or an email link AAL2, and the policy report would repeat the claim
instead of checking it. NIST SP 800-63B-4 also ties levels to properties of the authenticator and the ceremony, not to
the name of a method:

- §2.3.2: "syncable authenticators SHALL NOT be used at AAL3"; the authenticator at AAL3 "SHALL have a
  non-exportable private key and SHALL provide phishing resistance".
- Appendix B: verifiers prefer user verification and inspect the UV flag; without UV, a passkey is single-factor.
  Attestation SHOULD be used when available and SHOULD NOT block syncable authenticators. Nothing says attestation
  alone establishes AAL3.
- §3.1.3.1: "Email SHALL NOT be used for out-of-band authentication".

## Decision

### 1. Every ceremony yields evidence

A successful ceremony produces `AuthenticationEvidence`: the method, the factors, whether it is phishing-resistant and
replay-resistant, the key protection (`non-exportable`, `syncable` or `unknown`), whether user verification happened,
when, and for federation the issuer and the upstream `acr` and `amr`. A failed ceremony produces none.

Why: the level rules below need these properties, and recording them as data lets the policy report recompute every
level from what was proven.

### 2. The verifier computes session assurance from the evidence still valid

`SessionAssurance` holds the level, the evidence it rests on, the time of the last multi-factor ceremony and of the
last phishing-resistant ceremony, the step-up history, the policy version, and the idle and absolute expiry. It is
computed from the evidence still valid, every time it is read. It is never stored as a bare level.

Evidence expires. When the evidence supporting a level expires, the level decays to what the remaining evidence
supports. When the policy version changes, the next read recomputes the assurance under the new policy from the same
evidence.

Why: a stored level outlives the proof behind it. Recomputing from evidence makes decay and policy changes automatic,
and makes the session cache bypass of ADR 0001 impossible by construction: there is no cached level to bypass.

The evidence a session stores is bounded: only the newest evidence of each (method, authenticator), and only the newest
step-up of each method, are kept, so a ceremony repeated a thousand times leaves one entry. The newest ceremony with an
authenticator is what that authenticator proves now, and the level rules and recency times need nothing older. The
times are computed in one pass over the evidence sorted by time (a suffix scan), so a read costs a sort and a linear
scan (`test/sessions/evidence-bound.test.ts`, `test/property/recency.property.test.ts`).

Why the bound: without it a signed-in attacker could add an entry with every step-up (about 2,880 a day) and slow
every read of their own session, and the per-item check the times used before was quadratic in the entries.

### 3. The level rules

| Evidence                                                                                            | Level                    |
| --------------------------------------------------------------------------------------------------- | ------------------------ |
| Password                                                                                            | AAL1                     |
| TOTP                                                                                                | AAL1                     |
| Password plus TOTP                                                                                  | AAL2                     |
| Passkey or security key with user verification                                                      | AAL2, phishing-resistant |
| Passkey or security key without user verification                                                   | Single-factor: AAL1      |
| Passkey meeting every AAL3 condition (below)                                                        | AAL3                     |
| Email sign-in code or magic link                                                                    | Adds nothing (section 5) |
| OIDC, issuer not in the trust config or context unmapped                                            | AAL1                     |
| OIDC, issuer in the trust config with an `acr`/`amr` mapping, within its maximum authentication age | The mapped level, ≤ AAL2 |

AAL3 needs all four of:

- a non-exportable key (the backup-eligible flag clear);
- attestation verified to a trusted root;
- user verification;
- phishing resistance.

Attestation alone never establishes AAL3, and a synced passkey (backup-eligible) stops at AAL2.

Federated evidence stops at AAL2. The trust config (`TrustConfig`, one `TrustedIssuer` per issuer, scoped to a tenant
by ADR 0012) maps an issuer's `acr` or `amr` values to AAL1 or AAL2 only. A mapping that names AAL3 is refused when
`createAuth` starts, with a `ConfigError` (ADR 0003). The same rule applies to SAML's `AuthnContextClassRef`
(ADR 0028).

The evidence records its key protection as a `KeyProtection` value, and a level is an `AssuranceLevel` (`AAL1`, `AAL2`
or `AAL3`).

Why: each rule restates a NIST property as a check on evidence. Combining evidence (password plus TOTP) is how two
single-factor ceremonies make a multi-factor session, and how step-up adds to a session instead of replacing it.

Override: none. An app cannot move a method to another level. The trust config is the only way to let an
upstream `acr` count, up to AAL2, and it is listed in the policy report.

Why federation stops at AAL2: AAL3 needs a non-exportable key, attestation to a trusted root, user verification and
phishing resistance, and test-cap observes none of the four for a sign-in that happened at an identity provider. An
`acr` that claims AAL3 is the provider's word, and raising a level on a word without evidence is what this model
exists to prevent.

### 4. The policy declares requirements by test-cap's own ids

`defineAuthPolicy` returns an `AuthPolicy` that holds the requirements (each a `Requirement`), each under a requirement
id owned by test-cap, such as `billing.update`. A requirement states the session assurance a route or operation needs: a
level, and optionally how recent the last multi-factor or phishing-resistant ceremony must be. The default requirement,
used by deny by default (ADR 0024), is AAL2.

An app, or access-cap, maps its own capability ids to these requirement ids. Neither package imports the other.

Why: if test-cap used access-cap's ids, the two packages would have to release together. Separate ids with a mapping
in the app keep each package independent, and "which roles must use MFA" (question 5) becomes a mapping from a role's
capabilities to requirements that need AAL2 or above.

Override: the app defines its own requirements. Raising one is free. Lowering the default below AAL2 is a deviation
(section 6).

### 5. Email never raises the level

Email sign-in codes and magic links are off by default. Turning them on is a deviation. Email produces no
`AuthenticationEvidence`, so it can neither satisfy AAL2 nor contribute a factor to it. ADR 0021 owns email's role.

Why: §3.1.3.1, quoted above. A deviation can make email usable; it cannot make it worth more.

### 6. Every relaxation is a deviation

A deviation (`Deviation`) is a line in the policy that relaxes a strict default: turning on email sign-in, lowering the
default requirement, lengthening a timeout past the limits of ADR 0006. The policy report, a `PolicyReport` that
`renderPolicyReport` turns into Markdown, lists every deviation. A deviation never raises what evidence is worth: the
level rules of section 3 hold whatever the policy says.

Why: an internal reader of the policy report should see every place the app chose to be weaker than the default,
in one list, without reading code.

### 7. `auth.require` answers with one of five outcomes

`auth.require(req, requirementId)` returns a `RequireResult`, exactly one of:

| Outcome           | When                                                     | Carries              |
| ----------------- | -------------------------------------------------------- | -------------------- |
| `allow`           | The session assurance meets the requirement              | The subject          |
| `step-up`         | A session exists but its assurance falls short           | The missing evidence |
| `enroll`          | The session is in the pre-auth state: MFA not yet set up | Nothing more         |
| `recovery-only`   | The session is in the recovery state (ADR 0007)          | Nothing more         |
| `unauthenticated` | No valid session                                         | Nothing more         |

`step-up` names what is missing (a level, phishing resistance, or a fresher ceremony), so the default pages and
`<StepUp/>` can offer only the methods that would satisfy it.

Why: five explicit outcomes leave an adapter nothing to infer. A boolean would collapse "sign in", "finish enrolling",
"you are recovering" and "prove more" into one denial, and the UI could not route the person to the right page.

## Consequences

- A method can be added without touching the level rules, and a level rule can be tightened without touching any
  method.
- The policy report can check every level it prints, because it recomputes them from the same evidence the runtime
  used.
- Step-up is precise: a session at AAL2 asked for a phishing-resistant requirement is asked for a passkey, not for
  "more".
- access-cap and test-cap share a mapping, not a dependency.

## Limits

- **The key-protection signal comes from the authenticator.** The backup-eligible flag and attestation are what the
  authenticator reports, verified by `@simplewebauthn/server` against the trusted roots the app configures. test-cap
  cannot check a key's storage beyond that.
- **`unknown` key protection is treated as exportable.** It can support AAL2 with user verification, never AAL3.
- **Requirement ids do not authorise.** `allow` means the session's assurance is enough; whether the subject may act
  is access-cap's decision.
- **Machine and agent subjects carry no level.** `auth.require` for a `service` or `agent` subject follows ADR 0013.
- **The plan names what decays but not each evidence lifetime.** See Open.
- **Federated sign-in never reaches AAL3.** An app whose IdP really does meet AAL3 still gets AAL2 from it; a
  requirement at AAL3 needs a local passkey that meets every AAL3 condition, by step-up if need be.

## Open

1. **Evidence lifetimes.** Recommendation: evidence that supports AAL3 expires at AAL3's limits (12 h absolute, 15
   min idle); the session then decays to AAL2 if AAL2 evidence is still valid, and ends at AAL2's limits (24 h, 1 h
   idle), as ADR 0006 sets them.
2. **An unknown requirement id.** Recommendation: requirement ids are a string-literal type derived from
   `defineAuthPolicy`, so an unknown id is a type error; at run time an unknown id throws, failing closed, rather than
   falling back to the default requirement.
