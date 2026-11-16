# 0022: Environment variables

## Status

Accepted (2026-11-15). Implemented in phase 2 (`src/env.schema.ts`, `test-cap/env`, the shared variables and the core
keys); the audit keys land in phase 8 with the audit trail, and the SAML keys in phase 8 with SAML. Pinned by:

- `test/env/schema.test.ts`
- `test/env/shared-variables-fixture.test.ts`
- `test/env/no-drift.test.ts`
- `test/env/package-discovery.test.ts`
- `test/env/plain-values.test.ts`
- `test/env/secrets-documented.test.ts`
- `test/examples/env-startup-validation.test.ts`

The recommendations under Open are provisional defaults until the owner decides.

## Context

Owner requirement 7: env-cap shares the required environment variables across the cap packages. Each cap needs some
of the same facts (where the app is served, which system it is, which deployment mode it runs in), and test-cap also
needs secrets of its own.

Two env-cap decisions make this possible:

- **env-cap ADR 0014** lets a package publish its contract. The package names an uncompiled `.ts` schema file in a
  `"envCap": { "schema": "<path>" }` field of its `package.json` and ships that file. An app opts in by listing the
  package in env-cap's `packages` allowlist; env-cap reads the file and never runs it. The generated manifest imports
  the contract by the bare package name, so the package must re-export the contract under the same export name from
  its main entry.
- **env-cap ADR 0050** merges documentation when a package's contract and another contract declare the same variable.
  A field one declaration leaves unset is filled from the other. `DUPLICATE_VARIABLE_DOCUMENTATION` is reported only
  when both declarations set a field to different values.

## Decision

### 1. test-cap publishes its contract

test-cap ships `src/env.schema.ts`, names it in `package.json` as `"envCap": { "schema": "./src/env.schema.ts" }`, and
adds the file to `files`. The `test-cap/env` entry exports the contract. The examples list `test-cap` in env-cap's
`packages` and validate the environment at startup.

Why: this is the mechanism env-cap ADR 0014 defines, so an app gets test-cap's variables documented and validated
alongside its own without copying them.

Override: an app that does not use env-cap ignores it (section 4).

### 2. Three variables are shared by every cap

`APP_ORIGIN`, `APP_SYSTEM_ID` and `APP_ENV` are declared by every cap that reads them, identically: the same validator,
default and documentation. Each cap's declaration is pinned to one shared fixture, and env-cap reports any drift as
`DUPLICATE_VARIABLE_DOCUMENTATION`.

| Variable        | What test-cap uses it for                                                    |
| --------------- | ---------------------------------------------------------------------------- |
| `APP_ORIGIN`    | the expected `Origin` of state-changing requests, and every link in an email |
| `APP_SYSTEM_ID` | the system named in security events and audit records                        |
| `APP_ENV`       | the deployment mode (ADR 0026)                                               |

Why: one flat process environment holds one value per name. If two caps documented the same variable differently, a
reader could not tell which description is true. Pinning both to one fixture keeps them identical; env-cap's report
catches the case where they are not.

Override: none for the declarations. The app sets the values.

### 3. test-cap's own variables

| Variable                   | Purpose                                            | Needed when       |
| -------------------------- | -------------------------------------------------- | ----------------- |
| `AUTH_ENCRYPTION_KEY`      | encrypts OTP secrets at rest (ADR 0027)            | always            |
| `AUTH_CSRF_KEY`            | the synchronizer token for CSRF (ADR 0011)         | always            |
| `AUTH_AUDIT_KEY`           | links the audit chain (ADR 0020)                   | audit trail is on |
| `AUTH_AUDIT_SIGNING_KEY`   | signs audit checkpoints with Ed25519 (ADR 0020)    | audit trail is on |
| `AUTH_SAML_SP_PRIVATE_KEY` | the SAML service provider's signing key (ADR 0028) | SAML is on        |
| `AUTH_SAML_SP_CERT`        | the certificate for that key (ADR 0028)            | SAML is on        |

Every key is documented with `sensitivity: "secret"`, refresh instructions, and an `expiresAt`. The certificate is
public, but it expires, so it carries an `expiresAt` too. Following env-cap ADR 0050, test-cap's declaration holds
the explanation, and the app adds only what is its own, such as `{ expiresAt: "2027-01-01" }` for its copy of a key.
Test keys are generated at run time and never committed.

Why: each secret has one job, so leaking one does not grant another's power, and an `expiresAt` lets env-cap warn
before a key lapses.

Override: the app supplies every value and its expiry.

### 4. Plain values work without env-cap

`createAuth({ env })` reads these variables from whatever object it is given. An env-cap contract is one such object;
a plain object of strings is another.

Why: env-cap is a convenience for documentation and validation, not a requirement for signing in.

Override: the app passes plain values.

## Consequences

- An app that uses env-cap sees test-cap's variables in its own environment documentation, with their sensitivity
  and expiry, and env-cap reports when a shared variable drifts between caps.
- Moving or renaming `src/env.schema.ts` breaks every app that discovers it, the same as moving a file named in
  `exports` (env-cap ADR 0014, Decision 1).
- test-cap carries env-cap's two package obligations: ship the schema source file, and re-export the contract from the
  main entry.

## Limits

- **env-cap checks declarations, not secret stores.** An `expiresAt` says what the app declared, not when the key in
  its vault really expires.
- **Drift is reported, not prevented.** A cap that changes a shared declaration without updating the fixture fails its
  own test; an app that pins two cap versions with different declarations sees the env-cap finding, not an error.
- **The app's own variables** (for example `DATABASE_URL` in the quick start) are the app's to declare.

## Open

1. **Main entry versus `test-cap/env`.** env-cap ADR 0014 imports the contract by the bare package name, so it must be
   exported from `test-cap` itself, not only from `test-cap/env`. That makes env-cap a runtime dependency of the main
   entry. Recommendation: re-export the contract from the main entry, keep `test-cap/env` as the documented import,
   make `@maverickcer/env-cap` a regular dependency, and count it in the main entry's size budget (ADR 0018).
2. **Where the shared fixture lives.** The plan pins the three shared variables to "one fixture" without naming its
   home. Recommendation: internal-package-contract, which every cap already depends on, with each cap's test comparing
   its own declarations against it.
3. **Variables needed only for some capabilities.** The audit and SAML keys are required only when those capabilities
   are on. Recommendation: three contracts, `testCapEnv` (core), `testCapAuditEnv` (audit) and `testCapSamlEnv`
   (SAML), so an app without audit is never asked for audit keys. Phase 2 built them this way.
4. **The key format.** `AUTH_ENCRYPTION_KEY`, `AUTH_CSRF_KEY`, `AUTH_AUDIT_KEY` and `AUTH_AUDIT_SIGNING_KEY` each carry
   a key id and rotate, so one variable holds more than one key. Recommendation: each is a key ring, a comma-separated
   list of `id:base64url` entries, the first one current and the rest used only to decrypt or verify; each parsed entry
   is a `RingKey` (its id and bytes). ADRs 0011, 0020 and 0027 use this format, and phase 2's startup check parses all
   four this way. `AUTH_SAML_SP_PRIVATE_KEY` and `AUTH_SAML_SP_CERT` are single PEM blocks, not key rings.
