# 0004: Package entries, capability gates and distribution

## Status

Accepted (2026-11-15). Each entry is implemented in the phase the table in section 1 names; the gate rule applies from
phase 2; the release tarball is built in phase 9.

Answers [handoff question](../../GLOSSARY.md) 4 (package shape).

Planned tests:

- `test/package/exports-have-gates.test.ts` (every subpath in `package.json` `exports` names its gate, and every test
  that gate lists exists and is in the suite);
- `test/package/entries-resolve.test.ts` (each entry imports from the built `dist/` under ESM);
- `test/package/core-imports-no-adapter.test.ts` (the core entry pulls in no adapter, store, UI or SAML code);
- `test/package/peer-dependencies.test.ts` (framework packages are optional peers of the entry that needs them);
- `test/package/tarball-install.test.ts` (the release tarball installs with scripts disabled and every entry resolves);
- `test/package/size-budgets.test.ts` (each entry within its budget, ADR 0018).

The recommendations under Open are provisional defaults until the owner decides.

## Context

Question 4 asked for the entry points, whether the package is scoped, and whether everything is tree-shakable so that
a passkey-only app does not ship SAML.

Requirement 5 asks for every secure, free method from the start. A review proposed splitting the first release to
drop methods, adapters and the audit trail; the plan rejected that because it conflicts with requirement 5, and
replaced it with build order plus a gate per capability. The entries are where that gate becomes visible: a
capability that is not finished is not importable.

The package is internal. It is public on GitHub for the free review apps, `"private": true`, and never published to
npm (ADR 0019).

## Decision

### 1. One entry per capability

| Entry                     | Holds                                                                                               | Phase |
| ------------------------- | --------------------------------------------------------------------------------------------------- | ----- |
| `test-cap`                | `createAuth`, the dispatcher, sessions, assurance, policy, events and the human methods             | 3, 5  |
| `test-cap/env`            | The env-cap schema for `APP_*` and `AUTH_*` variables (ADR 0022)                                    | 2     |
| `test-cap/store/memory`   | The development store (ADR 0002)                                                                    | 2     |
| `test-cap/conformance`    | The store conformance kit (ADR 0002)                                                                | 2     |
| `test-cap/store/sql`      | The SQL store and its migrations: Postgres first, then SQLite and MySQL (ADR 0002)                  | 3, 6  |
| `test-cap/express`        | Express adapter (ADR 0003, ADR 0024)                                                                | 3     |
| `test-cap/fetch`          | `fetch` handler wrapper                                                                             | 6     |
| `test-cap/nest`           | Nest global guard and `@Public()`                                                                   | 6     |
| `test-cap/next`           | Next.js route handler, server helpers and optional `proxy`                                          | 6     |
| `test-cap/tanstack-start` | TanStack Start global middleware                                                                    | 6     |
| `test-cap/client`         | Browser client on `@simplewebauthn/browser`, with conditional-mediation autofill                    | 7     |
| `test-cap/forms`          | The framework-free form model (ADR 0025)                                                            | 7     |
| `test-cap/react`          | `<SignInForm/>`, `<SignUpForm/>`, `<RecoverForm/>` and the other components (ADR 0025)              | 7     |
| `test-cap/machine`        | API keys and the `service` subject (ADR 0013)                                                       | 8     |
| `test-cap/delegation`     | Delegations and the `agent` subject (ADR 0013)                                                      | 8     |
| `test-cap/audit`          | The opt-in audit trail, checkpoints, `verifyAudit`, `sessionTimeline` and `accessReport` (ADR 0020) | 8     |
| `test-cap/report`         | The policy report (ADR 0005)                                                                        | 8     |
| SAML entry (name open)    | The SAML 2.0 SP, Node only at first (ADR 0028)                                                      | 8     |

`./package.json` is also exported. The package is ESM with `"sideEffects": false`.

Why: an app imports only what it uses. Adapters, stores, UI, machine identity, audit and SAML each carry dependencies
(a framework, `@simplewebauthn/browser`, React, `@node-saml/node-saml`) that most apps do not need, and a separate
entry keeps them out of the core's graph.

### 2. An entry enters `exports` only when its gate passes

A capability's gate is the set of tests it must pass before it is added to `package.json` `exports`:

- its unit, contract, negative and attack tests;
- its rows in the runtime matrix over the built `dist/` (ADR 0023);
- its size budget (ADR 0018);
- for a store, the conformance kit (ADR 0002);
- for an adapter, the adapter conformance suite (ADR 0003);
- for a protocol, its conformance and vector tests (ADR 0016);
- for UI, the UX contract tests (ADR 0025).

`test/package/exports-have-gates.test.ts` fails when an export names no gate or its gate's tests are missing.

Why: requirement 5 keeps every method in scope, and the gate keeps an unfinished one out of reach. Build order decides
when a capability ships; the gate decides whether it can.

### 3. Framework packages are optional peer dependencies of their entry

React is a peer of `test-cap/react`; Express, Nest, Next.js and TanStack Start are peers of their adapters. The core's
dependencies are the libraries every app needs (ADR 0001). The app's database driver is never a dependency: the app
passes a `query` function (ADR 0002).

Why: a Next.js app should not install Express, and an Express app should not install React.

### 4. Distribution is a GitHub Release tarball

The release workflow builds the package and attaches `test-cap-X.Y.Z.tgz` to the GitHub Release. Apps install it by
URL:

```sh
npm i https://github.com/MaverickCER/test-cap/releases/download/vX.Y.Z/test-cap-X.Y.Z.tgz
```

The tarball is prebuilt, so it has no install-time script (IPC forbids them, and npm does not run `prepare` for a
tarball URL). `package.json` keeps `"private": true`, which stops an accidental `npm publish`. The name is unscoped
`test-cap`: it never reaches a registry, so npm availability does not matter.

Why: an internal package needs a pinned, verifiable artefact without a registry. A git install would run `prepare`
and build on the app's machine; a prebuilt tarball installs the bytes CI tested.

## Consequences

- A passkey-only app does not ship SAML, an adapter it does not use, or the audit trail.
- The `exports` map is a live list of what has passed its gate; reading it answers "what can I use today".
- Each entry has its own size budget and its own runtime rows, so a regression is attributed to one entry.
- The private-phase channel needs a decision before the repository goes private.

## Limits

- **The human methods share the core entry.** Methods are on by default (requirement 5), so passwords, TOTP,
  passkeys, recovery codes, email and OIDC are all reachable from `createAuth`. A passkey-only app still ships the
  password and OIDC code unless the bundler can drop it; question 4's tree-shaking aim is met for SAML, adapters, UI,
  machine identity and audit, and only partly met for the human methods. See Open.
- **A gate for an in-core method cannot use `exports`.** Section 2 works by subpath; a method inside the core needs
  another switch. See Open.
- **Tarball installs have no registry features.** No `npm outdated`, no semver ranges, no provenance from a registry;
  version bumps are edits to the URL.

## Open

1. **Name of the SAML entry.** Recommendation: `test-cap/saml`, with `@node-saml/node-saml` as an optional peer
   dependency, so an app that does not use SAML never installs `xml-crypto` or `@xmldom/xmldom`.
2. **Gating and loading the in-core methods.** Recommendation: a method that has not passed its gate is absent from
   the build and from the `createAuth` config type, not merely switched off; and each method's library is loaded with
   a dynamic `import()` the first time the method is used, so its weight is paid only by apps that use it. ADR 0018's
   budgets measure the result.
3. **The optional stylesheet.** The UX contract mentions an optional stylesheet for WCAG 2.2 target sizes but names no
   entry. Recommendation: `test-cap/styles.css`, added with the phase 7 gate.
4. **Private-phase channel.** Already an owner question in the plan: a token-authenticated tarball or GitHub Packages.
   Recommendation: a token-authenticated tarball, which keeps the install command and the artefact unchanged.
