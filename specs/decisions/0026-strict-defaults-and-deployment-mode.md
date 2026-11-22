# 0026: Strict defaults and deployment mode

## Status

Accepted (2026-11-15). Implemented in phase 2 (deployment mode, the production refusals and the deviation register);
each default lands with its capability in phases 3 to 8. Pinned by the tests each owning ADR lists (section 1) and by:

- `test/config/deployment-mode.test.ts`
- `test/config/node-env-ignored.test.ts`
- `test/config/production-refusals.test.ts`
- `test/policy/deviations-reported.test.ts`
- `test/assurance/deviation-never-raises-evidence.test.ts`

The recommendations under Open are provisional defaults until the owner decides.

## Context

Owner requirement 9: withstand XSS, CSRF, brute force and the usual bypasses, with strict secure defaults and AAL2
everywhere by default. A default only protects the apps that keep it, and every app will want to relax something. The
question is how a relaxation stays visible.

test-cap's answer is the deviation: a line in the policy that relaxes a strict default. The policy report lists every
deviation, and a deviation never raises what evidence is worth.

Most auth libraries switch their checks on `NODE_ENV`. Bundlers and hosts set `NODE_ENV` for their own reasons, and a
production server that starts without it would run with development behaviour.

## Decision

### 1. The strict defaults

This table is the register of the strict defaults: each default by name and the ADR that owns it. The owning ADR
holds the value and lists the tests that pin it; the register repeats neither, so it cannot drift from them.

| Area                | Default                                    | Owner               |
| ------------------- | ------------------------------------------ | ------------------- |
| Sign-in             | the default requirement                    | ADR 0005            |
| Sign-up             | enrolment in the pre-auth state            | ADR 0005            |
| Sessions            | server-side opaque tokens                  | ADR 0006            |
| Session cookie      | `__Host-test-cap`                          | ADR 0006            |
| Federation cookie   | `__Host-test-cap-tx`                       | ADR 0006            |
| Session limits      | idle and absolute limits per level         | ADR 0006            |
| Rotation            | rotation on every change of trust          | ADR 0006            |
| CSRF                | origin check and synchronizer token        | ADR 0011            |
| XSS                 | escaping renderer and strict CSP           | ADR 0011            |
| Caching             | `no-store` and immutable assets            | ADR 0011            |
| Brute force         | throttles and the failure ceiling          | ADR 0009            |
| Credential stuffing | the detector and challenge hook            | ADR 0009            |
| Client IP           | socket address and `trustedProxies`        | ADR 0009            |
| Enumeration         | uniform replies and timing                 | ADR 0009            |
| Email sending       | send throttles                             | ADR 0009            |
| Passwords           | blocklist and breach screening             | ADR 0010            |
| Email sign-in       | off                                        | ADR 0021            |
| OTP secrets         | encryption at rest                         | ADR 0027            |
| Federated assurance | at most AAL2                               | ADR 0005            |
| Redirects           | same-origin `returnTo`                     | this ADR, section 5 |
| Email links         | links from `APP_ORIGIN`                    | this ADR, section 5 |
| Federation fetches  | the SSRF block                             | this ADR, section 5 |
| Deployment mode     | production unless `APP_ENV` says otherwise | this ADR, section 3 |

Why: one register lets a reader see every default at once, and lets the policy report check that each relaxation of
one appears as a deviation.

Override: see section 2.

### 2. Every relaxation is a declared deviation

An app relaxes a default only by a line in its policy. The policy report lists every such line, and a relaxation made
any other way does not exist: there is no global "insecure" switch. A deviation changes what test-cap enforces; it
never changes what a piece of evidence is worth.

Why: an app owner, a reviewer or access-cap can read one report and know every way this app is weaker than the
default.

Override: this is the override mechanism.

### 3. Deployment mode comes from `APP_ENV`, and an unknown mode is production

`APP_ENV` must be set. test-cap reads it as a `DeploymentMode`. When it is missing, or holds a value test-cap does not
know, test-cap runs as production. test-cap never reads `NODE_ENV`.

Why: the failure that matters is a production server that believes it is in development. Making production the fallback
means a missing or mistyped variable fails safe. `APP_ENV` is shared by every cap
([ADR 0022](0022-environment-variables.md)), so all of them agree on the mode.

Override: the app sets `APP_ENV`.

### 4. Production refuses to start without its prerequisites

In production, `createAuth(config)` (its `config` is an `AuthConfig`) throws a configuration error, naming each failed
check, unless:

- `APP_ORIGIN` is an HTTPS origin;
- the store is a real store, not `store/memory`;
- every secret the enabled capabilities need is present and is not a default or example value;
- the clock, the random source and the argon2id cost are test-cap's defaults. A custom `Clock`, `RandomSource` or
  `argon2Cost` ([ADR 0018](0018-budgets.md) §1) is accepted only in `test` mode.

Why: each of these turns a working deployment into an insecure one silently: an HTTP origin drops the `__Host-`
cookie's protection, the memory store loses revocations and counters on restart, a known key is no key, a frozen
clock disables every expiry, a predictable random source makes every token guessable (800-63B-4 §3.2.12, ASVS
6.5.3), and a lowered argon2id cost makes every stored hash cheaper to crack.

Override: none in production. A non-production mode relaxes them (Open 1).

### 5. Redirects, email links and federation fetches

- **Redirects.** `returnTo` accepts a same-origin relative path only, checked after URL parsing; a protocol-relative
  target (`//host`, `/\host`), an origin that only starts with the app's, and a `javascript:` or `data:` target are all
  refused.
- **Email links.** Every link in an email is built from `APP_ORIGIN`, never from the `Host` header.
- **Federation fetches.** Issuers come from an allowlist; no discovery or endpoint URL comes from a user; and a fetch
  to a private or link-local address is blocked.

Why: each closes a class Better Auth's advisories show (open redirects, Host poisoning, discovery SSRF), and none
has a legitimate use an app would lose.

Override: whether these three can be relaxed at all is Open 2, which recommends never.

Planned tests: `test/attacks/open-redirect-protocol-relative.test.ts`,
`test/attacks/open-redirect-origin-prefix.test.ts`, `test/attacks/open-redirect-scheme.test.ts`,
`test/attacks/host-header-poisoning.test.ts`, `test/attacks/federation-discovery-ssrf.test.ts`.

## Consequences

- A new app starts strict and stays strict until its policy says otherwise, in writing.
- A mistyped `APP_ENV` or a missing secret stops a deploy at startup, before the first request.
- The policy report becomes the single place to review how far an app has moved from the defaults.

## Limits

- **A deviation is visible, not prevented.** The report lists it; whether it is wise is the app owner's call.
- **Refusals check presence and shape, not secrecy.** A key that is present, long enough and not a known example, but
  leaked, passes.
- **WebKit and `http://localhost`.** Every test-cap cookie is `__Host-` and so `Secure`. WebKit does not store or send a
  `Secure` cookie to `http://localhost` (WebKit bug 232088, still open; a partial fix landed in 2026-04 without the
  cookie-storage change it needs), so sign-in on `http://localhost` works in Chromium and Firefox but not in Safari
  or Playwright's WebKit. Development mode therefore documents `https://localhost` with a local certificate for
  WebKit, which the origin check already accepts.
- **Defaults outside test-cap's response are not covered.** Headers the app sets on its own pages, and its own
  redirects, are the app's.

## Open

1. **Which `APP_ENV` values exist and what each relaxes.** Recommendation: `production`, `staging`, `development` and
   `test`. `staging` behaves as production. `development` and `test` allow an `http://localhost` origin (or
   `https://localhost`, which WebKit needs; see Limits), the memory store and keys generated at startup, and the policy
   report names the mode. The value set is shared by every cap, so it belongs in the shared fixture (ADR 0022, Open 2).
2. **Which defaults cannot be relaxed at all.** The plan says each relaxation is a deviation but not whether some are
   fixed. Recommendation: fixed in every mode are the session token stored only as a hash, the session cookie's
   `__Host-`, Secure and HttpOnly attributes, CSRF on state-changing routes, the escaping renderer, same-origin
   `returnTo`, email links from `APP_ORIGIN`, and the federation SSRF block. Declaring `trustedProxies` is
   configuration, not a deviation.
