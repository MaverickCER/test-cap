# 0026: Strict defaults and deployment mode

## Status

Accepted (2026-11-15). Implemented in phase 2 (deployment mode, the production refusals and the deviation register);
each default lands with its capability in phases 3 to 8. Pinned by the table in section 1 and by:

- `test/config/deployment-mode.test.ts`
- `test/config/node-env-ignored.test.ts`
- `test/config/production-refusals.test.ts`
- `test/policy/deviations-reported.test.ts`
- `test/assurance/deviation-never-raises-evidence.test.ts`

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

Each default is owned by the ADR named beside it; this table is the register of them.

| Area                | Default                                                                                                                                   | Owner    | Test                                               |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | -------- | -------------------------------------------------- |
| Sign-in             | AAL2 on every requirement                                                                                                                 | ADR 0005 | `test/policy/default-requirement-aal2.test.ts`     |
| Sign-up             | enrols a passkey, or a password plus TOTP, in the pre-auth state; a phishing-resistant option is always offered                           | ADR 0005 | `test/flows/sign-up-enrolment.test.ts`             |
| Sessions            | server-side, opaque 256-bit tokens, stored only as SHA-256                                                                                | ADR 0006 | `test/sessions/token-entropy-and-hashing.test.ts`  |
| Session cookie      | `__Host-test-cap`: Secure, HttpOnly, SameSite=Lax, `Path=/`, no Domain                                                                    | ADR 0006 | `test/sessions/cookie-attributes.test.ts`          |
| Federation cookie   | `__Host-test-cap-tx`: SameSite=None, 10 minutes, random id only, bound to a single-use federation transaction                             | ADR 0006 | `test/attacks/tx-cookie-replay.test.ts`            |
| Session limits      | idle 1 h and absolute 24 h at AAL2; 15 min and 12 h at AAL3                                                                               | ADR 0006 | `test/sessions/timeouts.test.ts`                   |
| Rotation            | token rotates on sign-in, step-up, privilege change and impersonation; no cached session skips revocation or assurance                    | ADR 0006 | `test/attacks/session-cache-2fa-bypass.test.ts`    |
| CSRF                | Origin / `Sec-Fetch-Site` check plus a synchronizer token (`AUTH_CSRF_KEY`) on every state-changing route                                 | ADR 0011 | `test/attacks/login-csrf.test.ts`                  |
| XSS                 | one escaping renderer, strict CSP, `nosniff`, `frame-ancestors 'none'`                                                                    | ADR 0011 | `test/attacks/xss-reflected-default-pages.test.ts` |
| Caching             | `no-store` on auth responses, immutable on hashed assets                                                                                  | ADR 0011 | `test/security/cache-control.test.ts`              |
| Brute force         | throttle, never lock out: per account, account+IP, IP and IPv6 /64 on atomic counters; at most 100 consecutive failures per authenticator | ADR 0009 | `test/attacks/ipv6-rate-limit-bypass.test.ts`      |
| Credential stuffing | a detector escalates to the app's challenge hook; no CAPTCHA by default                                                                   | ADR 0009 | `test/attacks/credential-stuffing.test.ts`         |
| Client IP           | from the socket; `X-Forwarded-For` only from declared `trustedProxies`                                                                    | ADR 0009 | `test/attacks/xff-spoofing.test.ts`                |
| Enumeration         | uniform replies and timing, with a dummy argon2 when the account does not exist                                                           | ADR 0009 | `test/attacks/enumeration-timing.test.ts`          |
| Redirects           | `returnTo` accepts same-origin relative paths only                                                                                        | this ADR | `test/attacks/open-redirect.test.ts`               |
| Email links         | built from `APP_ORIGIN`, never from the `Host` header                                                                                     | this ADR | `test/attacks/host-header-poisoning.test.ts`       |
| Federation          | issuer allowlist, no user-supplied discovery URL, private and link-local addresses blocked                                                | this ADR | `test/attacks/oidc-ssrf.test.ts`                   |
| Email sign-in       | off                                                                                                                                       | ADR 0021 | `test/report/email-sign-in-deviation.test.ts`      |
| OTP secrets         | encrypted at rest                                                                                                                         | ADR 0027 | `test/crypto/secret-encryption.test.ts`            |
| Deployment mode     | production unless `APP_ENV` says otherwise                                                                                                | this ADR | `test/config/deployment-mode.test.ts`              |

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

`APP_ENV` must be set. When it is missing, or holds a value test-cap does not know, test-cap runs as production.
test-cap never reads `NODE_ENV`.

Why: the failure that matters is a production server that believes it is in development. Making production the fallback
means a missing or mistyped variable fails safe. `APP_ENV` is shared by every cap
([ADR 0022](0022-environment-variables.md)), so all of them agree on the mode.

Override: the app sets `APP_ENV`.

### 4. Production refuses to start without its prerequisites

In production, `createAuth` throws a configuration error, naming each failed check, unless:

- `APP_ORIGIN` is an HTTPS origin;
- the store is a real store, not `store/memory`;
- every secret the enabled capabilities need is present and is not a default or example value.

Why: each of these turns a working deployment into an insecure one silently: an HTTP origin drops the `__Host-`
cookie's protection, the memory store loses revocations and counters on restart, and a known key is no key.

Override: none in production. A non-production mode relaxes them (Open 1).

## Consequences

- A new app starts strict and stays strict until its policy says otherwise, in writing.
- A mistyped `APP_ENV` or a missing secret stops a deploy at startup, before the first request.
- The policy report becomes the single place to review how far an app has moved from the defaults.

## Limits

- **A deviation is visible, not prevented.** The report lists it; whether it is wise is the app owner's call.
- **Refusals check presence and shape, not secrecy.** A key that is present, long enough and not a known example, but
  leaked, passes.
- **Defaults outside test-cap's response are not covered.** Headers the app sets on its own pages, and its own
  redirects, are the app's.

## Open

1. **Which `APP_ENV` values exist and what each relaxes.** Recommendation: `production`, `staging`, `development` and
   `test`. `staging` behaves as production. `development` and `test` allow an `http://localhost` origin, the memory
   store and keys generated at startup, and the policy report names the mode. The value set is shared by every cap, so
   it belongs in the shared fixture (ADR 0022, Open 2).
2. **Which defaults cannot be relaxed at all.** The plan says each relaxation is a deviation but not whether some are
   fixed. Recommendation: fixed in every mode are the session token stored only as a hash, the session cookie's
   `__Host-`, Secure and HttpOnly attributes, CSRF on state-changing routes, the escaping renderer, same-origin
   `returnTo`, email links from `APP_ORIGIN`, and the federation SSRF block. Declaring `trustedProxies` is
   configuration, not a deviation.
