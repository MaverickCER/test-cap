# test-cap guide

One story per task, from starting the app to signing a person up, protecting a route and revoking a session. The
[README](README.md) says what test-cap is and whether it fits; [ADOPTION.md](ADOPTION.md) gives the rollout steps.
Each section names the decision record that owns its rules, and anything not built yet is marked **planned**.

## How a request flows

```text
framework request ─► adapter ─► PlainRequest (bytes) ─► core ─► PlainResponse ─► adapter ─► framework response
```

The adapter only converts. The core parses the body, reads the cookies, checks CSRF and runs the route against the
app's `AuthStore` ([ADR 0003](specs/decisions/0003-byte-transport-and-dispatcher.md)). An app with no adapter calls
`auth.handle(req)` with its own `PlainRequest`: method, URL, `Headers`, body bytes, and optionally the client address
and an abort signal.

## Starting it: `createAuth`

```ts
const auth = createAuth({
  store,
  env: process.env,
  hibpFetch: fetch,
  sendEmail: (message) => mailer.send(message),
  onEvent: (event) => events.write(event),
})
```

| Option            | What it is                                                                           |
| ----------------- | ------------------------------------------------------------------------------------ |
| `store`           | The app's `AuthStore`. Production and staging refuse one that is not durable.        |
| `env`             | `process.env`, env-cap's parsed values or a plain object with the same names.        |
| `hibpFetch`       | The `fetch` the breached-password check calls to reach HIBP. Required.               |
| `sendEmail`       | Sends each `EmailMessage` test-cap builds: sign-up's confirmation code. Not awaited. |
| `policy`          | From `defineAuthPolicy`; without one, every requirement is the default AAL2.         |
| `onEvent`         | Receives every security event. A sink that throws never changes an outcome.          |
| `tenant`          | The tenant every operation is scoped to; `default` when absent.                      |
| `clock`, `random` | Replacements for tests. Any mode but `test` refuses to start with one.               |

`createAuth` reads five variables ([ADR 0022](specs/decisions/0022-environment-variables.md),
[docs/ENVIRONMENT.md](https://github.com/MaverickCER/test-cap/blob/main/docs/ENVIRONMENT.md)):

- `APP_ENV`: the deployment mode, `production`, `staging`, `development` or `test`. Missing or unknown runs as
  `production` ([ADR 0026](specs/decisions/0026-strict-defaults-and-deployment-mode.md)).
- `APP_ORIGIN`: the bare origin, such as `https://app.example`. It must be `https`, except on `localhost`,
  `127.0.0.1` or `[::1]` outside production and staging.
- `APP_SYSTEM_ID`: the system's name in every security event. Production refuses to start without it.
- `AUTH_ENCRYPTION_KEY` and `AUTH_CSRF_KEY`: key rings of comma-separated `id:base64url` entries of at least 32 bytes,
  newest first. Production and staging require both. Elsewhere a missing key is generated for the life of the process.

A deployment that may not start throws one `ConfigError` whose `problems` name every reason at once.

## Sign up

Every `POST` under `/auth/` needs a same-origin signal and a synchronizer token. The signal is an `Origin` equal to
`APP_ORIGIN`, or `Sec-Fetch-Site: same-origin` when `Origin` is absent or `null`. A browser gets its first token from
`GET /auth/session`. It sends the token back as the `X-CSRF-Token` header or a `csrfToken` form field, never both. A
response that starts or changes a session carries the next token in its own `X-CSRF-Token` header.

| Step | Request                                             | Answer                                                                  |
| ---- | --------------------------------------------------- | ----------------------------------------------------------------------- |
| 1    | `GET /auth/session`                                 | `{ session: null, csrfToken }` and a pre-session cookie                 |
| 2    | `POST /auth/sign-up` `identifier`                   | a `pre-auth` session, `{ outcome: "enroll", returnTo }` and an email    |
| 3    | `POST /auth/email/confirm` `code`                   | the address confirmed, and `{ outcome: "enroll" }`                      |
| 4    | `POST /auth/password` `password`                    | `{ outcome: "enroll", enrolled: ["password"] }`                         |
| 5    | `POST /auth/totp/enrol`                             | `{ authenticatorId, secret }` for the authenticator app                 |
| 6    | `POST /auth/totp/confirm` `authenticatorId`, `code` | an `authenticated` session at AAL2 and `{ outcome: "allow", returnTo }` |

Sign-up mails the address a 6-digit code through `sendEmail`. The code is valid for 24 hours and works once. The store
keeps only an HMAC of it, under a key derived from `AUTH_ENCRYPTION_KEY`, so a database read alone cannot test
guesses offline. The person types the code in; the email's one link goes to the confirmation page and never carries
the code. `POST /auth/email/resend` mails a new code and retires the old one.

Sends are limited per address to one a minute and five an hour. Per IP address or IPv6 /64, the limit is twenty an
hour. Over a limit, nothing is sent, and the reply is the same with `retryAfterMs`. Five wrong tries end a code for
the rest of its life, and further tries answer `429` with `Retry-After`. A resend gives a new code with five tries of
its own. Confirming adds no assurance: email never raises the level
([ADR 0021](specs/decisions/0021-excluded-methods-and-emails-role.md),
[ADR 0009](specs/decisions/0009-abuse-and-proxy-trust.md)). The password waits for the confirmation
(`409 confirm-email-first`), and the session stays at `enroll` until every step is done.

Password rules map to NIST SP 800-63B-4 ([ADR 0010](specs/decisions/0010-passwords-and-breach-screening.md)):

- at least 8 characters when a second factor is required (the default);
- at least 15 when a policy deviation lets a password alone pass;
- at most 256, and no composition rules;
- screened against a bundled blocklist, and through `hibpFetch` against the HIBP range API with padding.

The TOTP secret is stored encrypted under `AUTH_ENCRYPTION_KEY`. A code is refused if its time step was already used.
An account holds at most five TOTP authenticators; a sixth answers `409 too-many-authenticators`
([ADR 0027](specs/decisions/0027-otp-on-web-crypto-and-encrypted-secrets.md)).

Sign-up never looks an account up, so its replies say nothing about whether the address is taken. An unconfirmed
sign-up never claims the address; the confirmation claims it. When another account confirmed the address first, the
reply is the same and nothing is claimed ([ADR 0008](specs/decisions/0008-account-linking.md)).

## Default pages

`auth.handle` also serves server-rendered pages for these steps, so an app needs no UI code for them
([ADR 0025](specs/decisions/0025-default-ui-and-form-contract.md)). The pages answer `GET` on `/auth/sign-up`,
`/auth/email/confirm`, `/auth/password`, `/auth/totp/enrol`, `/auth/sign-in`, `/auth/step-up` and `/auth/sign-out`.

- Each page posts its form to the route of the same step.
- A form post that sends `Accept: text/html` gets a `303` to the next page, or the page again with the refusal in its
  form. A JSON post keeps its JSON.
- The pages work without JavaScript, carry the strict CSP with no inline script or style, and are never cached.
- Their script and stylesheet are served under `/auth/assets/test-cap.<hash>.<js|css>`, cached as immutable.

## Sign in

| Step | Request                                       | Answer                                                   |
| ---- | --------------------------------------------- | -------------------------------------------------------- |
| 1    | `POST /auth/sign-in` `identifier`, `password` | a session at AAL1 and `{ outcome: "step-up", returnTo }` |
| 2    | `POST /auth/totp/verify` `code`               | the session at AAL2 and `{ outcome: "allow", returnTo }` |

A form post that ends at `allow` answers `303` to `returnTo`. `returnTo` must be a same-origin relative path;
anything else is a 400. A wrong password, an unknown or unconfirmed address and a disabled account all answer
`401 invalid-credentials`. Each spends the same argon2id work
([ADR 0009](specs/decisions/0009-abuse-and-proxy-trust.md)).

Sign-in finds an account only through a confirmed identifier, so an account signs in again later by the address it
confirmed at sign-up.

## Requirements and step-up

The default requirement is AAL2. A route that needs more names a requirement in the policy and checks it next to the
data:

```ts
const policy = defineAuthPolicy({
  version: "2026-11",
  requirements: { "billing.update": { level: "AAL2", multiFactorWithinMs: 5 * 60_000 } },
})
const auth = createAuth({ store, env: process.env, hibpFetch: fetch, sendEmail, policy })

app.post("/billing", async (req, res) => {
  const result = await auth.require(toPlainRequest(req), "billing.update")
  if (result.outcome !== "allow") return res.status(403).json({ outcome: result.outcome })
  // update billing for result.subject
})
```

`toPlainRequest` stands for the app's own conversion; the Express adapter already did the default check before the
handler ran. `auth.require` answers one of five outcomes ([ADR 0005](specs/decisions/0005-policy-and-evidence-based-assurance.md)):

| Outcome           | Meaning                                                                    |
| ----------------- | -------------------------------------------------------------------------- |
| `allow`           | The session meets the requirement; `subject` and `assurance` are included. |
| `step-up`         | A session exists but falls short; `missing` says what a step-up must add.  |
| `enroll`          | The session is `pre-auth`: MFA is not set up yet.                          |
| `recovery-only`   | The session may only recover the account (recovery is planned, phase 4).   |
| `unauthenticated` | No valid session.                                                          |

A step-up is two requests. `POST /auth/step-up/start` returns a single-use `challenge`. `POST /auth/step-up` sends that
`challenge` with either `password` or `code`, never both. It adds fresh evidence and rotates the session token.

The level comes from evidence, not from the method's name. Password alone is AAL1, TOTP alone is AAL1, and both
together are AAL2. A level drops when the evidence behind it expires. By default, AAL2 lasts one hour idle or 24 hours
in all. AAL3 lasts 15 minutes idle or 12 hours, though phase 3 has no method that reaches it; hardware keys are planned
for phase 5. `defineAuthPolicy({ timeouts })` changes the limits.

## Sessions and sign-out

- `GET /auth/session` returns `{ session, csrfToken }`. `session` holds `id`, `subject`, `state`, `level`, `methods`,
  `idleExpiresAt` and `absoluteExpiresAt`, or is `null`.
- `GET /auth/sessions` lists the account's sessions: `id`, `current`, `state`, `startedAt`, `lastSeenAt`, `methods`.
- `POST /auth/sessions/revoke` `sessionId` ends one of them. The next request on it fails, with no cache in between.
- `POST /auth/sign-out` ends the current session and clears its cookie.
- `auth.admin.revoke(subject)`, on the server, ends every session of an account and resolves to how many it ended.

The token is 256 random bits. The store keeps only its SHA-256, and the cookie is `__Host-test-cap`: `Secure`,
`HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain` ([ADR 0006](specs/decisions/0006-sessions-and-cookies.md)). The
token rotates on sign-in, MFA and step-up.

## Security events

`onEvent` receives OCSF 1.9.0 events ([ADR 0015](specs/decisions/0015-security-events.md)):

- Authentication (3002), Logon: each password sign-in, successful or not, and each TOTP verification and step-up.
- Authentication (3002), Logoff: each sign-out, remote revoke and admin revoke.
- User Management (3007): account creation, address confirmation and each MFA enrolment.

Every event names `APP_SYSTEM_ID`. None carries a password, a code or a token. A session appears as a 16-character
prefix of its stored hash. test-cap stores no event; keeping them is the app's job. A sink that throws or rejects never
changes the reply.

## The Express adapter

```js
app.use(expressAuth(auth, { public: ["/", "/about", "/blog/*"] }))
```

- Mount it before any body parser. Under `/auth/` it reads the raw request stream itself; if a parser consumed it
  first, the request fails closed with a 500.
- `/auth/*` goes to `auth.handle`. Every other path continues to the app, its body stream untouched for the app's own
  parsers. `req.auth` is `{ subject }` on a protected route and `null` on a public one.
- A path not on the `public` list needs a session that meets the default requirement. No session is a 401; too weak
  a session is a 403.
- A public entry matches exactly (`"/"` is the root only) or ends in `/*` to match one or more segments below it.
  Matching is case-sensitive and never normalises. A path two parsers could read differently, such as `//account` or
  `/admin/x/../about`, is a 400 before any match ([ADR 0024](specs/decisions/0024-adapters-and-deny-by-default.md)).
- A malformed `public` entry throws a `ConfigError` when the middleware is created.

## The other adapters

Each is a byte converter. One differential test sends the same requests through each built adapter and compares what
the core sees and answers ([ADR 0024](specs/decisions/0024-adapters-and-deny-by-default.md)). Nest is **planned**
(phase 4):

| Entry                     | Exports                                                     | Deny by default                    |
| ------------------------- | ----------------------------------------------------------- | ---------------------------------- |
| `test-cap/fetch`          | `withAuth(auth, handler, options)`, `fetchAuth(auth)`       | a wrapper around the app's handler |
| `test-cap/tanstack-start` | `tanstackStartAuth`, `tanstackStartMiddleware`              | global middleware                  |
| `test-cap/next`           | `nextAuthHandler`, `nextServerAuth`, `nextProxy`            | the server helpers, near the data  |
| `test-cap/nest`           | `TestCapModule`, `AuthGuard`, `@Public()`, `@RequireAuth()` | a global guard (**planned**)       |

Next.js has three surfaces. The route handler serves `/auth/*`. The server helpers are the check, inside route
handlers, server functions and the data-access layer. The optional `nextProxy` only redirects early, for example a
signed-out visitor to the sign-in page; it is never the protection.

## Errors

Every error is JSON `{ "error": "<code>" }` with `no-store` and the security headers.

| Status | Codes                                                                                                                     |
| ------ | ------------------------------------------------------------------------------------------------------------------------- |
| 400    | the request: `invalid-path`, `malformed-body`, `ambiguous-header`, `duplicate-field`, `too-many-fields`, `aborted`        |
| 400    | the fields: `undeclared-field`, `invalid-field`, `missing-field`, `invalid-identifier`, `invalid-return-to`, `one-secret` |
| 400    | the secret: `invalid-code`, `too-short`, `too-long`, `too-common`, `breached`                                             |
| 401    | `unauthenticated`, `invalid-credentials`, `invalid-code`                                                                  |
| 403    | `csrf`, `not-enrolling`, `invalid-challenge`, and a protected route's unmet requirement                                   |
| 404    | `not-found`                                                                                                               |
| 405    | `method-not-allowed`, with `Allow`                                                                                        |
| 409    | `password-first`, `confirm-email-first`, `no-identifier`, `already-confirmed`, `too-many-authenticators`, `conflict`      |
| 413    | `body-too-large`                                                                                                          |
| 415    | `unsupported-media-type`                                                                                                  |
| 429    | `rate-limited`, with `Retry-After`                                                                                        |
| 500    | `internal`, and `body-already-read` when a body parser consumed the stream first                                          |
| 503    | `busy`: the argon2id concurrency limit is full                                                                            |

## Testing an app that uses it

Run with `APP_ENV=test`, and pass `clock` and `random` to control time and randomness. Session expiry, TOTP time steps
and token values all follow them. Only `test` mode accepts them, so `createAuth` refuses a test double in production.
