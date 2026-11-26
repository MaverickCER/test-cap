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

| Option                 | What it is                                                                                                               |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `store`                | The app's `AuthStore`. Production and staging refuse one that is not durable.                                            |
| `env`                  | `process.env`, env-cap's parsed values or a plain object with the same names.                                            |
| `hibpFetch`            | The `fetch` the breached-password check calls to reach HIBP. Required.                                                   |
| `sendEmail`            | Sends each `EmailMessage` test-cap builds: sign-up's confirmation code. Not awaited.                                     |
| `policy`               | From `defineAuthPolicy`; without one, every requirement is the default AAL2.                                             |
| `onEvent`              | Receives every security event. A sink that throws never changes an outcome.                                              |
| `tenant`               | The tenant every operation is scoped to; `default` when absent.                                                          |
| `clock`, `random`      | Replacements for tests. Any mode but `test` refuses to start with one.                                                   |
| `trustedProxies`       | The app's own proxies (addresses, CIDR ranges) or a `platform` preset; none by default.                                  |
| `forwardedHeader`      | The one header those proxies set: `x-forwarded-for` (default) or `forwarded`.                                            |
| `throttle`             | The guessing throttle's values, your own `Throttle`, or `false` outside production.                                      |
| `failureCeiling`       | Failures in a row before an authenticator stops: 100, or lower.                                                          |
| `rateLimit`            | The request limits on every route, or your own limiter; see [Rate limits](#rate-limits-defaults-and-how-to-change-them). |
| `stuffing`             | The credential-stuffing detector's values, your own `StuffingDetector`, or `false` outside production.                   |
| `emailLimit`           | The confirmation-mail send limits, your own rate-limiter-flexible limiters, or `false` outside production.               |
| `emailCodeAttempts`    | Attempts an emailed code allows: 5, or lower.                                                                            |
| `refusalEvents`        | `"first"` (default): one event per refused client or account per window; `"every"`: one per refusal.                     |
| `challengeHook`        | The app's own challenge for a flagged client, such as a CAPTCHA it already uses.                                         |
| `publicBasePath`       | The prefix a gateway strips, such as `/accounts`; links and redirects keep it.                                           |
| `requireClientAddress` | `false` serves a request with no client address uncounted in production; reported once.                                  |
| `argon2Hasher`         | Your own argon2id computation in place of the built-in one; test-cap still checks what it returns.                       |
| `onDiagnostic`         | Told once about a deployment problem test-cap can see, such as an undeclared proxy.                                      |

`createAuth` reads five variables ([ADR 0022](specs/decisions/0022-environment-variables.md),
[docs/ENVIRONMENT.md](https://github.com/MaverickCER/test-cap/blob/main/docs/ENVIRONMENT.md)):

- `APP_ENV`: the deployment mode, `production`, `staging`, `development` or `test`. Missing or unknown runs as
  `production` ([ADR 0026](specs/decisions/0026-strict-defaults-and-deployment-mode.md)).
- `APP_ORIGIN`: the bare origin, such as `https://app.example`. It must be `https`, except on `localhost`,
  `127.0.0.1` or `[::1]` outside production and staging.
- `APP_SYSTEM_ID`: the system's name in every security event. Every mode refuses to start without it.
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

Sends are limited per address to one a minute and five an hour. Per IP address or IPv6 /64, the limit is twenty an hour.
Over a limit, nothing is sent, and the reply is the same with `retryAfterMs`. Five wrong tries end a code for the rest
of its life, and further tries answer `429` with `Retry-After`. Each try counts against the newest code, and a resend
gives a new code with five tries of its own. Confirming adds no assurance: email never raises the level ([ADR
0021](specs/decisions/0021-excluded-methods-and-emails-role.md), [ADR
0009](specs/decisions/0009-abuse-and-proxy-trust.md)). The password waits for the confirmation (`409
confirm-email-first`), and the session stays at `enroll` until every step is done. A person who stops before TOTP and
signs in later gets `enroll` again, with a `pre-auth` session that continues at TOTP enrolment. That session cannot set
a new password (`409 password-set`): once set, a password changes only through [recovery](#recovery-codes). Until a
second factor is confirmed, the password is the account's only factor, so whoever holds it can finish enrolment too. The
first to confirm keeps the account, and every other session is signed out.

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

An account with a password but no second factor yet answers `{ outcome: "enroll", returnTo }` at step 1. Its `pre-auth`
session continues at TOTP enrolment ([Sign up](#sign-up)). A form post that ends at `allow` answers `303` to `returnTo`.
`returnTo` must be a same-origin relative path; anything else is a 400. A wrong password, an unknown or unconfirmed
address and a disabled account all answer `401 invalid-credentials`. Each spends the same argon2id work ([ADR
0009](specs/decisions/0009-abuse-and-proxy-trust.md)). Too many failures answer `429 rate-limited` with a `Retry-After`
in seconds; see [Throttling and proxies](#throttling-and-proxies).

Sign-in finds an account only through a confirmed identifier, so an account signs in again later by the address it
confirmed at sign-up.

## Requirements and step-up

The default requirement is AAL2. A route that needs a different level, more (such as AAL3) or less (such as
`{ level: "AAL1" }` for a page a password alone may open), names a requirement in the policy and checks it next to the
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

| Outcome           | Meaning                                                                      |
| ----------------- | ---------------------------------------------------------------------------- |
| `allow`           | The session meets the requirement; `subject` and `assurance` are included.   |
| `step-up`         | A session exists but falls short; `missing` says what a step-up must add.    |
| `enroll`          | The session is `pre-auth`: MFA is not set up yet.                            |
| `recovery-only`   | The session may only recover the account: [Recovery codes](#recovery-codes). |
| `unauthenticated` | No valid session.                                                            |

A step-up is two requests. `POST /auth/step-up/start` returns a single-use `challenge`. `POST /auth/step-up` sends that
`challenge` with either `password` or `code`, never both. It adds fresh evidence and rotates the session token.

The level comes from evidence, not from the method's name. Password alone is AAL1, TOTP alone is AAL1, and both
together are AAL2. A level drops when the evidence behind it expires. By default, AAL2 lasts one hour idle or 24 hours
in all. AAL3 lasts 15 minutes idle or 12 hours, though phase 3 has no method that reaches it; hardware keys are planned
for phase 5. `defineAuthPolicy({ timeouts })` changes the limits.

## Throttling and proxies

Failed guesses slow further guesses; they never lock an account
([ADR 0009](specs/decisions/0009-abuse-and-proxy-trust.md)). A password, a TOTP code and a saved recovery code each
go through the throttle, which counts under three keys:

- the identifier as typed, so an address no account holds is slowed exactly like one an account holds;
- that identifier together with the client;
- the client alone: an IPv4 address, or the /64 of an IPv6 address, since one host usually holds a whole /64.

The two identifier keys are kept per kind of secret. Sign-in and a password step-up share the password's keys; TOTP
verification and a code step-up share the TOTP code's; recovery codes have their own. So a correct password never
clears the failures of TOTP guesses.

The first 5 failures on a key in 15 minutes cost nothing. Each failure after that blocks the key for a wait that doubles
from 1 second, never past 15 minutes. The count restarts with each 15-minute window. With these values, about 15 guesses
fit in a window, and the longest wait is about 8.5 minutes. An attempt on a blocked key answers `429 rate-limited` with
`Retry-After`, before any secret is checked. A success clears its own kind's identifier keys, never the client's. [Rate
limits](#rate-limits-defaults-and-how-to-change-them) says how to change the values.

Each authenticator also stops after 100 failures in a row (NIST SP 800-63B-4's ceiling). The account's other
authenticators keep working, and a password at the ceiling comes back by [recovery](#recovery-codes), which sets a new
one.

**Credential stuffing.** A client that fails against 20 different identifiers in 15 minutes is flagged (`stuffing: {
distinctAccounts, windowMs }`). A sign-in the throttle refuses counts too, since it still names an identifier the client
tried. Otherwise the client's own throttle would stop a spray before it reached 20. With a `challengeHook`, a flagged
client's sign-in answers `403 challenge-required` until the hook returns `true` for that request:

```ts
const auth = createAuth({
  store,
  env: process.env,
  hibpFetch: fetch,
  sendEmail,
  challengeHook: async ({ request }) => myCaptcha.verify(request.headers.get("x-captcha-token")),
})
```

Without a hook, a flagged client gets no free attempts. Its failure events name `credential-stuffing`.

The default pages send no challenge answer, so an app with a `challengeHook` serves its own sign-in form that carries
one, as the header in the example above does.

**Behind a proxy.** By default the client is the socket's peer, so behind a load balancer every request seems to come
from the balancer, and one client's failures slow everyone. Name the balancer, by address or CIDR range:

```ts
createAuth({ ...config, trustedProxies: ["10.0.0.5", "10.1.0.0/16"] })
```

`X-Forwarded-For` is read only when the socket's peer is in `trustedProxies`, from the right, skipping every hop in
the list. A CDN in front of the balancer is handled by listing the CDN's ranges too. Set
`forwardedHeader: "forwarded"` when the proxy sets the standard `Forwarded` header (RFC 7239) instead; it is read the
same way, one element at a time from the right, so elements a client sends before its proxy's never count. Only the
header named is read: a proxy that sets one passes a client's forged copy of the other through untouched.

**On a platform**, use its preset, which names the one header that platform sets:

| Deployed on       | `trustedProxies`                                                   | Reads                       |
| ----------------- | ------------------------------------------------------------------ | --------------------------- |
| AWS load balancer | `platform("aws-alb", { peers: ["10.0.0.0/16"] })`, its subnets     | `X-Forwarded-For`           |
| CloudFront        | `platform("cloudfront", { peers })`, its origin-facing ranges      | `CloudFront-Viewer-Address` |
| Cloudflare        | `platform("cloudflare", { peers })`, Cloudflare's published ranges | `CF-Connecting-IP`          |
| Vercel            | `platform("vercel")`                                               | `x-real-ip`                 |
| Fly.io            | `platform("fly")`                                                  | `Fly-Client-IP`             |
| Netlify           | `platform("netlify")`                                              | `x-nf-client-connection-ip` |
| Your own nginx    | `platform("nginx", { peers: ["10.0.0.5"] })`                       | `X-Real-IP`                 |

test-cap ships no address ranges, so none go stale inside it: pass the vendor's current list, from
<https://www.cloudflare.com/ips/> or AWS's `ip-ranges.json` (service `CLOUDFRONT_ORIGIN_FACING`). CloudFront sends
`CloudFront-Viewer-Address` only once an origin request policy adds it. Your nginx must set the header itself
(`proxy_set_header X-Real-IP $remote_addr;`), or pass `header: "x-forwarded-for"` when it appends to that one instead.

Each preset follows the vendor's documentation and is tested in simulation through every adapter. None has been
verified on the real platform. Two limits from
[ADR 0009](specs/decisions/0009-abuse-and-proxy-trust.md) are worth knowing before relying on one:

- Cloudflare's and CloudFront's ranges are shared by every customer of theirs, so a request from one of them is not
  proof it came through your account. Cloudflare's Authenticated Origin Pulls or a Tunnel close that gap.
- `vercel`, `fly` and `netlify` assume every request reaches the app through the platform. An app also reachable
  another way, such as Fly's private network, can be sent a forged header that way.

**Next.js and TanStack Start** get no socket address from their frameworks. With the `vercel`, `fly` or `netlify` preset
they need nothing more, since every request comes through the platform. Anywhere else, including behind the
`cloudflare`, `cloudfront`, `aws-alb` and `nginx` presets, pass what the server knows. `nextAuthHandler(auth, {
clientAddress })` and `tanstackStartAuth(auth, { clientAddress })` each take a function of the `Request`, as `fetchAuth`
and `withAuth` do. In production and staging, these adapters refuse to start without that option unless the preset is
`vercel`, `fly` or `netlify`. A request that still arrives with no client address gets a 500. If your gateway limits
requests instead, set `requireClientAddress: false` to serve such requests uncounted.

**When test-cap sees a proxy you have not declared**, a forwarding header it read none of, it tells the
`onDiagnostic` hook once. A platform that sets its own header beside `X-Forwarded-For` is not reported:

```ts
createAuth({
  ...config,
  onDiagnostic: (diagnostic) => logger.warn(diagnostic.code, diagnostic.message),
})
```

`forwarded-header-ignored` means a forwarding header went unread: its peer is untrusted, or it is not the declared one.
`origin-unverifiable` means a sign-in or other state-changing request carried neither a site `Origin` nor
`Sec-Fetch-Site`, so the CSRF check refused it; a proxy in front of the app may be removing them.
`client-address-missing` means a request reached test-cap with no client address, so the per-client limits did not
count it, or in production and staging it was refused. `client-address-optional` repeats that the app set
`requireClientAddress: false`, and `rate-limit-off`, `throttle-off`, `email-limit-off` and `stuffing-off` that it
turned that limit off. `argon2-fallback` means the runtime cannot compile WebAssembly, such as Cloudflare Workers, so
argon2id runs on `@noble/hashes`, more slowly.

**Behind a gateway that strips a path prefix**, set `publicBasePath`:

```ts
createAuth({ ...config, publicBasePath: "/accounts" }) // the browser asks for /accounts/auth/sign-in
```

Every link, redirect and email URL test-cap builds then starts with `/accounts`, while routes are still matched on the
path the app receives ([ADR 0024](specs/decisions/0024-adapters-and-deny-by-default.md)).

## Rate limits: defaults and how to change them

Besides the throttle, test-cap counts every request to `/auth` per client before anything else runs, so no route can
be called without bound. A route's limit is keyed by its route id: its path after `/auth/`, such as `sign-in`.
`pages` covers every default page, `assets` the page assets, and `unmatched` every path no route has. Over its limit,
a request answers `429 rate-limited` with `Retry-After` in seconds, and a default page's form shows the wait.
Each limit is on in every mode, development and test included.

| Limit                                                                                                      | Default                                                                      | Change it with                                                   |
| ---------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| Requests to any route, per client                                                                          | 100 per 10 seconds                                                           | `rateLimit: { windowMs, max }`                                   |
| Requests to `sign-in`, `step-up`, `totp/verify`, `totp/enrol`, `totp/confirm`, `email/confirm`, `recovery` | 10 per 10 seconds                                                            | `rateLimit: { rules: { [routeId]: … } }`                         |
| Sign-ups, per client                                                                                       | 20 per hour                                                                  | `rateLimit: { rules: { "sign-up": … } }`                         |
| Guesses of a password, TOTP code or recovery code                                                          | 5 free failures in 15 minutes, then a wait from 1 second, at most 15 minutes | `throttle: { freeFailures, windowMs, firstDelayMs, maxDelayMs }` |
| Failures in a row on one authenticator                                                                     | 100                                                                          | `failureCeiling`, from 1 to 100                                  |
| Distinct identifiers one client fails on before it is flagged                                              | 20 in 15 minutes                                                             | `stuffing: { distinctAccounts, windowMs }`                       |
| Confirmation mail                                                                                          | 1 a minute and 5 an hour per address, 20 an hour per client                  | `emailLimit: { perAddress: [rules], perClient }`                 |
| Attempts at one emailed code                                                                               | 5 over its 24 hours                                                          | `emailCodeAttempts`, from 1 to 5                                 |

Change a value. Every value left out keeps its default:

```ts
createAuth({
  ...config,
  rateLimit: { max: 300, rules: { "sign-up": { windowMs: 60 * 60_000, max: 50 } } },
})
```

Turn one route's limit off with `false`, or decide per request with a function that returns a rule or `false`:

```ts
createAuth({
  ...config,
  rateLimit: {
    rules: {
      "sign-up": false,
      "sign-in": (request) =>
        request.headers.get("x-load-test") === loadTestToken
          ? false
          : { windowMs: 10_000, max: 10 },
    },
  },
})
```

Plug in your own limiter. test-cap counts with [rate-limiter-flexible](https://github.com/animir/node-rate-limiter-flexible)
and takes any limiter with its interface. test-cap's tests run the library's memory limiter and the store limiter over
your `AuthStore`; the library's Redis, Valkey, Postgres, Prisma and other stores are yours to check where you run. Give
`limiter` a function that builds one per rule from the library's own options, and every default keeps its values on
your backend:

```ts
import { RateLimiterRedis } from "rate-limiter-flexible"

const auth = createAuth({
  ...config,
  rateLimit: { limiter: (options) => new RateLimiterRedis({ storeClient: redis, ...options }) },
})
```

`options` is `{ points, duration, keyPrefix }`, the rule's `max`, its window in seconds and a prefix of its own. A
route's rule can also be a limiter instance (`rules: { "sign-in": myLimiter }`), and `rateLimit` itself can be one
limiter that counts every route in place of the defaults. Keys are the route id and the client, such as
`sign-in|203.0.113.7`. The default, `createStoreLimiter({ store, points, duration })`, is the library's store limiter
over your `AuthStore`, and it combines with the library's own pieces, such as a `RateLimiterUnion`.

A rule keyed by anything but a route id refuses to start, naming the ids. A limiter that refuses rejects with its
`RateLimiterRes`, as the library's do; one that fails with an error ends the request with a 500, never lets it through.

`rateLimit: false` turns every request limit off, in any mode, for an app that limits requests at its gateway.
`throttle: false` turns the guessing throttle off in development and test only: production and staging refuse it,
because NIST SP 800-63B-4 requires throttling failed attempts. `throttle` also takes your own `Throttle`, an object
with `attempt`, `failed` and `succeeded`. Whatever the throttle is, the failure ceiling stays on.

Refusing `false` guards against switching a limit off by mistake; it does not judge your values. Any value is yours to
choose, so production also starts with values loose enough to be off in effect, such as `throttle: { freeFailures:
1_000_000 }`. The throttle's and the stuffing detector's windows and delays are at most a year. Past that, the store's
expiry times leave the range of safe integers.

The other limits follow the same pattern. `emailLimit` takes `perAddress` (a list of rules or limiters), `perClient`
(a rule, a limiter or `false`) and its own `limiter` factory; its limiters get keys such as `address:ada@example.com`. `stuffing` takes
your own `StuffingDetector`, an object with `flagged` and `failed`. Production and staging refuse `emailLimit: false`,
since the send limits stop inbox flooding, and `stuffing: false`. `emailCodeAttempts` can only go down: a 6-digit code
stays hard to guess only while it allows at most 5 attempts.

A request with no client address cannot be counted, because there is no client to count it under; give the adapter
its `clientAddress` option. In development and test it is served uncounted; production and staging refuse it, unless
`requireClientAddress: false` (see Next.js and TanStack Start above). `auth.session`, `auth.require` and `auth.admin`
are calls in your own server, never counted.
[ADR 0009 §8](specs/decisions/0009-abuse-and-proxy-trust.md) gives the reason for each default.

**What the limits keep in your store.** No email address and no client address. Each counter, and the key of each
`rate-limit-block` record, is named by an HMAC of its key under a key derived from `AUTH_ENCRYPTION_KEY`
([ADR 0032](specs/decisions/0032-limit-keys-hold-no-address.md)). Rotating that key starts every count again from zero.
A limiter you pass through `rateLimit.limiter` or `emailLimit.limiter` gets the plain key, as its library expects.
Expired counters and blocks stay until you delete them: delete counters whose reset time has passed, and
`rate-limit-block` records whose expiry has passed.

## Recovery codes

A person who loses their authenticator recovers the account with a saved recovery code
([ADR 0007](specs/decisions/0007-recovery.md)).

| Step | Request                                             | Answer                                                            |
| ---- | --------------------------------------------------- | ----------------------------------------------------------------- |
| 1    | `POST /auth/recovery-codes` (signed in, at AAL2)    | `{ codes }`: 10 codes, shown this once                            |
| 2    | later, `POST /auth/recovery` `identifier`, `code`   | a recovery-only session, `{ outcome: "recovery-only", returnTo }` |
| 3    | `POST /auth/password`, `POST /auth/totp/enrol`, ... | new authenticators; the session still has no level                |
| 4    | `POST /auth/recovery/finish`                        | the session ends; the person signs in with the new authenticators |

- Each code is `XXXXXX-XXXX-XXXX-XXXX-XXXX`: a row prefix, then 80 random bits. The store keeps only an argon2id hash
  of each. Spaces, hyphens and case are ignored when one is typed.
- A code works once. A new set ends the old one once it is current: of two requests at once, one gets codes and the
  other `401`.
- Making a set is a credential change. It rotates the session that made it and signs out the account's other
  sessions, as a new password does ([ADR 0006](specs/decisions/0006-sessions-and-cookies.md)).
- Redeeming a code signs out every other session of the account and emails its confirmed address at once, so a
  recovery the owner did not start is visible to them. Where the store has transactions, a failure partway leaves the
  code unspent.
- A recovery-only session reaches nothing: `auth.require` answers `recovery-only` for every requirement. It can only
  set a password, enrol TOTP or make new codes. The level comes from signing in again afterwards.
- A wrong code, a used code and an unknown identifier get one reply, `401 invalid-credentials`, after the same
  argon2id work, and the attempts are throttled.

**Fresh proof for credential changes.** Enrolling TOTP and making recovery codes need a multi-factor sign-in or
step-up within the last 15 minutes, even at AAL2. An older session gets `403` with
`{ error: "step-up", missing: [{ kind: "fresh-multi-factor", withinMs: 900000 }] }`. The change needs a password and a
code both proven within the window, and a step-up proves one factor, so one step-up with a code is not enough. Signing
in again (the password, then the code) makes the change possible again, and so do two step-ups, one with the password
and one with a code ([ADR 0005](specs/decisions/0005-policy-and-evidence-based-assurance.md)).

## Sessions and sign-out

- `GET /auth/session` returns `{ session, csrfToken }`. `session` holds `id`, `subject`, `state`, `level`, `methods`,
  `idleExpiresAt` and `absoluteExpiresAt`, or is `null`.
- `GET /auth/sessions` lists the account's sessions: `id`, `current`, `state`, `startedAt`, `lastSeenAt`, `methods`.
- `POST /auth/sessions/revoke` `sessionId` ends one of them. The next request on it fails, with no cache in between.
- `POST /auth/sign-out` ends the current session and clears its cookie.
- `auth.admin.revoke(subject)`, on the server, ends every session of an account and resolves to how many it ended.
- `auth.admin.deprovision(subject)`, on the server, disables the account and ends every session it holds. A disabled
  account cannot sign in or recover, and a session it still held is refused on its next request. It resolves to
  `false` when no such account exists. Call it from the app's offboarding or SCIM handler.

The token is 256 random bits. The store keeps only its SHA-256, and the cookie is `__Host-test-cap`: `Secure`,
`HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain` ([ADR 0006](specs/decisions/0006-sessions-and-cookies.md)). The
token rotates on sign-in, MFA and step-up.

## Security events

`onEvent` receives OCSF 1.9.0 events ([ADR 0015](specs/decisions/0015-security-events.md)):

- Authentication (3002), Logon: each password sign-in, successful or not, and each TOTP verification and step-up.
- Authentication (3002), Logoff: each sign-out, remote revoke and admin revoke.
- User Management (3007): account creation, address confirmation and each MFA enrolment.

A refusal by a limit (`rate-limited`, `request-limit`) is reported once per client or account until that limit's
wait ends, so a flood of refused requests is one event; set `refusalEvents: "every"` to report each one.

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
the core sees and answers ([ADR 0024](specs/decisions/0024-adapters-and-deny-by-default.md)). Nest is in progress
and follows phase 4:

| Entry                     | Exports                                                     | Deny by default                    |
| ------------------------- | ----------------------------------------------------------- | ---------------------------------- |
| `test-cap/fetch`          | `withAuth(auth, handler, options)`, `fetchAuth(auth)`       | a wrapper around the app's handler |
| `test-cap/tanstack-start` | `tanstackStartAuth`, `tanstackStartMiddleware`              | global middleware                  |
| `test-cap/next`           | `nextAuthHandler`, `nextServerAuth`, `nextProxy`            | the server helpers, near the data  |
| `test-cap/nest`           | `TestCapModule`, `AuthGuard`, `@Public()`, `@RequireAuth()` | a global guard (**planned**)       |

Next.js has three surfaces. The route handler serves `/auth/*`. The server helpers are the check, inside route
handlers, server functions and the data-access layer. The optional `nextProxy` only redirects early, for example a
signed-out visitor to the sign-in page; it is never the protection.

TanStack Start's middleware applies only the default requirement. A page that asks for less, such as AAL1, goes on
the `public` list and checks its own requirement with `tanstackStartAuth(auth).require` in its server function. Link to
it with a plain anchor: a client-side navigation calls the server function through the middleware, at AAL2.

## Errors

Every error is JSON `{ "error": "<code>" }` with `no-store` and the security headers.

| Status | Codes                                                                                                                                |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| 400    | the request: `invalid-path`, `malformed-body`, `ambiguous-header`, `duplicate-field`, `too-many-fields`, `aborted`                   |
| 400    | the fields: `undeclared-field`, `invalid-field`, `missing-field`, `invalid-identifier`, `invalid-return-to`, `one-secret`            |
| 400    | the secret: `invalid-code`, `too-short`, `too-long`, `too-common`, `breached`                                                        |
| 401    | `unauthenticated`, `invalid-credentials`, `invalid-code`                                                                             |
| 403    | `csrf`, `not-enrolling`, `not-recovering`, `invalid-challenge`, `challenge-required` (the app's stuffing challenge)                  |
| 403    | a protected route's unmet requirement: `step-up`, `enroll`, `recovery-only`                                                          |
| 404    | `not-found`                                                                                                                          |
| 405    | `method-not-allowed`, with `Allow`                                                                                                   |
| 409    | `password-first`, `password-set`, `confirm-email-first`, `no-identifier`, `already-confirmed`, `too-many-authenticators`, `conflict` |
| 413    | `body-too-large`                                                                                                                     |
| 415    | `unsupported-media-type`                                                                                                             |
| 429    | `rate-limited`, with `Retry-After`                                                                                                   |
| 500    | `internal`, and `body-already-read` when a body parser consumed the stream first                                                     |
| 503    | `busy`: the argon2id concurrency limit is full                                                                                       |

## Testing an app that uses it

Run with `APP_ENV=test`, and pass `clock` and `random` to control time and randomness. Session expiry, TOTP time steps
and token values all follow them. Only `test` mode accepts them, so `createAuth` refuses a test double in production.
