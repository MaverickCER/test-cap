# test-cap

[![CI](https://github.com/MaverickCER/test-cap/actions/workflows/contract.yml/badge.svg)](https://github.com/MaverickCER/test-cap/actions/workflows/contract.yml)

**Sign-up, sign-in, sessions and MFA for MaverickCER apps. On Express, `fetch` and TanStack Start, every route needs
AAL2 unless you list it as public.**

`test-cap` is an internal authentication package. It decides who a request belongs to and how strongly that was
proven. What that person may do is access-cap's decision.

[Why](#why-it-exists) · [See it run](#see-it-run) · [Install](#install-and-verify) · [Fit](#fit-and-capabilities) ·
[Limits](#limits-and-when-not-to-use-it) · [Security](#security-and-supply-chain) ·
[Maturity](#maturity-versioning-and-support) · [Docs](#documentation)

## Why it exists

**The problem:** the owner's apps used Better Auth. It published 49 repository advisories between 2024-12-30 and
2026-11-03, and it patches only its latest release. About 180 of its calls read the system clock, and a test cannot
replace them. An app on it inherits that patch cadence and cannot test its own session expiry.

**What changes:** a `createAuth` call and one `app.use` give an Express app sign-up, sign-in, TOTP, sessions and CSRF
protection. Every other route then needs AAL2. The package never opens a database connection. Tests can replace its
clock and random source.

**Who it is for:** developers of the owner's own apps. It has no outside users, is not on npm, and makes no promise to
anyone else ([ADR 0019](specs/decisions/0019-internal-use-disclosure-and-distribution.md)).

## How it differs

A hosted identity provider runs sign-in for you and keeps the accounts. test-cap runs inside the app, in the app's
own store. test-cap writes the flows, sessions and assurance rules itself, and leaves each protocol to a library that
specialises in it. Today that is `hash-wasm` for argon2id, with `@noble/hashes` where WebAssembly cannot compile
([ADR 0031](specs/decisions/0031-replaceable-argon2id-and-a-fallback-without-webassembly.md)), rate-limiter-flexible for
every limit, and ipaddr.js and forwarded-parse for client addresses
([ADR 0030](specs/decisions/0030-use-existing-libraries-for-limits-and-client-addresses.md)). `@simplewebauthn/server` and `oauth4webapi` are planned for
passkeys and OpenID Connect (phase 5). Web Crypto covers TOTP and every key test-cap holds
([ADR 0001](specs/decisions/0001-compose-audited-primitives-instead-of-better-auth.md)).

Three choices follow from that:

- **Assurance is computed, never declared.** Each sign-in ceremony produces evidence: the factors it proved, whether
  it resists phishing, and when. The session's level is computed from the evidence that is still valid, and it drops
  when that evidence expires ([ADR 0005](specs/decisions/0005-policy-and-evidence-based-assurance.md)). Password plus
  TOTP is AAL2. Email never raises the level.
- **Deny by default.** The Express, `fetch` and TanStack Start adapters protect every route at the default requirement
  unless the app lists it as public. On Next.js, each route calls the server helper itself
  ([ADR 0024](specs/decisions/0024-adapters-and-deny-by-default.md)).
- **One core, thin adapters.** The core takes bytes and returns bytes. An adapter only converts a framework's request
  and response, so a fix to the core reaches every framework at once.

## What it does

`createAuth` checks that the deployment may start, then returns an `Auth`. `auth.handle` serves every `/auth/*` route,
and `auth.require(req, id)` answers whether a request's session meets a requirement: `allow`, `step-up`, `enroll`,
`recovery-only` or `unauthenticated`. Security events go to the app's `onEvent` sink as OCSF 1.9.0 Authentication (3002)
and User Management (3007) events.

### See it run

The quick start below, started with `APP_ENV=development`, answering `curl` (headers trimmed):

```text
$ curl -i localhost:3000/account
HTTP/1.1 401 Unauthorized
cache-control: no-store
content-security-policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
{"error":"unauthenticated"}

$ curl -i localhost:3000/auth/session
HTTP/1.1 200 OK
set-cookie: __Host-test-cap-csrf=AHcU…I2I; Path=/; Secure; HttpOnly; SameSite=Lax
{"session":null,"csrfToken":"generated.1794855793133.ZFne…Jo0"}

$ curl -i -X POST -H "Origin: http://localhost:3000" -d "identifier=a%40example.com&password=x" localhost:3000/auth/sign-in
HTTP/1.1 403 Forbidden
{"error":"csrf"}
```

`/account` is not listed as public, so it needs a session at AAL2. A `POST` without the token from `/auth/session` is
refused before the route runs. The same file started with no `APP_ENV` runs as production and refuses to start:

```text
ConfigError: test-cap refused to start:
- APP_ORIGIN must use https in production.
- The "memory" store keeps nothing across restarts or processes; production needs a durable store.
- AUTH_ENCRYPTION_KEY is missing.
- AUTH_CSRF_KEY is missing.
```

## Install and verify

test-cap is not on npm. No release has been cut yet, so build a tarball with `npm pack` in a checkout and install it.
A prebuilt tarball on each GitHub Release is planned for phase 9; today's release workflow attaches none
([ADR 0004](specs/decisions/0004-package-entries-and-capability-gates.md)). Once it does, the install is:

```sh
npm i https://github.com/MaverickCER/test-cap/releases/download/vX.Y.Z/test-cap-X.Y.Z.tgz
```

`package.json` asks for Node 22 or later. CI tests Node 22 and 24.

### Quick start

An Express app with sign-up, sign-in, TOTP and deny by default. Mount the adapter before any body parser.

<!-- quick-start:begin -->

```js
import express from "express"
import { createAuth } from "test-cap"
import { expressAuth } from "test-cap/express"
import { memoryStore } from "test-cap/store/memory"

const auth = createAuth({
  store: memoryStore(), // development and test only: production refuses it
  env: process.env, // APP_ENV, APP_ORIGIN, APP_SYSTEM_ID, AUTH_ENCRYPTION_KEY, AUTH_CSRF_KEY
  hibpFetch: fetch, // the breached-password check
  sendEmail: async (message) => console.log(message), // your mailer: sign-up mails a code
})

const app = express()
app.use(expressAuth(auth, { public: ["/"] })) // serves /auth/*; every other route needs AAL2
app.get("/", (req, res) => res.send("Welcome"))
app.get("/account", (req, res) => res.json(req.auth))
app.listen(3000)
```

<!-- quick-start:end -->

`GET /auth/session` returns the session and a CSRF token; send it as `X-CSRF-Token` with each `POST` to `/auth/*`.
`test/docs/quick-start-lines.test.ts` runs this block and keeps it under 20 lines. `memoryStore()` keeps nothing
across restarts, so production and staging refuse it: pass a durable `AuthStore` there.

**Check it:** start it with `APP_ENV=development APP_ORIGIN=http://localhost:3000 APP_SYSTEM_ID=my-app`, then follow
the [Guide](GUIDE.md) from sign-up to `/account` answering with your subject.

## Fit and capabilities

**Use it for** a server-rendered or API app of the owner's that needs its own accounts. It gives MFA by default and
evidence of how each session was proven.

| Capability                                                    | Status                                        |
| ------------------------------------------------------------- | --------------------------------------------- |
| Password (argon2id, breach screening) + TOTP, AAL2 by design  | built (phase 3)                               |
| Sessions: rotation, idle and absolute limits, remote revoke   | built (phase 3)                               |
| `require`, step-up, `defineAuthPolicy`                        | built (phase 3)                               |
| Express, `fetch`, Next.js and TanStack Start adapters         | built (phase 3)                               |
| OCSF security events                                          | built (phase 3)                               |
| Email address confirmation at sign-up                         | built (phase 3)                               |
| Default pages and hashed assets, served by `handle()`         | built (phase 3)                               |
| SQL store (Postgres, SQLite, MySQL)                           | built, not exported; export planned (phase 6) |
| Throttling, recovery codes, proxy trust                       | built (phase 4)                               |
| Request limits on every route, each changeable or replaceable | built (phase 4)                               |
| Nest adapter                                                  | in progress, after phase 4                    |
| Passkeys, email recovery, OpenID Connect                      | planned (phase 5)                             |
| Browser client, React components                              | planned (phase 7)                             |
| Machine keys, delegation, impersonation, audit trail, SAML    | planned (phase 8)                             |

**How it fits together:** the adapter turns the framework's request into a `PlainRequest` of bytes and hands it to
the core. The core parses, checks CSRF and runs the route against the app's `AuthStore`. A store implements a few
atomic operations (`consumeOnce`, `increment`, `createUnique`, `appendAudit`) over the app's own database. Today the
only exported store is the memory store; the SQL store passes the conformance kit on SQLite and PGlite.

**Runtimes:** the core uses Web Crypto and standard globals, and imports no `node:` module. CI runs the full suite on
Node 22 and 24. On Node 22 and 24, Bun 1.3.14, Deno 2.9.4 and Cloudflare workerd (with `nodejs_compat`), CI also
runs the built package through `test-cap/fetch` and the memory store: sign-up, email confirmation, a password and
TOTP enrolment, sign-out, a refused and an accepted sign-in, and a TOTP step-up. That journey hashes at a test cost.
On Workers, argon2id runs on `@noble/hashes`, and each hash at the production cost spent 200 to 300 ms of CPU in a
local probe ([ADR 0031](specs/decisions/0031-replaceable-argon2id-and-a-fallback-without-webassembly.md)). The
per-capability matrix of [ADR 0023](specs/decisions/0023-runtime-support-per-capability.md) is planned for phase 6.

**Configure and extend:** `defineAuthPolicy` names requirements (`billing.update: { level: "AAL2",
multiFactorWithinMs: 300_000 }`) that routes check with `auth.require`. `createAuth` reads `APP_ENV`, `APP_ORIGIN`,
`APP_SYSTEM_ID`, `AUTH_ENCRYPTION_KEY` and `AUTH_CSRF_KEY`, from `process.env` or env-cap's parsed values
([docs/ENVIRONMENT.md](https://github.com/MaverickCER/test-cap/blob/main/docs/ENVIRONMENT.md)).

## Limits and when not to use it

- **Internal use only.** There is no support promise and no npm package. An app outside the owner's should use a
  maintained provider or framework.
- **Phase 4 of 9.** Passwords and TOTP are the only sign-in methods today. An app that needs passkeys, social sign-in
  or SAML waits for the phase that adds them, or uses something else.
- **No Nest adapter yet.** Express, `fetch`, Next.js and TanStack Start are built; Nest is in progress and follows phase 4.
- **No durable store exported.** Only the memory store is exported, so test-cap runs in development and test only.
- **No authorization.** test-cap says who the subject is and at what level; access-cap decides what they may do.
- **No hosted pieces.** The app stores the accounts, sends any email and keeps the security events.
- **Edge runtimes other than Cloudflare Workers** are not claimed. On Workers, test-cap needs the `nodejs_compat`
  flag (the default from compatibility date 2026-08-04), and your plan's CPU limit must allow 200 to 300 ms for each
  password hash.

## Security and supply chain

**What it promises, and where that stops:**

- Every route outside `/auth/*` and the public list needs AAL2 in the Express, `fetch` and TanStack Start adapters.
  On Next.js, a route is protected when it calls `nextServerAuth`. Within a route, the app's own checks are the app's.
- Every `POST` under `/auth/` checks a same-origin signal and a synchronizer token. Every response carries a strict
  CSP and `nosniff`. Every response but the hashed page assets carries `no-store`.
- Session tokens are 256-bit random values. The store holds only their SHA-256. The cookie is `__Host-`, `Secure`,
  `HttpOnly` and `SameSite=Lax`.
- Sign-up and sign-in replies never say whether an account exists. A failed sign-in for an unknown account spends the
  same argon2id work.
- Production refuses to start without HTTPS, a durable store and both keys.

**Trust boundaries:** the app's store, its mail sender and its event sink are trusted. The HIBP breach check reaches
the network through the `hibpFetch` the app hands it.

[specs/attack-catalogue.md](specs/attack-catalogue.md) maps each attack class to the design element that stops it and
its negative test. An entry reads `tested` only when that test exists, and `test/docs/attack-catalogue.test.ts` keeps it
so. Standards appear only as "maps to" (NIST SP 800-63B-4, OWASP ASVS 5.0). There has been no
external penetration test. Report a vulnerability privately as [SECURITY.md](SECURITY.md) describes. Installing
test-cap adds five packages, each with no dependencies of its own; [ADOPTION.md](ADOPTION.md) lists them with their
reasons.

## Maturity, versioning and support

test-cap is pre-1.0 and has not cut its first release. Before 1.0, a minor release may break the API, and its
changeset says so ([VERSIONING.md](VERSIONING.md)). Only the latest release receives fixes, by policy. The first
release starts `CHANGELOG.md`; read it before you upgrade. Report bugs as [SUPPORT.md](SUPPORT.md) describes.

## Documentation

- [Guide](GUIDE.md): the flows, the routes, the policy and the adapters, one story each.
- [ADOPTION.md](ADOPTION.md): adopting it in an app, step by step, and what installing it adds.
- [API reference](https://github.com/MaverickCER/test-cap/blob/main/docs/api-report/README.md), generated from source.
  The site holds Storybook (every form page in every state) and the HTTP API reference of every `/auth` route. CI
  publishes it to GitHub Pages once this branch merges.
- [Architecture](specs/architecture.md), [threat model](specs/threat-model.md) and
  [decision records](specs/decisions/).
- [GLOSSARY.md](GLOSSARY.md): method, factor, evidence, assurance level and the other terms kept apart.

## Next steps

- **Evaluate:** read [ADOPTION.md](ADOPTION.md) and the limits above, then the capability table.
- **Integrate:** run the quick start, then follow the [Guide](GUIDE.md) from sign-up to step-up.
- **Verify:** read the [threat model](specs/threat-model.md) and the
  [attack catalogue](specs/attack-catalogue.md), and the tests each entry names.

Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). Release process: [RELEASING.md](RELEASING.md). License: [MIT](LICENSE).
