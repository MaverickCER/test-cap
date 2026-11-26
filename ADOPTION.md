# Adopting test-cap

Adopting `test-cap` in one of the owner's apps costs a store, two keys and one adapter line. `package.json` asks for
Node 22 or later, and CI tests Node 22 and 24. The steps below take an Express app from nothing to every route
protected, one route at a time if you prefer.

## Steps

1. **Install a tarball** (see [Install](#install)), and `express` if the app does not have it.
2. **Start in development with the memory store.** Run the [README quick start](README.md#quick-start) with
   `APP_ENV=development`, `APP_ORIGIN=http://localhost:3000` and `APP_SYSTEM_ID` set to the app's name. Outside
   production and staging, a missing key is generated for the process, so nothing else is needed yet.
3. **Sign up once by hand.** Follow the [Guide](GUIDE.md#sign-up): sign-up, the emailed code, a password, then TOTP
   enrolment and its confirming code. `GET /account` then answers with your subject.
4. **Give it a durable store.** No durable store is exported yet. Two pieces wait for CI to run them against real
   database servers, planned for phase 6. They are the SQL store for Postgres, SQLite and MySQL, and the conformance
   kit that checks a store's atomic guarantees
   ([ADR 0002](specs/decisions/0002-store-port-and-atomic-operations.md)). Until then, use test-cap in development and
   test only. No exported check covers an `AuthStore` you write yourself.
5. **Set the keys.** Generate `AUTH_ENCRYPTION_KEY` and `AUTH_CSRF_KEY`, one each, and keep them in the app's secret
   store:

   ```sh
   node -e 'console.log("k1:" + require("node:crypto").randomBytes(32).toString("base64url"))'
   ```

   A key is a ring of `id:base64url` entries, newest first, so a key rotates by adding an entry in front.

6. **Roll out route by route.** Deny by default protects every route not listed as public. To adopt gradually, start
   with `public: ["/", "/*"]`, which leaves every existing route open while `/auth/*` works. Then replace `"/*"` with
   the routes that should stay public, one release at a time.
7. **Name stronger requirements.** Define a requirement above the default with `defineAuthPolicy`. Check it with
   `auth.require(req, id)` inside the handler ([Guide](GUIDE.md#requirements-and-step-up)).
8. **Keep the security events.** Pass `onEvent` and store what it receives. test-cap keeps none itself.
9. **Go to production.** Set `APP_ENV=production` and an `https` `APP_ORIGIN`. `createAuth` throws one `ConfigError`
   naming every problem left: a memory store, a missing key, an `http` origin.

## What it costs

| Cost             | Detail                                                                                     |
| ---------------- | ------------------------------------------------------------------------------------------ |
| A store          | An `AuthStore` over the app's database, checked by the conformance kit once it is exported |
| Two keys         | `AUTH_ENCRYPTION_KEY` (TOTP secrets, emailed codes) and `AUTH_CSRF_KEY`, rotated as rings  |
| Argon2id work    | Every password check, failed or not, spends 19 MiB and 2 iterations; at most 4 run at once |
| MFA for everyone | AAL2 is the default: each person enrols a second factor at sign-up                         |
| Pre-1.0 churn    | A minor release may break the API before 1.0 ([VERSIONING.md](VERSIONING.md))              |

## What it refuses to do

| It will not                                                      | Where it stops                                                                                                                    |
| ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Start in production with a memory store, `http` or a missing key | `createAuth` throws a `ConfigError` naming each problem ([ADR 0026](specs/decisions/0026-strict-defaults-and-deployment-mode.md)) |
| Let a body parser change what it reads                           | The Express adapter reads the raw stream; a consumed stream fails closed with a 500                                               |
| Match a public path after normalising it                         | An ambiguous path is a 400 before any match ([ADR 0024](specs/decisions/0024-adapters-and-deny-by-default.md))                    |
| Say at sign-up or sign-in whether an account exists              | One reply either way, and the same argon2id work for an unknown account                                                           |
| Decide what a person may do                                      | Authorization is access-cap's                                                                                                     |
| Reach HIBP on its own                                            | The breach check calls the `hibpFetch` the app passes it                                                                          |

## Requirements

- Node.js 22 or later, as `engines` asks. CI tests Node 22 and 24.
- A durable `AuthStore` for any mode but `development` and `test`.

## Install

test-cap is not on npm ([ADR 0019](specs/decisions/0019-internal-use-disclosure-and-distribution.md)). No release has
been cut yet, so run `npm pack` in a checkout and install the tarball it writes. A prebuilt tarball on each GitHub
Release is planned for phase 9; today's release workflow attaches none. Once it does, the install is:

```sh
npm i https://github.com/MaverickCER/test-cap/releases/download/vX.Y.Z/test-cap-X.Y.Z.tgz
```

## What installing it adds

Generated from `package.json` by `internal-package-contract generate`; give each dependency's reason in
`docs/surface.json` under `"dependencies"`.

<!-- ipc:begin dependencies -->

Installing `test-cap` installs 5 packages directly, and whatever they depend on. It names 1 optional peer, which you install yourself when you use the part that needs it.

| Package                 | Kind          | Range                | Why                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ----------------------- | ------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `@noble/hashes`         | dependency    | `2.4.0`              | Runtime. argon2id in plain JavaScript, used only where WebAssembly cannot compile, such as Cloudflare Workers, at the same cost and with the same encoded hashes as hash-wasm (ADR 0031). Loaded on first use, by its `argon2.js` path only. Several times slower than hash-wasm: check the CPU time limit of your Workers plan. MIT, no dependencies of its own.                                                                                                                                 |
| `forwarded-parse`       | dependency    | `2.2.0`              | Runtime. Parses the RFC 7239 `Forwarded` header when the app's proxies set it (ADR 0030). It requires Node's `util`, which Bun, Deno and Cloudflare Workers with `nodejs_compat` provide. Workers turn that flag on by default from compatibility date 2026-08-04; without it, a Worker's build cannot resolve `util`. MIT, no dependencies of its own.                                                                                                                                           |
| `hash-wasm`             | dependency    | `^4.13.0`            | Runtime. argon2id password hashing in WebAssembly, with no native build (ADR 0018). It runs on Node, Bun and Deno, where CI signs in through it (ADR 0023). Cloudflare Workers refuse to compile its WebAssembly, so there `@noble/hashes` takes over (ADR 0031). MIT, no dependencies of its own.                                                                                                                                                                                                |
| `ipaddr.js`             | dependency    | `2.5.0`              | Runtime. Parses IPv4 and IPv6 client addresses, reads an IPv4-mapped address as IPv4 and matches the CIDR ranges of `trustedProxies` and the platform presets (ADR 0030). Runs on Node, Bun, Deno and workerd. MIT, no dependencies of its own.                                                                                                                                                                                                                                                   |
| `rate-limiter-flexible` | dependency    | `11.5.0`             | Runtime. Counts every limit: the request limits, the mail send limits, the guessing throttle, the failure ceiling and the stuffing detector's counts (ADR 0030), so an app can plug in any limiter with the library's interface; test-cap's tests run its memory limiter and the store limiter over the app's store. Imported by deep path only: its index loads every store it ships, one of which needs Node's `cluster`. Runs on Node, Bun, Deno and workerd. ISC, no dependencies of its own. |
| `@maverickcer/env-cap`  | optional peer | `^0.7.7 \|\| ^0.8.0` | Optional peer. Only `src/env.schema.ts` imports it, so env-cap can document and validate test-cap's variables in an app that uses env-cap; without it, `createAuth` takes plain values (ADR 0022).                                                                                                                                                                                                                                                                                                |

<!-- ipc:end dependencies -->
