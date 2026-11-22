# test-cap on TanStack Start

A TanStack Start app on `test-cap/tanstack-start`: a public home page, a protected billing page, and server functions
that check their own requirement. It is also test-cap's end-to-end test for that entry:
`test/examples/tanstack-start.test.ts` builds it, starts it and walks the journey below over real HTTP.

Its settings are in the committed `.env`: `APP_ENV=development`, `APP_ORIGIN` on localhost, an `APP_SYSTEM_ID` and both
key rings. Those values are for local development only. They are public, so production and staging refuse the keys,
and the memory store too. `server.mjs`, which serves the production build, loads `.env` with Node's
`process.loadEnvFile`. A variable already set in the environment wins. `vite dev` loads `.env` itself, as TanStack
Start documents; no test here runs `vite dev`.

## Files

| File                       | What it does                                                                                     |
| -------------------------- | ------------------------------------------------------------------------------------------------ |
| `src/auth.server.ts`       | Creates the one `Auth` over a memory store, the policy's requirements, and the adapter's pieces. |
| `src/start.ts`             | Registers test-cap's global request middleware: deny by default, `/` public.                     |
| `src/routes/auth/$.ts`     | The `/auth/$` server route: every `/auth/*` route and default page.                              |
| `src/billing.functions.ts` | Server functions that check `billing.export` and `billing.close` themselves.                     |
| `src/routes/billing.tsx`   | The protected page.                                                                              |
| `server.mjs`               | Serves the production build on Node, after loading `.env`.                                       |
| `.env`                     | The local-development settings and keys. Never use them in production.                           |

## Email

Sign-up mails the address a 6-digit confirmation code. `sendEmail` in `src/auth.server.ts` keeps every email in an
in-memory outbox and prints each as one `outbox` line. Run locally, the code is in the server's output. The end-to-end
test reads the code from those lines and posts it to `/auth/email/confirm`.

## The journey the test walks

1. `/` answers 200 and names the server function endpoints; `/billing` and the server functions answer 401.
2. Sign-up, the emailed code, a password, then TOTP enrolment: the session is AAL2 and `/billing` renders.
3. Sign-out, then sign-in with the password alone: `step-up`. A TOTP step-up brings back AAL2.
4. `billing.export` allows; `billing.close` (AAL3) answers `step-up`. Sign-out refuses everything again.

## Run it

From the repository root: `npm run build && npm pack --pack-destination examples/tanstack-start`. Then in this
folder:

1. `npm ci`. The lockfile names the tarball `test-cap-0.0.0.tgz` in this folder, so `npm ci` installs the one you
   packed.
2. `npm run build && npm start`, and open `http://localhost:3000`. The settings come from `.env`.
3. Sign up at `http://localhost:3000/auth/sign-up` and follow the pages. The confirmation code is printed in the
   server's output on its `outbox` line.

The end-to-end test runs from the repository root: `npx vitest run test/examples/tanstack-start.test.ts`.
