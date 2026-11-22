# test-cap on Next.js

A Next.js 16 App Router app on `test-cap/next`. It is also test-cap's end-to-end test for that entry:
`test/examples/nextjs.test.ts` builds it, starts it and walks the journey below over real HTTP.

Its settings are in the committed `.env`, which Next.js loads: `APP_ENV=development`, `APP_ORIGIN` on localhost, an
`APP_SYSTEM_ID` and both key rings. Those values are for local development only. They are public, so production and
staging refuse the keys, and the memory store too. The breach check asks the real HIBP range API unless
`HIBP_STUB_ORIGIN` names a stand-in, as the end-to-end test does.

## Files

| File                            | What it does                                                                                            |
| ------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `server/auth.ts`                | Creates the one `Auth` over a memory store, from the environment, with an in-memory outbox for email.   |
| `.env`                          | The local-development settings and keys. Never use them in production; production refuses the keys.     |
| `server/server-auth.ts`         | `nextServerAuth(auth, { headers })`: the server helper every protected route calls.                     |
| `server/billing.ts`             | The data-access layer for billing. It calls the server helper itself, next to the data.                 |
| `app/auth/[...path]/route.ts`   | `nextAuthHandler(auth)`: serves every `/auth/*` route.                                                  |
| `app/billing/page.tsx`          | Protected page. Without a session, or with one that needs a step-up, it redirects home with the reason. |
| `app/billing/invoices/route.ts` | The same data as JSON: 401 without a session, 403 naming what the session lacks.                        |
| `app/page.tsx`                  | The public home page.                                                                                   |
| `proxy.ts`                      | `nextProxy`: sends a visitor with no session cookie home before `/billing` renders. Redirects only.     |

`proxy.ts` is not the protection. Next.js's own guide says a proxy "should not be your only line of defense in
protecting your data". It passes any request that carries a session cookie, forged or not; `/billing` and
`/billing/invoices` check the session themselves through `server/billing.ts`.

## Email

Sign-up mails the address a 6-digit confirmation code. `sendEmail` in `server/auth.ts` keeps every email in an
in-memory outbox and prints each as one `test-cap-outbox` line. Run locally, the code is in the server's output.
The end-to-end test's `confirmEmail(client, outbox)` reads the code from those lines and posts it to
`/auth/email/confirm`, as a person types it from their inbox.

## The journey the test walks

1. `/` answers 200 to anyone.
2. Signed out, `/billing` redirects home (the proxy). With a forged session cookie the proxy lets the request by,
   and the page redirects with `need=unauthenticated` while `/billing/invoices` answers 401 (the server helper).
3. Sign-up: `/auth/sign-up`, the emailed code at `/auth/email/confirm`, a password, then TOTP enrolment and
   confirmation. The session is AAL2 and `/billing` answers 200.
4. Sign-out.
5. Sign-in with the password alone. `/billing` redirects with `need=step-up` and `/billing/invoices` answers 403
   `step-up`.
6. A TOTP code at `/auth/totp/verify`. `/billing` and `/billing/invoices` answer 200.
7. Sign-out. `/billing` redirects home, and the old cookie gets a 401 from `/billing/invoices`.

## Run it

From the repository root: `npm run build && npm pack`. Then in this folder:

1. `npm ci`, then `npm install --no-save ../../test-cap-*.tgz`.
2. `npx next build && npx next start`, and open `http://localhost:3000`. The settings come from `.env`.
3. Sign up at `http://localhost:3000/auth/sign-up` and follow the pages. The confirmation code is printed in the
   server's output on its `test-cap-outbox` line.

The end-to-end test runs from the repository root: `npx vitest run test/examples/nextjs.test.ts`.
