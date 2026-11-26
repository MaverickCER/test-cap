# test-cap on Next.js

A Next.js 16 App Router app on `test-cap/next`, with a protected page at each of two assurance levels. It is also test-cap's end-to-end test for that entry:
`test/examples/nextjs.test.ts` builds it, starts it and walks the journey below over real HTTP.

Its settings are in the committed `.env`, which Next.js loads: `APP_ENV=development`, `APP_ORIGIN` on localhost, an
`APP_SYSTEM_ID` and both key rings. Those values are for local development only. They are public, so production and
staging refuse the keys, and the memory store too. The breach check asks the real HIBP range API unless
`HIBP_STUB_ORIGIN` names a stand-in, as the end-to-end test does.

## Files

| File                            | What it does                                                                                              |
| ------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `server/auth.ts`                | Creates the one `Auth` over a memory store, from the environment, with an in-memory outbox for email.     |
| `.env`                          | The local-development settings and keys. Never use them in production; production refuses the keys.       |
| `server/server-auth.ts`         | `nextServerAuth(auth, { headers })`: the server helper every protected route calls.                       |
| `server/billing.ts`             | The data-access layer for billing. It calls the server helper itself, next to the data.                   |
| `server/account.ts`             | The same for the account, which names `account.view`: a signed-in session (AAL1) is enough.               |
| `app/auth/[...path]/route.ts`   | `nextAuthHandler(auth)`: serves every `/auth/*` route.                                                    |
| `app/billing/page.tsx`          | Protected page. Without a session, or with one that needs a step-up, it redirects home with the reason.   |
| `app/billing/invoices/route.ts` | The same data as JSON: 401 without a session, 403 naming what the session lacks.                          |
| `app/account/page.tsx`          | Protected page at AAL1. It shows the subject and the session's level; refusals redirect home.             |
| `app/account/session/route.ts`  | The same data as JSON: 401 without a session, 403 naming what the session lacks.                          |
| `app/page.tsx`                  | The public home page.                                                                                     |
| `proxy.ts`                      | `nextProxy`: sends a visitor with no session cookie home before a protected page renders. Redirects only. |

`/billing` and `/account` ask for different levels. `/billing` names no requirement and gets the default, AAL2: a
password and a TOTP code. `/account` names `account.view`, defined in `server/auth.ts` as `{ level: "AAL1" }`, so a
password alone opens it. A session still in enrolment (`enroll`) or in recovery gets neither.

`proxy.ts` is not the protection. Next.js's own guide says a proxy "should not be your only line of defense in
protecting your data". It passes any request that carries a session cookie, forged or not; `/billing`,
`/billing/invoices`, `/account` and `/account/session` check the session themselves through `server/billing.ts` and
`server/account.ts`.

## Email

Sign-up mails the address a 6-digit confirmation code. `sendEmail` in `server/auth.ts` keeps every email in an
in-memory outbox and prints each as one `test-cap-outbox` line. Run locally, the code is in the server's output.
The end-to-end test's `confirmEmail(client, outbox)` reads the code from those lines and posts it to
`/auth/email/confirm`, as a person types it from their inbox.

## The journey the test walks

1. `/` answers 200 to anyone.
2. Signed out, `/billing` and `/account` redirect home (the proxy). With a forged session cookie the proxy lets the
   request by, and each page redirects with `need=unauthenticated` while `/billing/invoices` and `/account/session`
   answer 401 (the server helper).
3. Sign-up: `/auth/sign-up`, the emailed code at `/auth/email/confirm`, a password. Mid-enrolment `/account` redirects
   with `need=enroll` and `/account/session` answers 403 `enroll`. Then TOTP enrolment and confirmation: the session
   is AAL2, `/billing` answers 200, and `/account` answers 200 with level AAL2.
4. Sign-out.
5. Sign-in with the password alone. `/account` answers 200 with level AAL1. `/billing` redirects with
   `need=step-up` and `/billing/invoices` answers 403 `step-up`.
6. A TOTP code at `/auth/totp/verify`. `/billing`, `/billing/invoices` and `/account` answer 200, `/account` now at
   level AAL2.
7. Sign-out. `/billing` and `/account` redirect home, and the old cookie gets a 401 from `/billing/invoices` and
   `/account/session`, and `need=unauthenticated` from `/account`.

## Run it

From the repository root: `npm run build && npm pack`. Then in this folder:

1. `npm ci`, then `npm install --no-save ../../test-cap-*.tgz`.
2. `npx next build && npx next start`, and open `http://localhost:3000`. The settings come from `.env`.
3. Sign up at `http://localhost:3000/auth/sign-up` and follow the pages. The confirmation code is printed in the
   server's output on its `test-cap-outbox` line.

The end-to-end test runs from the repository root: `npx vitest run test/examples/nextjs.test.ts`.
