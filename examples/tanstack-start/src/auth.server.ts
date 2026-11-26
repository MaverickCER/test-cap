// test-cap for this app: one Auth over the memory store, the policy's requirements, and the adapter's pieces.
import { createAuth, defineAuthPolicy, type EmailMessage, type HibpFetch } from "test-cap"
import { memoryStore } from "test-cap/store/memory"
import { tanstackStartAuth, tanstackStartMiddleware } from "test-cap/tanstack-start"

/**
 * The example's mail: every email test-cap asks the app to send (sign-up mails each address its confirmation code)
 * stays here, and is printed as one `outbox` line so the end-to-end test can read it from the server's output. A real
 * app hands each message to its mail provider.
 */
const outbox: EmailMessage[] = []

/**
 * The breached-password check (ADR 0010) asks the real HIBP range API through `fetch`, as a real app does. The
 * end-to-end test sets `HIBP_STUB_ORIGIN` to a local stand-in's origin, and only then is each range request sent there
 * instead, so the test runs offline and never asks the real service.
 */
const stubOrigin = process.env["HIBP_STUB_ORIGIN"]
const hibpFetch: HibpFetch =
  stubOrigin === undefined
    ? fetch
    : (url, init) => fetch(new URL(new URL(url).pathname, stubOrigin), init)

export const auth = createAuth({
  // The memory store keeps nothing across restarts; APP_ENV=production or staging refuses to start with it.
  store: memoryStore(),
  policy: defineAuthPolicy({
    version: "tanstack-start example 1",
    requirements: {
      // Viewing the account needs a signed-in session and no more: a password alone (AAL1) is enough. Billing names no
      // requirement, so it keeps the default, AAL2.
      "account.view": { level: "AAL1" },
      // Exporting invoices needs both factors proved in the last 15 minutes.
      "billing.export": { level: "AAL2", multiFactorWithinMs: 15 * 60_000 },
      // Closing the account needs a phishing-resistant authenticator, which this example does not enrol.
      "billing.close": { level: "AAL3" },
    },
  }),
  // APP_ENV, APP_ORIGIN, APP_SYSTEM_ID, AUTH_ENCRYPTION_KEY, AUTH_CSRF_KEY: server.mjs loads them from the committed
  // .env, whose values are for local development only (production refuses its keys).
  env: process.env,
  hibpFetch, // the breached-password check: `fetch` unless the test names a stand-in
  sendEmail: (message) => {
    outbox.push(message)
    console.log(`outbox ${JSON.stringify(message)}`)
    return Promise.resolve()
  },
})

/** The `/auth/$` server route's handlers, and `require` and `session` for server functions. */
export const authRoutes = tanstackStartAuth(auth)

/**
 * Deny by default: `/` is public; every other page and every server function call needs AAL2. `/account` is listed
 * too, but not because it is open: the middleware only knows the default requirement, which would turn a password-only
 * session away, so the page's own server function checks `account.view` instead (src/account.functions.ts).
 */
export const authMiddlewareServer = tanstackStartMiddleware(auth, { public: ["/", "/account"] })
