// The one Auth this app uses, over a memory store. Next.js loads APP_ENV, APP_ORIGIN, APP_SYSTEM_ID and the two key
// rings from the committed .env, whose values are for local development only: production and staging refuse the
// memory store and those keys.
import { createAuth, defineAuthPolicy, type EmailMessage, type HibpFetch } from "test-cap"
import { memoryStore } from "test-cap/store/memory"

/**
 * Every email the app was asked to send, kept in memory: sign-up mails each address its confirmation code. Each is
 * also printed as one `test-cap-outbox` JSON line, which is how the end-to-end test, outside this process, reads it.
 * A real app hands each message to its mail provider.
 */
export const outbox: EmailMessage[] = []

async function sendEmail(message: EmailMessage): Promise<void> {
  outbox.push(message)
  console.log(`test-cap-outbox ${JSON.stringify(message)}`)
}

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

/**
 * Deny by default: a route that names no requirement needs AAL2, a password and a TOTP code, as /billing does.
 * `account.view` is the one relaxation this app makes: a signed-in session (AAL1) is enough, so a password alone opens
 * /account. A requirement below AAL2 is a conscious choice, and `policy.deviations` lists it.
 */
const policy = defineAuthPolicy({
  version: "nextjs example 1",
  requirements: { "account.view": { level: "AAL1" } },
})

function build() {
  return createAuth({
    store: memoryStore(), // keeps nothing across restarts; production and staging refuse it
    policy,
    env: process.env, // APP_ENV, APP_ORIGIN, APP_SYSTEM_ID, AUTH_ENCRYPTION_KEY, AUTH_CSRF_KEY
    hibpFetch,
    sendEmail,
  })
}

// Next.js may load this module once per bundle. One Auth per process keeps one store and one set of keys.
const KEY = Symbol.for("test-cap.example.nextjs.auth")
const scope = globalThis as typeof globalThis & { [KEY]?: ReturnType<typeof build> }

export const auth = (scope[KEY] ??= build())
