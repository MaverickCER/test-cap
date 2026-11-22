/**
 * Email address confirmation (F08; ADR 0021 §2, ADR 0008 §4, ADR 0009 §7). Sign-up mails a code of 6 digits from the
 * `RandomSource`, valid for 24 hours. The store never holds the code: the record's key is an HMAC-SHA-256 over its
 * purpose, account, address and code, under a key HKDF derives from the current `AUTH_ENCRYPTION_KEY` ring key, so a
 * database read alone cannot try the 10^6 codes offline, and a code issued to one account or address never redeems
 * for another. `consumeOnce` redeems it once. Every attempt counts with the atomic `increment` before the code is checked,
 * over the code's whole life, so the count alone refuses a sixth attempt even when the write that kills the code at
 * its limit failed. Every send counts per address and per IP or IPv6 /64, and over a limit nothing is sent.
 *
 * Email proves control of a mailbox, never an authenticator: a confirmation adds no evidence (ADR 0021 §3).
 */

import { clientKey } from "./client-address.js"
import { randomDigits, type Clock, type RandomSource } from "./clock.js"
import { hexEncode, utf8Encode } from "./encoding.js"
import type { RingKey } from "./mode.js"
import type { AuthStore, TenantId } from "../store/port.js"

/** One email test-cap asks the app to send (ADR 0021). */
export interface EmailMessage {
  /** The normalised address to send to. */
  readonly to: string
  /** The subject line. */
  readonly subject: string
  /** The plain-text body. */
  readonly text: string
}

/** The app's mail sender (ADR 0021 §2). */
export type SendEmail = (message: EmailMessage) => Promise<void>

/** Confirmation codes, keyed by the hash of purpose, account, address and code, and owned by the account. */
export const CONFIRMATION_COLLECTION = "email-confirmation"
/** The code's length: NIST SP 800-63A-4 §3.8's minimum. */
export const CONFIRMATION_DIGITS = 6
/** How long a code can be redeemed: the 24-hour ceiling of ADR 0021 §2. */
export const CONFIRMATION_LIFETIME_MS = 24 * 60 * 60_000
/** Attempts per code over its whole life; the code dies at the last one (ADR 0009 Open 1, ADR 0021 §2). */
export const CONFIRMATION_FAILURE_LIMIT = 5

/** The send limits of ADR 0009 Open 1: per address 1 a minute and 5 an hour, per IP or /64 20 an hour. */
const ADDRESS_LIMITS = [
  { windowMs: 60_000, max: 1 },
  { windowMs: 60 * 60_000, max: 5 },
] as const
const CLIENT_LIMIT = { windowMs: 60 * 60_000, max: 20 } as const

/** What confirmation needs injected. */
export interface EmailDeps {
  readonly store: AuthStore
  readonly tenant: TenantId
  readonly clock: Clock
  readonly random: RandomSource
  /** `APP_ORIGIN`: the only origin a link in an email is built on (ADR 0026 §5). */
  readonly origin: string
  readonly sendEmail: SendEmail
  /** The parsed `AUTH_ENCRYPTION_KEY` ring, current key first: the code's HMAC key is derived from it. */
  readonly keyRing: readonly RingKey[]
}

/**
 * The account's attempt counter. An account has one live code at a time, and a send resets the counter only after the
 * codes before it are revoked, so the count is the live code's.
 */
function failureCounter(accountId: string): string {
  return `email-confirm-failures:${accountId}`
}

/** The HKDF `info` that keeps the derived key apart from every other use of the ring. */
const LABEL = utf8Encode("email-confirm")

/** The record key of a code under `ringKey`: an HMAC bound to purpose, account and address. */
async function codeKey(
  ringKey: RingKey,
  accountId: string,
  address: string,
  code: string,
): Promise<string> {
  const base = await crypto.subtle.importKey(
    "raw",
    ringKey.bytes,
    "HKDF",
    // Stryker disable next-line BooleanLiteral: equivalent, extractability only matters to exportKey, which nothing calls
    false,
    ["deriveKey"],
  )
  const hmac = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: LABEL },
    base,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    // Stryker disable next-line BooleanLiteral: equivalent, extractability only matters to exportKey, which nothing calls
    false,
    ["sign"],
  )
  const message = utf8Encode(["email-confirm", accountId, address, code].join("\n"))
  return hexEncode(new Uint8Array(await crypto.subtle.sign("HMAC", hmac, message)))
}

/** Hands the message to the app without waiting: neither a slow nor a failing mailer changes the reply. */
function deliver(sendEmail: SendEmail, message: EmailMessage): void {
  void (async () => sendEmail(message))().catch(() => undefined)
}

/**
 * Sends a new confirmation code to `address` for the account, unless a send limit is reached; any code sent before
 * stops working. `retryAfterMs` is how long until the address may be sent to again.
 */
export async function sendConfirmation(
  deps: EmailDeps,
  input: {
    readonly accountId: string
    readonly address: string
    readonly clientAddress: string | undefined
  },
): Promise<{ readonly retryAfterMs: number }> {
  const now = deps.clock.now()
  const client = clientKey(input.clientAddress)
  const limits = [
    ...ADDRESS_LIMITS.map((limit) => ({
      ...limit,
      key: `email-send:address:${limit.windowMs}:${input.address}`,
    })),
    ...(client === null ? [] : [{ ...CLIENT_LIMIT, key: `email-send:client:${client}` }]),
  ]
  let retryAfterMs = 0
  for (const limit of limits) {
    const counter = await deps.store.increment(deps.tenant, limit.key, limit.windowMs, now)
    const wait = counter.resetAt - now
    if (counter.count > limit.max) return { retryAfterMs: wait }
    // The first limit is the shortest window: the wait before the next send.
    retryAfterMs ||= wait
  }
  await deps.store.revokeByOwner(deps.tenant, CONFIRMATION_COLLECTION, input.accountId, now)
  // Only now that no earlier code can redeem does the new one get a count of its own.
  await deps.store.resetCounter(deps.tenant, failureCounter(input.accountId))
  const code = randomDigits(deps.random, CONFIRMATION_DIGITS)
  // The ring always holds a current key: a parsed one, or outside production one generated at startup.
  const current = deps.keyRing[0] as RingKey
  const key = await codeKey(current, input.accountId, input.address, code)
  // A code drawn again for the same account and address left its old, now revoked, record under the same key.
  await deps.store.delete(deps.tenant, CONFIRMATION_COLLECTION, key)
  await deps.store.createUnique(deps.tenant, {
    collection: CONFIRMATION_COLLECTION,
    key,
    owner: input.accountId,
    expiresAt: now + CONFIRMATION_LIFETIME_MS,
    data: { address: input.address, keyId: current.id },
  })
  deliver(deps.sendEmail, {
    to: input.address,
    subject: "Confirm your email address",
    text: [
      `Your confirmation code is ${code}. It expires in 24 hours.`,
      "",
      `Enter it on the confirmation page: ${deps.origin}/auth/email/confirm`,
      "",
      "If you did not create an account, ignore this email.",
    ].join("\n"),
  })
  return { retryAfterMs }
}

/** The outcome of redeeming a code. */
export type RedeemResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: "invalid-code" }
  | { readonly ok: false; readonly reason: "rate-limited"; readonly retryAfterMs: number }

/**
 * Redeems `code` for the account and address. Each attempt counts first, in a window as long as the code's life: the
 * window starts at the first attempt, at or after the code was issued, so it ends at or after the code expires.
 */
export async function redeemConfirmation(
  deps: EmailDeps,
  input: { readonly accountId: string; readonly address: string; readonly code: string },
): Promise<RedeemResult> {
  const now = deps.clock.now()
  const counter = failureCounter(input.accountId)
  const attempts = await deps.store.increment(deps.tenant, counter, CONFIRMATION_LIFETIME_MS, now)
  if (attempts.count > CONFIRMATION_FAILURE_LIMIT) {
    return { ok: false, reason: "rate-limited", retryAfterMs: attempts.resetAt - now }
  }
  // A code issued before a key rotation is keyed under an older key of the ring.
  for (const ringKey of deps.keyRing) {
    const key = await codeKey(ringKey, input.accountId, input.address, input.code)
    if ((await deps.store.consumeOnce(deps.tenant, CONFIRMATION_COLLECTION, key, now)) !== null) {
      await deps.store.resetCounter(deps.tenant, counter)
      return { ok: true }
    }
  }
  if (attempts.count === CONFIRMATION_FAILURE_LIMIT) {
    await deps.store.revokeByOwner(deps.tenant, CONFIRMATION_COLLECTION, input.accountId, now)
  }
  return { ok: false, reason: "invalid-code" }
}
