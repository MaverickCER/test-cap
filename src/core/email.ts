/**
 * Email address confirmation (F08; ADR 0021 §2, ADR 0008 §4, ADR 0009 §7). Sign-up mails a code of 6 digits from the
 * `RandomSource`, valid for 24 hours. The store never holds the code: the record's key is an HMAC-SHA-256 over its
 * purpose, account, address and code, under a key HKDF derives from the current `AUTH_ENCRYPTION_KEY` ring key, so a
 * database read alone cannot try the 10^6 codes offline, and a code issued to one account or address never redeems
 * for another. `consumeOnce` redeems it once. Each issued code has its own attempt counter, named by its record key: an
 * attempt counts with the atomic `increment` against the account's newest code before anything is checked, over the
 * code's whole life, and can redeem only that code. The count alone refuses a sixth attempt even when the write that
 * kills the code at its limit failed, and a new code starts at none. Every send counts per address and per IP or IPv6
 * /64, and over a limit nothing is sent.
 *
 * Email proves control of a mailbox, never an authenticator: a confirmation adds no evidence (ADR 0021 §3).
 */

import { clientKey } from "./client-address.js"
import { randomDigits, type Clock, type RandomSource } from "./clock.js"
import { hexEncode, utf8Encode } from "./encoding.js"
import type { RingKey } from "./mode.js"
import {
  decide,
  type LimiterFactory,
  limitersBy,
  type RateLimiterLike,
  type RateRule,
} from "../security/rate-limit.js"
import { createStoreLimiter } from "../security/store-limiter.js"
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
/**
 * Attempts per code over its whole life; the code dies at the last one (ADR 0009 Open 1, ADR 0021 §2). An app may
 * lower it (`emailCodeAttempts`), never raise it: 5 guesses at a 6-digit code succeed 1 time in 200,000.
 */
export const CONFIRMATION_FAILURE_LIMIT = 5

/** The `emailLimit` option of `createAuth` (ADR 0009 §7, §8). Each value left out keeps its default. */
export interface EmailLimitConfig {
  /**
   * The limits per destination address, each counted on its own: 1 a minute and 5 an hour by default. Each is a
   * `{ windowMs, max }` or a rate-limiter-flexible limiter.
   */
  readonly perAddress?: readonly (RateRule | RateLimiterLike)[] | undefined
  /** The limit per client (an IPv4 address or an IPv6 /64): 20 an hour by default; `false` for none. */
  readonly perClient?: RateRule | RateLimiterLike | false | undefined
  /** Builds the limiter for each `{ windowMs, max }` rule, over the app's own backend; the `AuthStore` by default. */
  readonly limiter?: LimiterFactory | undefined
}

/** The send limits in force: one limiter per address limit, and the client's, if any. */
export interface EmailSendLimits {
  readonly perAddress: readonly RateLimiterLike[]
  readonly perClient: RateLimiterLike | false
}

/** Builds the send limits of an `emailLimit` option whose problems were checked; `factory` builds each rule's limiter. */
export function emailSendLimits(
  config: EmailLimitConfig,
  factory: LimiterFactory,
): EmailSendLimits {
  const limiterOf = limitersBy(config.limiter ?? factory, "email-send")
  const perClient = config.perClient ?? DEFAULT_EMAIL_LIMITS.perClient
  return {
    perAddress: (config.perAddress ?? DEFAULT_EMAIL_LIMITS.perAddress).map(limiterOf),
    perClient: perClient === false ? false : limiterOf(perClient),
  }
}

/** The send limits of ADR 0009 Open 1: per address 1 a minute and 5 an hour, per IP or /64 20 an hour. */
export const DEFAULT_EMAIL_LIMITS: {
  readonly perAddress: readonly RateRule[]
  readonly perClient: RateRule
} = {
  perAddress: [
    { windowMs: 60_000, max: 1 },
    { windowMs: 60 * 60_000, max: 5 },
  ],
  perClient: { windowMs: 60 * 60_000, max: 20 },
}

/** What confirmation needs injected. */
export interface EmailDeps {
  readonly store: AuthStore
  readonly tenant: TenantId
  readonly clock: Clock
  readonly random: RandomSource
  /**
   * `APP_ORIGIN` plus any gateway prefix and `/auth`: the only base a link in an email is built on, never the `Host`
   * header (ADR 0026 §5, ADR 0024 §6).
   */
  readonly linkBase: string
  readonly sendEmail: SendEmail
  /** The parsed `AUTH_ENCRYPTION_KEY` ring, current key first: the code's HMAC key is derived from it. */
  readonly keyRing: readonly RingKey[]
  /** The send limits; the defaults over this store when absent, `false` for none (development and test only). */
  readonly sendLimits?: EmailSendLimits | false | undefined
  /** Attempts per code, from 1 to `CONFIRMATION_FAILURE_LIMIT`; that limit when absent. */
  readonly attemptLimit?: number | undefined
}

/** The attempt counter of one issued code, named by the code's record key, so no other code shares or resets it. */
function failureCounter(codeKey: string): string {
  return `email-confirm-failures:${codeKey}`
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
  const limits =
    deps.sendLimits ??
    emailSendLimits({}, (options) =>
      createStoreLimiter({
        ...options,
        store: deps.store,
        tenant: deps.tenant,
        clock: deps.clock,
        blocks: false,
      }),
    )
  let retryAfterMs = 0
  if (limits !== false) {
    const client = clientKey(input.clientAddress)
    const checks = [
      ...limits.perAddress.map((limiter) => ({ limiter, key: `address:${input.address}` })),
      ...(client === null || limits.perClient === false
        ? []
        : [{ limiter: limits.perClient, key: `client:${client}` }]),
    ]
    for (const { limiter, key } of checks) {
      const decision = await decide(limiter, key)
      if (!decision.allowed) return { retryAfterMs: decision.retryAfterMs }
      // The wait before the next send is the longest any limit now asks for.
      retryAfterMs = Math.max(retryAfterMs, decision.retryAfterMs)
    }
  }
  await deps.store.revokeByOwner(deps.tenant, CONFIRMATION_COLLECTION, input.accountId, now)
  const code = randomDigits(deps.random, CONFIRMATION_DIGITS)
  // The ring always holds a current key: a parsed one, or outside production one generated at startup.
  const current = deps.keyRing[0] as RingKey
  const key = await codeKey(current, input.accountId, input.address, code)
  // A code drawn again for the same account and address left its old, now revoked, record and its count under the
  // same key; the new code starts with neither.
  await deps.store.resetCounter(deps.tenant, failureCounter(key))
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
      `Enter it on the confirmation page: ${deps.linkBase}/email/confirm`,
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
 * Redeems `code` for the account and address. The attempt is counted against the account's newest code, first, in a
 * window as long as the code's life: the window starts at the first attempt, at or after the code was issued, so it
 * ends at or after the code expires. Only that code can be redeemed or killed by the attempt, so a code issued while it
 * runs neither inherits its count nor loses to it.
 */
export async function redeemConfirmation(
  deps: EmailDeps,
  input: { readonly accountId: string; readonly address: string; readonly code: string },
): Promise<RedeemResult> {
  const now = deps.clock.now()
  const target = (
    await deps.store.listByOwner(deps.tenant, CONFIRMATION_COLLECTION, input.accountId)
  ).at(-1)
  if (target === undefined) return { ok: false, reason: "invalid-code" }
  const limit = deps.attemptLimit ?? CONFIRMATION_FAILURE_LIMIT
  const attempts = await deps.store.increment(
    deps.tenant,
    failureCounter(target.key),
    CONFIRMATION_LIFETIME_MS,
    now,
  )
  if (attempts.count > limit) {
    return { ok: false, reason: "rate-limited", retryAfterMs: attempts.resetAt - now }
  }
  // A code issued before a key rotation is keyed under an older key of the ring.
  for (const ringKey of deps.keyRing) {
    if (
      (await codeKey(ringKey, input.accountId, input.address, input.code)) === target.key &&
      (await deps.store.consumeOnce(deps.tenant, CONFIRMATION_COLLECTION, target.key, now)) !== null
    )
      return { ok: true }
  }
  if (attempts.count === limit) {
    await deps.store.revoke(deps.tenant, CONFIRMATION_COLLECTION, target.key, now)
  }
  return { ok: false, reason: "invalid-code" }
}
