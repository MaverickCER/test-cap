/**
 * The TOTP method (ADR 0027, flows F03 and F04) as pure logic: no HTTP and no dispatcher. Enrolment draws a 160-bit
 * secret, shows it once and stores it encrypted and unconfirmed; one valid code confirms it, and only then does it
 * produce evidence. A verification accepts a step only when it is later than the last accepted one, and records the
 * new step with a compare-and-set, so of two requests with the same code only one succeeds.
 */

import type { FailureCeiling } from "../../security/ceiling.js"
import type { AuthenticationEvidence } from "../../assurance/evidence.js"
import { type Clock, type RandomSource, randomBytes, randomToken } from "../../core/clock.js"
import type { RingKey } from "../../core/mode.js"
import type { AuthStore, JsonValue, StoredRecord, TenantId } from "../../store/port.js"
import { openSecret, type SealedSecret, sealSecret } from "./secret-box.js"
import { findStep } from "./totp.js"

/** The collection TOTP authenticators live in, keyed by authenticator id and owned by the account. */
export const TOTP_COLLECTION = "totp"
/** 160 bits, above the 112-bit floor of SP 800-63B-4 §3.1.4.1 (ADR 0027 Open 1). */
export const TOTP_SECRET_BYTES = 20
/** How long an unconfirmed enrolment can be confirmed. */
export const TOTP_ENROLMENT_TTL_MS = 10 * 60_000
/** The most confirmed TOTP authenticators one account holds (ADR 0027): every verification reads them all. */
export const TOTP_MAX_AUTHENTICATORS = 5

/** What the method needs injected. */
export interface TotpDeps {
  /** The injected clock: the only time a code is checked against. */
  readonly clock: Clock
  /** The injected random source; secrets, IVs and authenticator ids come from it. */
  readonly random: RandomSource
  /** The app's store. */
  readonly store: AuthStore
  /** The parsed `AUTH_ENCRYPTION_KEY` ring, current key first. */
  readonly keyRing: readonly RingKey[]
  /** The failure ceiling (ADR 0009 §3); `createAuth` always supplies it, a bare method test may leave it out. */
  readonly ceiling?: FailureCeiling | undefined
}

/** The outcome of a TOTP ceremony. `replayed` covers a used step and a lost compare-and-set. */
export type TotpResult =
  | { readonly ok: true; readonly evidence: AuthenticationEvidence }
  | { readonly ok: false; readonly reason: "invalid" | "replayed" }

interface TotpRecord {
  readonly confirmed: boolean
  readonly lastStep: number | null
  readonly secret: SealedSecret
}

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

/** RFC 4648 base32 without padding, the form authenticator apps take. */
export function base32Encode(bytes: Uint8Array): string {
  const bits = [...bytes].map((byte) => byte.toString(2).padStart(8, "0")).join("")
  const groups = bits.match(/.{1,5}/g) ?? []
  return groups.map((group) => ALPHABET.charAt(parseInt(group.padEnd(5, "0"), 2))).join("")
}

/** Decodes unpadded upper-case base32; throws on any other character. Trailing bits short of a byte are dropped. */
export function base32Decode(text: string): Uint8Array {
  const bits = [...text]
    .map((char) => {
      const value = ALPHABET.indexOf(char)
      if (value === -1) throw new TypeError("Invalid base32: character outside the alphabet.")
      return value.toString(2).padStart(5, "0")
    })
    .join("")
  const bytes = bits.match(/.{8}/g) ?? []
  return Uint8Array.from(bytes.map((byte) => parseInt(byte, 2)))
}

function readRecord(data: JsonValue): TotpRecord | undefined {
  const { confirmed, lastStep, secret } = (data ?? {}) as Readonly<Record<string, JsonValue>>
  if (typeof confirmed !== "boolean") return undefined
  if (lastStep !== null && typeof lastStep !== "number") return undefined
  // The sealed secret is not checked field by field: `openSecret` refuses any malformed one as it refuses a forged one.
  return { confirmed, lastStep, secret: (secret ?? {}) as unknown as SealedSecret }
}

function evidence(authenticatorId: string, at: number): AuthenticationEvidence {
  return {
    method: "totp",
    authenticatorId,
    factors: ["possession"],
    phishingResistant: false,
    replayResistant: true,
    keyProtection: "unknown",
    userVerified: false,
    attestationVerified: false,
    at,
  }
}

/** Checks `code` against one stored authenticator and, on success, records the step. */
async function attempt(
  deps: TotpDeps,
  tenant: TenantId,
  accountId: string,
  stored: StoredRecord,
  code: string,
  confirming: boolean,
): Promise<TotpResult> {
  const now = deps.clock.now()
  const record = readRecord(stored.data)
  const usable =
    record !== undefined &&
    stored.revokedAt === null &&
    record.confirmed !== confirming &&
    (stored.expiresAt === null || now < stored.expiresAt)
  if (!usable) return { ok: false, reason: "invalid" }
  const binding = { tenant, accountId, authenticatorId: stored.key }
  const secret = await openSecret(record.secret, deps.keyRing, binding)
  if (secret === null) return { ok: false, reason: "invalid" }
  const step = await findStep(secret, code, now, record.lastStep)
  if (step === null) {
    const used = (await findStep(secret, code, now, null)) !== null
    return { ok: false, reason: used ? "replayed" : "invalid" }
  }
  // Re-encrypt under the current key on success, so an old key can be retired (ADR 0027 Open 4).
  const sealedUnderCurrent =
    deps.keyRing.findIndex((ringKey) => ringKey.id === record.secret.keyId) === 0
  const sealed = sealedUnderCurrent
    ? record.secret
    : await sealSecret(secret, deps.keyRing, deps.random, binding)
  const written = await deps.store.update(tenant, TOTP_COLLECTION, stored.key, stored.version, {
    data: { confirmed: true, lastStep: step, secret: { ...sealed } },
    expiresAt: null,
  })
  if (written !== "updated") return { ok: false, reason: "replayed" }
  return { ok: true, evidence: evidence(stored.key, now) }
}

/** How many confirmed, unrevoked TOTP authenticators the account holds. */
export async function confirmedTotpCount(
  deps: Pick<TotpDeps, "store">,
  input: { readonly tenant: TenantId; readonly accountId: string },
): Promise<number> {
  const records = await deps.store.listByOwner(input.tenant, TOTP_COLLECTION, input.accountId)
  return records.filter(
    (record) => record.revokedAt === null && readRecord(record.data)?.confirmed === true,
  ).length
}

/** True while the account holds fewer than `TOTP_MAX_AUTHENTICATORS` confirmed, unrevoked TOTP authenticators. */
export async function totpEnrolmentAllowed(
  deps: TotpDeps,
  input: { readonly tenant: TenantId; readonly accountId: string },
): Promise<boolean> {
  return (await confirmedTotpCount(deps, input)) < TOTP_MAX_AUTHENTICATORS
}

/**
 * Starts an enrolment. The secret is returned once, base32, and is never shown again. Any enrolment of the account
 * still waiting for its code is removed, so at most one waits.
 */
export async function beginTotpEnrolment(
  deps: TotpDeps,
  input: { readonly tenant: TenantId; readonly accountId: string },
): Promise<{ readonly authenticatorId: string; readonly secret: string }> {
  for (const record of await deps.store.listByOwner(
    input.tenant,
    TOTP_COLLECTION,
    input.accountId,
  )) {
    if (readRecord(record.data)?.confirmed === false) {
      await deps.store.delete(input.tenant, TOTP_COLLECTION, record.key)
    }
  }
  const authenticatorId = randomToken(deps.random)
  const secret = randomBytes(deps.random, TOTP_SECRET_BYTES)
  const sealed = await sealSecret(secret, deps.keyRing, deps.random, {
    tenant: input.tenant,
    accountId: input.accountId,
    authenticatorId,
  })
  const created = await deps.store.createUnique(input.tenant, {
    collection: TOTP_COLLECTION,
    key: authenticatorId,
    owner: input.accountId,
    expiresAt: deps.clock.now() + TOTP_ENROLMENT_TTL_MS,
    data: { confirmed: false, lastStep: null, secret: { ...sealed } },
  })
  // A 256-bit id that already exists means the random source repeats; nothing must be shown for a row not written.
  if (created === "exists") throw new Error("The new TOTP authenticator id already exists.")
  return { authenticatorId, secret: base32Encode(secret) }
}

/** Confirms an enrolment with one valid code; the authenticator counts only from then on. */
export async function confirmTotpEnrolment(
  deps: TotpDeps,
  input: {
    readonly tenant: TenantId
    readonly accountId: string
    readonly authenticatorId: string
    readonly code: string
  },
): Promise<TotpResult> {
  const stored = await deps.store.get(input.tenant, TOTP_COLLECTION, input.authenticatorId)
  // Another account's row is refused by the additional data, which binds the secret to its account.
  if (stored === null) return { ok: false, reason: "invalid" }
  return attempt(deps, input.tenant, input.accountId, stored, input.code, true)
}

/**
 * Verifies a code against the account's confirmed authenticators. A failure counts toward an authenticator's ceiling
 * only when none of them takes the code, so a person who always uses one device never wears out another.
 */
export async function verifyTotp(
  deps: TotpDeps,
  input: { readonly tenant: TenantId; readonly accountId: string; readonly code: string },
): Promise<TotpResult> {
  const records = await deps.store.listByOwner(input.tenant, TOTP_COLLECTION, input.accountId)
  let result: TotpResult = { ok: false, reason: "invalid" }
  for (const stored of records) {
    // An authenticator at the ceiling accepts no attempt; the account's others still do (ADR 0009 §3).
    if ((await deps.ceiling?.reached(stored.key)) === true) continue
    const outcome = await attempt(deps, input.tenant, input.accountId, stored, input.code, false)
    if (outcome.ok) {
      await deps.ceiling?.succeeded(stored.key)
      return outcome
    }
    if (outcome.reason === "replayed") result = outcome
  }
  // No authenticator took the code, so each confirmed one counts a failure; a pending one counts nothing. One revoked or
  // already at the ceiling is never tried again, so what it counts does not matter.
  for (const stored of records) {
    if (readRecord(stored.data)?.confirmed === true) await deps.ceiling?.failed(stored.key)
  }
  return result
}
