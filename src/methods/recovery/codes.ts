/**
 * Saved recovery codes (ADR 0007 §1 and Open 3). A set holds 10 codes. Each is a 6-character non-secret prefix that
 * names its store row, followed by 16 base32 characters: 80 bits from the injected random source. The store keeps only
 * an argon2id hash of the secret part, with its own salt, at the password cost (ADR 0018), so a copy of the store
 * cannot be brute-forced cheaply. A code is shown once, when the set is made. An account has one current set, named by
 * its record in `RECOVERY_SET_COLLECTION`, and only codes of that set redeem: a new set becomes current by one
 * compare-and-set, so of two parallel requests exactly one gets its codes. Redeeming uses `consumeOnce`, so a code
 * works once even under parallel requests, in one transaction with whatever the redemption grants.
 *
 * Redeeming proves control of a code, not possession of a lost authenticator, so it yields no evidence and no level:
 * the dispatcher turns it into a recovery-only session (ADR 0007 §3).
 */

import { randomBytes, randomToken, type RandomSource } from "../../core/clock.js"
import type { Clock } from "../../core/clock.js"
import { normalisePassword } from "../password/rules.js"
import { QueueFullError } from "../password/semaphore.js"
import type { PasswordHasher } from "../password/argon2.js"
import { base32Encode } from "../totp/method.js"
import {
  atomically,
  type AuthStore,
  type StoreOperations,
  type TenantId,
} from "../../store/port.js"

/** The collection recovery codes live in, keyed by their prefix and owned by the account. */
export const RECOVERY_CODE_COLLECTION = "recovery-code"

/** The collection holding each account's current set id, keyed and owned by the account. */
const RECOVERY_SET_COLLECTION = "recovery-code-set"

/** Codes per set (ADR 0007 Open 3). */
export const RECOVERY_CODES_PER_SET = 10

/** Base32 characters of the non-secret prefix: 30 random bits, so rows of one store do not collide in practice. */
const PREFIX_LENGTH = 6

/** Base32 characters of the secret: 80 bits (ADR 0007 §1). */
const SECRET_LENGTH = 16

/**
 * Prefixes drawn for one code before the random source is called broken. A 30-bit prefix collides with a stored one
 * rarely; three in a row means the source repeats itself.
 */
const PREFIX_DRAWS = 3

/** What the recovery code functions need. */
export interface RecoveryDeps {
  readonly store: AuthStore
  readonly clock: Clock
  readonly random: RandomSource
  readonly hasher: PasswordHasher
}

/** `XXXXXX-XXXX-XXXX-XXXX-XXXX`: the prefix, then the secret in groups of four. */
function display(prefix: string, secret: string): string {
  return [prefix, ...(secret.match(/.{4}/g) as string[])].join("-")
}

/** The prefix and secret of a code as typed: spaces, hyphens and case are ignored; `null` when it is not a code. */
export function parseRecoveryCode(
  typed: string,
): { readonly prefix: string; readonly secret: string } | null {
  const compact = typed.replace(/[\s-]/g, "").toUpperCase()
  if (!new RegExp(`^[A-Z2-7]{${String(PREFIX_LENGTH + SECRET_LENGTH)}}$`).test(compact)) return null
  return { prefix: compact.slice(0, PREFIX_LENGTH), secret: compact.slice(PREFIX_LENGTH) }
}

/** A run of base32 characters from `bits` random bits. */
function base32Of(random: RandomSource, characters: number): string {
  // Five bits per character; the bytes drawn cover them, and the extra bits are dropped.
  return base32Encode(randomBytes(random, Math.ceil((characters * 5) / 8))).slice(0, characters)
}

/**
 * Makes a new set for the account and resolves to its codes, to be shown once; `null` when a parallel request made a
 * set first. Every code is hashed and stored before the set becomes current, so a busy or failing hasher or store
 * leaves the old set the only one that redeems. The switch is a compare-and-set on the account's set record against
 * the version read first, so of parallel requests exactly one wins; the codes of the others never redeem. A new set is
 * a credential change: `commit` runs the switch with the session's rotation and the revocation of the account's other
 * sessions (ADR 0006 §7), and resolves to whether all of it was written.
 */
export async function generateRecoveryCodes(
  deps: RecoveryDeps,
  input: { readonly tenant: TenantId; readonly accountId: string },
  commit: (apply: (ops: StoreOperations) => Promise<boolean>) => Promise<boolean> = (apply) =>
    apply(deps.store),
): Promise<readonly string[] | null> {
  const current = await deps.store.get(input.tenant, RECOVERY_SET_COLLECTION, input.accountId)
  const hashed: (readonly [string, string])[] = []
  for (const secret of Array.from({ length: RECOVERY_CODES_PER_SET }, () =>
    base32Of(deps.random, SECRET_LENGTH),
  )) {
    hashed.push([secret, await deps.hasher.hash(normalisePassword(secret), deps.random)])
  }
  const set = randomToken(deps.random, 16)
  const codes: string[] = []
  for (const [secret, hash] of hashed) codes.push(await storeCode(deps, input, set, secret, hash))
  const switchSet = async (ops: StoreOperations): Promise<boolean> => {
    const switched =
      current === null
        ? await ops.createUnique(input.tenant, {
            collection: RECOVERY_SET_COLLECTION,
            key: input.accountId,
            owner: input.accountId,
            data: set,
          })
        : await ops.update(
            input.tenant,
            RECOVERY_SET_COLLECTION,
            input.accountId,
            current.version,
            {
              data: set,
            },
          )
    return switched === "created" || switched === "updated"
  }
  return (await commit(switchSet)) ? codes : null
}

/**
 * Stores one code's hash under a fresh prefix and resolves to the code as shown. A prefix another row already holds is
 * drawn again, at most `PREFIX_DRAWS` times; the secret was stored nowhere, so it is kept.
 */
async function storeCode(
  deps: RecoveryDeps,
  input: { readonly tenant: TenantId; readonly accountId: string },
  set: string,
  secret: string,
  hash: string,
): Promise<string> {
  // Fixed draws, not a loop condition, so a store that always collides ends in an error instead of running forever.
  for (const prefix of Array.from({ length: PREFIX_DRAWS }, () =>
    base32Of(deps.random, PREFIX_LENGTH),
  )) {
    const created = await deps.store.createUnique(input.tenant, {
      collection: RECOVERY_CODE_COLLECTION,
      key: prefix,
      owner: input.accountId,
      expiresAt: null,
      data: { hash, set },
    })
    if (created === "created") return display(prefix, secret)
  }
  throw new Error(
    `${String(PREFIX_DRAWS)} recovery code prefixes in a row were already stored; the random source is broken.`,
  )
}

/** The outcome of redeeming a code: on success, what `apply` resolved to. */
export type RecoveryResult<T> =
  | { readonly ok: true; readonly value: T | undefined }
  | { readonly ok: false; readonly reason: "invalid" | "busy" }

/**
 * Redeems a code for the account. A code that does not parse, names no row of this account, is used, or does not
 * verify fails the same way, after the same argon2id work, so the reply says nothing about which. A verified code is
 * spent, checked against the account's current set, and handed to `apply` in one transaction when the store has
 * them, so a failure in `apply` leaves the code unspent. Without transactions the code is spent first, so a failure
 * after it costs the code and never grants a second use.
 */
export async function redeemRecoveryCode<T>(
  deps: RecoveryDeps,
  input: { readonly tenant: TenantId; readonly accountId: string | null; readonly code: string },
  apply?: (ops: StoreOperations) => Promise<T>,
): Promise<RecoveryResult<T>> {
  const parsed = parseRecoveryCode(input.code)
  const stored =
    parsed === null
      ? null
      : await deps.store.get(input.tenant, RECOVERY_CODE_COLLECTION, parsed.prefix)
  const hash = (stored?.data as { readonly hash?: unknown } | undefined)?.hash
  // A used code, or one of a replaced set, verifies here and is then refused, after the same work as any other.
  const live = stored?.owner === input.accountId && typeof hash === "string"
  // Text that is no code still costs the same argon2id work, against a stand-in, since an empty input cannot be hashed.
  const secret = normalisePassword(parsed?.secret ?? "unparsable recovery code")
  // A full hashing queue answers `busy`, which is no failure: the code is kept and nothing is counted (ADR 0018 §2).
  try {
    if (!live) {
      await deps.hasher.dummyVerify(secret)
      return { ok: false, reason: "invalid" }
    }
    if (!(await deps.hasher.verify(secret, hash))) return { ok: false, reason: "invalid" }
  } catch (error) {
    if (error instanceof QueueFullError) return { ok: false, reason: "busy" }
    throw error
  }
  const now = deps.clock.now()
  const redeemed = await atomically(deps.store, async (ops): Promise<RecoveryResult<T> | null> => {
    // Of two parallel redemptions of one code, exactly one consumes it (ADR 0002).
    const spent = await ops.consumeOnce(
      input.tenant,
      RECOVERY_CODE_COLLECTION,
      (parsed as { readonly prefix: string }).prefix,
      now,
    )
    const set = await ops.get(input.tenant, RECOVERY_SET_COLLECTION, input.accountId as string)
    // Read after the code is spent, the set id shows the code's set was current when it was spent.
    if (spent === null || (spent.data as { readonly set?: unknown }).set !== set?.data) return null
    return { ok: true, value: await apply?.(ops) }
  })
  return redeemed ?? { ok: false, reason: "invalid" }
}

/** How many codes of the account's current set are still unused. */
export async function remainingRecoveryCodes(
  deps: Pick<RecoveryDeps, "store">,
  input: { readonly tenant: TenantId; readonly accountId: string },
): Promise<number> {
  const set = await deps.store.get(input.tenant, RECOVERY_SET_COLLECTION, input.accountId)
  const records = await deps.store.listByOwner(
    input.tenant,
    RECOVERY_CODE_COLLECTION,
    input.accountId,
  )
  return records.filter(
    (record) =>
      record.revokedAt === null &&
      record.consumedAt === null &&
      (record.data as { readonly set?: unknown }).set === set?.data,
  ).length
}
