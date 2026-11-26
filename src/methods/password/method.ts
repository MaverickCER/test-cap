/**
 * The password method (ADR 0010, ADR 0018, ADR 0009 §6) as pure logic: no HTTP and no dispatcher. `setPassword` runs
 * at sign-up, change and reset; `signInWithPassword` verifies and returns `AuthenticationEvidence`. Both normalise the
 * password once, before the length check and the hash.
 */

import type { FailureCeiling } from "../../security/ceiling.js"
import type { AuthenticationEvidence } from "../../assurance/evidence.js"
import { type Clock, type RandomSource, randomToken } from "../../core/clock.js"
import type {
  AuthStore,
  JsonValue,
  StoredRecord,
  StoreOperations,
  TenantId,
} from "../../store/port.js"
import type { PasswordHasher } from "./argon2.js"
import { type HibpFetch, screenWithHibp } from "./hibp.js"
import {
  checkPasswordLength,
  codePointLength,
  isBlocklisted,
  normalisePassword,
  PASSWORD_MAX_LENGTH,
} from "./rules.js"
import { QueueFullError } from "./semaphore.js"

/** The collection password authenticators live in, one per account, keyed by the account id. */
export const PASSWORD_COLLECTION = "password"

/** What the method needs injected. `hibp: "off"` is the declared deviation of ADR 0010 §2. */
export interface PasswordDeps {
  /** The injected clock; evidence times come from it. */
  readonly clock: Clock
  /** The injected random source; salts and authenticator ids come from it. */
  readonly random: RandomSource
  /** The app's store. */
  readonly store: AuthStore
  /** The fetch for the HIBP range check, or `"off"` when the policy turns the check off. */
  readonly hibp: HibpFetch | "off"
  /** argon2id at the ADR 0018 cost, or in test mode the cost the test chose (ADR 0026 §4). */
  readonly hasher: PasswordHasher
  /** The failure ceiling (ADR 0009 §3); `createAuth` always supplies it, a bare method test may leave it out. */
  readonly ceiling?: FailureCeiling | undefined
}

/** What breach screening found when the password was set; `breached` passwords are never stored. */
type PasswordScreening = "clear" | "indeterminate" | "off"

interface PasswordRecord {
  readonly authenticatorId: string
  readonly hash: string
  readonly screening: PasswordScreening
}

const SCREENINGS: ReadonlySet<unknown> = new Set(["clear", "indeterminate", "off"])

/** The usable password record of an account, or `undefined` when there is none, it is revoked or malformed. */
function readRecord(
  stored: StoredRecord | null,
): (PasswordRecord & { readonly key: string; readonly version: number }) | undefined {
  if (stored === null || stored.revokedAt !== null) return undefined
  const { authenticatorId, hash, screening } = (stored.data ?? {}) as Readonly<
    Record<string, JsonValue>
  >
  if (typeof authenticatorId !== "string" || typeof hash !== "string") return undefined
  if (!SCREENINGS.has(screening)) return undefined
  const { key, version } = stored
  return { authenticatorId, hash, screening: screening as PasswordScreening, key, version }
}

/** Runs `work`, answering `busy` when the hashing queue is full. */
async function unlessBusy<T>(work: () => Promise<T>): Promise<T | { ok: false; reason: "busy" }> {
  try {
    return await work()
  } catch (error) {
    if (error instanceof QueueFullError) return { ok: false, reason: "busy" }
    throw error
  }
}

/** The outcome of `setPassword`. */
export type SetPasswordResult =
  | { readonly ok: true; readonly authenticatorId: string; readonly screening: PasswordScreening }
  | {
      readonly ok: false
      readonly reason: "too-short" | "too-long" | "too-common" | "breached" | "busy" | "conflict"
    }

/** Validates, screens and stores a new password for an account, replacing any it had. */
export async function setPassword(
  deps: PasswordDeps,
  input: {
    readonly tenant: TenantId
    readonly accountId: string
    readonly password: string
    /** True when a deviation lets this password alone satisfy a requirement: the minimum is then 15. */
    readonly alone: boolean
    /** The app's system id, the account identifier and other words a password must not contain. */
    readonly contextWords?: readonly string[]
    /**
     * Runs the write, for instance inside the caller's transaction; resolves to false when nothing was written. The
     * write runs on the store when absent.
     */
    readonly commit?: (write: (ops: StoreOperations) => Promise<boolean>) => Promise<boolean>
  },
): Promise<SetPasswordResult> {
  const password = normalisePassword(input.password)
  const lengthProblem = checkPasswordLength(password, { alone: input.alone })
  if (lengthProblem !== undefined) return { ok: false, reason: lengthProblem }
  if (isBlocklisted(password, input.contextWords ?? [])) return { ok: false, reason: "too-common" }
  const screening = deps.hibp === "off" ? "off" : await screenWithHibp(password, deps.hibp)
  if (screening === "breached") return { ok: false, reason: "breached" }
  return unlessBusy(async (): Promise<SetPasswordResult> => {
    const record: PasswordRecord = {
      authenticatorId: randomToken(deps.random),
      hash: await deps.hasher.hash(password, deps.random),
      screening,
    }
    const data = { ...record }
    const write = async (ops: StoreOperations): Promise<boolean> => {
      const existing = await ops.get(input.tenant, PASSWORD_COLLECTION, input.accountId)
      return existing === null
        ? (await ops.createUnique(input.tenant, {
            collection: PASSWORD_COLLECTION,
            key: input.accountId,
            owner: input.accountId,
            data,
          })) === "created"
        : (await ops.update(input.tenant, PASSWORD_COLLECTION, input.accountId, existing.version, {
            data,
          })) === "updated"
    }
    const written = await (input.commit === undefined ? write(deps.store) : input.commit(write))
    if (!written) return { ok: false, reason: "conflict" }
    return { ok: true, authenticatorId: record.authenticatorId, screening }
  })
}

/** The outcome of `signInWithPassword`. */
export type PasswordSignInResult =
  | {
      readonly ok: true
      readonly evidence: AuthenticationEvidence
      readonly screening: PasswordScreening
    }
  | { readonly ok: false; readonly reason: "invalid" | "too-long" | "busy" | "ceiling" }

/**
 * Verifies a password. `accountId` is `null` when the identifier matched no account; a dummy hash then runs, as it
 * does for an account with no usable password, so timing does not tell them apart (ADR 0009 §6).
 */
export async function signInWithPassword(
  deps: PasswordDeps,
  input: {
    readonly tenant: TenantId
    readonly accountId: string | null
    readonly password: string
  },
): Promise<PasswordSignInResult> {
  const password = normalisePassword(input.password)
  if (codePointLength(password) > PASSWORD_MAX_LENGTH) return { ok: false, reason: "too-long" }
  const record = readRecord(
    input.accountId === null
      ? null
      : await deps.store.get(input.tenant, PASSWORD_COLLECTION, input.accountId),
  )
  return unlessBusy(async (): Promise<PasswordSignInResult> => {
    if (record === undefined) {
      await deps.hasher.dummyVerify(password)
      return { ok: false, reason: "invalid" }
    }
    // At the ceiling the password is not checked, but the same argon2id work runs, so the reply time says nothing.
    if ((await deps.ceiling?.reached(record.authenticatorId)) === true) {
      await deps.hasher.dummyVerify(password)
      return { ok: false, reason: "ceiling" }
    }
    if (!(await deps.hasher.verify(password, record.hash))) {
      await deps.ceiling?.failed(record.authenticatorId)
      return { ok: false, reason: "invalid" }
    }
    await deps.ceiling?.succeeded(record.authenticatorId)
    if (deps.hasher.needsRehash(record.hash)) {
      const hash = await deps.hasher.hash(password, deps.random)
      // A lost race leaves the old hash in place; it still verifies and is moved at the next sign-in.
      await deps.store.update(input.tenant, PASSWORD_COLLECTION, record.key, record.version, {
        data: { authenticatorId: record.authenticatorId, hash, screening: record.screening },
      })
    }
    return {
      ok: true,
      screening: record.screening,
      evidence: {
        method: "password",
        authenticatorId: record.authenticatorId,
        factors: ["knowledge"],
        phishingResistant: false,
        replayResistant: false,
        keyProtection: "unknown",
        userVerified: false,
        attestationVerified: false,
        at: deps.clock.now(),
      },
    }
  })
}
