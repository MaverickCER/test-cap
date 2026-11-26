/**
 * Accounts and their email identifiers (architecture "Data model", ADR 0021 §6, ADR 0012 §5).
 *
 * Sign-up records the identifier as **unconfirmed**: a record owned by the new account, under a random key, with no
 * uniqueness claim, because an identifier nobody has proved is the attacker's word. Two sign-ups with one address make
 * two accounts, each holding its own unconfirmed record. Only a **confirmed** identifier resolves to an account: it is
 * keyed by the normalised value, so `createUnique` makes it unique per tenant, and a redeemed confirmation code (F08)
 * is what writes it. Sign-in looks accounts up by confirmed identifiers only.
 */

import { randomToken, type RandomSource } from "./clock.js"
import type { AuthStore, StoreOperations, JsonValue, TenantId } from "../store/port.js"

/** Accounts, keyed by account id. */
export const ACCOUNT_COLLECTION = "account"
/** Confirmed identifiers, keyed by the normalised value; `data.account` names the account. */
export const IDENTIFIER_COLLECTION = "identifier"
/** Unconfirmed identifiers, keyed at random and owned by the account that typed them. */
export const UNCONFIRMED_IDENTIFIER_COLLECTION = "identifier-unconfirmed"

/** Creates an active account holding `identifier` unconfirmed; resolves to the new account's id. */
export async function createAccount(
  store: AuthStore,
  tenant: TenantId,
  random: RandomSource,
  input: { readonly identifier: string; readonly now: number },
): Promise<string> {
  const accountId = randomToken(random, 16)
  const create = async (key: string, collection: string, owner: string, data: JsonValue) => {
    if ((await store.createUnique(tenant, { collection, key, owner, data })) === "exists") {
      throw new Error(
        "A new account record collided with a stored one; the random source is broken.",
      )
    }
  }
  await create(accountId, ACCOUNT_COLLECTION, accountId, { status: "active", createdAt: input.now })
  await create(randomToken(random, 16), UNCONFIRMED_IDENTIFIER_COLLECTION, accountId, {
    kind: "email",
    value: input.identifier,
  })
  return accountId
}

/** True when the account exists and is active; a disabled account produces no evidence (ADR 0012 §5). */
export async function accountActive(
  store: Pick<StoreOperations, "get">,
  tenant: TenantId,
  accountId: string,
): Promise<boolean> {
  const record = await store.get(tenant, ACCOUNT_COLLECTION, accountId)
  const data = record?.data as Readonly<Record<string, JsonValue>> | null | undefined
  return data?.["status"] === "active"
}

/** The active account a confirmed identifier names, or `null`: an unconfirmed identifier resolves to nothing. */
export async function resolveConfirmed(
  store: AuthStore,
  tenant: TenantId,
  identifier: string,
): Promise<string | null> {
  const record = await store.get(tenant, IDENTIFIER_COLLECTION, identifier)
  const data = record?.data as Readonly<Record<string, JsonValue>> | null | undefined
  const account = data?.["account"]
  if (record?.revokedAt !== null || typeof account !== "string") return null
  return (await accountActive(store, tenant, account)) ? account : null
}

/** The identifier values the account typed at sign-up, for the password context words (ADR 0010). */
export async function identifierValues(
  store: AuthStore,
  tenant: TenantId,
  accountId: string,
): Promise<readonly string[]> {
  const records = await store.listByOwner(tenant, UNCONFIRMED_IDENTIFIER_COLLECTION, accountId)
  return records.flatMap((record) => {
    const value = (record.data as Readonly<Record<string, JsonValue>> | null)?.["value"]
    return typeof value === "string" ? [value] : []
  })
}

/**
 * Claims `identifier` for the account once its confirmation code is redeemed (ADR 0008 §4). `false` when another
 * account confirmed it first: then nothing is written.
 */
export async function claimIdentifier(
  store: AuthStore,
  tenant: TenantId,
  input: { readonly accountId: string; readonly identifier: string; readonly now: number },
): Promise<boolean> {
  const written = await store.createUnique(tenant, {
    collection: IDENTIFIER_COLLECTION,
    key: input.identifier,
    owner: input.accountId,
    data: { account: input.accountId, kind: "email", confirmedAt: input.now },
  })
  return written === "created"
}

/** True when the account holds a confirmed identifier that is not revoked. */
export async function hasConfirmedIdentifier(
  store: AuthStore,
  tenant: TenantId,
  accountId: string,
): Promise<boolean> {
  const records = await store.listByOwner(tenant, IDENTIFIER_COLLECTION, accountId)
  return records.some((record) => record.revokedAt === null)
}

/** Lost writes `deactivateAccount` retries before it gives up: a bound, so contention can never loop forever. */
const DEACTIVATE_TRIES = 5

/**
 * Marks the account disabled (ADR 0012 Open 15: deprovision). Every ceremony and every session read checks the status,
 * so nothing the account holds works afterwards; resolves to `false` when there is no such account. A write that loses
 * a race to another change is retried against the newer version, at most `DEACTIVATE_TRIES` times.
 */
export async function deactivateAccount(
  store: AuthStore,
  tenant: TenantId,
  accountId: string,
  now: number,
): Promise<boolean> {
  /** One try: `true` when written, `false` when there is no such account, `null` when another change won the race. */
  const once = async (): Promise<boolean | null> => {
    const record = await store.get(tenant, ACCOUNT_COLLECTION, accountId)
    if (record === null) return false
    const data = record.data as Readonly<Record<string, JsonValue>>
    const written = await store.update(tenant, ACCOUNT_COLLECTION, accountId, record.version, {
      data: { ...data, status: "disabled", disabledAt: now },
    })
    return written === "updated" ? true : null
  }
  // A fixed number of tries, each after the last lost a race; no loop condition, so nothing can make it run forever.
  const outcome = await Array.from({ length: DEACTIVATE_TRIES }).reduce<Promise<boolean | null>>(
    async (previous) => (await previous) ?? once(),
    Promise.resolve(null),
  )
  if (outcome !== null) return outcome
  throw new Error(`The account could not be disabled after ${String(DEACTIVATE_TRIES)} tries.`)
}
