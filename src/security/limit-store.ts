/**
 * The store the limits count in (ADR 0032). The keys of counters and limit blocks name an email address, a client
 * address or both, so this view of the app's store names each one by an HMAC of its key instead, under a key derived
 * from the current `AUTH_ENCRYPTION_KEY`. The same key always gets the same name, so counts still add up; the store
 * holds no address that can be read back without the key.
 */
import { base64UrlEncode, utf8Encode } from "../core/encoding.js"
import type { RingKey } from "../core/mode.js"
import type { AuthStore, NewRecord } from "../store/port.js"
import { LIMIT_BLOCK_COLLECTION } from "./store-limiter.js"

/** The HKDF `info` that keeps this key apart from every other use of the ring. */
const LABEL = utf8Encode("limit-keys")

/** Names a limit key by HMAC-SHA-256 under a key derived from `ringKey`, in unpadded base64url. */
export function limitKeyName(ringKey: RingKey): (key: string) => Promise<string> {
  const hmac = (async () =>
    crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: LABEL },
      // Stryker disable next-line BooleanLiteral: equivalent, extractability only matters to exportKey, which nothing calls
      await crypto.subtle.importKey("raw", ringKey.bytes, "HKDF", false, ["deriveKey"]),
      { name: "HMAC", hash: "SHA-256", length: 256 },
      // Stryker disable next-line BooleanLiteral: equivalent, extractability only matters to exportKey, which nothing calls
      false,
      ["sign"],
    ))()
  return async (key) =>
    base64UrlEncode(new Uint8Array(await crypto.subtle.sign("HMAC", await hmac, utf8Encode(key))))
}

/** `store`, with every counter and limit block named by `name` of its key; every other record passes unchanged. */
export function limitStore(store: AuthStore, name: (key: string) => Promise<string>): AuthStore {
  /** The key a record of `collection` is stored under. */
  const keyIn = async (collection: string, key: string) =>
    collection === LIMIT_BLOCK_COLLECTION ? name(key) : key
  return new Proxy(store, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver) as unknown
      if (typeof value !== "function") return value
      const call = (args: unknown[]) =>
        (value as (...a: unknown[]) => unknown).apply(target, args) as Promise<unknown>
      switch (property) {
        case "increment":
        case "resetCounter":
          return async (tenant: string, counter: string, ...rest: unknown[]) =>
            call([tenant, await name(counter), ...rest])
        case "get":
        case "update":
        case "delete":
          return async (tenant: string, collection: string, key: string, ...rest: unknown[]) =>
            call([tenant, collection, await keyIn(collection, key), ...rest])
        case "createUnique":
          return async (tenant: string, record: NewRecord) =>
            call([tenant, { ...record, key: await keyIn(record.collection, record.key) }])
        default:
          return (value as (...a: unknown[]) => unknown).bind(target)
      }
    },
  })
}
