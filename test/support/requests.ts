// Raw requests for the request-limit tests: from a chosen client address, or from none, straight into `auth.handle`,
// and a store that records the name of every counter it increments.
import type { Auth } from "../../src/core/auth.js"
import type { RateLimiterLike } from "../../src/security/rate-limit.js"
import { memoryStore } from "../../src/store/memory.js"
import type { AuthStore } from "../../src/store/port.js"
import { type Outgoing, plainRequest, type Reply, replyOf } from "./auth.js"
import { plainKeyOf } from "./limit-keys.js"

/** The client most tests send from. */
export const CLIENT = "203.0.113.7"

/** A request's shape, less the client address, which the sender fixes. */
export type Shape = Omit<Outgoing, "clientAddress">

/**
 * Sends requests from `clientAddress` (`null`: an adapter that knows none). A path outside `/auth` answers status 0,
 * as `inProcess` does.
 */
export function sendFrom(
  auth: Pick<Auth<string>, "handle">,
  clientAddress: string | null = CLIENT,
): (request: Shape) => Promise<Reply> {
  return async (request) => {
    const response = await auth.handle({
      ...plainRequest(request),
      clientAddress: clientAddress ?? undefined,
    })
    return response === null
      ? { status: 0, headers: new Headers(), text: "", json: undefined }
      : replyOf(response)
  }
}

/**
 * A memory store that records every store call by operation, every counter name `increment` is given, and the
 * collection of every record `createUnique` is asked to write.
 */
export function recordingStore(): {
  readonly store: AuthStore
  readonly counters: string[]
  readonly calls: string[]
  readonly created: string[]
} {
  const inner = memoryStore()
  const counters: string[] = []
  const calls: string[] = []
  const created: string[] = []
  const store = new Proxy(inner, {
    get(target, property, receiver) {
      const value: unknown = Reflect.get(target, property, receiver)
      if (typeof value !== "function") return value
      return (...args: unknown[]) => {
        calls.push(String(property))
        if (property === "increment") counters.push(plainKeyOf(String(args[1])))
        if (property === "createUnique")
          created.push((args[1] as { collection: string }).collection)
        return (value as (...a: unknown[]) => unknown).apply(target, args)
      }
    },
  })
  return { store, counters, calls, created }
}

/** What a fake limiter answers for one key: the library's resolved or rejected `RateLimiterRes`, or an error. */
export type Answer =
  | { readonly allowed: true; readonly remainingPoints?: number; readonly msBeforeNext?: number }
  | { readonly allowed: false; readonly msBeforeNext: number }
  | Error

/**
 * A rate-limiter-flexible-compatible limiter whose answers a test decides: it records each key, then resolves with a
 * `RateLimiterRes`-shaped answer, rejects with one, or rejects with an error, as the real ones do.
 */
export function fakeLimiter(answer: (key: string, seen: number) => Answer | Promise<Answer>): {
  readonly limiter: RateLimiterLike
  readonly keys: string[]
} {
  const keys: string[] = []
  const limiter = {
    async consume(key: string | number) {
      keys.push(String(key))
      const decided = await answer(String(key), keys.length)
      if (decided instanceof Error) throw decided
      const res = {
        msBeforeNext: decided.msBeforeNext ?? 0,
        remainingPoints: decided.allowed ? (decided.remainingPoints ?? 1) : 0,
        consumedPoints: keys.length,
        isFirstInDuration: keys.length === 1,
      }
      if (!decided.allowed) throw res
      return res
    },
  }
  return { limiter: limiter as unknown as RateLimiterLike, keys }
}
