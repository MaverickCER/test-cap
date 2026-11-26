import { memoryStore } from "../../src/store/memory.js"
import type { AuthStore, StoreOperations } from "../../src/store/port.js"

/** The `AuthStore` operations a fault can be injected into. */
const STORE_OPERATIONS = [
  "createUnique",
  "get",
  "listByOwner",
  "update",
  "revoke",
  "revokeByOwner",
  "delete",
  "consumeOnce",
  "increment",
  "resetCounter",
  "appendAudit",
  "readAudit",
] as const

/** One operation of the store port. */
export type StoreOperation = (typeof STORE_OPERATIONS)[number]

/**
 * How an injected fault behaves:
 *
 * - `throw`: the operation throws before returning a promise, as a broken driver call does;
 * - `reject`: it returns a promise that rejects at once, as a refused connection does;
 * - `timeout`: it rejects a few milliseconds later, as a driver's statement timeout does;
 * - `hang`: it never settles, as a dead connection without a timeout does;
 * - `answer`: it resolves with `answer` without touching the data, as a store that misreports does.
 */
export type FaultMode = "throw" | "reject" | "timeout" | "hang" | "answer"

/** A fault on the `call`-th call (1-based, counted from `arm`) of one operation. */
export interface Fault {
  readonly op: StoreOperation
  readonly call: number
  readonly mode: FaultMode
  /** What an `answer` fault resolves with. */
  readonly answer?: unknown
}

/** The error every injected fault throws or rejects with. */
export const STORE_DOWN = "injected store failure"

function failure({ mode, answer }: Fault): Promise<unknown> {
  if (mode === "answer") return Promise.resolve(answer)
  if (mode === "throw") throw new Error(STORE_DOWN)
  if (mode === "reject") return Promise.reject(new Error(STORE_DOWN))
  if (mode === "timeout") {
    return new Promise((_, reject) => {
      setTimeout(() => {
        reject(new Error(STORE_DOWN))
      }, 2)
    })
  }
  return new Promise(() => undefined)
}

/**
 * A memory store that records every operation called after `arm`, and fails one of them as `fault` says. With
 * `transactional: false` it has no `transaction`, as a SQL store built without one, so multi-step changes run step by
 * step; otherwise every step inside a transaction goes through the same recorder.
 */
export function faultyStore(options: { readonly transactional?: boolean } = {}) {
  const base = memoryStore()
  let armed = false
  let fault: Fault | null = null
  let fired = false
  const calls: StoreOperation[] = []
  /** The collection (or counter, or stream) each recorded call names, beside `calls`. */
  const targets: string[] = []

  const wrap = (ops: StoreOperations): StoreOperations => {
    const wrapped: Partial<Record<StoreOperation, unknown>> = {}
    for (const name of STORE_OPERATIONS) {
      wrapped[name] = (...args: unknown[]) => {
        if (armed) {
          calls.push(name)
          const target = args[1]
          targets.push(
            typeof target === "string" ? target : (target as { collection: string }).collection,
          )
          const count = calls.filter((call) => call === name).length
          if (fault?.op === name && fault.call === count) {
            fired = true
            return failure(fault)
          }
        }
        return (ops[name] as (...a: unknown[]) => Promise<unknown>)(...args)
      }
    }
    return wrapped as unknown as StoreOperations
  }

  const store: AuthStore = {
    kind: base.kind,
    durable: base.durable,
    ...wrap(base),
    ...(options.transactional === false
      ? {}
      : {
          transaction: <T>(fn: (tx: StoreOperations) => Promise<T>) =>
            base.transaction((tx) => fn(wrap(tx))),
        }),
  }

  return {
    store,
    /** The store underneath, which no fault reaches: for checks after the faulted request. */
    base,
    /** Starts recording, and fails the operation `next` names, if any. */
    arm(next: Fault | null = null): void {
      calls.length = 0
      targets.length = 0
      fault = next
      fired = false
      armed = true
    },
    /** Stops recording and failing. */
    heal(): void {
      armed = false
      fault = null
    },
    /** The operations called since `arm`, in order. */
    calls(): readonly StoreOperation[] {
      return [...calls]
    },
    /** The calls since `arm`, each with the collection, counter or stream it names. */
    trace(): readonly { readonly op: StoreOperation; readonly target: string }[] {
      return calls.map((op, index) => ({ op, target: targets[index] as string }))
    },
    /** True once the armed fault was injected. */
    fired(): boolean {
      return fired
    },
  }
}
