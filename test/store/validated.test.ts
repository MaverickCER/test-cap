import { describe, expect, it } from "vitest"
import type { NewRecord, StoreOperations } from "../../src/store/port.js"
import { validated } from "../../src/store/validated.js"

type Op = keyof StoreOperations

/** Inner operations that record each call and answer with the operation's name. */
function recording(): { ops: StoreOperations; calls: [Op, unknown[]][] } {
  const calls: [Op, unknown[]][] = []
  const names: Op[] = [
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
  ]
  const ops = Object.fromEntries(
    names.map((name) => [
      name,
      async (...args: unknown[]) => {
        calls.push([name, args])
        return name
      },
    ]),
  ) as unknown as StoreOperations
  return { ops, calls }
}

const record: NewRecord = { collection: "c", key: "k", owner: "o", expiresAt: 5, data: { a: 1 } }

/** One valid call per operation. */
const VALID: Record<Op, unknown[]> = {
  createUnique: ["t", record],
  get: ["t", "c", "k"],
  listByOwner: ["t", "c", "o"],
  update: ["t", "c", "k", 1, { data: 1, expiresAt: null }],
  revoke: ["t", "c", "k", 0],
  revokeByOwner: ["t", "c", "o", 0, { except: "k" }],
  delete: ["t", "c", "k"],
  consumeOnce: ["t", "c", "k", 0],
  increment: ["t", "n", 1, 0],
  resetCounter: ["t", "n"],
  appendAudit: ["t", "s", 1, { r: 1 }],
  readAudit: ["t", "s", 1, 1],
}

const nameError = (what: string): [ErrorConstructor, string] => [
  TypeError,
  `${what} must be a non-empty string.`,
]
const wholeError = (what: string, min: number): [ErrorConstructor, string] => [
  RangeError,
  `${what} must be a whole number of at least ${min}.`,
]

/** [operation, argument index, bad value, expected error]. */
const CASES: [Op, number, unknown, [ErrorConstructor, string]][] = [
  ["createUnique", 0, "", nameError("The tenant")],
  ["createUnique", 1, { ...record, collection: "" }, nameError("The collection")],
  ["createUnique", 1, { ...record, key: "" }, nameError("The key")],
  ["createUnique", 1, { ...record, owner: "" }, nameError("The owner")],
  ["createUnique", 1, { ...record, expiresAt: 1.5 }, wholeError("expiresAt", 0)],
  ["createUnique", 1, { ...record, data: Number.NaN }, [TypeError, "data is not a finite number."]],
  ["get", 0, "", nameError("The tenant")],
  ["get", 1, "", nameError("The collection")],
  ["get", 2, "", nameError("The key")],
  ["listByOwner", 0, "", nameError("The tenant")],
  ["listByOwner", 1, "", nameError("The collection")],
  ["listByOwner", 2, "", nameError("The owner")],
  ["update", 0, "", nameError("The tenant")],
  ["update", 1, "", nameError("The collection")],
  ["update", 2, "", nameError("The key")],
  ["update", 3, 0, wholeError("The expected version", 1)],
  ["update", 4, { data: Number.NaN }, [TypeError, "data is not a finite number."]],
  ["update", 4, { expiresAt: -1 }, wholeError("expiresAt", 0)],
  ["revoke", 0, "", nameError("The tenant")],
  ["revoke", 1, "", nameError("The collection")],
  ["revoke", 2, "", nameError("The key")],
  ["revoke", 3, -1, wholeError("The revocation time", 0)],
  ["revokeByOwner", 0, "", nameError("The tenant")],
  ["revokeByOwner", 1, "", nameError("The collection")],
  ["revokeByOwner", 2, "", nameError("The owner")],
  ["revokeByOwner", 3, 1.5, wholeError("The revocation time", 0)],
  ["delete", 0, "", nameError("The tenant")],
  ["delete", 1, "", nameError("The collection")],
  ["delete", 2, "", nameError("The key")],
  ["consumeOnce", 0, "", nameError("The tenant")],
  ["consumeOnce", 1, "", nameError("The collection")],
  ["consumeOnce", 2, "", nameError("The key")],
  ["consumeOnce", 3, -1, wholeError("The time", 0)],
  ["increment", 0, "", nameError("The tenant")],
  ["increment", 1, "", nameError("The counter")],
  ["increment", 2, 0, wholeError("The window", 1)],
  ["increment", 3, -1, wholeError("The time", 0)],
  ["resetCounter", 0, "", nameError("The tenant")],
  ["resetCounter", 1, "", nameError("The counter")],
  ["appendAudit", 0, "", nameError("The tenant")],
  ["appendAudit", 1, "", nameError("The stream")],
  ["appendAudit", 2, 0, wholeError("The sequence number", 1)],
  ["appendAudit", 3, Number.NaN, [TypeError, "record is not a finite number."]],
  ["readAudit", 0, "", nameError("The tenant")],
  ["readAudit", 1, "", nameError("The stream")],
  ["readAudit", 2, 0, wholeError("The first sequence number", 1)],
  ["readAudit", 3, 0, wholeError("The limit", 1)],
]

describe("validated", () => {
  it.each(CASES)("%s refuses argument %i = %j", async (op, index, bad, [type, message]) => {
    const { ops, calls } = recording()
    const args = [...VALID[op]]
    args[index] = bad
    const call = validated(ops)[op] as (...a: unknown[]) => Promise<unknown>
    const error = await call(...args).then(
      () => undefined,
      (caught: unknown) => caught,
    )
    expect(error).toBeInstanceOf(type)
    expect((error as Error).message).toBe(message)
    expect(calls).toEqual([])
  })

  it.each(Object.keys(VALID) as Op[])("%s passes a valid call through unchanged", async (op) => {
    const { ops, calls } = recording()
    const call = validated(ops)[op] as (...a: unknown[]) => Promise<unknown>
    expect(await call(...VALID[op])).toBe(op)
    expect(calls).toEqual([[op, VALID[op]]])
  })

  it("lets an update leave data and expiry unchanged", async () => {
    const { ops, calls } = recording()
    await validated(ops).update("t", "c", "k", 1, {})
    expect(calls).toEqual([["update", ["t", "c", "k", 1, {}]]])
  })
})
