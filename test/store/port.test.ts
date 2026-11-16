import { describe, expect, it } from "vitest"
import { assertJson, assertName, assertNewRecord, assertWhole } from "../../src/store/port.js"

describe("assertName", () => {
  it("accepts a non-empty string", () => {
    expect(() => assertName("k", "The key")).not.toThrow()
  })

  it("refuses an empty string and anything that is not a string, naming the argument", () => {
    expect(() => assertName("", "The key")).toThrow(
      new TypeError("The key must be a non-empty string."),
    )
    expect(() => assertName(7 as never, "The tenant")).toThrow(
      new TypeError("The tenant must be a non-empty string."),
    )
  })
})

describe("assertWhole", () => {
  it("accepts a whole number at the minimum, which defaults to 0", () => {
    expect(() => assertWhole(0, "The time")).not.toThrow()
    expect(() => assertWhole(1, "The limit", 1)).not.toThrow()
  })

  it("refuses a value below the minimum, a fraction and an unsafe integer, naming both", () => {
    expect(() => assertWhole(-1, "The time")).toThrow(
      new RangeError("The time must be a whole number of at least 0."),
    )
    expect(() => assertWhole(0, "The limit", 1)).toThrow(
      new RangeError("The limit must be a whole number of at least 1."),
    )
    expect(() => assertWhole(1.5, "The window", 1)).toThrow(
      new RangeError("The window must be a whole number of at least 1."),
    )
    expect(() => assertWhole(2 ** 53, "The time")).toThrow(
      new RangeError("The time must be a whole number of at least 0."),
    )
  })
})

describe("assertJson", () => {
  it("accepts every kind of plain JSON, including objects without a prototype", () => {
    const bare = Object.assign(Object.create(null) as Record<string, unknown>, { a: 1 })
    for (const value of [
      null,
      true,
      false,
      0,
      -1.5,
      "",
      "s",
      [],
      [1, [null]],
      {},
      { a: [{}] },
      bare,
    ]) {
      expect(() => assertJson(value)).not.toThrow()
    }
  })

  it("refuses a value that does not survive a JSON round trip, naming where it is", () => {
    expect(() => assertJson(undefined)).toThrow(new TypeError("data is not plain JSON."))
    expect(() => assertJson(() => 1)).toThrow(new TypeError("data is not plain JSON."))
    expect(() => assertJson(1n)).toThrow(new TypeError("data is not plain JSON."))
    expect(() => assertJson(new Date(0))).toThrow(new TypeError("data is not plain JSON."))
    expect(() => assertJson(Number.NaN)).toThrow(new TypeError("data is not a finite number."))
    expect(() => assertJson(Number.POSITIVE_INFINITY, "record")).toThrow(
      new TypeError("record is not a finite number."),
    )
    expect(() => assertJson([1, [2, Number.NaN]])).toThrow(
      new TypeError("data[1][1] is not a finite number."),
    )
    expect(() => assertJson({ a: { b: undefined } })).toThrow(
      new TypeError("data.a.b is not plain JSON."),
    )
  })

  it("refuses a sparse array, which a JSON round trip would turn into nulls", () => {
    expect(() => assertJson(new Array(1))).toThrow(
      new TypeError("data[0] is missing, so the array is not plain JSON."),
    )
    // eslint-disable-next-line no-sparse-arrays -- the hole is the case under test
    expect(() => assertJson({ list: [1, , 3] }, "record")).toThrow(
      new TypeError("record.list[1] is missing, so the array is not plain JSON."),
    )
    expect(() => assertJson([undefined])).toThrow(new TypeError("data[0] is not plain JSON."))
  })
})

describe("assertNewRecord", () => {
  const record = { collection: "c", key: "k", owner: null, data: 1 }

  it("accepts a record with or without an owner and an expiry", () => {
    expect(() => assertNewRecord(record)).not.toThrow()
    expect(() => assertNewRecord({ ...record, owner: "o", expiresAt: 0 })).not.toThrow()
    expect(() => assertNewRecord({ ...record, expiresAt: null })).not.toThrow()
  })

  it("names the field that is wrong", () => {
    expect(() => assertNewRecord({ ...record, collection: "" })).toThrow(
      new TypeError("The collection must be a non-empty string."),
    )
    expect(() => assertNewRecord({ ...record, key: "" })).toThrow(
      new TypeError("The key must be a non-empty string."),
    )
    expect(() => assertNewRecord({ ...record, owner: "" })).toThrow(
      new TypeError("The owner must be a non-empty string."),
    )
    expect(() => assertNewRecord({ ...record, expiresAt: -1 })).toThrow(
      new RangeError("expiresAt must be a whole number of at least 0."),
    )
    expect(() => assertNewRecord({ ...record, data: [undefined] as never })).toThrow(
      new TypeError("data[0] is not plain JSON."),
    )
  })
})
