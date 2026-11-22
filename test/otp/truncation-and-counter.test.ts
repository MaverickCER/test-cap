import { describe, expect, it } from "vitest"
import { utf8Encode } from "../../src/core/encoding.js"
import { hotp } from "../../src/methods/totp/hotp.js"
import {
  findStep,
  TOTP_DIGITS,
  TOTP_DRIFT_STEPS,
  TOTP_STEP_MS,
  timeStep,
} from "../../src/methods/totp/totp.js"

const SECRET = utf8Encode("12345678901234567890")

describe("HOTP truncation and the counter", () => {
  it("encodes the counter as 8 big-endian bytes, beyond 32 bits too", async () => {
    // The RFC 6238 vector at T = 20000000000 s has step 0x27BC86AA; 2^32 + that step must differ from it.
    expect(await hotp(SECRET, 0x27bc86aa + 2 ** 32, 8)).not.toBe("65353130")
    expect(await hotp(SECRET, 2 ** 32, 6)).toMatch(/^\d{6}$/)
    expect(await hotp(SECRET, 2 ** 32, 6)).not.toBe(await hotp(SECRET, 0, 6))
  })

  it("pads a short code with leading zeros", async () => {
    // RFC 6238: T = 1111111109 gives 07081804 at 8 digits; at 6 digits it is 081804.
    expect(await hotp(SECRET, 0x23523ec, 6)).toBe("081804")
  })

  it("refuses a counter or digit count out of range", async () => {
    await expect(hotp(SECRET, -1, 6)).rejects.toThrow(
      new RangeError("The HOTP counter must be a whole number of at least 0."),
    )
    await expect(hotp(SECRET, 1.5, 6)).rejects.toThrow(RangeError)
    await expect(hotp(SECRET, 0, 5)).rejects.toThrow(
      new RangeError("An HOTP code has 6, 7 or 8 digits."),
    )
    await expect(hotp(SECRET, 0, 9)).rejects.toThrow(RangeError)
    expect(await hotp(SECRET, 0, 7)).toBe("4755224")
  })
})

describe("TOTP parameters and matching (ADR 0027 Open 1 and 2)", () => {
  it("uses 6 digits, a 30-second step and one step of drift", () => {
    expect([TOTP_DIGITS, TOTP_STEP_MS, TOTP_DRIFT_STEPS]).toEqual([6, 30_000, 1])
  })

  it("counts steps from the epoch", () => {
    expect(timeStep(0)).toBe(0)
    expect(timeStep(29_999)).toBe(0)
    expect(timeStep(30_000)).toBe(1)
  })

  it("accepts the current step and one either side, and no further", async () => {
    const now = 100 * TOTP_STEP_MS + 12_345
    for (const step of [99, 100, 101]) {
      expect(await findStep(SECRET, await hotp(SECRET, step, 6), now, null)).toBe(step)
    }
    for (const step of [98, 102]) {
      expect(await findStep(SECRET, await hotp(SECRET, step, 6), now, null)).toBeNull()
    }
  })

  it("skips steps before the epoch rather than failing", async () => {
    expect(await findStep(SECRET, await hotp(SECRET, 0, 6), 0, null)).toBe(0)
    expect(await findStep(SECRET, await hotp(SECRET, 1, 6), 0, null)).toBe(1)
  })

  it("refuses a step at or before the last accepted one", async () => {
    const now = 100 * TOTP_STEP_MS
    const code = await hotp(SECRET, 100, 6)
    expect(await findStep(SECRET, code, now, 99)).toBe(100)
    expect(await findStep(SECRET, code, now, 100)).toBeNull()
    expect(await findStep(SECRET, code, now, 101)).toBeNull()
    expect(await findStep(SECRET, await hotp(SECRET, 99, 6), now, 99)).toBeNull()
    expect(await findStep(SECRET, await hotp(SECRET, 101, 6), now, 100)).toBe(101)
  })

  it("refuses a code that is not exactly 6 digits", async () => {
    const now = 100 * TOTP_STEP_MS
    const code = await hotp(SECRET, 100, 6)
    for (const bad of [`${code} `, ` ${code}`, code.slice(1), `${code}0`, "abcdef", ""]) {
      expect(await findStep(SECRET, bad, now, null), JSON.stringify(bad)).toBeNull()
    }
  })
})
