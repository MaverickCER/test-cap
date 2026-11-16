import { describe, expect, it } from "vitest"
import {
  fixedClock,
  randomBytes,
  randomDigits,
  randomToken,
  sequenceRandom,
  systemClock,
  systemRandom,
} from "../../src/core/clock.js"

describe("systemClock", () => {
  it("reads the current time in epoch milliseconds", () => {
    const before = Date.now()
    const now = systemClock.now()
    expect(now).toBeGreaterThanOrEqual(before)
    expect(now).toBeLessThanOrEqual(Date.now())
  })
})

describe("fixedClock", () => {
  it("returns the time it was set to until advanced", () => {
    const clock = fixedClock(1_000)
    expect(clock.now()).toBe(1_000)
    clock.advance(250)
    expect(clock.now()).toBe(1_250)
    clock.set(5)
    expect(clock.now()).toBe(5)
  })

  it("refuses a time that is not a finite integer, naming which one", () => {
    expect(() => fixedClock(Number.NaN)).toThrow(
      new RangeError("The start time must be a whole number of milliseconds."),
    )
    expect(() => fixedClock(1.5)).toThrow(
      new RangeError("The start time must be a whole number of milliseconds."),
    )
    const clock = fixedClock(0)
    expect(() => clock.advance(Number.POSITIVE_INFINITY)).toThrow(
      new RangeError("The step must be a whole number of milliseconds."),
    )
    expect(() => clock.set(-0.5)).toThrow(
      new RangeError("The time must be a whole number of milliseconds."),
    )
    expect(clock.now()).toBe(0)
  })
})

describe("systemRandom", () => {
  it("fills the requested number of bytes from Web Crypto", () => {
    const a = systemRandom.fill(new Uint8Array(32))
    const b = systemRandom.fill(new Uint8Array(32))
    expect(a).toHaveLength(32)
    expect(a).not.toEqual(b)
  })
})

describe("sequenceRandom", () => {
  it("replays its bytes in order and repeats from the start", () => {
    const random = sequenceRandom([1, 2, 3])
    expect([...random.fill(new Uint8Array(4))]).toEqual([1, 2, 3, 1])
    expect([...random.fill(new Uint8Array(2))]).toEqual([2, 3])
  })

  it("refuses an empty sequence or a value outside a byte", () => {
    expect(() => sequenceRandom([])).toThrow(
      new RangeError("The sequence needs at least one byte."),
    )
    const notAByte = new RangeError("Every value in the sequence must be a byte (0-255).")
    expect(() => sequenceRandom([256])).toThrow(notAByte)
    expect(() => sequenceRandom([-1])).toThrow(notAByte)
    expect(() => sequenceRandom([1.5])).toThrow(notAByte)
    expect([...sequenceRandom([0, 255]).fill(new Uint8Array(2))]).toEqual([0, 255])
  })
})

describe("randomBytes", () => {
  it("draws exactly the requested length from the source", () => {
    expect([...randomBytes(sequenceRandom([7, 8]), 3)]).toEqual([7, 8, 7])
  })

  it("refuses a length that is not a positive integer", () => {
    const length = new RangeError("The length must be a positive integer.")
    expect(() => randomBytes(systemRandom, 0)).toThrow(length)
    expect(() => randomBytes(systemRandom, 2.5)).toThrow(length)
  })
})

describe("randomToken", () => {
  it("encodes 32 random bytes as unpadded base64url by default", () => {
    const token = randomToken(sequenceRandom([0xfb, 0xff]))
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(token.startsWith("-_")).toBe(true)
  })

  it("accepts another byte length", () => {
    expect(randomToken(sequenceRandom([0]), 3)).toBe("AAAA")
  })
})

describe("randomDigits", () => {
  it("draws decimal digits", () => {
    expect(randomDigits(sequenceRandom([0, 1, 9, 123]), 4)).toBe("0193")
  })

  it("rejects bytes at or above 250 so every digit is equally likely", () => {
    // 250..255 would favour 0..5; they are skipped, not reduced.
    expect(randomDigits(sequenceRandom([250, 255, 7]), 1)).toBe("7")
  })

  it("draws digits from its own buffer, one byte per digit when none are rejected", () => {
    expect(randomDigits(sequenceRandom([10, 21, 32, 43, 54, 65]), 6)).toBe("012345")
  })

  it("draws only the digits still missing after a round with rejected bytes", () => {
    const random = sequenceRandom([250, 1, 2, 3, 4])
    // Round one draws [250, 1] and keeps "1"; round two draws one byte, [2], and stops.
    expect(randomDigits(random, 2)).toBe("12")
    expect([...random.fill(new Uint8Array(1))]).toEqual([3])
  })

  it("refuses a length that is not a positive integer", () => {
    const length = new RangeError("The length must be a positive integer.")
    expect(() => randomDigits(systemRandom, 0)).toThrow(length)
    expect(() => randomDigits(systemRandom, 1.5)).toThrow(length)
  })

  it("draws for at most 64 rounds", () => {
    const rejected = (rounds: number): number[] => [...Array.from({ length: rounds }, () => 255), 7]
    expect(randomDigits(sequenceRandom(rejected(63)), 1)).toBe("7")
    expect(() => randomDigits(sequenceRandom(rejected(64)), 1)).toThrow(
      new Error(
        "The random source kept yielding rejected bytes; it is not a usable random source.",
      ),
    )
  })

  it("gives up rather than loop forever on a source that only yields rejected bytes", () => {
    expect(() => randomDigits(sequenceRandom([255]), 6)).toThrow(
      new Error(
        "The random source kept yielding rejected bytes; it is not a usable random source.",
      ),
    )
  })
})
