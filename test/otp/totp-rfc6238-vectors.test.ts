import { describe, expect, it } from "vitest"
import { utf8Encode } from "../../src/core/encoding.js"
import { hotp } from "../../src/methods/totp/hotp.js"
import { timeStep } from "../../src/methods/totp/totp.js"

// RFC 6238 Appendix B, SHA-1 rows (the only hash the module accepts): 8 digits, a 30-second step, T0 = 0.
const SECRET = utf8Encode("12345678901234567890")
const VECTORS: readonly [seconds: number, step: number, code: string][] = [
  [59, 0x1, "94287082"],
  [1_111_111_109, 0x23523ec, "07081804"],
  [1_111_111_111, 0x23523ed, "14050471"],
  [1_234_567_890, 0x273ef07, "89005924"],
  [2_000_000_000, 0x3f940aa, "69279037"],
  [20_000_000_000, 0x27bc86aa, "65353130"],
]

describe("TOTP against RFC 6238 Appendix B (SHA-1)", () => {
  for (const [seconds, step, code] of VECTORS) {
    it(`time ${seconds} is step ${step.toString(16)} and gives ${code}`, async () => {
      expect(timeStep(seconds * 1000)).toBe(step)
      expect(await hotp(SECRET, timeStep(seconds * 1000), 8)).toBe(code)
    })
  }
})
