import { describe, expect, it } from "vitest"
import { utf8Encode } from "../../src/core/encoding.js"
import { hotp } from "../../src/methods/totp/hotp.js"

// RFC 4226 Appendix D: the secret is the ASCII string "12345678901234567890".
const SECRET = utf8Encode("12345678901234567890")
const EXPECTED = [
  "755224",
  "287082",
  "359152",
  "969429",
  "338314",
  "254676",
  "287922",
  "162583",
  "399871",
  "520489",
]

describe("HOTP against RFC 4226 Appendix D", () => {
  for (const [counter, code] of EXPECTED.entries()) {
    it(`counter ${counter} gives ${code}`, async () => {
      expect(await hotp(SECRET, counter, 6)).toBe(code)
    })
  }
})
