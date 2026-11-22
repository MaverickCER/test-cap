import { describe, expect, it } from "vitest"
import { BUNDLED_BLOCKLIST } from "../../src/methods/password/blocklist.js"
import {
  isBlocklisted,
  normalisePassword,
  PASSWORD_MIN_WITH_MFA,
} from "../../src/methods/password/rules.js"

describe("the bundled blocklist (ADR 0010 §1)", () => {
  it("holds lowercase entries no shorter than the shortest accepted password", () => {
    expect(BUNDLED_BLOCKLIST.size).toBeGreaterThanOrEqual(100)
    for (const entry of BUNDLED_BLOCKLIST) {
      expect([...entry].length, entry).toBeGreaterThanOrEqual(PASSWORD_MIN_WITH_MFA)
      expect(entry, entry).toBe(entry.toLowerCase())
    }
  })

  it("rejects a common password whatever its case", () => {
    expect(isBlocklisted(normalisePassword("password"), [])).toBe(true)
    expect(isBlocklisted(normalisePassword("PassWord"), [])).toBe(true)
    expect(isBlocklisted(normalisePassword("12345678"), [])).toBe(true)
    expect(isBlocklisted(normalisePassword("qwertyuiop"), [])).toBe(true)
  })

  it("compares the whole password, so a longer one that contains an entry passes", () => {
    expect(isBlocklisted(normalisePassword("password horse battery"), [])).toBe(false)
  })

  it("rejects a password that contains a context word, whatever its case", () => {
    const context = ["Acme-Portal", "alice@example.test"]
    expect(isBlocklisted(normalisePassword("my acme-portal pass"), context)).toBe(true)
    expect(isBlocklisted(normalisePassword("ALICE@EXAMPLE.TEST!"), context)).toBe(true)
    expect(isBlocklisted(normalisePassword("correct horse battery"), context)).toBe(false)
  })

  it("ignores context words shorter than four characters, which would block too much", () => {
    expect(isBlocklisted(normalisePassword("bob is a builder"), ["bob"])).toBe(false)
    expect(isBlocklisted(normalisePassword("bobby is a builder"), ["bobb"])).toBe(true)
    expect(isBlocklisted(normalisePassword("anything at all"), [""])).toBe(false)
  })

  it("normalises context words to NFC before comparing", () => {
    expect(isBlocklisted(normalisePassword("cafécafé!"), ["café"])).toBe(true)
  })
})
