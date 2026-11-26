// `@noble/hashes` is loaded only when the fallback starts (ADR 0031): where hash-wasm compiles, the module is never
// imported. The mock's factory runs only on an import, so it counts the loads.
import { describe, expect, it, vi } from "vitest"
import { sequenceRandom } from "../../src/core/clock.js"
import { createHasher } from "../../src/methods/password/argon2.js"
import { normalisePassword } from "../../src/methods/password/rules.js"
import { TEST_ARGON2_COST } from "../support/argon2.js"

const loads = vi.hoisted(() => ({ count: 0 }))

vi.mock("@noble/hashes/argon2.js", async (importOriginal) => {
  loads.count += 1
  return importOriginal()
})

describe("the @noble/hashes fallback", () => {
  it("is never loaded where hash-wasm compiles", async () => {
    const hasher = createHasher(TEST_ARGON2_COST)
    const password = normalisePassword("correct horse")
    const encoded = await hasher.hash(password, sequenceRandom([7]))
    expect(await hasher.verify(password, encoded)).toBe(true)
    expect(await hasher.dummyVerify(password)).toBe(false)
    expect(loads.count).toBe(0)
  })
})
