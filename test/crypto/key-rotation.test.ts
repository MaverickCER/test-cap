import { describe, expect, it } from "vitest"
import { sequenceRandom } from "../../src/core/clock.js"
import type { RingKey } from "../../src/core/mode.js"
import { openSecret, sealSecret } from "../../src/methods/totp/secret-box.js"

const key = (id: string, seed: number): RingKey => ({
  id,
  bytes: Uint8Array.from({ length: 32 }, (_, i) => (i * 29 + seed) % 256),
})
const OLD = key("old", 1)
const NEW = key("new", 2)
const BINDING = { tenant: "t", accountId: "a", authenticatorId: "x" }
const SECRET = new Uint8Array(20).fill(42)

describe("key rotation (ADR 0027 §4)", () => {
  it("opens a secret sealed under an older key while that key stays in the ring", async () => {
    const sealed = await sealSecret(SECRET, [OLD], sequenceRandom([4]), BINDING)
    expect(sealed.keyId).toBe("old")
    expect(await openSecret(sealed, [NEW, OLD], BINDING)).toEqual(SECRET)
    expect((await sealSecret(SECRET, [NEW, OLD], sequenceRandom([4]), BINDING)).keyId).toBe("new")
  })

  it("refuses a secret whose key id has left the ring", async () => {
    const sealed = await sealSecret(SECRET, [OLD], sequenceRandom([4]), BINDING)
    expect(await openSecret(sealed, [NEW], BINDING)).toBeNull()
  })

  it("refuses a secret relabelled with another key id", async () => {
    const sealed = await sealSecret(SECRET, [OLD], sequenceRandom([4]), BINDING)
    expect(await openSecret({ ...sealed, keyId: "new" }, [NEW, OLD], BINDING)).toBeNull()
  })
})
