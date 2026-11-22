import { describe, expect, it } from "vitest"
import { sequenceRandom } from "../../src/core/clock.js"
import { base64UrlDecode, base64UrlEncode } from "../../src/core/encoding.js"
import type { RingKey } from "../../src/core/mode.js"
import { openSecret, sealSecret, type SecretBinding } from "../../src/methods/totp/secret-box.js"

const key = (id: string, seed: number): RingKey => ({
  id,
  bytes: Uint8Array.from({ length: 32 }, (_, i) => (i * 29 + seed) % 256),
})
const RING = [key("k2", 7)]
const BINDING: SecretBinding = { tenant: "t", accountId: "acct", authenticatorId: "auth-1" }
const SECRET = Uint8Array.from({ length: 20 }, (_, i) => i + 100)

describe("TOTP secret encryption (ADR 0027 §4, Open 3)", () => {
  it("seals under the current key with a fresh 96-bit IV from the random source, and records the key id", async () => {
    const sealed = await sealSecret(SECRET, RING, sequenceRandom([1, 2, 3]), BINDING)
    expect(sealed.keyId).toBe("k2")
    expect(base64UrlDecode(sealed.iv)).toEqual(
      Uint8Array.from([1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3]),
    )
    // AES-GCM: ciphertext the length of the secret plus a 16-byte tag.
    expect(base64UrlDecode(sealed.ciphertext)).toHaveLength(36)
    expect(sealed.ciphertext).not.toContain(base64UrlEncode(SECRET).slice(0, 8))
    expect(await openSecret(sealed, RING, BINDING)).toEqual(SECRET)
  })

  it("matches a known answer, which pins the key derivation and the additional data", async () => {
    const sealed = await sealSecret(SECRET, RING, sequenceRandom([1, 2, 3]), BINDING)
    expect(sealed).toEqual({
      keyId: "k2",
      iv: "AQIDAQIDAQIDAQID",
      ciphertext: "4OSsSB2DfXFvjvDaFK2bJvMKnr3A4su8CLS3Q9LB_ORaFd1U",
    })
  })

  it("uses a different IV and ciphertext for each encryption", async () => {
    const random = sequenceRandom([1, 2, 3, 4, 5, 6, 7])
    const a = await sealSecret(SECRET, RING, random, BINDING)
    const b = await sealSecret(SECRET, RING, random, BINDING)
    expect(a.iv).not.toBe(b.iv)
    expect(a.ciphertext).not.toBe(b.ciphertext)
  })

  it("binds the ciphertext to its tenant, account and authenticator", async () => {
    const sealed = await sealSecret(SECRET, RING, sequenceRandom([9]), BINDING)
    for (const other of [
      { ...BINDING, tenant: "t2" },
      { ...BINDING, accountId: "acct2" },
      { ...BINDING, authenticatorId: "auth-2" },
      { tenant: "t", accountId: "acc", authenticatorId: "tauth-1" },
    ]) {
      expect(await openSecret(sealed, RING, other), JSON.stringify(other)).toBeNull()
    }
  })

  it("refuses a tampered ciphertext or IV", async () => {
    const sealed = await sealSecret(SECRET, RING, sequenceRandom([9]), BINDING)
    const bytes = base64UrlDecode(sealed.ciphertext)
    bytes[0] = (bytes[0] ?? 0) ^ 1
    expect(
      await openSecret({ ...sealed, ciphertext: base64UrlEncode(bytes) }, RING, BINDING),
    ).toBeNull()
    expect(
      await openSecret({ ...sealed, iv: base64UrlEncode(new Uint8Array(12)) }, RING, BINDING),
    ).toBeNull()
    expect(await openSecret({ ...sealed, iv: "***" }, RING, BINDING)).toBeNull()
    expect(
      await openSecret({ ...sealed, iv: base64UrlEncode(new Uint8Array(16)) }, RING, BINDING),
    ).toBeNull()
  })

  it("derives the AES key from the ring key, so the raw ring key does not decrypt", async () => {
    const sealed = await sealSecret(SECRET, RING, sequenceRandom([9]), BINDING)
    const raw = await crypto.subtle.importKey(
      "raw",
      RING[0]?.bytes ?? new Uint8Array(),
      "AES-GCM",
      false,
      ["decrypt"],
    )
    await expect(
      crypto.subtle.decrypt(
        { name: "AES-GCM", iv: base64UrlDecode(sealed.iv) },
        raw,
        base64UrlDecode(sealed.ciphertext),
      ),
    ).rejects.toThrow()
  })

  it("refuses to seal without a key", async () => {
    await expect(sealSecret(SECRET, [], sequenceRandom([1]), BINDING)).rejects.toThrow(
      new Error("AUTH_ENCRYPTION_KEY has no key to encrypt with."),
    )
  })
})
