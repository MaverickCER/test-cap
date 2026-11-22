// Attack: a database read yields usable TOTP seeds.
// Stopped by: seeds are AES-GCM encrypted under AUTH_ENCRYPTION_KEY, held outside the database (ADR 0027).
import { describe, expect, it } from "vitest"
import { base64UrlDecode } from "../../src/core/encoding.js"
import { base32Decode, beginTotpEnrolment, TOTP_COLLECTION } from "../../src/methods/totp/method.js"
import { openSecret } from "../../src/methods/totp/secret-box.js"
import { ringKey, totpDeps } from "../support/totp.js"

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("")

describe("totp-secret-read-at-rest", () => {
  it("stores no form of the seed a dump could read", async () => {
    const d = totpDeps()
    const { authenticatorId, secret } = await beginTotpEnrolment(d, { tenant: "t", accountId: "a" })
    const dump = JSON.stringify(await d.store.listByOwner("t", TOTP_COLLECTION, "a"))
    const seed = base32Decode(secret)
    expect(dump).not.toContain(secret)
    expect(dump).not.toContain(hex(seed))
    expect(dump).not.toContain(Buffer.from(seed).toString("base64").slice(0, 20))
    const record = await d.store.get("t", TOTP_COLLECTION, authenticatorId)
    const sealed = (record?.data as { secret: { keyId: string; iv: string; ciphertext: string } })
      .secret
    expect(base64UrlDecode(sealed.ciphertext)).not.toEqual(seed)
    expect(hex(base64UrlDecode(sealed.ciphertext))).not.toContain(hex(seed).slice(0, 16))
  })

  it("cannot be opened without the key, or with another key under the same id", async () => {
    const d = totpDeps()
    const { authenticatorId } = await beginTotpEnrolment(d, { tenant: "t", accountId: "a" })
    const record = await d.store.get("t", TOTP_COLLECTION, authenticatorId)
    const sealed = (record?.data as { secret: { keyId: string; iv: string; ciphertext: string } })
      .secret
    const binding = { tenant: "t", accountId: "a", authenticatorId }
    expect(await openSecret(sealed, [], binding)).toBeNull()
    expect(await openSecret(sealed, [ringKey("k1", 99)], binding)).toBeNull()
  })
})
