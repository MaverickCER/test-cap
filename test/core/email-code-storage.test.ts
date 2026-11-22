// How a confirmation code is stored (ADR 0021 §2): never the code, and not a plain hash a database reader could
// reverse by trying the 10^6 codes. The record key is HMAC-SHA-256 under a key derived with HKDF from the current
// AUTH_ENCRYPTION_KEY ring key (info "email-confirm"), over purpose, account, address and code; the record keeps the key
// id, and a code issued before a key rotation still redeems while its key stays in the ring.
import { describe, expect, it } from "vitest"
import { fixedClock, type RandomSource, systemRandom } from "../../src/core/clock.js"
import {
  CONFIRMATION_COLLECTION,
  type EmailDeps,
  redeemConfirmation,
  sendConfirmation,
} from "../../src/core/email.js"
import { hexEncode, sha256, utf8Encode } from "../../src/core/encoding.js"
import type { RingKey } from "../../src/core/mode.js"
import { memoryStore } from "../../src/store/memory.js"

const ringKey = (id: string, seed: number): RingKey => ({
  id,
  bytes: Uint8Array.from({ length: 32 }, (_, i) => (i * 29 + seed) % 256),
})
const K1 = ringKey("e1", 3)
const K2 = ringKey("e2", 7)

/** Every draw of at most 6 bytes yields the code 123456. */
const fixedCode: RandomSource = {
  fill(bytes) {
    if (bytes.length > 6) return systemRandom.fill(bytes)
    bytes.set([1, 2, 3, 4, 5, 6].slice(0, bytes.length))
    return bytes
  },
}

function deps(keyRing: readonly RingKey[], store = memoryStore()): EmailDeps {
  return {
    store,
    tenant: "t",
    clock: fixedClock(1_800_000_000_000),
    random: fixedCode,
    origin: "https://app.example",
    sendEmail: () => Promise.resolve(),
    keyRing,
  }
}

/** The record key, computed independently with Web Crypto: HKDF-SHA-256 (no salt, info "email-confirm"), then HMAC. */
async function expectedKey(key: RingKey, message: string): Promise<string> {
  const base = await crypto.subtle.importKey("raw", key.bytes, "HKDF", false, ["deriveBits"])
  const derived = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8Encode("email-confirm") },
    base,
    256,
  )
  const mac = await crypto.subtle.importKey(
    "raw",
    derived,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  )
  return hexEncode(new Uint8Array(await crypto.subtle.sign("HMAC", mac, utf8Encode(message))))
}

const input = { accountId: "acct", address: "ada@example.com", clientAddress: undefined }
const message = ["email-confirm", "acct", "ada@example.com", "123456"].join("\n")

describe("the stored confirmation code", () => {
  it("is keyed by an HMAC under a key derived from the current ring key, and names that key", async () => {
    const d = deps([K1, K2])
    await sendConfirmation(d, input)
    const [record] = await d.store.listByOwner("t", CONFIRMATION_COLLECTION, "acct")
    expect(record?.key).toBe(await expectedKey(K1, message))
    expect(record?.data).toEqual({ address: "ada@example.com", keyId: "e1" })
    // Not the plain hash a database reader could reverse by trying every code.
    expect(record?.key).not.toBe(hexEncode(await sha256(utf8Encode(message))))
    expect(record?.key).not.toBe(await expectedKey(K2, message))
  })

  it("still redeems a code issued before a key rotation, while the old key stays in the ring", async () => {
    const store = memoryStore()
    await sendConfirmation(deps([K1], store), input)
    const redeemed = await redeemConfirmation(deps([K2, K1], store), { ...input, code: "123456" })
    expect(redeemed).toEqual({ ok: true })
  })

  it("refuses a code whose key left the ring", async () => {
    const store = memoryStore()
    await sendConfirmation(deps([K1], store), input)
    const redeemed = await redeemConfirmation(deps([K2], store), { ...input, code: "123456" })
    expect(redeemed).toEqual({ ok: false, reason: "invalid-code" })
  })

  it("redeems under the current key", async () => {
    const store = memoryStore()
    await sendConfirmation(deps([K2, K1], store), input)
    expect(await redeemConfirmation(deps([K2], store), { ...input, code: "123456" })).toEqual({
      ok: true,
    })
  })
})
