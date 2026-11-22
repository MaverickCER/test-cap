/**
 * TOTP secrets encrypted at rest (ADR 0027 §4, Open 3): AES-256-GCM from Web Crypto under a key derived by HKDF from
 * the current `AUTH_ENCRYPTION_KEY` ring key, a fresh 96-bit IV from the injected random source, and additional data
 * that binds the ciphertext to its tenant, account, authenticator and key id. The key id is stored with the
 * ciphertext; a key id that is no longer in the ring is refused.
 */

import { randomBytes, type RandomSource } from "../../core/clock.js"
import { base64UrlDecode, base64UrlEncode, utf8Encode } from "../../core/encoding.js"
import type { RingKey } from "../../core/mode.js"

/** A sealed secret as stored. */
export interface SealedSecret {
  /** The id of the ring key it was sealed under. */
  readonly keyId: string
  /** The 96-bit IV, base64url. */
  readonly iv: string
  /** The AES-GCM ciphertext and tag, base64url. */
  readonly ciphertext: string
}

/** The row a secret belongs to; a ciphertext moved to another row does not open. */
export interface SecretBinding {
  /** The tenant of the row. */
  readonly tenant: string
  /** The account the authenticator belongs to. */
  readonly accountId: string
  /** The authenticator's id. */
  readonly authenticatorId: string
}

const IV_BYTES = 12
const INFO = utf8Encode("test-cap/totp-secret/v1")

type AesKey = Awaited<ReturnType<typeof crypto.subtle.deriveKey>>

async function aesKey(ringKey: RingKey): Promise<AesKey> {
  const material = await crypto.subtle.importKey("raw", ringKey.bytes, "HKDF", false, ["deriveKey"])
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: INFO },
    material,
    { name: "AES-GCM", length: 256 },
    // Stryker disable next-line BooleanLiteral: equivalent, extractability only matters to exportKey, which nothing calls
    false,
    ["encrypt", "decrypt"],
  )
}

function additionalData(binding: SecretBinding, keyId: string): Uint8Array {
  return utf8Encode(
    JSON.stringify([
      "test-cap/totp-secret/v1",
      binding.tenant,
      binding.accountId,
      binding.authenticatorId,
      keyId,
    ]),
  )
}

/** Seals `secret` under the ring's current (first) key. */
export async function sealSecret(
  secret: Uint8Array,
  ring: readonly RingKey[],
  random: RandomSource,
  binding: SecretBinding,
): Promise<SealedSecret> {
  const current = ring[0]
  if (current === undefined) throw new Error("AUTH_ENCRYPTION_KEY has no key to encrypt with.")
  const iv = randomBytes(random, IV_BYTES)
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: additionalData(binding, current.id) },
    await aesKey(current),
    secret,
  )
  return {
    keyId: current.id,
    iv: base64UrlEncode(iv),
    ciphertext: base64UrlEncode(new Uint8Array(ciphertext)),
  }
}

/** Opens a sealed secret; `null` when its key id is not in the ring, or it was tampered with or moved. */
export async function openSecret(
  sealed: SealedSecret,
  ring: readonly RingKey[],
  binding: SecretBinding,
): Promise<Uint8Array | null> {
  const ringKey = ring.find((candidate) => candidate.id === sealed.keyId)
  if (ringKey === undefined) return null
  const key = await aesKey(ringKey)
  try {
    const plain = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64UrlDecode(sealed.iv),
        additionalData: additionalData(binding, sealed.keyId),
      },
      key,
      base64UrlDecode(sealed.ciphertext),
    )
    return new Uint8Array(plain)
  } catch {
    return null
  }
}
