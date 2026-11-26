// Sentinels for sealed and derived values, checked against vectors computed independently with Node's crypto
// (HKDF, AES-256-GCM, HMAC-SHA-256), so a change to a label, a binding or a message is caught even when sealing and
// opening change together. Also the session and account details every flow relies on.
import { describe, expect, it } from "vitest"
import { createAccount } from "../../src/core/accounts.js"
import { fixedClock, sequenceRandom } from "../../src/core/clock.js"
import {
  CONFIRMATION_COLLECTION,
  type EmailMessage,
  sendConfirmation,
} from "../../src/core/email.js"
import type { RingKey } from "../../src/core/mode.js"
import { openSecret, sealSecret } from "../../src/methods/totp/secret-box.js"
import { createCsrfTokens } from "../../src/security/csrf.js"
import { SESSION_COLLECTION } from "../../src/sessions/sessions.js"
import { memoryStore } from "../../src/store/memory.js"
import { HOUR, password, T0, totp } from "../support/evidence.js"
import { setup, TENANT } from "../support/sessions.js"

const KEY: RingKey = {
  id: "k1",
  bytes: new Uint8Array(32).map((_, index) => (index * 37 + 11) & 0xff),
}
const IV = Array.from({ length: 12 }, (_, index) => ((index + 1) * 9) & 0xff)
const SECRET = new Uint8Array(20).map((_, index) => index + 1)
const BINDING = { tenant: "t1", accountId: "acct-1", authenticatorId: "totp-1" }
/** AES-256-GCM of SECRET under HKDF(KEY, info "test-cap/totp-secret/v1"), IV and the binding as additional data. */
const SEALED = {
  keyId: "k1",
  iv: "CRIbJC02P0hRWmNs",
  ciphertext: "evM40eXF4NKrfazTtz_rMwD9DuPX8IEmh9vbdsyfgo4jt4T2",
}

describe("sealed TOTP secrets", () => {
  it("seal to the known vector and open it, bound to their row", async () => {
    expect(await sealSecret(SECRET, [KEY], sequenceRandom(IV), BINDING)).toEqual(SEALED)
    expect(await openSecret(SEALED, [KEY], BINDING)).toEqual(SECRET)
    expect(await openSecret(SEALED, [KEY], { ...BINDING, accountId: "acct-2" })).toBeNull()
  })

  it("refuse to seal without a key", async () => {
    await expect(sealSecret(SECRET, [], sequenceRandom(IV), BINDING)).rejects.toThrow(
      new Error("AUTH_ENCRYPTION_KEY has no key to encrypt with."),
    )
  })
})

describe("synchronizer tokens", () => {
  it("are the HMAC of purpose, key id, expiry and binding", async () => {
    const tokens = createCsrfTokens([KEY])
    const token = "k1.1800003600000.c7yeB1D8leoRlRktUj7zHygHYnm_2AoWDaBCUIb-ZK8"
    expect(await tokens.issue("b", T0)).toBe(token)
    expect(await tokens.verify(token, "b", T0 + HOUR - 1)).toBe(true)
    expect(await tokens.verify(token, "b", T0 + HOUR)).toBe(false)
    expect(await tokens.verify(token, "c", T0)).toBe(false)
  })
})

describe("email confirmation codes", () => {
  it("key the record by the known HMAC, send the code once a minute, and say where to enter it", async () => {
    const store = memoryStore()
    const sent: EmailMessage[] = []
    const deps = {
      store,
      tenant: "t1",
      clock: fixedClock(T0),
      random: sequenceRandom([1, 2, 3, 4, 5, 6]),
      linkBase: "https://app.example/auth",
      sendEmail: (message: EmailMessage) => {
        sent.push(message)
        return Promise.resolve()
      },
      keyRing: [KEY],
    }
    const input = { accountId: "acct-1", address: "ada@example.com", clientAddress: undefined }
    expect(await sendConfirmation(deps, input)).toEqual({ retryAfterMs: 60_000 })
    const key = "64df7525112ab33963b25ca80829939f0b76b5ba3c9eab76d82fde1e2c6645dd"
    expect(await store.get("t1", CONFIRMATION_COLLECTION, key)).toMatchObject({
      owner: "acct-1",
      data: { address: "ada@example.com", keyId: "k1" },
    })
    await Promise.resolve()
    expect(sent).toEqual([
      {
        to: "ada@example.com",
        subject: "Confirm your email address",
        text: [
          "Your confirmation code is 123456. It expires in 24 hours.",
          "",
          "Enter it on the confirmation page: https://app.example/auth/email/confirm",
          "",
          "If you did not create an account, ignore this email.",
        ].join("\n"),
      },
    ])
    deps.clock.advance(1_000)
    expect(await sendConfirmation(deps, input)).toEqual({ retryAfterMs: 59_000 })
    await Promise.resolve()
    expect(sent).toHaveLength(1)
  })

  it("counts sends with no client address per address only", async () => {
    const store = memoryStore()
    let sent = 0
    const deps = {
      store,
      tenant: "t1",
      clock: fixedClock(T0),
      random: sequenceRandom([1, 2, 3, 4, 5, 6]),
      linkBase: "https://app.example/auth",
      sendEmail: () => {
        sent += 1
        return Promise.resolve()
      },
      keyRing: [KEY],
    }
    // More than the 20 an hour one client address may send, none from a known address.
    for (const n of Array.from({ length: 21 }, (_, index) => index)) {
      const input = {
        accountId: `acct-${n}`,
        address: `a${n}@example.com`,
        clientAddress: undefined,
      }
      expect(await sendConfirmation(deps, input), String(n)).toEqual({ retryAfterMs: 60_000 })
    }
    await Promise.resolve()
    expect(sent).toBe(21)
  })
})

describe("sessions and accounts", () => {
  it("keep the newest evidence of each authenticator, oldest first, and no step-up at sign-in", async () => {
    const { sessions } = setup()
    const issued = await sessions.signIn(TENANT, null, {
      subject: "a",
      evidence: [totp({ at: T0 }), password({ at: T0 - 1_000 }), password({ at: T0 - 2_000 })],
    })
    expect(issued.state.evidence).toEqual([password({ at: T0 - 1_000 }), totp({ at: T0 })])
    expect(issued.state.stepUps).toEqual([])
  })

  it("record each read as activity, and revoke a session a read finds expired", async () => {
    const { sessions, store, clock } = setup()
    const issued = await sessions.signIn(TENANT, null, { subject: "a", evidence: [password()] })
    clock.advance(1_000)
    expect((await sessions.read(TENANT, issued.token))?.state.lastSeenAt).toBe(T0)
    const [touched] = await store.listByOwner(TENANT, SESSION_COLLECTION, "a")
    expect((touched?.data as { lastSeenAt: number }).lastSeenAt).toBe(T0 + 1_000)
    clock.advance(2 * HOUR)
    expect(await sessions.read(TENANT, issued.token)).toBeNull()
    const [revoked] = await store.listByOwner(TENANT, SESSION_COLLECTION, "a")
    expect(revoked?.revokedAt).toBe(T0 + 1_000 + 2 * HOUR)
  })

  it("refuse to hand out a session token or an account id that collides with a stored one", async () => {
    const repeating = setup({ random: sequenceRandom([7]) })
    await repeating.sessions.signIn(TENANT, null, { subject: "a", evidence: [password()] })
    await expect(
      repeating.sessions.signIn(TENANT, null, { subject: "b", evidence: [password()] }),
    ).rejects.toThrow(
      new Error("A new session token collided with a stored one; the random source is broken."),
    )
    const store = memoryStore()
    const input = { identifier: "ada@example.com", now: T0 }
    await createAccount(store, "t1", sequenceRandom([7]), input)
    await expect(
      createAccount(store, "t1", sequenceRandom([7]), { ...input, identifier: "bob@example.com" }),
    ).rejects.toThrow(
      new Error("A new account record collided with a stored one; the random source is broken."),
    )
  })
})
