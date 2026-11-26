import { describe, expect, it } from "vitest"
import { fixedClock, sequenceRandom } from "../../src/core/clock.js"
import type { RingKey } from "../../src/core/mode.js"
import { hotp } from "../../src/methods/totp/hotp.js"
import {
  base32Decode,
  base32Encode,
  beginTotpEnrolment,
  confirmTotpEnrolment,
  TOTP_COLLECTION,
  TOTP_ENROLMENT_TTL_MS,
  TOTP_SECRET_BYTES,
  type TotpDeps,
  verifyTotp,
} from "../../src/methods/totp/method.js"
import { timeStep } from "../../src/methods/totp/totp.js"
import { memoryStore } from "../../src/store/memory.js"
import type { JsonValue } from "../../src/store/port.js"

const T0 = 1_700_000_000_000
const ring = (id: string, seed: number): RingKey => ({
  id,
  bytes: Uint8Array.from({ length: 32 }, (_, i) => (i * 31 + seed) % 256),
})

function deps(
  overrides: Partial<TotpDeps> = {},
): TotpDeps & { clock: ReturnType<typeof fixedClock> } {
  return {
    clock: fixedClock(T0),
    random: sequenceRandom([11, 22, 33, 44, 55, 66, 77]),
    store: memoryStore(),
    keyRing: [ring("k1", 3)],
    ...overrides,
  } as TotpDeps & { clock: ReturnType<typeof fixedClock> }
}

const codeAt = async (secret: string, ms: number): Promise<string> =>
  hotp(base32Decode(secret), timeStep(ms), 6)

async function enrolled(d: TotpDeps) {
  const begun = await beginTotpEnrolment(d, { tenant: "t", accountId: "a" })
  const confirmed = await confirmTotpEnrolment(d, {
    tenant: "t",
    accountId: "a",
    authenticatorId: begun.authenticatorId,
    code: await codeAt(begun.secret, d.clock.now()),
  })
  expect(confirmed.ok).toBe(true)
  return begun
}

describe("base32", () => {
  it("encodes RFC 4648 test vectors without padding and decodes them back", () => {
    const cases: [string, string][] = [
      ["", ""],
      ["f", "MY"],
      ["fo", "MZXQ"],
      ["foo", "MZXW6"],
      ["foob", "MZXW6YQ"],
      ["fooba", "MZXW6YTB"],
      ["foobar", "MZXW6YTBOI"],
    ]
    for (const [plain, encoded] of cases) {
      expect(base32Encode(new TextEncoder().encode(plain))).toBe(encoded)
      expect(new TextDecoder().decode(base32Decode(encoded))).toBe(plain)
    }
    expect(base32Encode(Uint8Array.from([0xff, 0x00, 0x10]))).toBe("74ABA")
  })

  it("refuses a character outside the alphabet", () => {
    expect(() => base32Decode("MZ1")).toThrow(
      new TypeError("Invalid base32: character outside the alphabet."),
    )
    expect(() => base32Decode("mzxq")).toThrow(TypeError)
  })
})

describe("beginTotpEnrolment (F03)", () => {
  it("draws a 160-bit secret from the random source and stores it only encrypted, unconfirmed, with an expiry", async () => {
    const d = deps()
    const begun = await beginTotpEnrolment(d, { tenant: "t", accountId: "a" })
    expect(TOTP_SECRET_BYTES).toBe(20)
    expect(TOTP_ENROLMENT_TTL_MS).toBe(600_000)
    expect(base32Decode(begun.secret)).toHaveLength(20)
    expect(begun.secret).toHaveLength(32)
    const record = await d.store.get("t", TOTP_COLLECTION, begun.authenticatorId)
    expect(record?.owner).toBe("a")
    expect(record?.expiresAt).toBe(T0 + 600_000)
    expect(record?.data).toMatchObject({
      confirmed: false,
      lastStep: null,
      secret: { keyId: "k1" },
    })
    expect(JSON.stringify(record)).not.toContain(begun.secret)
  })
})

describe("beginTotpEnrolment id collisions", () => {
  it("refuses to hand out a secret when the authenticator id already exists", async () => {
    const d = deps({ random: sequenceRandom([5]) })
    await beginTotpEnrolment(d, { tenant: "t", accountId: "a" })
    // Another account's enrolment, so the first is not the one a new enrolment replaces.
    await expect(beginTotpEnrolment(d, { tenant: "t", accountId: "b" })).rejects.toThrow(
      new Error("The new TOTP authenticator id already exists."),
    )
  })
})

describe("confirmTotpEnrolment (F03)", () => {
  it("confirms with one valid code, returns possession evidence and stores the step", async () => {
    const d = deps()
    const begun = await beginTotpEnrolment(d, { tenant: "t", accountId: "a" })
    d.clock.advance(1_000)
    const result = await confirmTotpEnrolment(d, {
      tenant: "t",
      accountId: "a",
      authenticatorId: begun.authenticatorId,
      code: await codeAt(begun.secret, T0),
    })
    expect(result).toEqual({
      ok: true,
      evidence: {
        method: "totp",
        authenticatorId: begun.authenticatorId,
        factors: ["possession"],
        phishingResistant: false,
        replayResistant: true,
        keyProtection: "unknown",
        userVerified: false,
        attestationVerified: false,
        at: T0 + 1_000,
      },
    })
    const record = await d.store.get("t", TOTP_COLLECTION, begun.authenticatorId)
    expect(record?.expiresAt).toBeNull()
    expect(record?.data).toMatchObject({ confirmed: true, lastStep: timeStep(T0) })
  })

  it("refuses a wrong code, an expired enrolment, another account's enrolment and an unknown id", async () => {
    const d = deps()
    const begun = await beginTotpEnrolment(d, { tenant: "t", accountId: "a" })
    const good = await codeAt(begun.secret, T0)
    const wrong = good === "000000" ? "000001" : "000000"
    const base = { tenant: "t", accountId: "a", authenticatorId: begun.authenticatorId }
    expect(await confirmTotpEnrolment(d, { ...base, code: wrong })).toEqual({
      ok: false,
      reason: "invalid",
    })
    expect(await confirmTotpEnrolment(d, { ...base, accountId: "b", code: good })).toEqual({
      ok: false,
      reason: "invalid",
    })
    expect(await confirmTotpEnrolment(d, { ...base, authenticatorId: "nope", code: good })).toEqual(
      {
        ok: false,
        reason: "invalid",
      },
    )
    d.clock.set(T0 + TOTP_ENROLMENT_TTL_MS)
    expect(
      await confirmTotpEnrolment(d, { ...base, code: await codeAt(begun.secret, d.clock.now()) }),
    ).toEqual({
      ok: false,
      reason: "invalid",
    })
    d.clock.set(T0 + TOTP_ENROLMENT_TTL_MS - 1)
    expect(
      await confirmTotpEnrolment(d, { ...base, code: await codeAt(begun.secret, d.clock.now()) }),
    ).toMatchObject({
      ok: true,
    })
  })

  it("refuses to confirm when the key the secret was sealed under has left the ring", async () => {
    const d = deps()
    const begun = await beginTotpEnrolment(d, { tenant: "t", accountId: "a" })
    expect(
      await confirmTotpEnrolment(
        { ...d, keyRing: [ring("k9", 4)] },
        {
          tenant: "t",
          accountId: "a",
          authenticatorId: begun.authenticatorId,
          code: await codeAt(begun.secret, T0),
        },
      ),
    ).toEqual({ ok: false, reason: "invalid" })
  })

  it("does not confirm twice", async () => {
    const d = deps()
    const begun = await enrolled(d)
    d.clock.advance(60_000)
    expect(
      await confirmTotpEnrolment(d, {
        tenant: "t",
        accountId: "a",
        authenticatorId: begun.authenticatorId,
        code: await codeAt(begun.secret, d.clock.now()),
      }),
    ).toEqual({ ok: false, reason: "invalid" })
  })
})

describe("verifyTotp (F04)", () => {
  it("counts a wrong code toward the ceiling only on a confirmed authenticator (ADR 0009 §3)", async () => {
    const failed: string[] = []
    const ceiling = {
      reached: () => Promise.resolve(false),
      failed: (id: string) => {
        failed.push(id)
        return Promise.resolve()
      },
      succeeded: () => Promise.resolve(),
    }
    const pending = deps({ ceiling })
    await beginTotpEnrolment(pending, { tenant: "t", accountId: "a" })
    await verifyTotp(pending, { tenant: "t", accountId: "a", code: "000000" })
    expect(failed).toEqual([])
    const confirmed = deps({ ceiling })
    const begun = await enrolled(confirmed)
    await verifyTotp(confirmed, { tenant: "t", accountId: "a", code: "000000" })
    expect(failed).toEqual([begun.authenticatorId])
  })

  it("counts no failure on the account's other authenticators when one of them takes the code", async () => {
    const failed: string[] = []
    const ceiling = {
      reached: () => Promise.resolve(false),
      failed: (id: string) => {
        failed.push(id)
        return Promise.resolve()
      },
      succeeded: () => Promise.resolve(),
    }
    const d = deps({ ceiling })
    const first = await enrolled(d)
    const second = await enrolled(d)
    d.clock.advance(30_000)
    const code = await codeAt(second.secret, d.clock.now())
    expect(await verifyTotp(d, { tenant: "t", accountId: "a", code })).toMatchObject({ ok: true })
    expect(failed).toEqual([])
    // A code none of them takes counts once on each one checked.
    d.clock.advance(30_000)
    const right = [
      await codeAt(first.secret, d.clock.now()),
      await codeAt(second.secret, d.clock.now()),
    ]
    const wrong = ["000000", "111111", "222222"].find((each) => !right.includes(each)) as string
    expect(await verifyTotp(d, { tenant: "t", accountId: "a", code: wrong })).toEqual({
      ok: false,
      reason: "invalid",
    })
    expect(failed).toEqual([first.authenticatorId, second.authenticatorId])
  })

  it("accepts a later step and records it", async () => {
    const d = deps()
    const begun = await enrolled(d)
    d.clock.advance(30_000)
    const result = await verifyTotp(d, {
      tenant: "t",
      accountId: "a",
      code: await codeAt(begun.secret, d.clock.now()),
    })
    expect(result).toMatchObject({
      ok: true,
      evidence: { method: "totp", authenticatorId: begun.authenticatorId, at: T0 + 30_000 },
    })
    expect((await d.store.get("t", TOTP_COLLECTION, begun.authenticatorId))?.data).toMatchObject({
      lastStep: timeStep(T0 + 30_000),
    })
  })

  it("refuses a wrong code, and a revoked authenticator", async () => {
    const d = deps()
    const begun = await enrolled(d)
    d.clock.advance(30_000)
    const code = await codeAt(begun.secret, d.clock.now())
    expect(
      await verifyTotp(d, {
        tenant: "t",
        accountId: "a",
        code: code === "123456" ? "654321" : "123456",
      }),
    ).toEqual({
      ok: false,
      reason: "invalid",
    })
    await d.store.revoke("t", TOTP_COLLECTION, begun.authenticatorId, T0)
    expect(await verifyTotp(d, { tenant: "t", accountId: "a", code })).toEqual({
      ok: false,
      reason: "invalid",
    })
  })

  it("tries every confirmed authenticator of the account", async () => {
    const d = deps()
    await enrolled(d)
    const second = await enrolled(d)
    d.clock.advance(30_000)
    expect(
      await verifyTotp(d, {
        tenant: "t",
        accountId: "a",
        code: await codeAt(second.secret, d.clock.now()),
      }),
    ).toMatchObject({ ok: true, evidence: { authenticatorId: second.authenticatorId } })
  })

  it("reports a replay even when a later authenticator does not match", async () => {
    const d = deps()
    const first = await enrolled(d)
    d.clock.advance(30_000)
    const code = await codeAt(first.secret, d.clock.now())
    expect(await verifyTotp(d, { tenant: "t", accountId: "a", code })).toMatchObject({ ok: true })
    await enrolled(d)
    expect(await verifyTotp(d, { tenant: "t", accountId: "a", code })).toEqual({
      ok: false,
      reason: "replayed",
    })
  })

  it("refuses a record whose fields have the wrong types, even with a correct code", async () => {
    const d = deps()
    const begun = await enrolled(d)
    const stored = await d.store.get("t", TOTP_COLLECTION, begun.authenticatorId)
    const data = stored?.data as Record<string, JsonValue>
    d.clock.advance(30_000)
    const code = await codeAt(begun.secret, d.clock.now())
    for (const broken of [
      { ...data, lastStep: "x" },
      { ...data, confirmed: "yes" },
      null,
      { ...data, secret: null },
    ] as JsonValue[]) {
      const current = await d.store.get("t", TOTP_COLLECTION, begun.authenticatorId)
      await d.store.update("t", TOTP_COLLECTION, begun.authenticatorId, current?.version ?? 0, {
        data: broken,
      })
      expect(
        await verifyTotp(d, { tenant: "t", accountId: "a", code }),
        JSON.stringify(broken),
      ).toEqual({
        ok: false,
        reason: "invalid",
      })
    }
  })

  it("ignores unconfirmed and malformed records", async () => {
    const d = deps()
    const begun = await beginTotpEnrolment(d, { tenant: "t", accountId: "a" })
    await d.store.createUnique("t", {
      collection: TOTP_COLLECTION,
      key: "junk",
      owner: "a",
      data: [1],
    })
    await d.store.createUnique("t", {
      collection: TOTP_COLLECTION,
      key: "junk2",
      owner: "a",
      data: { confirmed: true, lastStep: "x", secret: { keyId: "k1", iv: "", ciphertext: "" } },
    })
    await d.store.createUnique("t", {
      collection: TOTP_COLLECTION,
      key: "junk3",
      owner: "a",
      data: { confirmed: true, lastStep: null, secret: { keyId: 1, iv: "", ciphertext: "" } },
    })
    await d.store.createUnique("t", {
      collection: TOTP_COLLECTION,
      key: "junk4",
      owner: "a",
      data: { confirmed: true, lastStep: null, secret: null },
    })
    expect(
      await verifyTotp(d, { tenant: "t", accountId: "a", code: await codeAt(begun.secret, T0) }),
    ).toEqual({
      ok: false,
      reason: "invalid",
    })
  })

  it("re-encrypts the secret under the current key after a successful verification", async () => {
    const old = ring("old", 5)
    const d = deps({ keyRing: [old] })
    const begun = await enrolled(d)
    const rotated: TotpDeps = { ...d, keyRing: [ring("new", 9), old] }
    d.clock.advance(30_000)
    expect(
      await verifyTotp(rotated, {
        tenant: "t",
        accountId: "a",
        code: await codeAt(begun.secret, d.clock.now()),
      }),
    ).toMatchObject({
      ok: true,
    })
    expect((await d.store.get("t", TOTP_COLLECTION, begun.authenticatorId))?.data).toMatchObject({
      secret: { keyId: "new" },
    })
    d.clock.advance(30_000)
    expect(
      await verifyTotp(
        { ...d, keyRing: [ring("new", 9)] },
        { tenant: "t", accountId: "a", code: await codeAt(begun.secret, d.clock.now()) },
      ),
    ).toMatchObject({ ok: true })
  })

  it("keeps the key id when it is already current", async () => {
    const d = deps()
    const begun = await enrolled(d)
    const before = (await d.store.get("t", TOTP_COLLECTION, begun.authenticatorId))?.data as {
      secret: unknown
    }
    d.clock.advance(30_000)
    await verifyTotp(d, {
      tenant: "t",
      accountId: "a",
      code: await codeAt(begun.secret, d.clock.now()),
    })
    const after = (await d.store.get("t", TOTP_COLLECTION, begun.authenticatorId))?.data as {
      secret: unknown
    }
    expect(after.secret).toEqual(before.secret)
  })

  it("lets a store error through rather than answering success", async () => {
    const d = deps({
      store: { ...memoryStore(), listByOwner: () => Promise.reject(new Error("store down")) },
    })
    await expect(verifyTotp(d, { tenant: "t", accountId: "a", code: "123456" })).rejects.toThrow(
      "store down",
    )
  })
})
