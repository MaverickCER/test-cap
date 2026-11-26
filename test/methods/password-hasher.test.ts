// The password hasher an app can replace (ADR 0031): `argon2Hasher` takes the place of hash-wasm, and test-cap
// holds whatever hashes to the rules it can check. Also @noble/hashes, the engine test-cap falls back to where
// WebAssembly cannot compile: it must write the same PHC string as hash-wasm, so a hash from one verifies with the other.
import { argon2id, argon2Verify } from "hash-wasm"
import { describe, expect, it, vi } from "vitest"
import { sequenceRandom } from "../../src/core/clock.js"
import { ConfigError } from "../../src/core/errors.js"
import {
  type Argon2Hasher,
  createHasher,
  DUMMY_HASH,
  nobleArgon2,
} from "../../src/methods/password/argon2.js"
import { PASSWORD_COLLECTION } from "../../src/methods/password/method.js"
import { normalisePassword } from "../../src/methods/password/rules.js"
import { memoryStore } from "../../src/store/memory.js"
import {
  account,
  Browser,
  ENV,
  expectOk,
  inProcess,
  PASSWORD,
  TENANT,
  testAuth,
} from "../support/auth.js"
import { TEST_ARGON2_COST } from "../support/argon2.js"
import { codeAt } from "../support/totp.js"

const SALT = Array.from({ length: 16 }, (_, i) => i + 1)
const password = normalisePassword("correct horse")

/** hash-wasm's encoded argon2id of `text` with `salt` at the test cost. */
const wasmHash = (text: string, salt: readonly number[] = SALT): Promise<string> =>
  argon2id({
    password: text,
    salt: Uint8Array.from(salt),
    memorySize: TEST_ARGON2_COST.memoryKiB,
    iterations: TEST_ARGON2_COST.iterations,
    parallelism: TEST_ARGON2_COST.parallelism,
    hashLength: 32,
    outputType: "encoded",
  })

/** A hasher that records what it is asked and answers with `answers`. */
function scripted(answers: { hash?: unknown; verify?: unknown }) {
  const asked: string[] = []
  const hasher = {
    hash: vi.fn(() => {
      asked.push("hash")
      return Promise.resolve(answers.hash)
    }),
    verify: vi.fn((_: string, encoded: string) => {
      asked.push(encoded)
      return Promise.resolve(answers.verify)
    }),
  } as unknown as Argon2Hasher
  return { hasher, asked }
}

/** An encoded argon2id string with these parts, valid or not. */
const encoded = (parts: { m?: string; t?: string; p?: string; salt?: string; digest?: string }) =>
  `$argon2id$v=19$m=${parts.m ?? "8"},t=${parts.t ?? "1"},p=${parts.p ?? "1"}$${parts.salt ?? "AQIDBAUGBwgJCgsMDQ4PEA"}$${parts.digest ?? "a".repeat(43)}`

describe("@noble/hashes beside hash-wasm (ADR 0031)", () => {
  it("writes the same PHC string as hash-wasm for the same password, salt and cost", async () => {
    const noble = await nobleArgon2.hash({
      password,
      salt: Uint8Array.from(SALT),
      cost: TEST_ARGON2_COST,
    })
    expect(noble).toBe(await wasmHash("correct horse"))
    expect(noble.startsWith("$argon2id$v=19$m=8,t=1,p=1$AQIDBAUGBwgJCgsMDQ4PEA$")).toBe(true)
  })

  it("writes the salt and digest in standard base64 without padding, as hash-wasm does", async () => {
    // These bytes encode to every character standard base64 has and base64url lacks: + and /.
    const salt = [
      0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff, 0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff, 1, 2, 3, 4,
    ]
    const noble = await nobleArgon2.hash({
      password,
      salt: Uint8Array.from(salt),
      cost: TEST_ARGON2_COST,
    })
    expect(noble).toBe(await wasmHash("correct horse", salt))
    expect(noble).toContain("$++++////++++////AQIDBA$")
    expect(noble.split("$").slice(4).join("$")).not.toContain("=")
  })

  it("verifies what hash-wasm hashed, and hash-wasm verifies what it hashed", async () => {
    const fromWasm = await wasmHash("correct horse")
    expect(await nobleArgon2.verify(password, fromWasm)).toBe(true)
    expect(await nobleArgon2.verify(normalisePassword("correct horsf"), fromWasm)).toBe(false)
    const fromNoble = await createHasher(TEST_ARGON2_COST, nobleArgon2).hash(
      password,
      sequenceRandom([9, 8, 7]),
    )
    expect(await argon2Verify({ password: "correct horse", hash: fromNoble })).toBe(true)
    expect(await argon2Verify({ password: "correct horsf", hash: fromNoble })).toBe(false)
  })

  it("verifies at the cost a hash records, not at the hasher's own", async () => {
    const atTestCost = await wasmHash("correct horse")
    const hasher = createHasher(undefined, nobleArgon2)
    expect(await hasher.verify(password, atTestCost)).toBe(true)
    expect(hasher.needsRehash(atTestCost)).toBe(true)
  })

  it("verifies nothing against the dummy hash", async () => {
    expect(await createHasher(TEST_ARGON2_COST, nobleArgon2).dummyVerify(password)).toBe(false)
  })
})

describe("nobleArgon2 on its own", () => {
  it("answers false for a stored hash that is no argon2id PHC string, computing nothing", async () => {
    for (const encoded of [
      "",
      "not a hash",
      "$argon2i$v=19$m=8,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$" + "A".repeat(43),
    ]) {
      expect(await nobleArgon2.verify("correct horse", encoded), encoded).toBe(false)
    }
  })
})

describe("an app's own argon2Hasher (ADR 0031)", () => {
  it("hashes and verifies every password of the Auth: sign-up, then sign-in", async () => {
    const calls: string[] = []
    const argon2Hasher: Argon2Hasher = {
      hash: (input) => {
        calls.push(`hash m=${input.cost.memoryKiB}`)
        return nobleArgon2.hash(input)
      },
      verify: (text, hash) => {
        calls.push("verify")
        return nobleArgon2.verify(text, hash)
      },
    }
    const setup = testAuth({ argon2Hasher })
    const { subject, identifier, browser } = await account(setup)
    const record = await setup.store.get(TENANT, PASSWORD_COLLECTION, subject)
    const stored = (record?.data as { hash: string }).hash
    expect(await argon2Verify({ password: PASSWORD, hash: stored })).toBe(true)
    const signedIn = await expectOk(
      browser.post("/auth/sign-in", { identifier, password: PASSWORD }),
    )
    expect(signedIn.json).toEqual({ outcome: "step-up", returnTo: "/" })
    expect(calls).toEqual(["hash m=8", "verify"])
  })

  it("is refused at startup without both hash and verify, and named", () => {
    const refusal = (argon2Hasher: unknown) => {
      try {
        testAuth({ argon2Hasher: argon2Hasher as Argon2Hasher })
        return []
      } catch (error) {
        return error instanceof ConfigError ? error.problems : [String(error)]
      }
    }
    const problem = "argon2Hasher must be an object with hash and verify functions."
    expect(refusal({ hash: nobleArgon2.hash })).toEqual([problem])
    expect(refusal({ verify: nobleArgon2.verify })).toEqual([problem])
    expect(refusal({})).toEqual([problem])
    expect(refusal(null)).toEqual([problem])
    expect(refusal(nobleArgon2)).toEqual([])
    expect(refusal(undefined)).toEqual([])
  })

  it("starts in production, where only the cost is fixed", () => {
    expect(() =>
      testAuth({
        argon2Hasher: nobleArgon2,
        argon2Cost: undefined,
        clock: undefined,
        store: { ...memoryStore(), kind: "sql", durable: true },
        env: { ...ENV, APP_ENV: "production" },
      }),
    ).not.toThrow()
  })
})

describe("the argon2id work recovery spends (ADR 0007)", () => {
  it("is one verify for a wrong code, an unknown account, text that is no code, and a used code", async () => {
    const calls: string[] = []
    const argon2Hasher: Argon2Hasher = {
      hash: (input) => nobleArgon2.hash(input),
      verify: (text, hash) => {
        calls.push("verify")
        return nobleArgon2.verify(text, hash)
      },
    }
    const setup = testAuth({ argon2Hasher })
    const { browser: owner, secret } = await account(setup)
    await owner.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD })
    setup.clock.advance(30_000)
    await owner.post("/auth/totp/verify", { code: await codeAt(secret, setup.clock.now()) })
    const { codes } = (await owner.post("/auth/recovery-codes")).json as { codes: string[] }
    // A stored code's prefix with the wrong secret: the real verify against the stored hash runs.
    const wrongSecret = `${(codes[0] ?? "").slice(0, 6)}-AAAA-AAAA-AAAA-AAAA`
    // A code used once already: redeemed here, then tried again below.
    const used = codes[1] ?? ""
    const redeemer = new Browser(inProcess(setup.auth))
    await redeemer.start()
    expect(
      (await redeemer.post("/auth/recovery", { identifier: "ada@example.com", code: used })).status,
    ).toBe(200)
    const perAttempt: number[] = []
    for (const [identifier, code] of [
      ["ada@example.com", wrongSecret],
      ["nobody@example.com", "AAAAAA-AAAA-AAAA-AAAA-AAAA"],
      ["ada@example.com", "not a code at all"],
      ["ada@example.com", used],
    ] as const) {
      const browser = new Browser(inProcess(setup.auth))
      await browser.start()
      calls.length = 0
      const reply = await browser.post("/auth/recovery", { identifier, code })
      expect([reply.status, reply.text]).toEqual([401, '{"error":"invalid-credentials"}'])
      perAttempt.push(calls.length)
    }
    expect(perAttempt).toEqual([1, 1, 1, 1])
  })
})

describe("the rules a replaced hasher is held to (ADR 0031)", () => {
  const random = () => sequenceRandom(SALT)
  const refusal =
    "argon2Hasher.hash must return the argon2id PHC string of the salt and cost it was given."

  it("accepts a hash that records the salt and cost it was given", async () => {
    const good = encoded({})
    const { hasher } = scripted({ hash: good })
    expect(await createHasher(TEST_ARGON2_COST, hasher).hash(password, random())).toBe(good)
  })

  it("refuses a hash at another cost, of another salt, or in another format", async () => {
    for (const bad of [
      encoded({ m: "16" }),
      encoded({ t: "2" }),
      encoded({ p: "2" }),
      encoded({ salt: "AQIDBAUGBwgJCgsMDQ4PEQ" }),
      encoded({ digest: "a".repeat(42) }),
      encoded({ digest: "a".repeat(44) }),
      encoded({ digest: `${"a".repeat(42)}=` }),
      `${encoded({})}\n`,
      encoded({}).replace("argon2id", "argon2i"),
      encoded({}).replace("v=19", "v=16"),
      "",
      undefined,
      42,
    ]) {
      const { hasher } = scripted({ hash: bad })
      await expect(
        createHasher(TEST_ARGON2_COST, hasher).hash(password, random()),
        String(bad),
      ).rejects.toThrow(new Error(refusal))
    }
  })

  it("counts only true as a match", async () => {
    for (const [answer, match] of [
      [true, true],
      [false, false],
      ["true", false],
      [1, false],
      [{}, false],
      [undefined, false],
    ] as const) {
      const { hasher } = scripted({ verify: answer })
      expect(
        await createHasher(TEST_ARGON2_COST, hasher).verify(password, DUMMY_HASH),
        String(answer),
      ).toBe(match)
    }
  })

  it("asks the hasher about every well-formed argon2id string, whatever its cost and digits", async () => {
    const { hasher, asked } = scripted({ verify: true })
    const verify = createHasher(TEST_ARGON2_COST, hasher).verify
    const wellFormed = [
      DUMMY_HASH,
      encoded({ m: "19456", t: "12", p: "10" }),
      encoded({ salt: "++++////++++////AQIDBA", digest: `${"+".repeat(21)}${"/".repeat(22)}` }),
      encoded({
        salt: "ABCDEFGHIJKLMNOPQRSTUV",
        digest: "WXYZabcdefghijklmnopqrstuvwxyz0123456789aaa",
      }),
    ]
    for (const hash of wellFormed) expect(await verify(password, hash), hash).toBe(true)
    expect(asked).toEqual(wellFormed)
  })

  it("refuses any other format without asking the hasher", async () => {
    const { hasher, asked } = scripted({ verify: true })
    const verify = createHasher(TEST_ARGON2_COST, hasher).verify
    for (const hash of [
      "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
      encoded({}).replace("argon2id", "argon2i"),
      encoded({}).replace("argon2id", "argon2d"),
      encoded({}).replace("v=19", "v=16"),
      encoded({ m: "x" }),
      encoded({ m: "" }),
      encoded({ t: "" }),
      encoded({ p: "" }),
      encoded({ salt: "AQIDBAUGBwgJCgsMDQ4PE" }),
      encoded({ salt: "AQIDBAUGBwgJCgsMDQ4PEAA" }),
      encoded({ salt: "AQIDBAUGBwgJCgsMDQ4PE-" }),
      encoded({ digest: "a".repeat(42) }),
      encoded({ digest: "a".repeat(44) }),
      encoded({ digest: `${"a".repeat(42)}_` }),
      `x${DUMMY_HASH}`,
      `${DUMMY_HASH}x`,
      `${DUMMY_HASH}\n`,
      "",
    ]) {
      expect(await verify(password, hash), hash).toBe(false)
    }
    expect(asked).toEqual([])
  })
})
