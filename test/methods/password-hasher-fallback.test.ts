// The fallback to @noble/hashes (ADR 0031). Cloudflare Workers refuse to compile WebAssembly from bytes at run
// time, so every hash-wasm call there rejects with a CompileError. hash-wasm is mocked here to fail that way, or
// another way, and the Auth must hash and verify on noble at the same cost, telling onDiagnostic once.
import * as hashWasm from "hash-wasm"
import { beforeEach, describe, expect, it, vi } from "vitest"
import type { AuthDiagnostic } from "../../src/core/auth.js"
import { sequenceRandom } from "../../src/core/clock.js"
import { createHasher, nobleArgon2 } from "../../src/methods/password/argon2.js"
import { PASSWORD_COLLECTION } from "../../src/methods/password/method.js"
import { normalisePassword } from "../../src/methods/password/rules.js"
import { account, expectOk, PASSWORD, TENANT, testAuth } from "../support/auth.js"
import { TEST_ARGON2_COST } from "../support/argon2.js"

vi.mock("hash-wasm", async (importOriginal) => {
  const original = await importOriginal<typeof import("hash-wasm")>()
  return {
    ...original,
    argon2Verify: vi.fn(original.argon2Verify),
    argon2id: vi.fn(original.argon2id),
  }
})

/** What workerd throws when code asks it to compile WebAssembly from bytes: an error named `CompileError`. */
const refused = () =>
  Object.assign(new Error("WebAssembly.compile(): Wasm code generation disallowed by embedder"), {
    name: "CompileError",
  })

const password = normalisePassword("correct horse")
const SALT = Array.from({ length: 16 }, (_, i) => i + 1)
const FALLBACK: AuthDiagnostic = {
  code: "argon2-fallback",
  message:
    "WebAssembly cannot compile here, so argon2id runs on @noble/hashes, slower: check your plan's CPU time limit (ADR 0031).",
}

beforeEach(() => {
  vi.mocked(hashWasm.argon2id).mockReset()
  vi.mocked(hashWasm.argon2Verify).mockReset()
})

describe("argon2id where WebAssembly cannot compile", () => {
  it("signs up and signs in on noble, and tells onDiagnostic once", async () => {
    vi.mocked(hashWasm.argon2id).mockRejectedValue(refused())
    vi.mocked(hashWasm.argon2Verify).mockRejectedValue(refused())
    const diagnostics: AuthDiagnostic[] = []
    const setup = testAuth({ onDiagnostic: (diagnostic) => diagnostics.push(diagnostic) })
    const { subject, identifier, browser } = await account(setup)
    const signedIn = await expectOk(
      browser.post("/auth/sign-in", { identifier, password: PASSWORD }),
    )
    expect(signedIn.json).toEqual({ outcome: "step-up", returnTo: "/" })
    expect(diagnostics.filter((each) => each.code === "argon2-fallback")).toEqual([FALLBACK])
    // hash-wasm is tried once; after its refusal every computation goes straight to noble.
    expect(vi.mocked(hashWasm.argon2id)).toHaveBeenCalledTimes(1)
    expect(vi.mocked(hashWasm.argon2Verify)).not.toHaveBeenCalled()
    const record = await setup.store.get(TENANT, PASSWORD_COLLECTION, subject)
    const stored = (record?.data as { hash: string }).hash
    expect(stored).toMatch(/^\$argon2id\$v=19\$m=8,t=1,p=1\$/)
    expect(await nobleArgon2.verify(PASSWORD, stored)).toBe(true)
  })

  it("verifies a hash-wasm hash on noble once the first verification is refused", async () => {
    const real = await vi.importActual<typeof import("hash-wasm")>("hash-wasm")
    const stored = await createHasher(TEST_ARGON2_COST, {
      hash: (input) =>
        real.argon2id({
          password: input.password,
          salt: input.salt,
          memorySize: input.cost.memoryKiB,
          iterations: input.cost.iterations,
          parallelism: input.cost.parallelism,
          hashLength: 32,
          outputType: "encoded",
        }),
      verify: (text, hash) => real.argon2Verify({ password: text, hash }),
    }).hash(password, sequenceRandom(SALT))
    vi.mocked(hashWasm.argon2Verify).mockRejectedValue(refused())
    const seen: string[] = []
    const hasher = createHasher(TEST_ARGON2_COST, undefined, (diagnostic) =>
      seen.push(diagnostic.code),
    )
    expect(await hasher.verify(password, stored)).toBe(true)
    expect(await hasher.verify(normalisePassword("correct horsf"), stored)).toBe(false)
    expect(seen).toEqual(["argon2-fallback"])
    expect(vi.mocked(hashWasm.argon2Verify)).toHaveBeenCalledTimes(1)
  })

  it("keeps hash-wasm, and reports nothing, where it compiles", async () => {
    const real = await vi.importActual<typeof import("hash-wasm")>("hash-wasm")
    vi.mocked(hashWasm.argon2id).mockImplementation(real.argon2id)
    vi.mocked(hashWasm.argon2Verify).mockImplementation(real.argon2Verify)
    const seen: string[] = []
    const hasher = createHasher(TEST_ARGON2_COST, undefined, (diagnostic) =>
      seen.push(diagnostic.code),
    )
    const stored = await hasher.hash(password, sequenceRandom(SALT))
    expect(await hasher.verify(password, stored)).toBe(true)
    expect(seen).toEqual([])
    expect(vi.mocked(hashWasm.argon2id)).toHaveBeenCalledTimes(1)
    expect(vi.mocked(hashWasm.argon2Verify)).toHaveBeenCalledTimes(1)
  })

  it("passes any other failure on, without falling back", async () => {
    const broken = new Error("out of memory")
    vi.mocked(hashWasm.argon2id).mockRejectedValue(broken)
    vi.mocked(hashWasm.argon2Verify).mockRejectedValue(broken)
    const seen: string[] = []
    const hasher = createHasher(TEST_ARGON2_COST, undefined, (diagnostic) =>
      seen.push(diagnostic.code),
    )
    await expect(hasher.hash(password, sequenceRandom(SALT))).rejects.toBe(broken)
    await expect(hasher.verify(password, hasher.dummyHash)).rejects.toBe(broken)
    expect(seen).toEqual([])
  })

  it("falls back without an onDiagnostic to tell", async () => {
    vi.mocked(hashWasm.argon2id).mockRejectedValue(refused())
    const stored = await createHasher(TEST_ARGON2_COST).hash(password, sequenceRandom(SALT))
    expect(await nobleArgon2.verify(password, stored)).toBe(true)
  })
})
