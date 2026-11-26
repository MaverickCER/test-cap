// Attack: a database read lets 80-bit recovery codes be recovered from what is stored. Stopped by: each code is
// stored only as an argon2id hash at the ADR 0018 cost, with its own salt, under a non-secret prefix (ADR 0007 §1).
import { describe, expect, it } from "vitest"
import { fixedClock, systemRandom } from "../../src/core/clock.js"
import { ARGON2_PARAMETERS, createHasher } from "../../src/methods/password/argon2.js"
import {
  generateRecoveryCodes,
  parseRecoveryCode,
  RECOVERY_CODE_COLLECTION,
} from "../../src/methods/recovery/codes.js"
import { memoryStore } from "../../src/store/memory.js"

describe("recovery-code-weak-storage", () => {
  it("stores nothing but an argon2id hash at the production cost, never the secret", async () => {
    const store = memoryStore()
    const codes = (await generateRecoveryCodes(
      { store, clock: fixedClock(1_000), random: systemRandom, hasher: createHasher(undefined) },
      { tenant: "t", accountId: "acct" },
    )) as readonly string[]
    const { memoryKiB, iterations, parallelism } = ARGON2_PARAMETERS
    for (const code of codes) {
      const { prefix, secret } = parseRecoveryCode(code) as { prefix: string; secret: string }
      const stored = await store.get("t", RECOVERY_CODE_COLLECTION, prefix)
      // Beside the hash, only the id of the set the code belongs to: random, and drawn apart from every secret.
      expect(Object.keys(stored?.data as object).sort()).toEqual(["hash", "set"])
      expect((stored?.data as { hash: string }).hash).toMatch(
        new RegExp(
          `^\\$argon2id\\$v=19\\$m=${String(memoryKiB)},t=${String(iterations)},p=${String(parallelism)}\\$`,
        ),
      )
      expect(JSON.stringify(stored)).not.toContain(secret)
    }
  }, 120_000)
})
