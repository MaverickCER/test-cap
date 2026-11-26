// Attack: parallel redemptions of one recovery code each succeed. Stopped by: redemption uses `consumeOnce`, so of
// any number of parallel redemptions exactly one wins (ADR 0002, 0007).
import { describe, expect, it } from "vitest"
import { fixedClock, systemRandom } from "../../src/core/clock.js"
import { createHasher } from "../../src/methods/password/argon2.js"
import { generateRecoveryCodes, redeemRecoveryCode } from "../../src/methods/recovery/codes.js"
import { memoryStore } from "../../src/store/memory.js"
import { TEST_ARGON2_COST } from "../support/argon2.js"

describe("redemption-race", () => {
  it("lets exactly one of twenty parallel redemptions of one code succeed", async () => {
    const deps = {
      store: memoryStore(),
      clock: fixedClock(1_000),
      random: systemRandom,
      hasher: createHasher(TEST_ARGON2_COST),
    }
    const [code] = (await generateRecoveryCodes(deps, { tenant: "t", accountId: "acct" })) as [
      string,
    ]
    const results = await Promise.all(
      Array.from({ length: 20 }, () =>
        redeemRecoveryCode(deps, { tenant: "t", accountId: "acct", code }),
      ),
    )
    expect(results.filter((result) => result.ok)).toHaveLength(1)
  })
})
