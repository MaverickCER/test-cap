// ADR 0030 ("Override and replace"): a route's rule and each mail limit take any rate-limiter-flexible limiter. The
// type checks below fail when one of the backends ADR 0030 names no longer fits. What runs for real: the stock
// `RateLimiterMemory` and an app-written limiter in test/security/rate-limit.test.ts, and `RateLimiterUnion` in
// test/security/store-limiter.test.ts. No test here runs Redis, Postgres or the other backends themselves.
import { readdirSync, readFileSync } from "node:fs"
import path from "node:path"
import type {
  RateLimiterDrizzle,
  RateLimiterDynamo,
  RateLimiterMemory,
  RateLimiterPostgres,
  RateLimiterPrisma,
  RateLimiterRedis,
  RateLimiterSQLite,
  RateLimiterValkey,
} from "rate-limiter-flexible"
import { describe, expect, expectTypeOf, it } from "vitest"
import type { LimiterFactory, RateRuleSetting } from "../../src/security/rate-limit.js"

const root = path.resolve(import.meta.dirname, "../..")

describe("the limiters ADR 0030 names", () => {
  it("each fit a route's rule and a limiter factory's result", () => {
    type Named =
      | RateLimiterRedis
      | RateLimiterPostgres
      | RateLimiterDrizzle
      | RateLimiterPrisma
      | RateLimiterDynamo
      | RateLimiterValkey
      | RateLimiterSQLite
      | RateLimiterMemory
    expectTypeOf<Named>().toExtend<RateRuleSetting>()
    expectTypeOf<Named>().toExtend<ReturnType<LimiterFactory>>()
  })

  it("never get the library's in-memory block, which reads Date.now instead of test-cap's clock", () => {
    const sources = readdirSync(path.join(root, "src"), { recursive: true, encoding: "utf8" })
      .filter((file) => file.endsWith(".ts"))
      .map((file) => readFileSync(path.join(root, "src", file), "utf8"))
    expect(sources.length).toBeGreaterThan(50)
    expect(sources.filter((text) => text.includes("inMemoryBlockOnConsumed"))).toEqual([])
  })
})
