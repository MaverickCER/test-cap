// Sentinels for createAuth's option shapes: every option of the wrong shape is named at startup. These run on every
// createAuth, so nearly every test covers them; here they fail first (vitest.config.ts runs test/sentinel/ first).
// Also the password length cap, which every password sign-in passes through.
import { describe, expect, it, vi } from "vitest"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import { createAuth } from "../../src/core/auth.js"
import { fixedClock, sequenceRandom } from "../../src/core/clock.js"
import { ConfigError } from "../../src/core/errors.js"
import { signInWithPassword } from "../../src/methods/password/method.js"
import { memoryStore } from "../../src/store/memory.js"
import { testHasher } from "../support/argon2.js"
import { discardEmail, ENV, hibpClear, keyRing } from "../support/auth.js"

const durable = () => ({ ...memoryStore(), kind: "sql", durable: true })

function problems(run: () => unknown): readonly string[] {
  try {
    run()
  } catch (error) {
    if (error instanceof ConfigError) return error.problems
    throw error
  }
  throw new Error("expected a ConfigError")
}

const production = {
  APP_ENV: "production",
  APP_SYSTEM_ID: "billing-web",
  APP_ORIGIN: "https://app.example",
  AUTH_ENCRYPTION_KEY: keyRing("e1", 3),
  AUTH_CSRF_KEY: keyRing("c1", 5),
}

describe("createAuth's option shapes", () => {
  const base = { store: memoryStore(), env: ENV, hibpFetch: hibpClear, sendEmail: discardEmail }

  it("names each option of the wrong shape, instead of failing later on its first use", () => {
    const cases: readonly (readonly [Record<string, unknown>, string])[] = [
      [{ env: undefined }, "env must be an object of settings, such as process.env."],
      [{ env: null }, "env must be an object of settings, such as process.env."],
      [
        { hibpFetch: undefined },
        "hibpFetch is required: the fetch the breached-password check calls, usually the global fetch.",
      ],
      [
        { sendEmail: undefined },
        "sendEmail is required: the function that delivers each email test-cap builds, such as sign-up's code.",
      ],
      [
        { onDiagnostic: 5 },
        "onDiagnostic must be a function that receives each operator diagnostic.",
      ],
      [{ tenant: "" }, 'tenant must be a non-empty string, not "".'],
      [{ tenant: 7 }, "tenant must be a non-empty string, not 7."],
      [{ policy: {} }, "policy must come from defineAuthPolicy."],
      [{ policy: { deviations: [] } }, "policy must come from defineAuthPolicy."],
      [
        { policy: { require: () => 0, assurance: () => 0, requirement: () => 0 } },
        "policy must come from defineAuthPolicy.",
      ],
      [
        { trustedProxies: "10.0.0.1" },
        'trustedProxies must be a list of IP addresses and CIDR ranges, or a platform() preset, such as ["10.0.0.0/8"].',
      ],
      [{ trustedProxies: [1] }, "trustedProxies: 1 is not an IP address or CIDR range."],
      [
        { forwardedHeader: "x-forwarded-for" },
        "forwardedHeader names the header the app's own proxies set; list those proxies in trustedProxies, or test-cap reads no header.",
      ],
      [
        { throttle: true },
        "throttle must be changed values ({ freeFailures, windowMs, firstDelayMs, maxDelayMs }), a Throttle with attempt, failed and succeeded, or false.",
      ],
      [
        { throttle: null },
        "throttle must be changed values ({ freeFailures, windowMs, firstDelayMs, maxDelayMs }), a Throttle with attempt, failed and succeeded, or false.",
      ],
      [
        { stuffing: 5 },
        "stuffing must be changed values ({ distinctAccounts, windowMs }), a StuffingDetector with flagged and failed, or false.",
      ],
      [
        { throttle: { maxDelayMs: 31_536_000_001 } },
        "throttle.maxDelayMs must be a whole number of milliseconds, from 1 to 31536000000 (a year).",
      ],
      [{ argon2Hasher: 5 }, "argon2Hasher must be an object with hash and verify functions."],
      [
        { argon2Hasher: { hash: () => Promise.resolve("") } },
        "argon2Hasher must be an object with hash and verify functions.",
      ],
      [
        { publicBasePath: "accounts" },
        'publicBasePath "accounts" must be empty or a path such as /accounts, with no trailing slash.',
      ],
      [
        { rateLimit: { windowMS: 1_000, mx: 5 } },
        'rateLimit has no value "windowMS": its values are windowMs, max, rules and limiter.',
      ],
    ]
    for (const [change, problem] of cases) {
      expect(
        problems(() => createAuth({ ...base, ...change } as Parameters<typeof createAuth>[0])),
        JSON.stringify(change),
      ).toContain(problem)
    }
  })

  it("refuses to start without APP_SYSTEM_ID in every mode", () => {
    for (const mode of ["development", "test", "staging", "production"]) {
      const env: Record<string, string | undefined> = { ...ENV, APP_ENV: mode }
      delete env["APP_SYSTEM_ID"]
      expect(
        problems(() => createAuth({ ...base, env })),
        mode,
      ).toContain("APP_SYSTEM_ID is missing.")
    }
  })

  it("starts in production with limit values loose enough to be off in effect: refusing false judges no value", () => {
    expect(() =>
      createAuth({
        ...base,
        store: durable(),
        env: production,
        throttle: { freeFailures: 1_000_000 },
        stuffing: { distinctAccounts: 1_000_000 },
      }),
    ).not.toThrow()
  })

  it("accepts the longest window and delay, a year, and a policy from defineAuthPolicy", () => {
    expect(() =>
      createAuth({
        ...base,
        tenant: "acme",
        policy: defineAuthPolicy({ version: "v" }),
        throttle: { windowMs: 31_536_000_000, maxDelayMs: 31_536_000_000 },
        stuffing: { windowMs: 31_536_000_000 },
      }),
    ).not.toThrow()
  })

  it("starts with an argon2Hasher that has hash and verify", () => {
    const argon2Hasher = { hash: () => Promise.resolve(""), verify: () => Promise.resolve(false) }
    expect(() =>
      createAuth({ ...base, argon2Hasher } as Parameters<typeof createAuth>[0]),
    ).not.toThrow()
  })

  it("caps only the millisecond values at a year, so a count may be larger", () => {
    expect(() =>
      createAuth({
        ...base,
        throttle: { freeFailures: 31_536_000_001 },
        stuffing: { distinctAccounts: 31_536_000_001 },
      }),
    ).not.toThrow()
  })
})

describe("the password length cap", () => {
  it("checks a password of 256 code points, and refuses one of 257 before any hash", async () => {
    const deps = {
      clock: fixedClock(0),
      random: sequenceRandom([2, 7]),
      store: memoryStore(),
      hibp: "off" as const,
      hasher: { ...testHasher, dummyVerify: vi.fn(testHasher.dummyVerify) },
    }
    const signIn = (password: string) =>
      signInWithPassword(deps, { tenant: "t", accountId: null, password })
    // An unknown account still pays for one hash, so the reply time says nothing; an oversized password pays for none.
    expect(await signIn("a".repeat(256))).toEqual({ ok: false, reason: "invalid" })
    expect(deps.hasher.dummyVerify).toHaveBeenCalledTimes(1)
    expect(await signIn("a".repeat(257))).toEqual({ ok: false, reason: "too-long" })
    expect(deps.hasher.dummyVerify).toHaveBeenCalledTimes(1)
  })
})
