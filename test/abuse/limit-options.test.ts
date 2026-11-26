// Overriding and replacing the guessing limits (ADR 0009 §8): `throttle` takes changed values, the app's own Throttle,
// or false outside production and staging; the failure ceiling can be lowered, never raised above NIST's 100; and
// `rateLimit: false` starts in production, for an app that limits requests at its gateway.
import { describe, expect, it } from "vitest"
import { type AuthConfig, type AuthDiagnostic, createAuth } from "../../src/core/auth.js"
import { ConfigError } from "../../src/core/errors.js"
import type { Throttle, ThrottleSubject } from "../../src/security/throttle.js"
import { memoryStore } from "../../src/store/memory.js"
import {
  Browser,
  discardEmail,
  ENV,
  hibpClear,
  keyRing,
  PASSWORD,
  seedAccount,
  testAuth,
} from "../support/auth.js"
import { sendFrom } from "../support/requests.js"

const durable = () => ({ ...memoryStore(), kind: "sql", durable: true })

const production = {
  APP_ENV: "production",
  APP_SYSTEM_ID: "billing-web",
  APP_ORIGIN: "https://app.example",
  AUTH_ENCRYPTION_KEY: keyRing("e1", 3),
  AUTH_CSRF_KEY: keyRing("c1", 5),
}

const NIST_THROTTLE =
  "throttle: false is refused in production and staging: NIST SP 800-63B-4 §3.2.2 requires throttling failed authentication attempts. Change its values or pass your own Throttle instead."

/** The problems createAuth names for `config` in `env`, or [] when it starts. */
function problems(config: Partial<AuthConfig<string>>, env: Record<string, string> = ENV) {
  try {
    createAuth({
      store: durable(),
      env,
      hibpFetch: hibpClear,
      sendEmail: discardEmail,
      ...config,
    })
    return []
  } catch (error) {
    if (error instanceof ConfigError) return error.problems
    throw error
  }
}

/** Signs in with `password` from a fresh browser, as many times as asked; resolves to each status. */
async function signIns(setup: ReturnType<typeof testAuth>, password: string, times: number) {
  const browser = new Browser(sendFrom(setup.auth))
  await browser.start()
  const seen: number[] = []
  for (let n = 0; n < times; n += 1) {
    seen.push(
      (await browser.post("/auth/sign-in", { identifier: "ada@example.com", password })).status,
    )
  }
  return seen
}

describe("throttle: false", () => {
  it("is refused in production and staging, citing NIST SP 800-63B", () => {
    for (const mode of ["production", "staging"]) {
      expect(problems({ throttle: false }, { ...production, APP_ENV: mode }), mode).toEqual([
        NIST_THROTTLE,
      ])
    }
  })

  it("is refused when APP_ENV is missing, since that runs as production", () => {
    const missing: Record<string, string> = { ...production }
    delete missing["APP_ENV"]
    expect(problems({ throttle: false }, missing)).toEqual([NIST_THROTTLE])
  })

  it("is allowed in test, lets every guess through, and tells the operator once", async () => {
    const diagnostics: AuthDiagnostic[] = []
    const setup = testAuth({
      throttle: false,
      rateLimit: { rules: { "sign-in": false } },
      onDiagnostic: (diagnostic) => diagnostics.push(diagnostic),
    })
    await seedAccount(setup, { password: true, totp: true })
    const wrong = await signIns(setup, "not the password", 12)
    expect(wrong).toEqual(Array<number>(12).fill(401))
    expect(await signIns(setup, PASSWORD, 1)).toEqual([200])
    expect(diagnostics).toEqual([
      {
        code: "throttle-off",
        message:
          "throttle is false, so password, TOTP and recovery-code guesses are not slowed. Production and staging refuse this (ADR 0009 §8).",
      },
    ])
  })

  it("is allowed in development", () => {
    expect(problems({ throttle: false }, { ...ENV, APP_ENV: "development" })).toEqual([])
  })
})

describe("the app's own Throttle", () => {
  it("is asked before every guess and told of each failure and success, in place of the default", async () => {
    const calls: string[] = []
    const subjects: ThrottleSubject[] = []
    const throttle: Throttle = {
      attempt(subject, strict) {
        calls.push(`attempt ${String(strict)}`)
        subjects.push(subject)
        return Promise.resolve(calls.length > 4 ? 4_100 : 0)
      },
      failed() {
        calls.push("failed")
        return Promise.resolve(0)
      },
      succeeded() {
        calls.push("succeeded")
        return Promise.resolve()
      },
    }
    const setup = testAuth({ throttle })
    await seedAccount(setup, { password: true, totp: true })
    expect(await signIns(setup, "not the password", 1)).toEqual([401])
    expect(await signIns(setup, PASSWORD, 1)).toEqual([200])
    const browser = new Browser(sendFrom(setup.auth))
    await browser.start()
    const blocked = await browser.post("/auth/sign-in", {
      identifier: "ada@example.com",
      password: PASSWORD,
    })
    expect([blocked.status, blocked.headers.get("retry-after")]).toEqual([429, "5"])
    expect(calls).toEqual([
      "attempt false",
      "failed",
      "attempt false",
      "succeeded",
      "attempt false",
    ])
    expect(subjects[0]).toEqual({
      account: "ada@example.com",
      clientAddress: "203.0.113.7",
      secret: "password",
    })
  })

  it("is refused when it lacks one of attempt, failed and succeeded", () => {
    const half = { attempt: () => Promise.resolve(0) }
    expect(problems({ throttle: half as never })).toEqual([
      "throttle must be changed values ({ freeFailures, windowMs, firstDelayMs, maxDelayMs }), a Throttle with attempt, failed and succeeded, or false.",
    ])
  })

  it("is used in production too", () => {
    const throttle: Throttle = {
      attempt: () => Promise.resolve(0),
      failed: () => Promise.resolve(0),
      succeeded: () => Promise.resolve(),
    }
    expect(problems({ throttle }, production)).toEqual([])
  })
})

describe("the failure ceiling", () => {
  it("can be lowered: the password stops after that many consecutive failures", async () => {
    const setup = testAuth({ failureCeiling: 3, throttle: false, rateLimit: false })
    await seedAccount(setup, { password: true, totp: true })
    expect(await signIns(setup, "not the password", 3)).toEqual([401, 401, 401])
    expect(await signIns(setup, PASSWORD, 1)).toEqual([401])
  })

  it("stays at 100 when it is not set, even with the throttle off", async () => {
    const under = testAuth({ throttle: false, rateLimit: false })
    await seedAccount(under, { password: true, totp: true })
    await signIns(under, "not the password", 99)
    expect(await signIns(under, PASSWORD, 1)).toEqual([200])
    const at = testAuth({ throttle: false, rateLimit: false })
    await seedAccount(at, { password: true, totp: true })
    await signIns(at, "not the password", 100)
    expect(await signIns(at, PASSWORD, 1)).toEqual([401])
  })

  it("cannot be raised above 100, citing NIST SP 800-63B", () => {
    for (const value of [101, 1_000, Number.POSITIVE_INFINITY]) {
      expect(problems({ failureCeiling: value }), String(value)).toEqual([
        "failureCeiling must be a whole number from 1 to 100: NIST SP 800-63B-4 §3.2.2 allows at most 100 consecutive failed attempts on one authenticator.",
      ])
    }
  })

  it("must be a whole number, 1 or more", () => {
    for (const value of [0, -5, 2.5, Number.NaN]) {
      expect(problems({ failureCeiling: value }), String(value)).toHaveLength(1)
    }
    expect(problems({ failureCeiling: 1 })).toEqual([])
    expect(problems({ failureCeiling: 100 })).toEqual([])
  })
})

describe("rateLimit: false", () => {
  it("starts in production, for an app that limits requests at its gateway", () => {
    expect(problems({ rateLimit: false }, production)).toEqual([])
  })
})
