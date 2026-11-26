// The owner's rule applied to the remaining limits (ADR 0009 §8): the confirmation-mail send limits, the email-code
// attempt limit and the credential-stuffing detector each keep today's values by default, take changed values, and are
// turned off or replaced where the reason for the limit allows it.
import { describe, expect, it } from "vitest"
import { type AuthConfig, type AuthDiagnostic, createAuth } from "../../src/core/auth.js"
import { ConfigError } from "../../src/core/errors.js"
import type { LimiterOptions } from "../../src/security/rate-limit.js"
import type { StuffingDetector } from "../../src/security/stuffing.js"
import { memoryStore } from "../../src/store/memory.js"
import {
  Browser,
  confirmationCode,
  discardEmail,
  ENV,
  expectOk,
  hibpClear,
  keyRing,
  testAuth,
} from "../support/auth.js"
import RateLimiterMemory from "rate-limiter-flexible/lib/RateLimiterMemory.js"
import { fakeLimiter, recordingStore, sendFrom } from "../support/requests.js"

const durable = () => ({ ...memoryStore(), kind: "sql", durable: true })

const production = {
  APP_ENV: "production",
  APP_SYSTEM_ID: "billing-web",
  APP_ORIGIN: "https://app.example",
  AUTH_ENCRYPTION_KEY: keyRing("e1", 3),
  AUTH_CSRF_KEY: keyRing("c1", 5),
}

/** The problems createAuth names for `config` in `env`, or [] when it starts. */
function problems(config: Partial<AuthConfig<string>>, env: Record<string, string> = ENV) {
  try {
    createAuth({ store: durable(), env, hibpFetch: hibpClear, sendEmail: discardEmail, ...config })
    return []
  } catch (error) {
    if (error instanceof ConfigError) return error.problems
    throw error
  }
}

/** Signs up `identifier` from `client` and returns the browser, which then holds the pre-auth session. */
async function signUp(
  setup: ReturnType<typeof testAuth>,
  identifier: string,
  client = "198.51.100.9",
) {
  const browser = new Browser(sendFrom(setup.auth, client))
  await browser.start()
  await expectOk(browser.post("/auth/sign-up", { identifier }))
  return browser
}

/** Sign-up's own request limit off, so the mail limits are what each test meets. */
const UNLIMITED_SIGN_UP = { rules: { "sign-up": false } } as const

describe("the confirmation-mail send limits", () => {
  it("default to 1 a minute and 5 an hour per address, and 20 an hour per client", async () => {
    const setup = testAuth({ rateLimit: UNLIMITED_SIGN_UP })
    const browser = await signUp(setup, "ada@example.com")
    const early = await browser.post("/auth/email/resend")
    expect(early.json).toEqual({ outcome: "enroll", retryAfterMs: 60_000 })
    expect(setup.outbox).toHaveLength(1)
    for (let n = 0; n < 21; n += 1) await signUp(setup, `person${n}@example.com`)
    expect(setup.outbox).toHaveLength(20)
  })

  it("take changed values, per address and per client", async () => {
    const setup = testAuth({
      rateLimit: UNLIMITED_SIGN_UP,
      emailLimit: {
        perAddress: [{ windowMs: 60_000, max: 2 }],
        perClient: { windowMs: 60 * 60_000, max: 3 },
      },
    })
    const browser = await signUp(setup, "ada@example.com")
    await browser.post("/auth/email/resend")
    await browser.post("/auth/email/resend")
    expect(setup.outbox).toHaveLength(2)
    await signUp(setup, "bob@example.com")
    await signUp(setup, "cy@example.com")
    expect(setup.outbox.map((message) => message.to)).toEqual([
      "ada@example.com",
      "ada@example.com",
      "bob@example.com",
    ])
  })

  it("count no client with perClient: false, and keep the per-address limits", async () => {
    const setup = testAuth({ rateLimit: UNLIMITED_SIGN_UP, emailLimit: { perClient: false } })
    for (let n = 0; n < 25; n += 1) await signUp(setup, `person${n}@example.com`)
    expect(setup.outbox).toHaveLength(25)
    const browser = await signUp(setup, "ada@example.com")
    await browser.post("/auth/email/resend")
    expect(setup.outbox).toHaveLength(26)
  })

  it("are off with emailLimit: false in test, which tells the operator once", async () => {
    const diagnostics: AuthDiagnostic[] = []
    const setup = testAuth({
      rateLimit: UNLIMITED_SIGN_UP,
      emailLimit: false,
      onDiagnostic: (diagnostic) => diagnostics.push(diagnostic),
    })
    const browser = await signUp(setup, "ada@example.com")
    for (let n = 0; n < 7; n += 1) await browser.post("/auth/email/resend")
    expect(setup.outbox).toHaveLength(8)
    expect(diagnostics).toEqual([
      {
        code: "email-limit-off",
        message:
          "emailLimit is false, so confirmation mail is sent without limit. Production and staging refuse this (ADR 0009 §8).",
      },
    ])
  })

  it("refuse emailLimit: false in production and staging, naming inbox flooding", () => {
    for (const mode of ["production", "staging"]) {
      expect(problems({ emailLimit: false }, { ...production, APP_ENV: mode }), mode).toEqual([
        "emailLimit: false is refused in production and staging: the send limits are what stop sign-up and resend from flooding someone's inbox with mail from the app's domain. Change their values or pass your own limiter instead.",
      ])
    }
    expect(problems({ emailLimit: false }, { ...ENV, APP_ENV: "development" })).toEqual([])
  })

  it("accept perClient: false in every mode, production and staging included", () => {
    for (const mode of ["production", "staging", "development", "test"]) {
      const env = mode === "production" || mode === "staging" ? production : ENV
      expect(
        problems({ emailLimit: { perClient: false } }, { ...env, APP_ENV: mode }),
        mode,
      ).toEqual([])
    }
  })

  it("build each limit over the app's own backend in place of the store's counters", async () => {
    const recorded = recordingStore()
    const seen: string[] = []
    const factory = (options: LimiterOptions) =>
      fakeLimiter((key) => {
        seen.push(`${options.keyPrefix} ${options.points}/${options.duration}s ${key}`)
        return key.startsWith("client:")
          ? { allowed: false, msBeforeNext: 9_000 }
          : { allowed: true }
      }).limiter
    const setup = testAuth({ store: recorded.store, emailLimit: { limiter: factory } })
    await signUp(setup, "ada@example.com")
    expect(seen).toEqual([
      "email-send:60000:1 1/60s address:ada@example.com",
      "email-send:3600000:5 5/3600s address:ada@example.com",
      "email-send:3600000:20 20/3600s client:198.51.100.9",
    ])
    expect(setup.outbox).toEqual([])
    expect(recorded.counters.filter((name) => name.includes("email-send"))).toEqual([])
  })

  it("take a stock rate-limiter-flexible limiter as a limit", async () => {
    const setup = testAuth({
      rateLimit: UNLIMITED_SIGN_UP,
      emailLimit: { perAddress: [new RateLimiterMemory({ points: 2, duration: 60 })] },
    })
    const browser = await signUp(setup, "ada@example.com")
    await browser.post("/auth/email/resend")
    await browser.post("/auth/email/resend")
    expect(setup.outbox).toHaveLength(2)
  })

  it("name each value that is wrong", () => {
    const perAddress =
      "emailLimit.perAddress must list at least one { windowMs, max } with whole numbers 1 or more, or a rate-limiter-flexible limiter."
    expect(problems({ emailLimit: { perAddress: [] } })).toEqual([perAddress])
    // A value that is no list at all is named the same way, not thrown as a TypeError.
    for (const wrong of [null, "1/min", 5, { windowMs: 1, max: 1 }]) {
      expect(problems({ emailLimit: { perAddress: wrong as never } })).toEqual([perAddress])
    }
    expect(problems({ emailLimit: { perAddress: [{ windowMs: 0, max: 1 }] } })).toEqual([
      perAddress,
    ])
    expect(problems({ emailLimit: { perClient: { windowMs: 1, max: 0 } } })).toEqual([
      "emailLimit.perClient must be { windowMs, max } with whole numbers 1 or more, a rate-limiter-flexible limiter, or false.",
    ])
    expect(problems({ emailLimit: { limiter: {} as never } })).toEqual([
      "emailLimit.limiter must be a function that builds a rate-limiter-flexible limiter from { points, duration, keyPrefix }.",
    ])
    expect(problems({ emailLimit: "off" as never })).toEqual([
      "emailLimit must be false or an object such as { perAddress, perClient, limiter }.",
    ])
  })
})

describe("the email-code attempt limit", () => {
  it("is 5 by default: the sixth attempt is refused even with the right code", async () => {
    const setup = testAuth()
    const browser = await signUp(setup, "ada@example.com")
    for (let n = 0; n < 5; n += 1) await browser.post("/auth/email/confirm", { code: "000000" })
    const right = await browser.post("/auth/email/confirm", {
      code: confirmationCode(setup.outbox, "ada@example.com"),
    })
    expect(right.status).toBe(429)
  })

  it("can be lowered: with 2, the third attempt is refused", async () => {
    const setup = testAuth({ emailCodeAttempts: 2 })
    const browser = await signUp(setup, "ada@example.com")
    expect((await browser.post("/auth/email/confirm", { code: "000000" })).status).toBe(400)
    expect((await browser.post("/auth/email/confirm", { code: "000000" })).status).toBe(400)
    const right = await browser.post("/auth/email/confirm", {
      code: confirmationCode(setup.outbox, "ada@example.com"),
    })
    expect(right.status).toBe(429)
  })

  it("lets the right code in on the last allowed attempt", async () => {
    const setup = testAuth({ emailCodeAttempts: 1 })
    const browser = await signUp(setup, "ada@example.com")
    const right = await browser.post("/auth/email/confirm", {
      code: confirmationCode(setup.outbox, "ada@example.com"),
    })
    expect(right.status).toBe(200)
  })

  it("can be neither raised above 5 nor turned off, and says why", () => {
    for (const value of [6, 100, 0, -1, 2.5, false, Number.NaN]) {
      expect(problems({ emailCodeAttempts: value as never }), String(value)).toEqual([
        "emailCodeAttempts must be a whole number from 1 to 5: a 6-digit code stays hard to guess only while it allows at most 5 attempts over its life, a 1 in 200,000 chance.",
      ])
    }
    expect(problems({ emailCodeAttempts: 5 })).toEqual([])
  })
})

describe("the credential-stuffing detector", () => {
  /** Fails a sign-in on `identifier` from one client; resolves to the status. */
  async function failOn(setup: ReturnType<typeof testAuth>, identifier: string) {
    const browser = new Browser(sendFrom(setup.auth, "192.0.2.10"))
    await browser.start()
    return (
      await browser.post("/auth/sign-in", { identifier, password: "wrong password entirely" })
    ).status
  }

  it("is off with stuffing: false in test, so failures on many accounts flag nothing", async () => {
    const diagnostics: AuthDiagnostic[] = []
    const calls: string[] = []
    const setup = testAuth({
      stuffing: false,
      challengeHook: () => {
        calls.push("hook")
        return false
      },
      throttle: { freeFailures: 1_000 },
      rateLimit: { rules: { "sign-in": false } },
      onDiagnostic: (diagnostic) => diagnostics.push(diagnostic),
    })
    for (let n = 0; n < 25; n += 1) await failOn(setup, `user${n}@example.com`)
    expect(await failOn(setup, "last@example.com")).toBe(401)
    expect(calls).toEqual([])
    expect(diagnostics.map((diagnostic) => diagnostic.message)).toEqual([
      "stuffing is false, so a client failing across many accounts is never flagged. Production and staging refuse this (ADR 0009 §8).",
    ])
  })

  it("refuses stuffing: false in production and staging", () => {
    for (const mode of ["production", "staging"]) {
      expect(problems({ stuffing: false }, { ...production, APP_ENV: mode }), mode).toEqual([
        "stuffing: false is refused in production and staging: without it, credential stuffing spread across many accounts is never slowed past the per-account throttle. Change its values or pass your own detector instead.",
      ])
    }
    expect(problems({ stuffing: false }, { ...ENV, APP_ENV: "development" })).toEqual([])
  })

  it("uses the app's StuffingDetector in place of the default", async () => {
    const recorded = recordingStore()
    const seen: string[] = []
    const stuffing: StuffingDetector = {
      flagged(clientAddress) {
        seen.push(`flagged ${String(clientAddress)}`)
        return Promise.resolve(seen.length > 2 ? "the-app's-key" : null)
      },
      failed(account, clientAddress) {
        seen.push(`failed ${account} ${String(clientAddress)}`)
        return Promise.resolve(true)
      },
    }
    const hooked: string[] = []
    const setup = testAuth({
      store: recorded.store,
      stuffing,
      challengeHook: ({ client }) => {
        hooked.push(client)
        return false
      },
    })
    expect(await failOn(setup, "ada@example.com")).toBe(401)
    expect(setup.events.at(-1)).toMatchObject({ status_detail: "credential-stuffing" })
    expect(await failOn(setup, "bob@example.com")).toBe(403)
    expect(seen).toEqual([
      "flagged 192.0.2.10",
      "failed ada@example.com 192.0.2.10",
      "flagged 192.0.2.10",
    ])
    expect(hooked).toEqual(["the-app's-key"])
    expect(recorded.counters.filter((name) => name.startsWith("stuffing"))).toEqual([])
  })

  it("refuses an object that is half a StuffingDetector", () => {
    expect(problems({ stuffing: { flagged: () => Promise.resolve(null) } as never })).toEqual([
      "stuffing must be changed values ({ distinctAccounts, windowMs }), a StuffingDetector with flagged and failed, or false.",
    ])
  })
})
