// Sentinels for createAuth's limit options and the default pages (ADR 0009 §8, ADR 0025): every test builds an Auth
// and most open a page, so a mutant in either is covered by the whole suite. These checks see each choice directly:
// what an option turns into, what a page posts to, and which pages a refused post may be answered with.
import { describe, expect, it } from "vitest"
import { type AuthConfig, type AuthDiagnostic, createAuth } from "../../src/core/auth.js"
import { ConfigError } from "../../src/core/errors.js"
import { memoryStore } from "../../src/store/memory.js"
import { discardEmail, ENV, hibpClear, testAuth } from "../support/auth.js"
import { sendFrom } from "../support/requests.js"

/** The problems createAuth names for `config` in `mode`, or [] when it starts. */
function problems(config: Partial<AuthConfig<string>>, mode = "test"): readonly string[] {
  try {
    createAuth({
      store: { ...memoryStore(), kind: "sql", durable: true },
      env: { ...ENV, APP_ENV: mode, APP_ORIGIN: "https://app.example" },
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

/** The diagnostic codes createAuth reports at startup for `config`. */
function reported(config: Partial<AuthConfig<string>>): readonly AuthDiagnostic["code"][] {
  const codes: AuthDiagnostic["code"][] = []
  testAuth({ ...config, onDiagnostic: (diagnostic) => codes.push(diagnostic.code) })
  return codes
}

const OWN_THROTTLE = {
  attempt: () => Promise.resolve(0),
  failed: () => Promise.resolve(0),
  succeeded: () => Promise.resolve(),
}
const OWN_STUFFING = { flagged: () => Promise.resolve(null), failed: () => Promise.resolve(false) }

describe("the limit options", () => {
  it("start without keys outside production, generating each key for the process", async () => {
    const auth = createAuth({
      store: memoryStore(),
      env: { APP_ENV: "test", APP_ORIGIN: "https://app.example", APP_SYSTEM_ID: "billing-web" },
      hibpFetch: hibpClear,
      sendEmail: discardEmail,
    })
    const reply = await sendFrom(auth)({ method: "GET", path: "/auth/session" })
    expect(reply.status).toBe(200)
  })

  it("start with nothing set, and report nothing", () => {
    expect(problems({})).toEqual([])
    expect(reported({})).toEqual([])
  })

  it("report each limit turned off, once, in order", () => {
    expect(
      reported({ throttle: false, stuffing: false, emailLimit: false, rateLimit: false }),
    ).toEqual(["throttle-off", "stuffing-off", "email-limit-off", "rate-limit-off"])
  })

  it("take the app's own throttle and detector, and refuse half of either", () => {
    expect(problems({ throttle: OWN_THROTTLE, stuffing: OWN_STUFFING }, "production")).toEqual([])
    expect(problems({ throttle: { attempt: OWN_THROTTLE.attempt } as never })).toHaveLength(1)
    expect(problems({ stuffing: { failed: OWN_STUFFING.failed } as never })).toHaveLength(1)
    expect(reported({ throttle: OWN_THROTTLE, stuffing: OWN_STUFFING })).toEqual([])
  })

  it("refuse each false that production and staging forbid, and allow it in development", () => {
    for (const mode of ["production", "staging"]) {
      expect(problems({ throttle: false }, mode), mode).toHaveLength(1)
      expect(problems({ stuffing: false }, mode), mode).toHaveLength(1)
      expect(problems({ emailLimit: false }, mode), mode).toHaveLength(1)
      expect(problems({ rateLimit: false }, mode), mode).toEqual([])
    }
    expect(
      problems({ throttle: false, stuffing: false, emailLimit: false }, "development"),
    ).toEqual([])
  })

  it("check changed values of the throttle and the detector", () => {
    expect(problems({ throttle: { freeFailures: -1 } })).toEqual([
      "throttle.freeFailures must be a whole number, 0 or more.",
    ])
    expect(problems({ stuffing: { distinctAccounts: 0 } })).toEqual([
      "stuffing.distinctAccounts must be a whole number, 1 or more.",
    ])
    expect(problems({ throttle: { freeFailures: 0 }, stuffing: { windowMs: 1 } })).toEqual([])
  })

  it("check the mail limits, the code attempts and the refusal events", () => {
    expect(problems({ emailLimit: {} })).toEqual([])
    expect(problems({ emailLimit: { perClient: false } })).toEqual([])
    expect(problems({ emailLimit: { perAddress: [] } })).toHaveLength(1)
    expect(problems({ emailLimit: null as never })).toHaveLength(1)
    expect(problems({ emailCodeAttempts: 0 })).toHaveLength(1)
    expect(problems({ emailCodeAttempts: 6 })).toHaveLength(1)
    expect(problems({ emailCodeAttempts: 1 })).toEqual([])
    expect(problems({ refusalEvents: "every" })).toEqual([])
    expect(problems({ refusalEvents: "all" as never })).toHaveLength(1)
  })
})

describe("the limit options' exact words", () => {
  it("say what each limit turned off means", () => {
    const messages: string[] = []
    testAuth({
      throttle: false,
      stuffing: false,
      emailLimit: false,
      rateLimit: false,
      onDiagnostic: (diagnostic) => messages.push(diagnostic.message),
    })
    expect(messages).toEqual([
      "throttle is false, so password, TOTP and recovery-code guesses are not slowed. Production and staging refuse this (ADR 0009 §8).",
      "stuffing is false, so a client failing across many accounts is never flagged. Production and staging refuse this (ADR 0009 §8).",
      "emailLimit is false, so confirmation mail is sent without limit. Production and staging refuse this (ADR 0009 §8).",
      "rateLimit is false, so test-cap limits no request to /auth. Limit them in front of the app, at its gateway or proxy (ADR 0009 §8).",
    ])
  })

  it("say why production refuses each, and name the field or shape that is wrong", () => {
    expect(problems({ throttle: false, stuffing: false, emailLimit: false }, "production")).toEqual(
      [
        "throttle: false is refused in production and staging: NIST SP 800-63B-4 §3.2.2 requires throttling failed authentication attempts. Change its values or pass your own Throttle instead.",
        "stuffing: false is refused in production and staging: without it, credential stuffing spread across many accounts is never slowed past the per-account throttle. Change its values or pass your own detector instead.",
        "emailLimit: false is refused in production and staging: the send limits are what stop sign-up and resend from flooding someone's inbox with mail from the app's domain. Change their values or pass your own limiter instead.",
      ],
    )
    expect(
      problems({
        throttle: { attempt: () => Promise.resolve(0) } as never,
        stuffing: { windowMs: 0 },
        emailLimit: {
          perAddress: [
            { windowMs: 1, max: 1 },
            { windowMs: 0, max: 1 },
          ],
        },
        failureCeiling: 101,
        emailCodeAttempts: 0,
      }),
    ).toEqual([
      "throttle must be changed values ({ freeFailures, windowMs, firstDelayMs, maxDelayMs }), a Throttle with attempt, failed and succeeded, or false.",
      "failureCeiling must be a whole number from 1 to 100: NIST SP 800-63B-4 §3.2.2 allows at most 100 consecutive failed attempts on one authenticator.",
      "stuffing.windowMs must be a whole number of milliseconds, from 1 to 31536000000 (a year).",
      "emailLimit.perAddress must list at least one { windowMs, max } with whole numbers 1 or more, or a rate-limiter-flexible limiter.",
      "emailCodeAttempts must be a whole number from 1 to 5: a 6-digit code stays hard to guess only while it allows at most 5 attempts over its life, a 1 in 200,000 chance.",
    ])
    expect(problems({ throttle: { windowMs: 0, firstDelayMs: 2_000, maxDelayMs: 1_000 } })).toEqual(
      [
        "throttle.windowMs must be a whole number of milliseconds, from 1 to 31536000000 (a year).",
        "throttle.firstDelayMs must not exceed throttle.maxDelayMs.",
      ],
    )
    expect(problems({ stuffing: { flagged: () => Promise.resolve(null) } as never })).toEqual([
      "stuffing must be changed values ({ distinctAccounts, windowMs }), a StuffingDetector with flagged and failed, or false.",
    ])
  })
})

describe("the default pages", () => {
  /** The form actions and links of the page at `path`. */
  async function pageOf(path: string) {
    const reply = await sendFrom(testAuth({ publicBasePath: "/p" }).auth)({ method: "GET", path })
    const actions = [...reply.text.matchAll(/action="([^"]+)"/g)].map((match) => match[1])
    const links = [...reply.text.matchAll(/href="([^"]+)" data-test-cap="link"/g)].map(
      (match) => match[1],
    )
    return { status: reply.status, actions, links }
  }

  it("post where each one must, and link where each one must, under the gateway's prefix", async () => {
    expect(await pageOf("/auth/sign-up")).toEqual({
      status: 200,
      actions: ["/p/auth/sign-up"],
      links: ["/p/auth/sign-in"],
    })
    expect(await pageOf("/auth/sign-in")).toEqual({
      status: 200,
      actions: ["/p/auth/sign-in"],
      links: ["/p/auth/sign-up"],
    })
    expect(await pageOf("/auth/email/confirm")).toEqual({
      status: 200,
      actions: ["/p/auth/email/confirm", "/p/auth/email/resend"],
      links: [],
    })
    expect(await pageOf("/auth/password")).toEqual({
      status: 200,
      actions: ["/p/auth/password"],
      links: [],
    })
    expect(await pageOf("/auth/sign-out")).toEqual({
      status: 200,
      actions: ["/p/auth/sign-out"],
      links: [],
    })
  })

  it("answer a refused form post with the page only where opening it touches no store", async () => {
    const statusOf = async (path: string) => {
      const send = sendFrom(
        testAuth({
          rateLimit: {
            max: 1,
            rules: {
              "totp/verify": { windowMs: 10_000, max: 1 },
              "totp/confirm": { windowMs: 10_000, max: 1 },
              "step-up": { windowMs: 10_000, max: 1 },
            },
          },
        }).auth,
      )
      const form = {
        method: "POST",
        path,
        headers: [
          ["Origin", "https://app.example"],
          ["Accept", "text/html"],
          ["Content-Type", "application/x-www-form-urlencoded"],
        ] as const,
        body: "",
      }
      await send(form)
      const over = await send(form)
      return [over.status, String(over.headers.get("content-type")).split(";")[0]]
    }
    expect(await statusOf("/auth/email/resend")).toEqual([429, "text/html"])
    expect(await statusOf("/auth/password")).toEqual([429, "text/html"])
    expect(await statusOf("/auth/sign-out")).toEqual([429, "text/html"])
    expect(await statusOf("/auth/totp/verify")).toEqual([429, "application/json"])
    // TOTP enrolment's and step-up's pages start a ceremony when they open, so their refused posts answer JSON.
    expect(await statusOf("/auth/totp/confirm")).toEqual([429, "application/json"])
    expect(await statusOf("/auth/step-up")).toEqual([429, "application/json"])
  })

  it("carry no Retry-After on a page answered for any refusal but a wait", async () => {
    const send = sendFrom(testAuth().auth)
    const reply = await send({
      method: "POST",
      path: "/auth/sign-in",
      headers: [
        ["Origin", "https://app.example"],
        ["Accept", "text/html"],
        ["Content-Type", "application/x-www-form-urlencoded"],
      ],
      body: "identifier=ada%40example.com&password=x",
    })
    expect(reply.status).toBe(403)
    expect(reply.headers.get("retry-after")).toBeNull()
  })
})
