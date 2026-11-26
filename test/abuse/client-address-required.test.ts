// ADR 0009 §8 and Open 4 (decided 2026-11-24): production and staging need a client address for the per-client limits.
// An adapter with no source of one refuses to start there, and a request that still arrives without one is refused
// with the fixed 500 before anything runs. `requireClientAddress: false` turns that off, and the operator is told
// once. Development and test serve such a request uncounted, as before.
import { describe, expect, it } from "vitest"
import { fetchAuth, withAuth } from "../../src/adapters/fetch/index.js"
import { nextAuthHandler } from "../../src/adapters/next/index.js"
import { tanstackStartAuth } from "../../src/adapters/tanstack-start/index.js"
import { type AuthConfig, type AuthDiagnostic, createAuth } from "../../src/core/auth.js"
import { ConfigError } from "../../src/core/errors.js"
import { platform } from "../../src/core/proxy-trust.js"
import { memoryStore } from "../../src/store/memory.js"
import { discardEmail, ENV, hibpClear, keyRing, ORIGIN } from "../support/auth.js"
import { CLIENT, recordingStore, sendFrom } from "../support/requests.js"

const production = {
  APP_ENV: "production",
  APP_SYSTEM_ID: "billing-web",
  APP_ORIGIN: ORIGIN,
  AUTH_ENCRYPTION_KEY: keyRing("e1", 3),
  AUTH_CSRF_KEY: keyRing("c1", 5),
}

const REFUSED: AuthDiagnostic = {
  code: "client-address-missing",
  message:
    "A request reached test-cap with no client address, so it was refused with a 500: production and staging need one for the per-client limits. Give the adapter the socket address (its clientAddress option), or set requireClientAddress: false and limit requests at the gateway (ADR 0009 §8).",
}

const UNCOUNTED: AuthDiagnostic = {
  code: "client-address-missing",
  message:
    "A request reached test-cap with no client address, so the per-client limits did not count it. Give the adapter the socket address (its clientAddress option), or limit requests at the gateway (ADR 0009 §8).",
}

const OPTIONAL: AuthDiagnostic = {
  code: "client-address-optional",
  message:
    "requireClientAddress is false, so a request with no client address is served, uncounted by the per-client limits. Limit requests at the gateway, or give the adapter the socket address (ADR 0009 §8).",
}

const NO_SOURCE =
  "requireClientAddress: production and staging refuse a request with no client address, and this adapter has no clientAddress option. Pass one, use the preset of a platform every request comes through (vercel, fly or netlify), or set requireClientAddress: false and limit requests at the gateway (ADR 0009 §8)."

/** An `Auth` in `env`'s mode over a durable memory store, recording every diagnostic. */
function authIn(env: Record<string, string>, config: Partial<AuthConfig<string>> = {}) {
  const diagnostics: AuthDiagnostic[] = []
  const recording = recordingStore()
  const auth = createAuth({
    store: { ...recording.store, kind: "sql", durable: true },
    env,
    hibpFetch: hibpClear,
    sendEmail: discardEmail,
    onDiagnostic: (diagnostic) => diagnostics.push(diagnostic),
    ...config,
  })
  return { auth, diagnostics, counters: recording.counters }
}

/** The problems createAuth names for `config` in `env`, or [] when it starts. */
function problems(config: Partial<AuthConfig<string>>, env: Record<string, string> = ENV) {
  try {
    createAuth({
      store: { ...memoryStore(), kind: "sql", durable: true },
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

/** The problems building each Web-Request adapter with no `clientAddress` option names, by adapter. */
function adapterProblems(config: Partial<AuthConfig<string>>, env: Record<string, string>) {
  const { auth } = authIn(env, config)
  const builders = {
    fetchAuth: () => fetchAuth(auth),
    withAuth: () => withAuth(auth, () => new Response("app")),
    nextAuthHandler: () => nextAuthHandler(auth),
    tanstackStartAuth: () => tanstackStartAuth(auth),
  }
  return Object.fromEntries(
    Object.entries(builders).map(([name, build]) => {
      try {
        build()
        return [name, []]
      } catch (error) {
        if (error instanceof ConfigError) return [name, error.problems]
        throw error
      }
    }),
  )
}

const SESSION = { method: "GET", path: "/auth/session" } as const

describe("a request with no client address in production and staging", () => {
  it("is refused with the fixed 500 before it is counted or run, and the operator is told once", async () => {
    for (const mode of ["production", "staging"]) {
      const { auth, diagnostics, counters } = authIn({ ...production, APP_ENV: mode })
      const send = sendFrom(auth, null)
      for (let n = 0; n < 2; n += 1) {
        const reply = await send(SESSION)
        expect([reply.status, reply.json], mode).toEqual([500, { error: "internal" }])
      }
      expect(counters, mode).toEqual([])
      expect(diagnostics, mode).toEqual([REFUSED])
    }
  })

  it("is refused with the request limit turned off too", async () => {
    const { auth, diagnostics } = authIn(production, { rateLimit: false })
    expect((await sendFrom(auth, null)(SESSION)).status).toBe(500)
    expect(diagnostics.map((diagnostic) => diagnostic.code)).toEqual([
      "rate-limit-off",
      "client-address-missing",
    ])
  })

  it("is refused when a trusted proxy sends no header and its peer is unknown", async () => {
    const { auth } = authIn(production, { trustedProxies: ["10.0.0.1"] })
    expect((await sendFrom(auth, null)(SESSION)).status).toBe(500)
  })

  it("is served when the address comes from the socket or a platform's header", async () => {
    const { auth, diagnostics } = authIn(production)
    expect((await sendFrom(auth, CLIENT)(SESSION)).status).toBe(200)
    const vercel = authIn(production, { trustedProxies: platform("vercel") })
    const reply = await vercel.auth.handle({
      method: "GET",
      url: `${ORIGIN}/auth/session`,
      headers: new Headers([["x-real-ip", CLIENT]]),
      body: null,
    })
    expect(reply?.status).toBe(200)
    expect([...diagnostics, ...vercel.diagnostics]).toEqual([])
  })

  it("is served uncounted with requireClientAddress: false, which the operator is told of once", async () => {
    const { auth, diagnostics, counters } = authIn(production, { requireClientAddress: false })
    expect(diagnostics).toEqual([OPTIONAL])
    const send = sendFrom(auth, null)
    expect((await send(SESSION)).status).toBe(200)
    expect((await send(SESSION)).status).toBe(200)
    expect(counters).toEqual([])
    expect(diagnostics).toEqual([OPTIONAL, UNCOUNTED])
  })

  it("is refused with requireClientAddress: true, the default", async () => {
    const { auth } = authIn(production, { requireClientAddress: true })
    expect((await sendFrom(auth, null)(SESSION)).status).toBe(500)
  })
})

describe("a request with no client address in development and test", () => {
  it("is served uncounted, as before", async () => {
    for (const mode of ["development", "test"]) {
      const { auth, diagnostics } = authIn({ ...ENV, APP_ENV: mode })
      expect((await sendFrom(auth, null)(SESSION)).status, mode).toBe(200)
      expect(diagnostics, mode).toEqual([UNCOUNTED])
    }
  })

  it("tells the operator of requireClientAddress: false in every mode", () => {
    expect(authIn(ENV, { requireClientAddress: false }).diagnostics).toEqual([OPTIONAL])
  })
})

describe("requireClientAddress", () => {
  it("must be true or false", () => {
    for (const value of ["yes", 0, null]) {
      expect(problems({ requireClientAddress: value as never }), String(value)).toEqual([
        "requireClientAddress must be true or false.",
      ])
    }
    expect(problems({ requireClientAddress: true })).toEqual([])
    expect(problems({ requireClientAddress: false }, production)).toEqual([])
  })
})

describe("a Web-Request adapter with no clientAddress option", () => {
  const every = (problem: readonly string[]) => ({
    fetchAuth: problem,
    withAuth: problem,
    nextAuthHandler: problem,
    tanstackStartAuth: problem,
  })

  it("refuses to start in production and staging, naming the fix", () => {
    for (const mode of ["production", "staging"]) {
      expect(adapterProblems({}, { ...production, APP_ENV: mode }), mode).toEqual(
        every([NO_SOURCE]),
      )
    }
  })

  it("refuses to start behind the app's own proxies, whose header is read only from a known peer", () => {
    expect(adapterProblems({ trustedProxies: ["10.0.0.1"] }, production)).toEqual(
      every([NO_SOURCE]),
    )
    for (const preset of [
      platform("cloudflare", { peers: ["10.0.0.0/8"] }),
      platform("cloudfront", { peers: ["10.0.0.0/8"] }),
      platform("aws-alb", { peers: ["10.0.0.0/8"] }),
      platform("nginx", { peers: ["10.0.0.0/8"] }),
    ]) {
      expect(adapterProblems({ trustedProxies: preset }, production), preset.name).toEqual(
        every([NO_SOURCE]),
      )
    }
  })

  it("starts on a platform every request comes through, with requireClientAddress: false, or outside production", () => {
    for (const name of ["vercel", "fly", "netlify"] as const) {
      expect(adapterProblems({ trustedProxies: platform(name) }, production), name).toEqual(
        every([]),
      )
    }
    expect(adapterProblems({ requireClientAddress: false }, production)).toEqual(every([]))
    expect(adapterProblems({}, { ...ENV, APP_ENV: "development" })).toEqual(every([]))
    expect(adapterProblems({}, ENV)).toEqual(every([]))
  })

  it("starts in production once it has the option", () => {
    const { auth } = authIn(production)
    const clientAddress = () => CLIENT
    expect(() => fetchAuth(auth, { clientAddress })).not.toThrow()
    expect(() => withAuth(auth, () => new Response("app"), { clientAddress })).not.toThrow()
    expect(() => nextAuthHandler(auth, { clientAddress })).not.toThrow()
    expect(() => tanstackStartAuth(auth, { clientAddress })).not.toThrow()
  })
})
