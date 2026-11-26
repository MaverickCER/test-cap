// The deployment settings behind the topology scenarios (ADR 0009 §5, ADR 0024 §6): presets and prefixes that are
// wrong refuse to start, each diagnostic reaches the operator once, and the Next.js proxy redirects under the prefix.
import { describe, expect, it } from "vitest"
import { nextProxy } from "../../src/adapters/next/index.js"
import { createAuth, type AuthConfig } from "../../src/core/auth.js"
import { ConfigError } from "../../src/core/errors.js"
import { platform, type PlatformTrust } from "../../src/core/proxy-trust.js"
import { memoryStore } from "../../src/store/memory.js"
import {
  Browser,
  ENV,
  hibpClear,
  inProcess,
  ORIGIN,
  outboxSender,
  testAuth,
} from "../support/auth.js"

const base = { store: memoryStore(), env: ENV, hibpFetch: hibpClear, sendEmail: outboxSender([]) }

function problems(config: Partial<AuthConfig<string>>): readonly string[] {
  try {
    createAuth({ ...base, ...config })
    return []
  } catch (error) {
    if (error instanceof ConfigError) return error.problems
    throw error
  }
}

describe("platform presets", () => {
  it("starts with each preset given what it needs", () => {
    for (const preset of [
      platform("vercel"),
      platform("fly"),
      platform("netlify"),
      platform("aws-alb", { peers: ["10.0.0.0/16"] }),
      platform("cloudfront", { peers: ["13.32.0.0/15", "2600:9000::/28"] }),
      platform("cloudflare", { peers: ["173.245.48.0/20"] }),
      platform("nginx", { peers: ["10.0.0.5"] }),
      platform("nginx", { peers: ["10.0.0.5"], header: "x-forwarded-for" }),
      platform("nginx", { peers: ["10.0.0.5"], header: "x-real-ip" }),
    ]) {
      expect(problems({ trustedProxies: preset }), preset.name).toEqual([])
    }
  })

  it("names each preset given the wrong thing", () => {
    expect(problems({ trustedProxies: platform("cloudflare", { peers: [] }) })).toEqual([
      'platform("cloudflare") needs peers: the addresses or CIDR ranges its requests arrive from.',
    ])
    expect(problems({ trustedProxies: platform("aws-alb", { peers: ["vpc"] }) })).toEqual([
      'platform("aws-alb") peers: "vpc" is not an IP address or CIDR range.',
    ])
    const vercelWithPeers = { ...platform("vercel"), peers: ["10.0.0.1"] }
    expect(problems({ trustedProxies: vercelWithPeers })).toEqual([
      'platform("vercel") takes no peers: every request comes through the platform.',
    ])
    const cloudflareHeader = {
      ...platform("cloudflare", { peers: ["10.0.0.0/8"] }),
      header: "x-real-ip" as const,
    }
    expect(problems({ trustedProxies: cloudflareHeader })).toEqual([
      'platform("cloudflare") takes no header option.',
    ])
    const nginxHeader = {
      ...platform("nginx", { peers: ["10.0.0.1"] }),
      header: "true-client-ip",
    } as unknown as PlatformTrust
    expect(problems({ trustedProxies: nginxHeader })).toEqual([
      'platform("nginx") takes no header option but x-real-ip or x-forwarded-for.',
    ])
    const unknown = { kind: "platform", name: "heroku", peers: [] } as unknown as PlatformTrust
    expect(problems({ trustedProxies: unknown })).toEqual([
      'platform "heroku" is not a preset test-cap has.',
    ])
    expect(problems({ trustedProxies: platform("vercel"), forwardedHeader: "forwarded" })).toEqual([
      "forwardedHeader applies to the app's own proxies; a platform preset names its own header.",
    ])
  })
})

describe("publicBasePath", () => {
  it.each(["", "/accounts", "/a/b-c/d_e~f.g"])("accepts %j", (publicBasePath) => {
    expect(problems({ publicBasePath })).toEqual([])
  })

  it.each(["accounts", "/accounts/", "/", "/a//b", "/a/../b", "/a/./b", "/..", "/a b", "/a?b"])(
    "refuses %j",
    (publicBasePath) => {
      expect(problems({ publicBasePath })).toEqual([
        `publicBasePath ${JSON.stringify(publicBasePath)} must be empty or a path such as /accounts, with no trailing slash.`,
      ])
    },
  )
})

describe("operator diagnostics", () => {
  it("are handed over once per code, and a sink that throws changes no reply", async () => {
    let calls = 0
    const setup = testAuth({
      onDiagnostic: () => {
        calls += 1
        throw new Error("sink down")
      },
    })
    for (let i = 0; i < 3; i += 1) {
      const reply = await new Browser(inProcess(setup.auth)).send({
        method: "GET",
        path: "/auth/session",
        headers: [["X-Forwarded-For", "198.51.100.7"]],
      })
      expect(reply.status).toBe(200)
    }
    expect(calls).toBe(1)
  })

  it("name the header and the peer", async () => {
    // An untrusted peer's header, then a header a trusted proxy did not set: the one message fits both.
    const cases = [
      { trustedProxies: [], header: "CF-Connecting-IP" },
      { trustedProxies: ["192.0.2.4"], header: "X-Real-IP" },
    ]
    for (const { trustedProxies, header } of cases) {
      const seen: string[] = []
      const setup = testAuth({
        trustedProxies,
        onDiagnostic: (diagnostic) => seen.push(diagnostic.message),
      })
      await new Browser(inProcess(setup.auth)).send({
        method: "GET",
        path: "/auth/session",
        headers: [[header, "198.51.100.7"]],
        clientAddress: "192.0.2.4",
      })
      expect(seen, header).toEqual([
        `A request from 192.0.2.4 carried ${header.toLowerCase()}, which test-cap did not read: it reads only the declared header, from a trusted proxy. Behind an undeclared proxy, every client shares its address in the throttle: declare it in trustedProxies, or use the platform preset (ADR 0009 §5).`,
      ])
    }
  })

  it("follow the proxy list createAuth read, so a later change to the list waits for a restart", async () => {
    for (const [first, later, ignored] of [
      [[], ["192.0.2.4"], true],
      [["192.0.2.4"], [], false],
    ] as const) {
      const trustedProxies: string[] = [...first]
      const seen: string[] = []
      const setup = testAuth({
        trustedProxies,
        onDiagnostic: (diagnostic) => seen.push(diagnostic.code),
      })
      trustedProxies.splice(0, trustedProxies.length, ...later)
      await new Browser(inProcess(setup.auth)).send({
        method: "GET",
        path: "/auth/session",
        headers: [["X-Forwarded-For", "198.51.100.7"]],
        clientAddress: "192.0.2.4",
      })
      expect(seen, `${first.length} proxies at start`).toEqual(
        ignored ? ["forwarded-header-ignored"] : [],
      )
    }
  })

  it("name a forwarding header on an adapter that knows no peer, behind the app's own proxies", async () => {
    const seen: string[] = []
    const messages: string[] = []
    const setup = testAuth({
      trustedProxies: ["10.0.0.1"],
      onDiagnostic: (diagnostic) => {
        seen.push(diagnostic.code)
        messages.push(diagnostic.message)
      },
    })
    const reply = await setup.auth.handle({
      method: "GET",
      url: "/auth/session",
      headers: new Headers([["X-Forwarded-For", "198.51.100.7"]]),
      body: null,
    })
    expect(reply?.status).toBe(200)
    // With no peer, the request limits count nothing for the request, and the operator hears of that too.
    expect(seen).toEqual(["forwarded-header-ignored", "client-address-missing"])
    expect(messages[0]).toMatch(/^A request with no socket address carried x-forwarded-for, /)
  })

  it("name a preset's own header when a peer outside its ranges sent it, before X-Forwarded-For", async () => {
    const seen: string[] = []
    const setup = testAuth({
      trustedProxies: platform("cloudflare", { peers: ["173.245.48.0/20"] }),
      onDiagnostic: (diagnostic) => seen.push(diagnostic.message),
    })
    await new Browser(inProcess(setup.auth)).send({
      method: "GET",
      path: "/auth/session",
      headers: [
        ["X-Forwarded-For", "198.51.100.7"],
        ["CF-Connecting-IP", "198.51.100.7"],
      ],
      clientAddress: "192.0.2.4",
    })
    expect(seen).toHaveLength(1)
    expect(seen[0]).toMatch(/^A request from 192\.0\.2\.4 carried cf-connecting-ip, /)
  })

  it("stay quiet when a platform's own header was read, though X-Forwarded-For came with it", async () => {
    for (const [preset, header] of [
      [platform("vercel"), "x-real-ip"],
      [platform("fly"), "fly-client-ip"],
      [platform("netlify"), "x-nf-client-connection-ip"],
    ] as const) {
      const seen: string[] = []
      const setup = testAuth({
        trustedProxies: preset,
        onDiagnostic: (diagnostic) => seen.push(diagnostic.code),
      })
      await new Browser(inProcess(setup.auth)).send({
        method: "GET",
        path: "/auth/session",
        headers: [
          [header, "198.51.100.7"],
          ["X-Forwarded-For", "198.51.100.7"],
        ],
        clientAddress: "192.0.2.4",
      })
      expect(seen, header).toEqual([])
    }
  })

  it("say what to look for when the browser's origin headers are missing", async () => {
    const seen: string[] = []
    const setup = testAuth({ onDiagnostic: (diagnostic) => seen.push(diagnostic.message) })
    await new Browser(inProcess(setup.auth)).send({
      method: "POST",
      path: "/auth/sign-out",
      headers: [],
    })
    expect(seen).toEqual([
      "A state-changing request carried neither an Origin header naming a site nor Sec-Fetch-Site, so the CSRF check refused it. Browsers send both; a proxy or CDN in front of the app may be removing them. See specs/dependency-failures.md.",
    ])
  })

  it("stay quiet for the header a trusted proxy set", async () => {
    const seen: string[] = []
    const setup = testAuth({
      trustedProxies: ["192.0.2.4"],
      onDiagnostic: (diagnostic) => seen.push(diagnostic.code),
    })
    await new Browser(inProcess(setup.auth)).send({
      method: "GET",
      path: "/auth/session",
      headers: [["X-Forwarded-For", "198.51.100.7"]],
      clientAddress: "192.0.2.4",
    })
    expect(seen).toEqual([])
  })
})

describe("nextProxy behind a prefix-stripping gateway", () => {
  it("sends the visitor to the prefixed sign-in page, with a prefixed returnTo", () => {
    const { auth } = testAuth({ publicBasePath: "/accounts" })
    const reply = nextProxy(auth, { public: ["/"] })(new Request(`${ORIGIN}/billing?tab=2`))
    expect(reply?.headers.get("location")).toBe(
      `${ORIGIN}/accounts/auth/sign-in?returnTo=${encodeURIComponent("/accounts/billing?tab=2")}`,
    )
  })
})
