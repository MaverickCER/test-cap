// Topology simulation (ADR 0009 §5): the client a failed sign-in is counted under, for each way an app is deployed,
// through every adapter. The throttle's client key is read off the store, so the test sees exactly what the throttle
// counted. Presets are simulated here only; none has been verified on the real platform.
import { afterEach, describe, expect, it, vi } from "vitest"
import type { AuthConfig, AuthDiagnostic } from "../../src/core/auth.js"
import { platform } from "../../src/core/proxy-trust.js"
import { memoryStore } from "../../src/store/memory.js"
import { Browser, hookedStore, testAuth } from "../support/auth.js"
import { DRIVERS, PEER } from "./drivers.js"
import { plainKeyOf } from "../support/limit-keys.js"

vi.mock("../../src/security/limit-store.js", async (importOriginal) =>
  (await import("../support/limit-keys.js")).recordingKeyNames(await importOriginal()),
)

interface Scenario {
  readonly name: string
  readonly config: Partial<AuthConfig<string>>
  readonly headers: readonly (readonly [string, string])[]
  /** The throttle's client key: the client's IPv4 address, or its IPv6 /64. */
  readonly key: string
  /** Whether the operator is told a forwarding header went unread. */
  readonly diagnosed?: boolean
}

const VISITOR = "198.51.100.7"
const SPOOF = "6.6.6.6"

const SCENARIOS: readonly Scenario[] = [
  { name: "direct: the socket is the client", config: {}, headers: [], key: PEER },
  {
    name: "direct, the client sends its own X-Forwarded-For",
    config: {},
    headers: [["X-Forwarded-For", SPOOF]],
    key: PEER,
    diagnosed: true,
  },
  {
    name: "one trusted load balancer",
    config: { trustedProxies: [PEER] },
    headers: [["X-Forwarded-For", VISITOR]],
    key: VISITOR,
  },
  {
    name: "a client spoofing X-Forwarded-For behind the load balancer",
    config: { trustedProxies: [PEER] },
    headers: [["X-Forwarded-For", `${SPOOF}, ${VISITOR}`]],
    key: VISITOR,
  },
  {
    name: "a CDN in front of the load balancer, both trusted by range",
    config: { trustedProxies: ["127.0.0.0/8", "203.0.113.0/24"] },
    headers: [["X-Forwarded-For", `${SPOOF}, ${VISITOR}, 203.0.113.40`]],
    key: VISITOR,
  },
  {
    name: "an untrusted peer's header is ignored",
    config: { trustedProxies: ["10.0.0.1"] },
    headers: [["X-Forwarded-For", VISITOR]],
    key: PEER,
    diagnosed: true,
  },
  {
    name: "duplicated X-Forwarded-For lines, merged in order",
    config: { trustedProxies: [PEER] },
    headers: [
      ["X-Forwarded-For", SPOOF],
      ["X-Forwarded-For", VISITOR],
    ],
    key: VISITOR,
  },
  {
    name: "HTTP/2-style lower-case header names",
    config: { trustedProxies: [PEER] },
    headers: [["x-forwarded-for", `${SPOOF}, ${VISITOR}`]],
    key: VISITOR,
  },
  {
    name: "RFC 7239 Forwarded with an IPv6 client, counted as its /64",
    config: { trustedProxies: [PEER], forwardedHeader: "forwarded" },
    headers: [
      ["X-Forwarded-For", SPOOF],
      ["Forwarded", 'for="[2001:db8:aa:bb::7]:443"'],
    ],
    key: "2001:db8:aa:bb::/64",
  },
  {
    name: "RFC 7239 Forwarded with a malformed element the client prepended",
    config: { trustedProxies: [PEER], forwardedHeader: "forwarded" },
    headers: [["Forwarded", `for="${SPOOF}, for=${VISITOR}`]],
    key: VISITOR,
  },
  {
    name: "Vercel: x-real-ip from the platform, X-Forwarded-For ignored",
    config: { trustedProxies: platform("vercel") },
    headers: [
      ["X-Forwarded-For", SPOOF],
      ["x-real-ip", VISITOR],
    ],
    key: VISITOR,
  },
  {
    name: "Cloudflare: CF-Connecting-IP from a Cloudflare range",
    config: { trustedProxies: platform("cloudflare", { peers: ["127.0.0.0/8"] }) },
    headers: [["CF-Connecting-IP", VISITOR]],
    key: VISITOR,
  },
  {
    name: "Cloudflare: CF-Connecting-IP from a peer outside its ranges is forged",
    config: { trustedProxies: platform("cloudflare", { peers: ["173.245.48.0/20"] }) },
    headers: [["CF-Connecting-IP", SPOOF]],
    key: PEER,
    diagnosed: true,
  },
  {
    name: "CloudFront: CloudFront-Viewer-Address, port removed",
    config: { trustedProxies: platform("cloudfront", { peers: ["127.0.0.0/8"] }) },
    headers: [["CloudFront-Viewer-Address", `${VISITOR}:46532`]],
    key: VISITOR,
  },
  {
    name: "AWS ALB: the hop it appended, with its client port",
    config: { trustedProxies: platform("aws-alb", { peers: ["127.0.0.0/8"] }) },
    headers: [["X-Forwarded-For", `${SPOOF}, ${VISITOR}:41022`]],
    key: VISITOR,
  },
  {
    name: "Fly.io: Fly-Client-IP",
    config: { trustedProxies: platform("fly") },
    headers: [["Fly-Client-IP", VISITOR]],
    key: VISITOR,
  },
  {
    name: "Netlify: x-nf-client-connection-ip",
    config: { trustedProxies: platform("netlify") },
    headers: [["x-nf-client-connection-ip", VISITOR]],
    key: VISITOR,
  },
  {
    name: "nginx: X-Real-IP from the app's nginx",
    config: { trustedProxies: platform("nginx", { peers: [PEER] }) },
    headers: [
      ["X-Real-IP", VISITOR],
      ["X-Forwarded-For", SPOOF],
    ],
    key: VISITOR,
  },
  {
    name: "nginx set to X-Forwarded-For",
    config: { trustedProxies: platform("nginx", { peers: [PEER], header: "x-forwarded-for" }) },
    headers: [["X-Forwarded-For", `${SPOOF}, ${VISITOR}`]],
    key: VISITOR,
  },
]

const closers: (() => Promise<void>)[] = []
afterEach(async () => {
  await Promise.all(closers.splice(0).map((close) => close()))
})

/** A sign-in that fails, sent through `driver`; resolves to the client keys the throttle counted and the diagnostics. */
async function failedSignIn(
  driver: (typeof DRIVERS)[number],
  scenario: Scenario,
  peer: string | null = PEER,
) {
  const counted: string[] = []
  const diagnostics: AuthDiagnostic[] = []
  const store = hookedStore(memoryStore(), (operation, args) => {
    const key = plainKeyOf(String(args[1]))
    if (operation === "increment" && key.startsWith("throttle:client:")) {
      counted.push(key.slice("throttle:client:".length))
    }
    return Promise.resolve()
  })
  const setup = testAuth({
    store,
    onDiagnostic: (diagnostic) => diagnostics.push(diagnostic),
    ...scenario.config,
  })
  const { transport, close } = await driver.open(setup.auth, peer ?? undefined)
  closers.push(close)
  const browser = new Browser(transport)
  await browser.start()
  const reply = await browser.post(
    "/auth/sign-in",
    { identifier: "nobody@example.com", password: "wrong password entirely" },
    { headers: scenario.headers },
  )
  return { reply, counted, diagnostics }
}

describe.each(DRIVERS)("topology through $name", (driver) => {
  // A loop, not `it.each`: Vitest shortens a long `$name` title, and Stryker then cannot select the test by name.
  for (const scenario of SCENARIOS)
    it(scenario.name, async () => {
      const { reply, counted, diagnostics } = await failedSignIn(driver, scenario)
      expect(reply.status).toBe(401)
      expect(counted).toEqual([scenario.key])
      expect(diagnostics.map((each) => each.code)).toEqual(
        scenario.diagnosed === true ? ["forwarded-header-ignored"] : [],
      )
    })
})

describe("platforms every request comes through, on adapters with no socket", () => {
  it.each(DRIVERS.filter((driver) => driver.name !== "express"))(
    "$name reads the Vercel header with no peer at all",
    async (driver) => {
      const { counted } = await failedSignIn(
        driver,
        {
          name: "vercel",
          config: { trustedProxies: platform("vercel") },
          headers: [["x-real-ip", VISITOR]],
          key: VISITOR,
        },
        null,
      )
      expect(counted).toEqual([VISITOR])
    },
  )

  it.each(DRIVERS.filter((driver) => driver.name !== "express"))(
    "$name counts no client key without a peer or a platform header",
    async (driver) => {
      const { counted } = await failedSignIn(
        driver,
        { name: "bare", config: {}, headers: [["X-Forwarded-For", VISITOR]], key: "" },
        null,
      )
      expect(counted).toEqual([])
    },
  )
})
