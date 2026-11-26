// One check function per value export of dist/index.js, keyed by the export's name. run.mjs runs every function here
// against dist/; test/cross-runtime/coverage.test.ts compares these keys with src/index.ts's value exports. A new export
// therefore needs a function that actually exercises it, not just a label. Its own module, so the coverage test can
// read the keys without running anything (run.mjs exits the process on a failure).

/** @type {Record<string, (dist: Record<string, any>, check: (condition: unknown, message: string) => void) => void | Promise<void>>} */
export const CHECKS = {
  TransportError(dist, check) {
    const transport = new dist.TransportError("body-too-large", "too big")
    check(
      transport instanceof Error && transport.name === "TransportError",
      "TransportError is an Error",
    )
    check(
      transport.code === "body-too-large" && transport.status === 413,
      "TransportError maps its code to 413",
    )
    check(
      new dist.TransportError("unsupported-media-type", "x").status === 415,
      "TransportError maps to 415",
    )
    check(new dist.TransportError("invalid-path", "x").status === 400, "TransportError maps to 400")
  },
  ConfigError(dist, check) {
    const config = new dist.ConfigError(["first problem", "second problem"])
    check(config instanceof Error && config.name === "ConfigError", "ConfigError is an Error")
    check(
      config.problems.length === 2 && config.message.includes("- second problem"),
      "ConfigError lists every problem",
    )
  },
  defineAuthPolicy(dist, check) {
    const policy = dist.defineAuthPolicy({
      version: "v1",
      requirements: { "billing.update": { level: "AAL3" } },
    })
    check(policy.version === "v1", "defineAuthPolicy keeps the version")
    check(policy.requirement("default").level === "AAL2", "defineAuthPolicy defaults to AAL2")
    check(
      policy.require(null, "billing.update", 0).outcome === "unauthenticated",
      "require refuses no session",
    )
    let refused
    try {
      dist.defineAuthPolicy({ version: "" })
    } catch (error) {
      refused = error
    }
    check(
      refused instanceof dist.ConfigError &&
        refused.problems[0] === "The policy version must be a non-empty string.",
      "defineAuthPolicy refuses an empty version",
    )
  },
  async createStoreLimiter(dist, check) {
    // A store with only what the limiter counts with, so the check needs no other entry of dist/.
    const counts = new Map()
    const store = {
      increment(tenant, counter, windowMs) {
        const key = `${tenant}/${counter}`
        const count = (counts.get(key) ?? 0) + 1
        counts.set(key, count)
        return Promise.resolve({ count, windowStart: 0, resetAt: windowMs })
      },
    }
    const clock = { now: () => 4_000 }
    const limiter = dist.createStoreLimiter({
      store,
      clock,
      points: 1,
      duration: 10,
      keyPrefix: "rate",
      blocks: false,
    })
    const first = await limiter.consume("sign-in|192.0.2.1")
    const second = await limiter.consume("sign-in|192.0.2.1").catch((refusal) => refusal)
    check(
      first.remainingPoints === 0 && second.consumedPoints === 2 && second.msBeforeNext === 6_000,
      "createStoreLimiter allows the rule's count, then refuses with the wait",
    )
    check(counts.has("default/rate:sign-in|192.0.2.1"), "createStoreLimiter counts in the store")
  },
  createAuth(dist, check) {
    let refused
    try {
      dist.createAuth({ store: { kind: "sql", durable: true }, env: {} })
    } catch (error) {
      refused = error
    }
    check(
      refused instanceof dist.ConfigError &&
        refused.problems.includes("AUTH_ENCRYPTION_KEY is missing."),
      "createAuth runs the readiness check and names a missing key",
    )
  },
  platform(dist, check) {
    const preset = dist.platform("cloudflare", { peers: ["173.245.48.0/20"] })
    check(
      preset.kind === "platform" && preset.name === "cloudflare" && preset.peers.length === 1,
      "platform builds a preset",
    )
    let refused
    try {
      dist.createAuth({
        store: { kind: "sql", durable: true },
        env: {},
        trustedProxies: dist.platform("cloudflare", { peers: [] }),
      })
    } catch (error) {
      refused = error
    }
    check(
      refused instanceof dist.ConfigError &&
        refused.problems.includes(
          'platform("cloudflare") needs peers: the addresses or CIDR ranges its requests arrive from.',
        ),
      "createAuth refuses a preset without the peers it needs",
    )
  },
}
