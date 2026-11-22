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
}
