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
}
