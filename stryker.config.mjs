// @ts-check
/**
 * Stryker config for test-cap. Extends the shared baseline; the mutation-score threshold is owned
 * by the `Mutation` check (MUTATION_THRESHOLD in internal-package-contract), never set here.
 * @type {import('@stryker-mutator/api/core').PartialStrykerOptions}
 */
export default {
  packageManager: "npm",
  testRunner: "vitest",
  reporters: ["json", "clear-text", "progress"],
  coverageAnalysis: "perTest",
  ignoreStatic: true,
  disableTypeChecks: "{src,test}/**/*.{ts,tsx}",
  mutate: ["src/**/*.ts", "!src/**/*.d.ts"],
}
