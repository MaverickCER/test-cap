import { defineConfig } from "vitest/config"
import { BaseSequencer, type TestSpecification } from "vitest/node"

/** True for a file under test/sentinel/, on any platform's path separator. */
function isSentinel(spec: TestSpecification): boolean {
  return spec.moduleId.replaceAll("\\", "/").includes("/test/sentinel/")
}

/**
 * Vitest's own order, with test/sentinel/ first. The sentinels check hot paths directly, so a mutant there fails in
 * the first file, under Vitest and under Stryker's Vitest runner (which keeps this config), instead of after the
 * whole suite and past the mutant's time budget.
 */
class SentinelsFirst extends BaseSequencer {
  override async sort(files: TestSpecification[]): Promise<TestSpecification[]> {
    const sorted = await super.sort(files)
    return [...sorted.filter(isSentinel), ...sorted.filter((spec) => !isSentinel(spec))]
  }
}

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    watch: false,
    testTimeout: 20_000,
    sequence: { sequencer: SentinelsFirst },
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      // "json" is load-bearing: it writes coverage/coverage-final.json, the raw per-file data the
      // Crap check hands to crap4ts.
      reporter: ["text", "html", "lcov", "json", "json-summary"],
      // Starting floor; raise as coverage improves, never lower it.
      thresholds: { branches: 90, functions: 100, lines: 95, statements: 95 },
    },
  },
})
