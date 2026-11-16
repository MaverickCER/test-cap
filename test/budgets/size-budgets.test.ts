import { readFileSync } from "node:fs"
import { describe, expect, it } from "vitest"
import budgets from "../../ci/size-budgets.mjs"

interface ExportTarget {
  readonly import?: { readonly default?: string }
}

const manifest = JSON.parse(
  readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
) as {
  readonly exports: Readonly<Record<string, ExportTarget | string>>
  readonly scripts: Readonly<Record<string, string>>
}

/** The ESM file of every code entry in `exports`, as a path from the package root. */
function entryFiles(): string[] {
  return Object.entries(manifest.exports)
    .filter(([key]) => key !== "./package.json")
    .map(([, target]) => (typeof target === "string" ? target : (target.import?.default ?? "")))
    .map((file) => file.replace(/^\.\//, ""))
}

describe("size budgets (ADR 0018)", () => {
  it("are checked by the Size check through the size script", () => {
    expect(manifest.scripts["size"]).toBe("internal-package-contract tool size")
  })

  it("budget every exports entry, by its exact file, and nothing that is not an entry", () => {
    expect(budgets.map((budget) => budget.file).sort()).toEqual(entryFiles().sort())
  })

  it("give each entry a unique label and a positive whole-byte limit no larger than 6 KB", () => {
    expect(new Set(budgets.map((budget) => budget.label)).size).toBe(budgets.length)
    for (const budget of budgets) {
      expect(Number.isSafeInteger(budget.maxGzipBytes), budget.label).toBe(true)
      expect(budget.maxGzipBytes, budget.label).toBeGreaterThan(0)
      expect(budget.maxGzipBytes, budget.label).toBeLessThanOrEqual(6 * 1024)
    }
  })
})
