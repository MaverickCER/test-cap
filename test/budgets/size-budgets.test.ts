import { readFileSync } from "node:fs"
import path from "node:path"
import { gzipSync } from "node:zlib"
import { describe, expect, it } from "vitest"
import budgets, { closure, MEASURED, plusTenPercent } from "../../ci/size-budgets.mjs"

interface ExportTarget {
  readonly import?: { readonly default?: string }
}

const root = path.resolve(import.meta.dirname, "../..")
const manifest = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")) as {
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

const servers = budgets.filter((budget) => budget.entry !== undefined)

describe("size budgets (ADR 0018)", () => {
  it("are checked by the Size check through the size script", () => {
    expect(manifest.scripts["size"]).toBe("internal-package-contract tool size")
  })

  it("budget every exports entry, by its exact file, and nothing that is not an entry", () => {
    expect(servers.map((budget) => budget.entry).sort()).toEqual(entryFiles().sort())
  })

  it("measure each entry with every chunk it imports, not the entry file alone", () => {
    for (const budget of servers) {
      const files = closure(path.join(root, budget.entry as string))
      const expected = files.map((file) => readFileSync(file, "utf8")).join("\n")
      expect(readFileSync(path.join(root, budget.file), "utf8"), budget.label).toBe(expected)
    }
    // The core entry only re-exports: nearly all of its size is in the chunk it imports.
    const core = servers.find((budget) => budget.label === "core")
    const entryAlone = gzipSync(readFileSync(path.join(root, "dist/index.js"))).length
    const withChunks = gzipSync(readFileSync(path.join(root, core?.file as string))).length
    expect(withChunks).toBeGreaterThan(entryAlone * 10)
  })

  it("give each server entry its first measurement plus 10 percent", () => {
    expect(new Set(budgets.map((budget) => budget.label)).size).toBe(budgets.length)
    expect(Object.keys(MEASURED).sort()).toEqual(servers.map((budget) => budget.label).sort())
    for (const budget of servers) {
      const measured = MEASURED[budget.label] ?? 0
      expect(measured, budget.label).toBeGreaterThan(0)
      expect(budget.maxGzipBytes, budget.label).toBe(Math.ceil(measured * 1.1))
    }
    expect(plusTenPercent(1000)).toBe(1100)
    expect(plusTenPercent(1001)).toBe(1102)
  })

  it("give the default pages' assets ADR 0018's fixed 15 KiB, measured as auth.handle serves them", () => {
    const assets = budgets.find((budget) => budget.label === "default page assets")
    expect(assets?.maxGzipBytes).toBe(15 * 1024)
    const served = readFileSync(path.join(root, assets?.file as string), "utf8")
    expect(served).toContain('"use strict"')
    expect(served).toContain("--test-cap-font")
  })
})
