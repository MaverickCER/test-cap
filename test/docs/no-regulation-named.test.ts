// ADR 0017 and ADR 0019: test-cap makes no compliance claim, so no doc, comment or page names a regulation. ADR 0020
// keeps the sentence it withdrew, as the record of what was accepted, and the phase 4 claims audit quotes that note.
import { readdirSync, readFileSync, statSync } from "node:fs"
import path from "node:path"
import { describe, expect, it } from "vitest"

const root = path.resolve(import.meta.dirname, "../..")

/** The only files allowed to name one: the withdrawn record, its audit quote, and this test's own pattern. */
const RECORDS = new Set([
  "specs/decisions/0020-audit-integrity-model.md",
  "specs/claims-phase-4.md",
  "test/docs/no-regulation-named.test.ts",
])

const REGULATION = /\b(?:HIPAA|PCI[ -]DSS|SOX|SOC ?2|GDPR|CCPA|ISO ?27001|FedRAMP)\b/

/** Every text file the package's readers or its agents see: docs, specs, source, examples, tests and the site. */
function files(dir: string): string[] {
  return readdirSync(path.join(root, dir), { recursive: true, encoding: "utf8" })
    .filter((file) => /\.(?:md|ts|tsx|mts|js|mjs|json|html)$/.test(file))
    .filter((file) => !file.split(path.sep).includes("node_modules"))
    .map((file) => `${dir}/${file.split(path.sep).join("/")}`)
    .filter((file) => statSync(path.join(root, file)).isFile())
}

const checked = [
  ...readdirSync(root).filter((file) => file.endsWith(".md")),
  ...["src", "specs", "docs", "examples", "test", "scripts", ".changeset"].flatMap(files),
]

describe("no regulation is named", () => {
  it("in any doc, page, example, source file or test outside ADR 0020's withdrawn sentence", () => {
    expect(checked.length).toBeGreaterThan(100)
    const named = checked
      .filter((file) => !RECORDS.has(file))
      .filter((file) => REGULATION.test(readFileSync(path.join(root, file), "utf8")))
    expect(named).toEqual([])
  })
})
