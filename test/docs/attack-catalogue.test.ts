import { existsSync, readdirSync, readFileSync } from "node:fs"
import path from "node:path"
import { describe, expect, it } from "vitest"

/**
 * Enforces the rules at the top of specs/attack-catalogue.md: stable ids, a named test per entry, honest status,
 * agreement with the threat model, full coverage of the Better Auth advisories, and existing ADRs.
 */
const root = path.resolve(import.meta.dirname, "../..")
const specs = path.join(root, "specs")
const attacksDir = path.join(root, "test", "attacks")

const catalogue = readFileSync(path.join(specs, "attack-catalogue.md"), "utf8")
const threatModel = readFileSync(path.join(specs, "threat-model.md"), "utf8")
const decisionNumbers = new Set(
  readdirSync(path.join(specs, "decisions"))
    .filter((file) => /^\d{4}-/.test(file))
    .map((file) => file.slice(0, 4)),
)

interface Entry {
  id: string
  source: string
  stoppedBy: string
  test: string
  status: string
}

const entries: Entry[] = catalogue
  .split("\n")
  .filter((line) => /^\| `[^`]+` +\|/.test(line))
  .map((line) => {
    const cells = line.split("|").map((cell) => cell.trim())
    return {
      id: (cells[1] ?? "").replaceAll("`", ""),
      source: cells[3] ?? "",
      stoppedBy: cells[4] ?? "",
      test: (cells[5] ?? "").replaceAll("`", ""),
      status: cells[7] ?? "",
    }
  })

/** Ids cited in the threat model's Entry column (the last cell of each threat row). */
const citedIds = new Set(
  threatModel
    .split("\n")
    .filter((line) => /^\| [STRIDE]+ +\|/.test(line))
    .flatMap((line) =>
      [...(line.split("|").at(-2) ?? "").matchAll(/`([a-z0-9-]+)`/g)].map((m) => m[1] ?? ""),
    ),
)

const testFiles = existsSync(attacksDir)
  ? readdirSync(attacksDir, { recursive: true, encoding: "utf8" }).filter((file) =>
      file.endsWith(".test.ts"),
    )
  : []

describe("attack catalogue", () => {
  it("has entries", () => {
    expect(entries.length).toBeGreaterThan(100)
  })

  it("uses unique kebab-case ids", () => {
    const ids = entries.map((entry) => entry.id)
    for (const id of ids) expect(id).toMatch(/^[a-z0-9]+(?:-[a-z0-9]+)*$/)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it("names test/attacks/<id>.test.ts for every applicable entry, and no test for a not-applicable one", () => {
    for (const entry of entries) {
      if (entry.status === "not applicable") expect(entry.test, entry.id).toBe("none")
      else expect(entry.test, entry.id).toBe(`test/attacks/${entry.id}.test.ts`)
    }
  })

  it("says tested exactly when the test file exists", () => {
    for (const entry of entries) {
      expect(["planned", "tested", "not applicable"], entry.id).toContain(entry.status)
      if (entry.status === "not applicable") continue
      const exists = existsSync(path.join(root, entry.test))
      expect(entry.status, entry.id).toBe(exists ? "tested" : "planned")
    }
  })

  it("has a row for every test file under test/attacks/", () => {
    const named = new Set(entries.map((entry) => entry.test))
    for (const file of testFiles) expect(named.has(`test/attacks/${file}`), file).toBe(true)
  })

  it("agrees with the threat model in both directions", () => {
    const ids = new Set(entries.map((entry) => entry.id))
    for (const id of citedIds) expect(ids.has(id), `threat model cites ${id}`).toBe(true)
    for (const entry of entries) {
      if (entry.status !== "not applicable")
        expect(citedIds.has(entry.id), `${entry.id} uncited`).toBe(true)
    }
  })

  it("covers all 49 Better Auth repository advisories", () => {
    const ghsa = new Set(
      entries.flatMap((entry) => entry.source.match(/GHSA(?:-[0-9a-z]{4}){3}/g) ?? []),
    )
    expect(ghsa.size).toBeGreaterThanOrEqual(49)
    // A source cell lists several sources separated by ";"; only the segments that start with "BA" are Better Auth's.
    const betterAuth = new Set(
      entries.flatMap((entry) =>
        entry.source
          .split(";")
          .map((segment) => segment.trim())
          .filter((segment) => segment.startsWith("BA "))
          .flatMap((segment) => segment.match(/GHSA(?:-[0-9a-z]{4}){3}/g) ?? []),
      ),
    )
    expect(betterAuth.size).toBe(49)
  })

  it("is the only source of attack-test paths: every test/attacks/ path in specs/ and GLOSSARY.md names an entry", () => {
    const ids = new Set(entries.map((entry) => entry.id))
    const documents = [
      path.join(root, "GLOSSARY.md"),
      ...readdirSync(specs, { recursive: true, encoding: "utf8" })
        .filter((file) => file.endsWith(".md"))
        .map((file) => path.join(specs, file)),
    ]
    const strays: string[] = []
    for (const file of documents) {
      readFileSync(file, "utf8")
        .split("\n")
        .forEach((line, index) => {
          for (const [mention] of line.matchAll(/test\/attacks\/[^\s`'"()[\]|,;]*/g)) {
            // A bare directory mention and the catalogue's own `<id>` placeholder name no test.
            if (mention === "test/attacks/" || mention === "test/attacks/<id>.test.ts") continue
            const id = /^test\/attacks\/([a-z0-9-]+)\.test\.ts$/.exec(mention)?.[1]
            if (id === undefined || !ids.has(id)) {
              strays.push(`${path.relative(root, file)}:${index + 1} ${mention}`)
            }
          }
        })
    }
    expect(strays).toEqual([])
  })

  it("names only ADRs that exist", () => {
    for (const entry of entries) {
      // ADR numbers are 00NN; a year such as 2026 in a reason is not one.
      for (const adr of entry.stoppedBy.match(/\b00\d{2}\b/g) ?? []) {
        expect(decisionNumbers.has(adr), `${entry.id}: ADR ${adr}`).toBe(true)
      }
    }
  })

  it("gives every entry an Invariant cell naming security invariants, or none (ADR 0029)", () => {
    const cells = catalogue
      .split("\n")
      .filter((line) => /^\| `[^`]+` +\|/.test(line))
      .map((line) => line.split("|").map((cell) => cell.trim())[8] ?? "")
    expect(cells.length).toBe(entries.length)
    for (const cell of cells) expect(cell).toMatch(/^(?:none|`INV-[A-Z-]+`(?:, `INV-[A-Z-]+`)*)$/)
  })
})

describe("threat model", () => {
  it("has a section for every flow F01 to F22, in order", () => {
    const headings = [...threatModel.matchAll(/^## (F\d{2}): /gm)].map((m) => m[1])
    expect(headings).toEqual(
      Array.from({ length: 22 }, (_, i) => `F${String(i + 1).padStart(2, "0")}`),
    )
  })
})
