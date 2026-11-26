// The phase 4 claims audit (specs/claims-phase-4.md, metric 9) pairs each claim with its evidence. This test keeps
// that evidence real: every test file and test name the table cites exists, and so does every CI job and invariant.
import { existsSync, readFileSync } from "node:fs"
import path from "node:path"
import { describe, expect, it } from "vitest"

const root = path.resolve(import.meta.dirname, "../..")
const read = (file: string): string => readFileSync(path.join(root, file), "utf8")

const audit = read("specs/claims-phase-4.md")
const [table = "", fixes = ""] = audit.split("## Claims that need a fix")
const rows = table.split("\n").filter((line) => /^\| \d+ +\|/.test(line))
const statusOf = (row: string): string | undefined => row.split("|").at(-2)?.trim()

/** Each cited test as `path` "name", in the order the table gives them. */
const tests = [...table.matchAll(/`(test\/[\w./-]+\.test\.ts)` "([^"]+)"/g)].map((match) => ({
  file: match[1] ?? "",
  name: match[2] ?? "",
}))
const jobs = [...table.matchAll(/CI job `([\w-]+)`/g)].map((match) => match[1] ?? "")
const invariants = [...table.matchAll(/invariant `(INV-[A-Z-]+)`/g)].map((match) => match[1] ?? "")

/** A test name as its file writes it: in double quotes, single quotes or backticks. */
function namedIn(text: string, name: string): boolean {
  return ['"', "'", "`"].some((quote) => text.includes(`${quote}${name}${quote}`))
}

describe("the phase 4 claims audit", () => {
  it("has a row for each claim, numbered in order, with a status from the rules", () => {
    expect(rows.length).toBeGreaterThan(100)
    rows.forEach((row, index) => {
      expect(row.startsWith(`| ${index + 1} `), row).toBe(true)
      expect(["backed", "narrowed", "removed"], row).toContain(statusOf(row))
    })
  })

  it("states the counts the table and the list of claims to fix hold", () => {
    const count = (status: string): number => rows.filter((row) => statusOf(row) === status).length
    const open = fixes.split("\n").filter((line) => line.startsWith("- `")).length
    expect(open).toBeGreaterThan(0)
    const summary = audit.split("\n## ")[0]?.replace(/\s+/g, " ") ?? ""
    expect(summary).toContain(
      `Of ${rows.length} claims in the table, ${count("backed")} are backed as written, ` +
        `${count("narrowed")} were narrowed by phase 4 and ${count("removed")} were removed by phase 4. ` +
        `A further ${open} claims`,
    )
  })

  it("cites test evidence", () => {
    expect(tests.length).toBeGreaterThan(100)
  })

  it("names only test files that exist", () => {
    const missing = [...new Set(tests.map(({ file }) => file))].filter(
      (file) => !existsSync(path.join(root, file)),
    )
    expect(missing).toEqual([])
  })

  it("names only tests their files contain", () => {
    const missing = tests
      .filter(({ file }) => existsSync(path.join(root, file)))
      .filter(({ file, name }) => !namedIn(read(file), name))
      .map(({ file, name }) => `${file}: ${name}`)
    expect(missing).toEqual([])
  })

  it("names only CI jobs the contract workflow has", () => {
    const workflow = read(".github/workflows/contract.yml")
    const defined = new Set(
      [...workflow.matchAll(/^ {2}([a-z0-9-]+):$/gm)].map((match) => match[1]),
    )
    expect(jobs.length).toBeGreaterThan(0)
    expect(jobs.filter((job) => !defined.has(job))).toEqual([])
  })

  it("names only security invariants the registry has", () => {
    const registry = read("specs/security-invariants.md")
    expect(invariants.length).toBeGreaterThan(0)
    expect(invariants.filter((id) => !registry.includes(`\`${id}\``))).toEqual([])
  })

  it("catches a missing name, so the check is not vacuous", () => {
    expect(namedIn('it("a real name", () => {})', "a real name")).toBe(true)
    expect(namedIn('it("a real name", () => {})', "a renamed test")).toBe(false)
  })
})
