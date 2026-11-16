import { existsSync, readdirSync, readFileSync } from "node:fs"
import path from "node:path"
import { describe, expect, it } from "vitest"

/**
 * The design documents point at each other: architecture names the ADR that owns each public type, the threat
 * model covers every flow, the attack catalogue names the test that proves each entry, and the requirement mapping
 * names an ADR for every row. These tests keep those pointers true, so a renamed ADR or a dropped flow fails here
 * instead of leaving a dangling reference.
 */
const root = path.resolve(import.meta.dirname, "../..")
const specs = path.join(root, "specs")
const decisionsDir = path.join(specs, "decisions")

const read = (file: string): string => readFileSync(file, "utf8")

const decisionFiles = readdirSync(decisionsDir).filter((file) => /^\d{4}-.+\.md$/.test(file))
const decisionNumbers = new Set(decisionFiles.map((file) => file.slice(0, 4)))

/** The 22 flow ids architecture.md and threat-model.md share. */
const FLOW_IDS = Array.from({ length: 22 }, (_, index) => `F${String(index + 1).padStart(2, "0")}`)

/** Mentions of another repository's ADRs (`env-cap ADR 0014`, `data-cap's ADR 0070`) are not test-cap's. */
const FOREIGN_ADR =
  /(?:env-cap|data-cap|repo-contract|internal-package-contract|access-cap)(?:'s)?\s+ADRs?\s*$/

/** Every `ADR NNNN` mention in the text that refers to test-cap's own records, with its line. */
function ownAdrMentions(text: string): { line: number; adr: string }[] {
  const mentions: { line: number; adr: string }[] = []
  text.split("\n").forEach((line, index) => {
    for (const match of line.matchAll(
      /ADRs?\s+((?:\d{4}(?:,\s*|\s+and\s+|\s*(?:–|-|to)\s*)?)+)/g,
    )) {
      const before = line.slice(0, match.index + match[0].indexOf("ADR") + "ADR".length + 1)
      if (FOREIGN_ADR.test(before.trimEnd())) continue
      for (const adr of match[1]?.match(/\d{4}/g) ?? []) mentions.push({ line: index + 1, adr })
    }
  })
  return mentions
}

const designDocuments = [
  path.join(root, "GLOSSARY.md"),
  ...readdirSync(specs)
    .filter((file) => file.endsWith(".md"))
    .map((file) => path.join(specs, file)),
  ...decisionFiles.map((file) => path.join(decisionsDir, file)),
]

describe("decision records", () => {
  it("number 0001 to 0028 with no gap and no duplicate", () => {
    const expected = Array.from({ length: 28 }, (_, index) => String(index + 1).padStart(4, "0"))
    expect(decisionFiles.map((file) => file.slice(0, 4))).toEqual(expected)
  })

  it.each(decisionFiles)("%s is titled with its number and accepted with a date", (file) => {
    const text = read(path.join(decisionsDir, file))
    expect(text.split("\n")[0]).toMatch(new RegExp(`^# ${file.slice(0, 4)}: \\S`))
    expect(text).toMatch(/^## Status\n\nAccepted \(\d{4}-\d{2}-\d{2}\)/m)
    for (const section of ["## Context", "## Decision", "## Consequences"])
      expect(text).toContain(section)
  })

  it("answer every one of the handoff's 19 questions in the record with the same number", () => {
    for (let question = 1; question <= 19; question += 1) {
      const number = String(question).padStart(4, "0")
      const file = decisionFiles.find((name) => name.startsWith(number))
      expect(file, `ADR ${number}`).toBeDefined()
    }
  })
})

describe("cross-references", () => {
  it.each(designDocuments.map((file) => [path.relative(root, file), file]))(
    "every ADR %s mentions exists",
    (_name, file) => {
      const missing = ownAdrMentions(read(file)).filter(({ adr }) => !decisionNumbers.has(adr))
      expect(missing).toEqual([])
    },
  )
})

describe("architecture", () => {
  const architecture = read(path.join(specs, "architecture.md"))

  it("describes every flow", () => {
    for (const id of FLOW_IDS) expect(architecture).toMatch(new RegExp(`^- \\*\\*${id} `, "m"))
  })

  it("names an existing ADR for every public type", () => {
    const section = architecture.slice(
      architecture.indexOf("## Public types"),
      architecture.indexOf("## Core API"),
    )
    const rows = section.split("\n").filter((line) => /^\| `/.test(line))
    expect(rows.length).toBeGreaterThan(30)
    for (const row of rows) {
      const adr = row.split("|").at(-2)?.trim() ?? ""
      expect(decisionNumbers.has(adr), row).toBe(true)
    }
  })
})

describe("requirement mapping", () => {
  const STATUSES = new Set(["met by design", "partly met", "not applicable", "out of scope"])
  const text = read(path.join(specs, "requirements.md"))
  const rows = text
    .split("\n")
    .filter((line) => /^\| (?:\d+\.\d+\.\d+|§[\d.]+|Appendix|App\.)/.test(line))
    .map((line) => line.split("|").map((cell) => cell.trim()))

  it("maps every ASVS 5.0.0 requirement of V6, V7, V9, V10 and V16", () => {
    const counts = new Map<string, number>()
    for (const cells of rows) {
      const chapter = /^(\d+)\./.exec(cells[1] ?? "")?.[1]
      if (chapter !== undefined) counts.set(chapter, (counts.get(chapter) ?? 0) + 1)
    }
    expect(Object.fromEntries(counts)).toEqual({ "6": 47, "7": 19, "9": 7, "10": 36, "16": 17 })
  })

  it("gives every row a known status, existing ADRs, and a planned test or a reason for none", () => {
    expect(rows.length).toBeGreaterThan(200)
    for (const cells of rows) {
      const [, id = "", , , status = "", adrs = "", test = ""] = cells
      expect(STATUSES.has(status), `${id}: status "${status}"`).toBe(true)
      const numbers = adrs.match(/\d{4}/g) ?? []
      expect(numbers.length, `${id}: ADR`).toBeGreaterThan(0)
      for (const adr of numbers) expect(decisionNumbers.has(adr), `${id}: ADR ${adr}`).toBe(true)
      expect(/^`test\/.+\.test\.tsx?`|^none: \S/.test(test), `${id}: test "${test}"`).toBe(true)
    }
  })
})

describe("design documents exist", () => {
  it.each(["architecture.md", "threat-model.md", "attack-catalogue.md", "requirements.md"])(
    "specs/%s",
    (file) => {
      expect(existsSync(path.join(specs, file))).toBe(true)
    },
  )
})
