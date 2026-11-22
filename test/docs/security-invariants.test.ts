import { existsSync, readdirSync, readFileSync } from "node:fs"
import path from "node:path"
import { pathToFileURL } from "node:url"
import { describe, expect, it } from "vitest"
import { FLOWS } from "../support/failure-flows.js"

/**
 * Enforces the rules at the top of specs/security-invariants.md and specs/dependency-failures.md (ADR 0029): the chain
 * attack → threat → invariant → enforcement point → test → assertion → evidence holds for every invariant, in both
 * directions, and every dependency has a complete failure policy whose tests exist.
 */
const root = path.resolve(import.meta.dirname, "../..")
const specs = path.join(root, "specs")
const read = (file: string): string => readFileSync(path.join(root, file), "utf8")

const registry = read("specs/security-invariants.md")
const catalogue = read("specs/attack-catalogue.md")
const threatModel = read("specs/threat-model.md")
const failures = read("specs/dependency-failures.md")

const STATUS = /^(tested|partial \(phase (\d)\)|planned \(phase (\d)\))$/
const INVARIANT_ID = /^INV-[A-Z]+(?:-[A-Z]+)*$/

interface TestRef {
  readonly file: string
  readonly name: string
}

interface Invariant {
  readonly id: string
  readonly status: string
  readonly phase: number | null
  readonly enforcement: readonly { readonly file: string; readonly name: string }[]
  readonly attacks: readonly string[]
  readonly flows: readonly string[]
  readonly positive: readonly TestRef[]
  readonly negative: readonly TestRef[]
  readonly mutation: readonly string[]
  readonly limitations: string
}

/** The text of the `- **Label:**` field of a section, up to the next field. */
function field(body: string, label: string): string {
  const start = body.indexOf(`- **${label}:**`)
  if (start === -1) return ""
  const rest = body.slice(start + label.length + 7)
  const end = rest.search(/^- \*\*/m)
  return (end === -1 ? rest : rest.slice(0, end)).trim()
}

const ticked = (text: string): string[] => [...text.matchAll(/`([^`]+)`/g)].map((m) => m[1] ?? "")

/** Test references written as `` `test/<file>.test.ts`: "<name>" ``, one per list item. */
function testRefs(text: string): TestRef[] {
  return [...text.matchAll(/^ *- `(test\/[^`]+)`: "(.+)"$/gm)].map((m) => ({
    file: m[1] ?? "",
    name: m[2] ?? "",
  }))
}

/** Each `src/<file>.ts` and the exports named after it, outside the parenthesised notes on inner steps. */
function enforcementPoints(text: string): { file: string; name: string }[] {
  const points: { file: string; name: string }[] = []
  let file = ""
  for (const token of ticked(text.replace(/\([^)]*\)/g, ""))) {
    if (/^src\/.+\.ts$/.test(token)) file = token
    else if (/^[A-Za-z_$][\w$]*$/.test(token) && file !== "") points.push({ file, name: token })
  }
  return points
}

const sections = registry.split(/^### /m).slice(1)
const invariants: Invariant[] = sections.map((section) => {
  const id = section.slice(0, section.indexOf(":"))
  const status = field(section, "Status")
  const match = STATUS.exec(status)
  const phase = match?.[2] ?? match?.[3]
  return {
    id,
    status,
    phase: phase === undefined ? null : Number(phase),
    enforcement: enforcementPoints(field(section, "Enforcement")),
    attacks: ticked(field(section, "Attacks")),
    flows: field(section, "Flows")
      .split(/,\s*/)
      .filter((flow) => flow !== ""),
    positive: testRefs(field(section, "Positive tests")),
    negative: testRefs(field(section, "Negative tests")),
    mutation: ticked(field(section, "Mutation evidence")),
    limitations: field(section, "Limitations"),
  }
})
const built = invariants.filter((invariant) => !invariant.status.startsWith("planned"))

/**
 * Every source module a built invariant names, imported while this file loads. Imported inside a test, a module's
 * top-level constants would count as covered by that test alone, and mutation testing would run only this test,
 * which cannot detect a changed constant, against them.
 */
const enforcing = new Map(
  await Promise.all(
    [...new Set(built.flatMap((invariant) => invariant.enforcement.map(({ file }) => file)))]
      .filter((file) => !file.startsWith("src/adapters/") && existsSync(path.join(root, file)))
      .map(
        async (file) =>
          [
            file,
            (await import(pathToFileURL(path.join(root, file)).href)) as Record<string, unknown>,
          ] as const,
      ),
  ),
)

const indexIds = registry
  .slice(registry.indexOf("## Index"), registry.indexOf("## Invariants"))
  .split("\n")
  .filter((line) => /^\| `INV-/.test(line))
  .map((line) => ticked(line)[0] ?? "")

interface Row {
  readonly id: string
  readonly phase: string
  readonly status: string
  readonly invariants: readonly string[]
  readonly cell: string
}

const rows: Row[] = catalogue
  .split("\n")
  .filter((line) => /^\| `[^`]+` +\|/.test(line))
  .map((line) => {
    const cells = line.split("|").map((cell) => cell.trim())
    return {
      id: (cells[1] ?? "").replaceAll("`", ""),
      phase: cells[6] ?? "",
      status: cells[7] ?? "",
      invariants: ticked(cells[8] ?? ""),
      cell: cells[8] ?? "",
    }
  })
const rowOf = new Map(rows.map((row) => [row.id, row]))

/** The attack ids each threat-model flow cites in its Entry column. */
const citedBy = new Map<string, Set<string>>()
for (const part of threatModel.split(/^## (?=F\d{2}: )/m).slice(1)) {
  const flow = part.slice(0, 3)
  const ids = new Set(
    part
      .split("\n")
      .filter((line) => /^\| [STRIDE]+ +\|/.test(line))
      .flatMap((line) => ticked(line.split("|").at(-2) ?? "")),
  )
  citedBy.set(flow, ids)
}

describe("security invariant registry", () => {
  it("has the invariants phase 3 implements, and the later ones planned", () => {
    expect(invariants.length).toBeGreaterThanOrEqual(20)
    expect(invariants.map((invariant) => invariant.id)).toEqual(
      expect.arrayContaining([
        "INV-AUTH-BYPASS",
        "INV-SESSION-IDENTITY",
        "INV-ASSURANCE-EVIDENCE",
        "INV-REVOCATION",
        "INV-EXPIRY",
        "INV-RECOVERY-NO-ELEVATION",
        "INV-SUBJECT-KINDS",
        "INV-DELEGATION-CEILING",
        "INV-IMPERSONATION",
        "INV-BREAK-GLASS",
      ]),
    )
  })

  it("uses unique, well-formed ids, the same in the index and the sections", () => {
    const ids = invariants.map((invariant) => invariant.id)
    for (const id of ids) expect(id).toMatch(INVARIANT_ID)
    expect(new Set(ids).size).toBe(ids.length)
    expect(indexIds).toEqual(ids)
  })

  it("gives every invariant a known status, its index status, a property and limitations", () => {
    const indexStatus = new Map(
      registry
        .split("\n")
        .filter((line) => /^\| `INV-/.test(line))
        .map((line) => [ticked(line)[0], line.split("|")[2]?.trim()]),
    )
    for (const invariant of invariants) {
      expect(invariant.status, invariant.id).toMatch(STATUS)
      expect(indexStatus.get(invariant.id), invariant.id).toBe(invariant.status)
      expect(
        field(sections[invariants.indexOf(invariant)] ?? "", "Property").length,
      ).toBeGreaterThan(40)
      expect(invariant.limitations.length, invariant.id).toBeGreaterThan(10)
    }
  })

  it("names only attacks the catalogue has, each once per invariant", () => {
    for (const invariant of invariants) {
      expect(invariant.attacks.length, invariant.id).toBeGreaterThan(0)
      expect(new Set(invariant.attacks).size, invariant.id).toBe(invariant.attacks.length)
      for (const id of invariant.attacks) expect(rowOf.has(id), `${invariant.id}: ${id}`).toBe(true)
    }
  })

  it("keeps status honest against the catalogue", () => {
    for (const invariant of invariants) {
      const statuses = invariant.attacks.map((id) => rowOf.get(id)?.status)
      expect(statuses, invariant.id).not.toContain("not applicable")
      if (invariant.status === "tested") expect(statuses, invariant.id).toContain("tested")
      if (invariant.status.startsWith("planned"))
        expect(new Set(statuses), invariant.id).toEqual(new Set(["planned"]))
    }
  })

  it("dates a partial or planned invariant by the latest phase of its planned attacks", () => {
    for (const invariant of invariants.filter((each) => each.phase !== null)) {
      const phases = invariant.attacks
        .map((id) => rowOf.get(id))
        .filter((row) => row?.status === "planned")
        .map((row) => Number(row?.phase))
      expect(Math.max(...phases), invariant.id).toBe(invariant.phase)
    }
  })

  it("traces every attack to a threat in one of the invariant's flows, and every flow to one of its attacks", () => {
    for (const invariant of invariants) {
      expect(invariant.flows.length, invariant.id).toBeGreaterThan(0)
      for (const flow of invariant.flows) {
        const cited = citedBy.get(flow)
        expect(cited, `${invariant.id}: ${flow}`).toBeDefined()
        expect(
          invariant.attacks.some((id) => cited?.has(id)),
          `${invariant.id}: ${flow} cites none of its attacks`,
        ).toBe(true)
      }
      for (const id of invariant.attacks) {
        expect(
          invariant.flows.some((flow) => citedBy.get(flow)?.has(id)),
          `${invariant.id}: no listed flow cites ${id}`,
        ).toBe(true)
      }
    }
  })
})

describe("the catalogue's Invariant column", () => {
  it("names exactly the invariants that list each attack", () => {
    for (const row of rows) {
      const listing = invariants
        .filter((invariant) => invariant.attacks.includes(row.id))
        .map((invariant) => invariant.id)
      expect(row.invariants, row.id).toEqual(listing)
      if (listing.length === 0) expect(row.cell, row.id).toBe("none")
    }
  })

  it("names at least one invariant for every tested attack, and none for a not-applicable one", () => {
    for (const row of rows) {
      if (row.status === "tested") expect(row.invariants.length, row.id).toBeGreaterThan(0)
      if (row.status === "not applicable") expect(row.cell, row.id).toBe("none")
    }
  })
})

describe("enforcement and evidence", () => {
  it.each(built.map((invariant) => [invariant.id, invariant] as const))(
    "%s is enforced by core exports that exist",
    async (_id, invariant) => {
      expect(invariant.enforcement.length).toBeGreaterThan(0)
      for (const { file, name } of invariant.enforcement) {
        expect(file.startsWith("src/adapters/"), `${file} is an adapter`).toBe(false)
        expect(existsSync(path.join(root, file)), file).toBe(true)
        const module = enforcing.get(file)
        expect(["function", "object"], `${file} exports ${name}`).toContain(typeof module?.[name])
      }
    },
  )

  it.each(built.map((invariant) => [invariant.id, invariant] as const))(
    "%s names positive and negative tests that exist and contain the named test",
    (_id, invariant) => {
      expect(invariant.positive.length).toBeGreaterThan(0)
      expect(invariant.negative.length).toBeGreaterThan(0)
      const refs = [...invariant.positive, ...invariant.negative]
      expect(new Set(refs.map((ref) => `${ref.file}:${ref.name}`)).size).toBe(refs.length)
      for (const { file, name } of refs) {
        expect(file, file).toMatch(/^test\/.+\.test\.ts$/)
        expect(existsSync(path.join(root, file)), file).toBe(true)
        expect(read(file).includes(`"${name}"`), `${file} has no test "${name}"`).toBe(true)
      }
    },
  )

  it.each(built.map((invariant) => [invariant.id, invariant] as const))(
    "%s lists every enforcement file under mutation evidence, and only files that exist",
    (_id, invariant) => {
      for (const file of invariant.mutation) {
        expect(file, file).toMatch(/^src\/.+\.ts$/)
        expect(existsSync(path.join(root, file)), file).toBe(true)
      }
      for (const { file } of invariant.enforcement) expect(invariant.mutation, file).toContain(file)
    },
  )
})

describe("dependency failure policies", () => {
  const POLICY_FIELDS = [
    "Expected failures",
    "Policy",
    "Unavailable while it fails",
    "Safe to expose",
    "Recovery",
    "Operator diagnostics",
    "Audit and events",
    "Tests",
  ]
  const dependencySections = failures
    .split(/^## /m)
    .slice(1)
    .filter((section) => section.includes("- **Policy:**"))
  const failureDir = path.join(root, "test", "failure")
  const failureFiles = readdirSync(failureDir).filter((file) => file.endsWith(".test.ts"))

  it("covers every dependency phase 3 uses", () => {
    expect(dependencySections.map((section) => section.slice(0, section.indexOf("\n")))).toEqual([
      "The store (SQL and memory)",
      "Email delivery",
      "HIBP",
      "The clock",
      "The random source",
      "Key material",
      "The event sink",
    ])
  })

  it.each(dependencySections.map((section) => [section.slice(0, section.indexOf("\n")), section]))(
    "%s states every part of its policy",
    (_name, section) => {
      for (const label of POLICY_FIELDS) {
        expect(field(section, label).length, label).toBeGreaterThan(10)
      }
      expect(field(section, "Policy")).toMatch(/^(Fail closed|Degraded)\./)
    },
  )

  it.each(dependencySections.map((section) => [section.slice(0, section.indexOf("\n")), section]))(
    "%s names failure tests that exist and contain the named test",
    (_name, section) => {
      const refs = testRefs(field(section, "Tests"))
      expect(refs.length).toBeGreaterThan(0)
      for (const { file, name } of refs) {
        expect(existsSync(path.join(root, file)), file).toBe(true)
        expect(read(file).includes(`"${name}"`), `${file} has no test "${name}"`).toBe(true)
      }
    },
  )

  it("names every failure test file, and no other", () => {
    const named = new Set(
      [...failures.matchAll(/`test\/failure\/([^`]+\.test\.ts)`/g)].map((m) => m[1] ?? ""),
    )
    expect([...named].sort()).toEqual([...failureFiles].sort())
  })

  it("lists each store-failure flow's store calls exactly as the failure tests run them", () => {
    const from = failures.indexOf("### Store calls per flow")
    const to = failures.indexOf("\n#", from + 1)
    const table = failures
      .slice(from, to === -1 ? undefined : to)
      .split("\n")
      .filter((line) => /^\| [A-Za-z]/.test(line) && !line.startsWith("| Flow "))
      .map((line) => {
        const [, flow = "", calls = ""] = line.split("|").map((cell) => cell.trim())
        return [flow, ticked(calls)] as const
      })
    expect(table).toEqual(FLOWS.map((flow) => [flow.name, [...flow.profile]]))
  })

  it("is the governing spec ADR 0029 names, beside the invariant registry", () => {
    const adr = readdirSync(path.join(specs, "decisions")).find((file) => file.startsWith("0029-"))
    expect(adr).toBeDefined()
    const text = readFileSync(path.join(specs, "decisions", String(adr)), "utf8")
    expect(text).toContain("security-invariants.md")
    expect(text).toContain("dependency-failures.md")
  })
})
