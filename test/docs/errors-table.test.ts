// GUIDE.md's "Errors" table says it lists every error the routes answer. This test keeps that true both ways: each code
// the source can send is in the table, and each code in the table is one the source can send.
import { readdirSync, readFileSync } from "node:fs"
import path from "node:path"
import { describe, expect, it } from "vitest"

const root = path.resolve(import.meta.dirname, "../..")
const read = (file: string): string => readFileSync(path.join(root, file), "utf8")

/** The TypeScript under `folder`, as one text. */
const sourcesIn = (folder: string): string =>
  readdirSync(path.join(root, folder), { recursive: true, encoding: "utf8" })
    .filter((file) => file.endsWith(".ts"))
    .map((file) => read(path.join(folder, file)))
    .join("\n")
const sources = sourcesIn("src")

/** The keys of the object literal assigned to `name` in `text`. */
function keysOf(text: string, name: string): string[] {
  const body = new RegExp(`const ${name}[^=]*= \\{([^}]*)\\}`).exec(text)?.[1] ?? ""
  return [...body.matchAll(/"?([a-z][a-z-]*)"?:/g)].map((match) => match[1] ?? "")
}

/** Every code the routes can answer with. */
const sent = new Set([
  // errorResponse(<status>, "<code>")
  ...[...sources.matchAll(/errorResponse\(\d{3}, "([a-z-]+)"/g)].map((match) => match[1] ?? ""),
  // transport refusals, answered with their own status
  ...keysOf(read("src/core/errors.ts"), "STATUS"),
  // password-setting outcomes, answered as their own code
  ...keysOf(read("src/core/dispatcher.ts"), "SET_PASSWORD_STATUS"),
  // a protected route's unmet requirement, answered as the session outcome
  ...[
    ...`${sourcesIn("src/sessions")}\n${sourcesIn("src/assurance")}`.matchAll(
      /outcome: "([a-z-]+)"/g,
    ),
  ]
    .map((match) => match[1] ?? "")
    .filter((outcome) => outcome !== "allow"),
])

const guide = read("GUIDE.md")
const section = guide.slice(
  guide.indexOf("## Errors"),
  guide.indexOf("\n## ", guide.indexOf("## Errors") + 1),
)
const listed = new Set(
  section
    .split("\n")
    .filter((line) => /^\| [45]\d\d /.test(line))
    .flatMap((line) => [...line.matchAll(/`([a-z][a-z-]*)`/g)].map((match) => match[1] ?? "")),
)

describe("GUIDE.md's errors table", () => {
  it("finds the codes on both sides", () => {
    expect(sent.size).toBeGreaterThan(30)
    expect(listed.size).toBeGreaterThan(30)
  })

  it("lists every code the routes can answer with", () => {
    expect([...sent].filter((code) => !listed.has(code)).sort()).toEqual([])
  })

  it("lists only codes the routes can answer with", () => {
    expect([...listed].filter((code) => !sent.has(code)).sort()).toEqual([])
  })
})
