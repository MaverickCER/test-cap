// ADR 0024 §4: test-cap's docs never claim that the Next.js proxy protects a route, and the places a reader meets
// `nextProxy` say it is not the protection, quoting Next.js's own warning.
import { existsSync, readdirSync, readFileSync } from "node:fs"
import path from "node:path"
import { describe, expect, it } from "vitest"

const root = path.resolve(import.meta.dirname, "../..")
const WARNING = "should not be your only line of defense"

/** Every Markdown file under `dir`, relative to the root. */
function markdown(dir: string): string[] {
  const full = path.join(root, dir)
  if (!existsSync(full)) return []
  return readdirSync(full, { recursive: true, encoding: "utf8" })
    .filter((file) => file.endsWith(".md") && !file.includes("node_modules"))
    .map((file) => path.join(dir, file))
}

const documents = [
  "README.md",
  "GLOSSARY.md",
  "examples/nextjs/README.md",
  "examples/nextjs/proxy.ts",
  ...markdown("specs"),
  ...markdown("docs"),
]

/** A file's prose: comment markers and code spans removed (an id such as `next-proxy-treated-as-protection` is not a claim), whitespace collapsed. */
function prose(file: string): string {
  return readFileSync(path.join(root, file), "utf8")
    .replaceAll(/^\s*\/\/ ?/gm, "")
    .replaceAll(/`[^`\n]*`/g, "code")
    .replaceAll(/\s+/g, " ")
}

/** A sentence that names the proxy and says it protects, with nothing in it saying it does not. */
const CLAIM = /\bproxy\b[^.]*\b(?:protects?|protection|secures?|guards?|enforces?)\b/i
const DENIAL = /\b(?:not|never|no|only line of defen[cs]e|redirects? only|optimistic)\b/i

describe("the Next.js proxy is never documented as protection", () => {
  it("no document says the proxy protects a route", () => {
    const claims: string[] = []
    for (const file of documents) {
      // Sentences end at a full stop, semicolon or colon, and a table cell ends at its bar.
      for (const sentence of prose(file).split(/(?<=[.;:])\s|\|/)) {
        if (CLAIM.test(sentence) && !DENIAL.test(sentence)) claims.push(`${file}: ${sentence}`)
      }
    }
    expect(claims).toEqual([])
  })

  it.each([
    "examples/nextjs/README.md",
    "examples/nextjs/proxy.ts",
    "docs/api-report/adapters/next.md",
  ])("%s quotes Next.js's warning", (file) => {
    const text = prose(file)
    expect(text).toContain(WARNING)
    expect(text).toMatch(/not (?:the )?protection/)
  })

  it("catches a claim, so the scan is not vacuous", () => {
    const sentence = "The proxy protects every route under /billing."
    expect(CLAIM.test(sentence) && !DENIAL.test(sentence)).toBe(true)
  })
})
