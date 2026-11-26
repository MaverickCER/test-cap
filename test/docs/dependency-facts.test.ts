// The facts README, ADOPTION, ADR 0030, ADR 0031 and the changesets state about test-cap's own dependencies: which are
// pinned to an exact version, that none brings dependencies of its own, each one's licence, and how many there are.
// The installed tree is read from package-lock.json, which `npm ci` installs exactly.
import { readFileSync } from "node:fs"
import path from "node:path"
import { describe, expect, it } from "vitest"

const root = path.resolve(import.meta.dirname, "../..")
const read = (file: string) => readFileSync(path.join(root, file), "utf8")
const manifest = JSON.parse(read("package.json")) as { dependencies: Record<string, string> }
const lock = JSON.parse(read("package-lock.json")) as {
  packages: Record<
    string,
    { version: string; license?: string; dependencies?: Record<string, string> }
  >
}
const installed = (name: string) => lock.packages[`node_modules/${name}`]
const names = Object.keys(manifest.dependencies)

describe("test-cap's dependencies", () => {
  it("pin the limit libraries and @noble/hashes to the exact versions installed (ADR 0030, ADR 0031)", () => {
    for (const name of ["rate-limiter-flexible", "ipaddr.js", "forwarded-parse", "@noble/hashes"]) {
      expect(manifest.dependencies[name], name).toMatch(/^\d+\.\d+\.\d+$/)
      expect(installed(name)?.version, name).toBe(manifest.dependencies[name])
    }
  })

  it("bring no dependencies of their own, as README and ADOPTION say", () => {
    for (const name of names) expect(installed(name)?.dependencies ?? {}, name).toEqual({})
    expect(read("README.md")).toContain(
      `test-cap adds ${["zero", "one", "two", "three", "four", "five", "six"][names.length]} packages, each with no dependencies of its own`,
    )
  })

  it("have the licence ADOPTION gives each one", () => {
    const rows = read("ADOPTION.md")
      .split("\n")
      .filter((line) => line.includes("| dependency "))
    expect(rows).toHaveLength(names.length)
    for (const name of names) {
      const row = rows.find((line) => line.startsWith(`| \`${name}\``)) ?? ""
      expect(row, name).toContain(
        `${installed(name)?.license ?? "no licence"}, no dependencies of its own`,
      )
    }
  })
})
