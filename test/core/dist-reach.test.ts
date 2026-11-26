// What the built dist/ reaches (ADR 0030): every file an entry loads, its own chunks and the dependencies' files, read
// import by import. rate-limiter-flexible is imported by deep path only, because its index requires every store it
// ships, one of which loads Node's `cluster`; and nothing reached may load a `node:` module. One bare Node built-in is
// allowed, because every runtime test-cap names provides it: `util`, which forwarded-parse requires for
// `util.inherits` and `util.format`.
import { readFileSync } from "node:fs"
import { builtinModules, createRequire } from "node:module"
import path from "node:path"
import { describe, expect, it } from "vitest"

const root = path.resolve(import.meta.dirname, "../..")
const ENTRIES = ["index", "express", "fetch", "next", "tanstack-start", "store/memory"]
/** Each module specifier a file imports or requires. */
const SPECIFIER = /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+|\brequire\s*\(\s*)["']([^"']+)["']/g
/** Bare Node built-ins allowed, each with the one package allowed to reach it. */
const ALLOWED_BUILTINS: Readonly<Record<string, string>> = { util: "forwarded-parse" }

/** Every file `entry` reaches and every specifier each one names, the entry first. */
function reach(entry: string): { readonly file: string; readonly specifier: string }[] {
  const seen = new Set<string>()
  const found: { file: string; specifier: string }[] = []
  const visit = (file: string): void => {
    if (seen.has(file)) return
    seen.add(file)
    for (const [, specifier = ""] of readFileSync(file, "utf8").matchAll(SPECIFIER)) {
      found.push({ file, specifier })
      if (specifier.startsWith("node:") || builtinModules.includes(specifier)) continue
      visit(createRequire(file).resolve(specifier))
    }
  }
  visit(path.join(root, "dist", `${entry}.js`))
  return found
}

describe("what dist/ reaches", () => {
  it("never loads rate-limiter-flexible's index or a node: module, from any entry", () => {
    for (const entry of ENTRIES) {
      const found = reach(entry)
      const index = found.filter(({ specifier }) =>
        /^rate-limiter-flexible(?:\/index(?:\.js)?)?$/.test(specifier),
      )
      expect(index, entry).toEqual([])
      expect(
        found.filter(({ specifier }) => specifier.startsWith("node:")),
        entry,
      ).toEqual([])
    }
  })

  it("loads a bare Node built-in only where it is allowed", () => {
    for (const entry of ENTRIES) {
      const builtins = reach(entry).filter(({ specifier }) => builtinModules.includes(specifier))
      for (const { file, specifier } of builtins) {
        expect(file, `${entry}: ${specifier}`).toContain(
          `node_modules/${String(ALLOWED_BUILTINS[specifier])}/`,
        )
      }
    }
  })

  it("does reach the libraries it uses, by their deep paths", () => {
    const specifiers = reach("index").map(({ specifier }) => specifier)
    expect(specifiers).toContain("rate-limiter-flexible/lib/RateLimiterStoreAbstract.js")
    expect(specifiers).toContain("ipaddr.js")
    expect(specifiers).toContain("forwarded-parse")
    // The argon2id fallback (ADR 0031) loads @noble/hashes's argon2 module alone, never the package's index.
    expect(specifiers).toContain("@noble/hashes/argon2.js")
    expect(
      specifiers.filter((specifier) => /^@noble\/hashes(?:\/index(?:\.js)?)?$/.test(specifier)),
    ).toEqual([])
  })

  it("catches the index and a node: module, so the check is not vacuous", () => {
    const named = (text: string) => [...text.matchAll(SPECIFIER)].map((match) => match[1])
    expect(named('const a = require("rate-limiter-flexible")')).toEqual(["rate-limiter-flexible"])
    expect(named('import cluster from "node:cluster"')).toEqual(["node:cluster"])
  })
})
