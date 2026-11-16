import { readdirSync, readFileSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../src")

function sources(): { file: string; text: string }[] {
  return readdirSync(SRC, { recursive: true, encoding: "utf8" })
    .filter((file) => file.endsWith(".ts"))
    .map((file) => ({
      file: file.split(path.sep).join("/"),
      text: readFileSync(path.join(SRC, file), "utf8"),
    }))
}

function offenders(pattern: RegExp, allowed: readonly string[] = []): string[] {
  return sources()
    .filter(({ file, text }) => !allowed.includes(file) && pattern.test(text))
    .map(({ file }) => file)
}

describe("source rules (ADR 0003)", () => {
  it("finds the source files it scans", () => {
    expect(sources().map(({ file }) => file)).toContain("core/clock.ts")
  })

  it("imports no node: module, so the same dist/ runs on Node, Bun and Deno", () => {
    expect(offenders(/from\s+["']node:|require\(\s*["']node:|import\(\s*["']node:/)).toEqual([])
  })

  it("reads the global clock only in core/clock.ts", () => {
    expect(
      offenders(/Date\.now\s*\(|new Date\s*\(|performance\.now\s*\(/, ["core/clock.ts"]),
    ).toEqual([])
  })

  it("reads global randomness only in core/clock.ts", () => {
    expect(
      offenders(/Math\.random\s*\(|getRandomValues\s*\(|randomUUID\s*\(/, ["core/clock.ts"]),
    ).toEqual([])
  })

  it("catches a violation when one exists", () => {
    expect(/Date\.now\s*\(/.test("const t = Date.now()")).toBe(true)
    expect(/from\s+["']node:/.test('import fs from "node:fs"')).toBe(true)
  })
})
