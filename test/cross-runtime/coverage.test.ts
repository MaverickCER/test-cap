import { describe, expect, it } from "vitest"
import * as index from "../../src/index.js"
import { CHECKS } from "./exercised.mjs"

describe("cross-runtime coverage (ADR 0023)", () => {
  it("has a check function for exactly the values src/index.ts exports, so a new export cannot skip Bun and Deno", () => {
    expect(Object.keys(CHECKS).sort()).toEqual(Object.keys(index).sort())
  })

  it("registers only functions, so every key run.mjs counts is something it executes", () => {
    for (const [name, run] of Object.entries(CHECKS)) expect(typeof run, name).toBe("function")
  })
})
