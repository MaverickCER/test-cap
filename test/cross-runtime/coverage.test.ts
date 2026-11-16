import { describe, expect, it } from "vitest"
import * as index from "../../src/index.js"
import { EXERCISED } from "./exercised.mjs"

describe("cross-runtime coverage (ADR 0023)", () => {
  it("exercises exactly the values src/index.ts exports, so a new export cannot skip Bun and Deno", () => {
    expect([...EXERCISED].sort()).toEqual(Object.keys(index).sort())
  })
})
