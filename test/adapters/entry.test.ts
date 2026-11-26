import { describe, expect, it } from "vitest"
import manifest from "../../package.json" with { type: "json" }
import * as express from "../../src/adapters/express/index.js"
import * as fetch from "../../src/adapters/fetch/index.js"
import * as next from "../../src/adapters/next/index.js"
import * as tanstackStart from "../../src/adapters/tanstack-start/index.js"
import * as memory from "../../src/store/memory.js"

describe("the adapter entries", () => {
  it("test-cap/express exports exactly one runtime value, expressAuth", () => {
    expect(Object.keys(express)).toEqual(["expressAuth"])
  })

  it("test-cap/fetch exports exactly fetchAuth and withAuth", () => {
    expect(Object.keys(fetch).sort()).toEqual(["fetchAuth", "withAuth"])
  })

  it("test-cap/next exports exactly its three surfaces", () => {
    expect(Object.keys(next).sort()).toEqual(["nextAuthHandler", "nextProxy", "nextServerAuth"])
  })

  it("test-cap/tanstack-start exports exactly tanstackStartAuth and tanstackStartMiddleware", () => {
    expect(Object.keys(tanstackStart).sort()).toEqual([
      "tanstackStartAuth",
      "tanstackStartMiddleware",
    ])
  })

  it("test-cap/store/memory exports exactly memoryStore", () => {
    expect(Object.keys(memory)).toEqual(["memoryStore"])
  })

  it("are four adapters and the memory store: Nest is not built yet (ADR 0024)", () => {
    expect(Object.keys(manifest.exports)).toEqual([
      ".",
      "./express",
      "./fetch",
      "./next",
      "./tanstack-start",
      "./store/memory",
      "./package.json",
    ])
  })
})
