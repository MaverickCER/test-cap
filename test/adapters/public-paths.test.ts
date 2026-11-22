// ADR 0024 §2 and Open 1: an exact entry matches only its own clean path; a prefix needs an explicit /* wildcard.
import { describe, expect, it } from "vitest"
import { ConfigError } from "../../src/core/errors.js"
import { compilePublicPaths } from "../../src/core/public-paths.js"

describe("public paths", () => {
  it("matches an exact entry only, so / is the root and nothing else", () => {
    const isPublic = compilePublicPaths(["/", "/about"])
    expect(isPublic("/")).toBe(true)
    expect(isPublic("/about")).toBe(true)
    expect(isPublic("/about/team")).toBe(false)
    expect(isPublic("/aboutx")).toBe(false)
    expect(isPublic("/admin")).toBe(false)
  })

  it("is case-sensitive and never decodes", () => {
    const isPublic = compilePublicPaths(["/about"])
    expect(isPublic("/About")).toBe(false)
    expect(isPublic("/ABOUT")).toBe(false)
    expect(isPublic("/ab%6Fut")).toBe(false)
  })

  it("matches a wildcard entry for one or more segments below its prefix, never the prefix itself", () => {
    const isPublic = compilePublicPaths(["/blog/*"])
    expect(isPublic("/blog/post")).toBe(true)
    expect(isPublic("/blog/2026/post")).toBe(true)
    expect(isPublic("/blog")).toBe(false)
    expect(isPublic("/blog/")).toBe(false)
    expect(isPublic("/blogpost")).toBe(false)
    expect(isPublic("/Blog/post")).toBe(false)
  })

  it("makes everything below the root public with /*, which an app must write out", () => {
    const isPublic = compilePublicPaths(["/*"])
    expect(isPublic("/x")).toBe(true)
    expect(isPublic("/")).toBe(false)
  })

  it("matches nothing with an empty list", () => {
    expect(compilePublicPaths([])("/")).toBe(false)
  })

  it("accepts the clean segment characters", () => {
    const isPublic = compilePublicPaths(["/a.b_c~d-e/F9", "/~x/*"])
    expect(isPublic("/a.b_c~d-e/F9")).toBe(true)
    expect(isPublic("/~x/y")).toBe(true)
  })

  it("names every malformed entry at once", () => {
    const entries = [
      "",
      "about",
      "/about/",
      "//about",
      "/./about",
      "/../about",
      "/.hidden",
      "/a b",
      "/a%2Fb",
      "/blog*",
      "/blog/*/x",
      "/*/x",
      "/blog/**",
      "*",
    ]
    let error: unknown
    try {
      compilePublicPaths(["/ok", ...entries])
    } catch (caught) {
      error = caught
    }
    expect(error).toBeInstanceOf(ConfigError)
    expect((error as ConfigError).problems).toEqual(
      entries.map(
        (entry) =>
          `The public path "${entry}" must be a clean path such as /about, or end in /* such as /blog/*.`,
      ),
    )
  })
})
