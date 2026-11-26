import { describe, expect, it } from "vitest"
import * as entry from "../src/index.js"

describe("the test-cap entry", () => {
  it("exports exactly its runtime values: createAuth, createStoreLimiter, defineAuthPolicy, platform and the two error types", () => {
    expect(Object.keys(entry).sort()).toEqual([
      "ConfigError",
      "TransportError",
      "createAuth",
      "createStoreLimiter",
      "defineAuthPolicy",
      "platform",
    ])
  })

  it("maps a transport refusal to its status and keeps the code", () => {
    const error = new entry.TransportError("body-too-large", "over the limit")
    expect([error.name, error.code, error.status]).toEqual([
      "TransportError",
      "body-too-large",
      413,
    ])
  })

  it("lists every configuration problem at once", () => {
    const error = new entry.ConfigError(["APP_ORIGIN is not https", "AUTH_CSRF_KEY is missing"])
    expect(error.problems).toHaveLength(2)
    expect(error.message).toBe(
      "test-cap refused to start:\n- APP_ORIGIN is not https\n- AUTH_CSRF_KEY is missing",
    )
  })
})
