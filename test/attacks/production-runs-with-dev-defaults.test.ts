// Attack: a production server believes it is in development (APP_ENV missing, mistyped or borrowed from NODE_ENV)
// and runs with the memory store, an http origin or generated keys.
// Stopped by: a missing or unknown APP_ENV runs as production, which refuses all three (ADR 0026).
import { describe, expect, it } from "vitest"
import { checkReadiness, resolveDeploymentMode } from "../../src/core/mode.js"
import { memoryStore } from "../../src/store/memory.js"

const devSetup = {
  origin: "http://localhost:3000",
  store: memoryStore(),
  secrets: { AUTH_ENCRYPTION_KEY: undefined, AUTH_CSRF_KEY: undefined },
}

describe("production-runs-with-dev-defaults", () => {
  it("treats a missing, empty, mistyped or NODE_ENV-style value as production", () => {
    for (const value of [
      undefined,
      "",
      "dev",
      "develop",
      "Development",
      "DEVELOPMENT",
      "local",
      "prod ",
    ]) {
      expect(resolveDeploymentMode(value).mode, String(value)).toBe("production")
    }
  })

  it("refuses the development setup once the mode falls back to production", () => {
    const { mode } = resolveDeploymentMode(undefined)
    expect(checkReadiness({ mode, ...devSetup })).toEqual([
      "APP_ORIGIN must use https in production.",
      'The "memory" store keeps nothing across restarts or processes; production needs a durable store.',
      "AUTH_ENCRYPTION_KEY is missing.",
      "AUTH_CSRF_KEY is missing.",
    ])
  })

  it("accepts the same setup only when APP_ENV names development exactly", () => {
    expect(
      checkReadiness({ mode: resolveDeploymentMode("development").mode, ...devSetup }),
    ).toEqual([])
  })

  it("never reads NODE_ENV", () => {
    const before = process.env["NODE_ENV"]
    process.env["NODE_ENV"] = "development"
    try {
      expect(resolveDeploymentMode(undefined).mode).toBe("production")
    } finally {
      if (before === undefined) delete process.env["NODE_ENV"]
      else process.env["NODE_ENV"] = before
    }
  })
})
