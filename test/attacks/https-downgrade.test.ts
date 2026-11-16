// Attack: the app runs over HTTP, or the session cookie is sent without TLS.
// Stopped by: production refuses a non-HTTPS origin; every cookie test-cap sets is Secure (ADR 0026, ADR 0006).
import { describe, expect, it } from "vitest"
import { checkReadiness } from "../../src/core/mode.js"
import { expireCookie, serializeCookie } from "../../src/transport/cookies.js"

const durable = { kind: "sql", durable: true }

describe("https-downgrade", () => {
  it("refuses to start production or staging on an http origin, loopback included", () => {
    for (const mode of ["production", "staging"] as const) {
      for (const origin of ["http://app.example", "http://localhost:3000", "http://127.0.0.1"]) {
        expect(
          checkReadiness({ mode, origin, store: durable, secrets: {} }),
          `${mode} ${origin}`,
        ).toEqual([`APP_ORIGIN must use https in ${mode}.`])
      }
    }
  })

  it("allows http only on a loopback host, and only in development or test", () => {
    for (const mode of ["development", "test"] as const) {
      expect(
        checkReadiness({ mode, origin: "http://app.example", store: durable, secrets: {} }),
      ).toHaveLength(1)
    }
  })

  it("marks every cookie Secure, whatever its other attributes", () => {
    for (const sameSite of ["Strict", "Lax", "None"] as const) {
      for (const httpOnly of [true, false]) {
        expect(serializeCookie("__Host-test-cap", "v", { httpOnly, sameSite })).toContain(
          "; Secure",
        )
        expect(expireCookie("__Host-test-cap", { httpOnly, sameSite })).toContain("; Secure")
      }
    }
  })

  it("only sets __Host- cookies, which a browser refuses without Secure, Path=/ and no Domain", () => {
    expect(() => serializeCookie("session", "v", { httpOnly: true, sameSite: "Lax" })).toThrow(
      /__Host-/,
    )
    const cookie = serializeCookie("__Host-test-cap", "v", { httpOnly: true, sameSite: "Lax" })
    expect(cookie).toContain("Path=/")
    expect(cookie).not.toMatch(/domain=/i)
  })
})
