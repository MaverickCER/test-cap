import { describe, expect, it } from "vitest"
import {
  CONTENT_SECURITY_POLICY,
  emptyResponse,
  errorResponse,
  jsonResponse,
} from "../../src/security/headers.js"

describe("response building (ADR 0011 §3, §4, Open 2)", () => {
  it("sets the strict CSP of ADR 0011 Open 2", () => {
    expect(CONTENT_SECURITY_POLICY).toBe(
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; " +
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    )
  })

  it("gives an empty response the security headers, the extras and each cookie on its own line", () => {
    const response = emptyResponse(303, {
      cookies: ["a=1; Path=/", "b=2; Path=/"],
      headers: { Location: "/next" },
    })
    expect(response.status).toBe(303)
    expect(response.body).toBeNull()
    expect([...response.headers.entries()]).toEqual([
      ["cache-control", "no-store"],
      ["content-security-policy", CONTENT_SECURITY_POLICY],
      ["location", "/next"],
      ["referrer-policy", "no-referrer"],
      ["set-cookie", "a=1; Path=/"],
      ["set-cookie", "b=2; Path=/"],
      ["x-content-type-options", "nosniff"],
    ])
  })

  it("lets an extra header replace a fixed one rather than repeat it", () => {
    expect(
      emptyResponse(200, { headers: { "Cache-Control": "private" } }).headers.get("cache-control"),
    ).toBe("private")
  })

  it("serialises JSON as UTF-8 with its content type", () => {
    const response = jsonResponse(200, { name: "Zoë" })
    expect(response.headers.get("content-type")).toBe("application/json; charset=utf-8")
    expect(new TextDecoder().decode(response.body ?? new Uint8Array())).toBe('{"name":"Zoë"}')
    expect(response.headers.get("x-content-type-options")).toBe("nosniff")
  })

  it("puts only the code in an error body", () => {
    const response = errorResponse(404, "not-found", { headers: { Allow: "GET" } })
    expect(response.status).toBe(404)
    expect(new TextDecoder().decode(response.body ?? new Uint8Array())).toBe(
      '{"error":"not-found"}',
    )
    expect(response.headers.get("allow")).toBe("GET")
  })
})
