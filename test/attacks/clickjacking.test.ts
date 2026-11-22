// Attack: an auth page is framed to trick a click.
// Stopped by: `frame-ancestors 'none'` (ADR 0011). Every reply the dispatcher gives carries it, ahead of the default
// pages that will use it most.
import { describe, expect, it } from "vitest"
import { Browser, inProcess, testAuth } from "../support/auth.js"

describe("clickjacking", () => {
  it("forbids framing on every reply, with the rest of the strict policy", async () => {
    const { auth } = testAuth()
    const browser = new Browser(inProcess(auth))
    for (const reply of [
      await browser.get("/auth/session"),
      await browser.get("/auth/missing"),
      await browser.send({ method: "POST", path: "/auth/sign-in" }),
    ]) {
      const policy = reply.headers.get("content-security-policy") ?? ""
      expect(policy.split("; ")).toContain("frame-ancestors 'none'")
      expect(policy.split("; ")).toContain("default-src 'none'")
      expect(reply.headers.get("x-content-type-options")).toBe("nosniff")
      expect(reply.headers.get("referrer-policy")).toBe("no-referrer")
    }
  })
})
