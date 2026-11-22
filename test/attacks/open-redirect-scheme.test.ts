// Attack: `returnTo=javascript:…` or `data:…` runs script after sign-in.
// Stopped by: only same-origin relative paths are ever navigation targets (ADR 0026, 0011).
import { describe, expect, it } from "vitest"
import { aal1, seedAccount, seedSession, testAuth } from "../support/auth.js"
import { codeAt } from "../support/totp.js"

describe("open-redirect-scheme", () => {
  it.each([
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:x",
    " /x",
  ])("refuses returnTo %j on every route that takes one", async (returnTo) => {
    const setup = testAuth()
    const { subject, secret } = await seedAccount(setup, { totp: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    const code = await codeAt(secret ?? "", setup.clock.now())
    for (const [path, fields] of [
      ["/auth/sign-up", { identifier: "x@example.com" }],
      ["/auth/sign-in", { identifier: "x@example.com", password: "p" }],
      ["/auth/totp/confirm", { authenticatorId: "A".repeat(43), code }],
      ["/auth/totp/verify", { code }],
      ["/auth/step-up", { challenge: "c", code }],
    ] as const) {
      const reply = await browser.postForm(path, { ...fields, returnTo })
      expect([path, reply.status, reply.text]).toEqual([path, 400, '{"error":"invalid-return-to"}'])
    }
    expect(setup.events).toEqual([])
  })
})
