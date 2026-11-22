// Attack: a target that starts with the app's origin (`https://app.example.evil.example`) passes a prefix check.
// Stopped by: origins are compared parsed and exact; there are no wildcard or prefix origins (ADR 0026).
import { describe, expect, it } from "vitest"
import { Browser, inProcess, ORIGIN, testAuth } from "../support/auth.js"

describe("open-redirect-origin-prefix", () => {
  it.each([
    "https://app.example.evil.example/",
    "https://app.example@evil.example/",
    "https://app.example:443.evil.example/",
    "https://app.example/",
  ])("refuses the absolute returnTo %s, even one on the app's own origin", async (returnTo) => {
    const { auth } = testAuth()
    const browser = new Browser(inProcess(auth))
    await browser.start()
    const reply = await browser.post("/auth/sign-up", { identifier: "ada@example.com", returnTo })
    expect([reply.status, reply.text]).toEqual([400, '{"error":"invalid-return-to"}'])
  })

  it("compares Origin exactly, so a prefix origin cannot post", async () => {
    const { auth } = testAuth()
    const browser = new Browser(inProcess(auth), `${ORIGIN}.evil.example`)
    await browser.start()
    expect((await browser.post("/auth/sign-up", { identifier: "ada@example.com" })).status).toBe(
      403,
    )
  })
})
