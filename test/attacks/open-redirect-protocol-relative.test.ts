// Attack: `returnTo=//evil.example` (or `/\evil.example`) sends the user off-site after sign-in.
// Stopped by: `returnTo` accepts same-origin relative paths only, checked after URL parsing (ADR 0026).
import { describe, expect, it } from "vitest"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import { Browser, inProcess, PASSWORD, seedAccount, testAuth } from "../support/auth.js"

const lenient = () =>
  testAuth({ policy: defineAuthPolicy({ version: "v", defaultRequirement: { level: "AAL1" } }) })

describe("open-redirect-protocol-relative", () => {
  it.each([
    "//evil.example/",
    "/\\evil.example/",
    "/\t/evil.example/",
    "//app.example@evil.example/",
  ])("refuses returnTo %j before signing in", async (returnTo) => {
    const setup = lenient()
    await seedAccount(setup, { password: true })
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    const reply = await browser.postForm("/auth/sign-in", {
      identifier: "ada@example.com",
      password: PASSWORD,
      returnTo,
    })
    expect([reply.status, reply.text, reply.headers.get("location")]).toEqual([
      400,
      '{"error":"invalid-return-to"}',
      null,
    ])
    expect(browser.cookies.has("__Host-test-cap")).toBe(false)
  })

  it("redirects to a same-origin path as given", async () => {
    const setup = lenient()
    await seedAccount(setup, { password: true })
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    const reply = await browser.postForm("/auth/sign-in", {
      identifier: "ada@example.com",
      password: PASSWORD,
      returnTo: "/inbox",
    })
    expect([reply.status, reply.headers.get("location")]).toEqual([303, "/inbox"])
  })
})
