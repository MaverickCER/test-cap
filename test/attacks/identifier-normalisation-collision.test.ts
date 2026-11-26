// Attack: two spellings of one address reach two accounts, or a padded value passes a check. Stopped by: one
// normalisation in the core, applied wherever an identifier enters; stores compare the normalised bytes (ADR 0021,
// 0002).
import { describe, expect, it } from "vitest"
import { normaliseEmail } from "../../src/core/identifier.js"
import { account, Browser, inProcess, PASSWORD, testAuth } from "../support/auth.js"

describe("identifier-normalisation-collision", () => {
  it("maps case, Unicode composition and IDNA spellings of one address to one value", () => {
    const composed = "josé@bücher.example"
    const decomposed = "JOSÉ@BÜCHER.EXAMPLE"
    expect(normaliseEmail(composed)).toBe("josé@xn--bcher-kva.example")
    expect(normaliseEmail(decomposed)).toBe(normaliseEmail(composed))
    expect(normaliseEmail("josé@xn--bcher-kva.example")).toBe(normaliseEmail(composed))
  })

  it("refuses padding and control characters instead of trimming them", () => {
    for (const padded of [
      " ada@example.com",
      "ada@example.com ",
      "ada@example.com\u0000",
      "ada\t@example.com",
    ]) {
      expect(normaliseEmail(padded), JSON.stringify(padded)).toBeNull()
    }
  })

  it("signs in to the one account whichever spelling is typed, and refuses a padded one", async () => {
    const setup = testAuth()
    await account(setup)
    for (const typed of ["ADA@EXAMPLE.COM", "Ada@Example.Com"]) {
      const browser = new Browser(inProcess(setup.auth))
      await browser.start()
      const reply = await browser.post("/auth/sign-in", { identifier: typed, password: PASSWORD })
      expect(reply.json, typed).toMatchObject({ outcome: "step-up" })
    }
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    const padded = await browser.post("/auth/sign-in", {
      identifier: " ada@example.com",
      password: PASSWORD,
    })
    expect(padded.status).toBe(401)
  })
})
