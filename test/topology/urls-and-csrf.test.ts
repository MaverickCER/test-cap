// Topology simulation, part two (ADR 0024 §6, ADR 0011, ADR 0026 §5): behind a gateway that strips a path prefix and
// terminates TLS, every link, redirect and email URL test-cap builds carries the public prefix and APP_ORIGIN's
// scheme, cookies keep their __Host- attributes, and the CSRF check decides the same way through every adapter.
import { afterEach, describe, expect, it } from "vitest"
import type { AuthDiagnostic } from "../../src/core/auth.js"
import { Browser, ORIGIN, testAuth } from "../support/auth.js"
import { DRIVERS, PEER } from "./drivers.js"

const closers: (() => Promise<void>)[] = []
afterEach(async () => {
  await Promise.all(closers.splice(0).map((close) => close()))
})

async function open(driver: (typeof DRIVERS)[number], publicBasePath?: string) {
  const diagnostics: AuthDiagnostic[] = []
  const setup = testAuth({
    publicBasePath,
    onDiagnostic: (diagnostic) => diagnostics.push(diagnostic),
  })
  const { transport, close } = await driver.open(setup.auth, PEER)
  closers.push(close)
  const browser = new Browser(transport)
  await browser.start()
  return { setup, browser, diagnostics }
}

describe.each(DRIVERS)("behind a prefix-stripping gateway, through $name", (driver) => {
  it("puts the prefix on every form action, link and asset of a default page", async () => {
    const { browser } = await open(driver, "/accounts")
    const page = await browser.send({
      method: "GET",
      path: "/auth/sign-in",
      headers: [["Accept", "text/html"]],
    })
    expect(page.status).toBe(200)
    const paths = [...page.text.matchAll(/(?:action|href|src)="([^"]+)"/g)].map((match) => match[1])
    expect(paths.length).toBeGreaterThan(2)
    for (const path of paths) expect(path).toMatch(/^\/accounts\/auth\//)
  })

  it("redirects a form post, and links its email, under the prefix and APP_ORIGIN", async () => {
    const { browser, setup } = await open(driver, "/accounts")
    const reply = await browser.send({
      method: "POST",
      path: "/auth/sign-up",
      headers: [
        ["Origin", ORIGIN],
        ["Accept", "text/html"],
        ["Content-Type", "application/x-www-form-urlencoded"],
      ],
      body: new URLSearchParams({
        identifier: "ada@example.com",
        csrfToken: browser.csrf ?? "",
      }).toString(),
    })
    expect([reply.status, reply.headers.get("location")]).toEqual([
      303,
      "/accounts/auth/email/confirm",
    ])
    await Promise.resolve()
    expect(setup.outbox.at(-1)?.text).toContain(`${ORIGIN}/accounts/auth/email/confirm`)
  })

  it("sends a signed-up browser to the prefixed root when no returnTo was asked for", async () => {
    const { browser } = await open(driver, "/accounts")
    const reply = await browser.post("/auth/sign-up", { identifier: "ada@example.com" })
    expect(reply.json).toEqual({ outcome: "enroll", returnTo: "/accounts/" })
  })

  it("keeps the __Host- cookie attributes, Secure included, with TLS ended upstream", async () => {
    const { browser } = await open(driver, "/accounts")
    const reply = await browser.post(
      "/auth/sign-up",
      { identifier: "ada@example.com" },
      { headers: [["X-Forwarded-Proto", "http"]] },
    )
    const session = reply.headers.getSetCookie().find((line) => line.startsWith("__Host-test-cap="))
    expect(session).toMatch(/; Path=\/; /)
    expect(session).toMatch(/; Secure/)
    expect(session).toMatch(/; HttpOnly/)
    expect(session).toMatch(/; SameSite=Lax/)
    expect(session).not.toMatch(/Domain=/i)
  })
})

describe.each(DRIVERS)("the CSRF decision through $name", (driver) => {
  const post = (browser: Browser, headers: readonly (readonly [string, string])[]) =>
    browser.send({
      method: "POST",
      path: "/auth/sign-in",
      headers: [
        ["Content-Type", "application/json"],
        ["X-CSRF-Token", browser.csrf ?? ""],
        ...headers,
      ],
      body: JSON.stringify({
        identifier: "nobody@example.com",
        password: "wrong password entirely",
      }),
    })

  it("refuses Origin null with no Sec-Fetch-Site, and tells the operator once", async () => {
    const { browser, diagnostics } = await open(driver)
    for (let i = 0; i < 2; i += 1) {
      const reply = await post(browser, [["Origin", "null"]])
      expect([reply.status, reply.text]).toEqual([403, '{"error":"csrf"}'])
    }
    expect(diagnostics.map((each) => each.code)).toEqual(["origin-unverifiable"])
  })

  it("refuses a request with neither header, and tells the operator", async () => {
    const { browser, diagnostics } = await open(driver)
    expect((await post(browser, [])).status).toBe(403)
    expect(diagnostics.map((each) => each.code)).toEqual(["origin-unverifiable"])
  })

  it("passes a same-origin request that carries Sec-Fetch-Site and no Origin", async () => {
    const { browser, diagnostics } = await open(driver)
    const reply = await post(browser, [["Sec-Fetch-Site", "same-origin"]])
    expect(reply.status).toBe(401)
    expect(diagnostics).toEqual([])
  })

  it("passes Origin null when Sec-Fetch-Site says same-origin, as a no-referrer page sends it", async () => {
    const { browser, diagnostics } = await open(driver)
    const reply = await post(browser, [
      ["Origin", "null"],
      ["Sec-Fetch-Site", "same-origin"],
    ])
    expect(reply.status).toBe(401)
    expect(diagnostics).toEqual([])
  })

  it("refuses another site's Origin without calling it a proxy problem", async () => {
    const { browser, diagnostics } = await open(driver)
    expect((await post(browser, [["Origin", "https://evil.example"]])).status).toBe(403)
    expect(diagnostics).toEqual([])
  })
})
