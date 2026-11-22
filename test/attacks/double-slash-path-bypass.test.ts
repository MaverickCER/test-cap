// Attack: `//auth/sign-in` or an encoded path skips deny by default, a disabled route or a throttle key.
// Stopped by: the core reads the raw path and refuses any ambiguous one with a 400, for every request (ADR 0003, 0024).
import express from "express"
import { afterEach, describe, expect, it } from "vitest"
import { expressAuth } from "../../src/adapters/express/index.js"
import { Browser, PASSWORD, seedAccount, testAuth } from "../support/auth.js"
import { listen } from "../support/http.js"

const closers: (() => Promise<void>)[] = []
afterEach(async () => {
  await Promise.all(closers.splice(0).map((close) => close()))
})

describe("double-slash-path-bypass", () => {
  it.each([
    "//auth/sign-in",
    "/auth//sign-in",
    "/auth/sign-in/",
    "/auth/./sign-in",
    "/x/../auth/sign-in",
    "/auth%2Fsign-in",
    "/auth/sign%2Din",
    "//admin",
    "/%2Fadmin",
    "/admin//",
  ])("refuses %s with a 400, reaching neither a route nor a ceremony", async (path) => {
    const setup = testAuth()
    await seedAccount(setup, { password: true })
    let reached = 0
    const app = express()
    app.use(expressAuth(setup.auth, { public: ["/"] }))
    app.all("/{*any}", (_req, res) => {
      reached += 1
      res.send("reached")
    })
    const server = await listen(app)
    closers.push(server.close)
    const browser = new Browser(server.transport)
    await browser.start()
    const reply = await browser.post(path, { identifier: "ada@example.com", password: PASSWORD })
    expect([reply.status, reply.text]).toEqual([400, '{"error":"invalid-path"}'])
    expect(reached).toBe(0)
    expect(setup.events).toEqual([])
    expect(browser.cookies.has("__Host-test-cap")).toBe(false)
  })
})
