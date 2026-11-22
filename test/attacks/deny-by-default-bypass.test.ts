// Attack: a protected route is reached through a trailing slash, case, encoding or HEAD / OPTIONS.
// Stopped by: ambiguous paths refused with a 400 for every method; public paths match only clean raw paths, exactly or
// by an explicit wildcard (ADR 0003, 0024).
import express from "express"
import { afterEach, describe, expect, it } from "vitest"
import { expressAuth } from "../../src/adapters/express/index.js"
import { Browser, testAuth } from "../support/auth.js"
import { listen } from "../support/http.js"

const closers: (() => Promise<void>)[] = []
afterEach(async () => {
  await Promise.all(closers.splice(0).map((close) => close()))
})

async function protectedApp() {
  const { auth } = testAuth()
  let reached = 0
  const app = express()
  app.use(expressAuth(auth, { public: ["/about", "/docs/*"] }))
  app.all("/{*any}", (_req, res) => {
    reached += 1
    res.send("reached")
  })
  const server = await listen(app)
  closers.push(server.close)
  return { browser: new Browser(server.transport), reached: () => reached }
}

describe("deny-by-default-bypass", () => {
  it.each([
    "/admin/",
    "/about/../admin",
    "/docs/../admin",
    "/docs/%2e%2e/admin",
    "/about/%2Fadmin",
    "/admin\\x",
  ])("refuses the ambiguous path %s with a 400 before any route", async (path) => {
    const { browser, reached } = await protectedApp()
    expect((await browser.get(path)).status).toBe(400)
    expect(reached()).toBe(0)
  })

  it.each(["/admin", "/ADMIN", "/About", "/adm%69n", "/ab%6Fut", "/docs", "/aboutx"])(
    "keeps %s protected: a public entry matches only its own clean raw path",
    async (path) => {
      const { browser, reached } = await protectedApp()
      const reply = await browser.get(path)
      expect([reply.status, reply.text]).toEqual([401, '{"error":"unauthenticated"}'])
      expect(reached()).toBe(0)
    },
  )

  it.each(["HEAD", "OPTIONS", "POST", "DELETE", "PATCH"])(
    "protects %s exactly as GET",
    async (method) => {
      const { browser, reached } = await protectedApp()
      expect((await browser.send({ method, path: "/admin" })).status).toBe(401)
      expect((await browser.send({ method, path: "/admin/" })).status).toBe(400)
      expect(reached()).toBe(0)
    },
  )

  it("lets only the listed public paths through", async () => {
    const { browser, reached } = await protectedApp()
    expect((await browser.get("/about")).text).toBe("reached")
    expect((await browser.get("/docs/intro")).text).toBe("reached")
    expect(reached()).toBe(2)
  })
})
