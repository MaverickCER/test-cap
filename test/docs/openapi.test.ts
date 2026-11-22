// The API reference (docs/api-reference/) reads docs/api-reference/openapi.json. This test builds that document from
// the dispatcher's own route table and fails when a route is missing from scripts/openapi/routes.ts, when that table
// names a route the dispatcher does not serve, or when the committed file is stale (`npm run docs:openapi` rewrites it).
import { readFileSync } from "node:fs"
import path from "node:path"
import { describe, expect, it } from "vitest"
import { createAuth, type Auth } from "../../src/core/auth.js"
import { internalsOf } from "../../src/core/auth.js"
import { memoryStore } from "../../src/store/memory.js"
import { buildOpenApi } from "../../scripts/openapi/document.js"
import { ROUTE_DOCS } from "../../scripts/openapi/routes.js"
import { ENV, discardEmail, hibpClear } from "../support/auth.js"
import { TEST_ARGON2_COST } from "../support/argon2.js"

const root = path.resolve(import.meta.dirname, "../..")
/** A fresh `Auth`, built inside each test so a mutant in `createAuth` is live when the test reads it. */
const fresh = (): Auth =>
  createAuth({
    store: memoryStore(),
    env: ENV,
    hibpFetch: hibpClear,
    sendEmail: discardEmail,
    argon2Cost: TEST_ARGON2_COST,
  })
const routeTable = () => internalsOf(fresh()).routes()
const { version } = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")) as {
  version: string
}

describe("the OpenAPI document of /auth/*", () => {
  it("documents exactly the routes the dispatcher serves", () => {
    const routes = routeTable()
    expect(Object.keys(ROUTE_DOCS).sort()).toStrictEqual(routes.map((route) => route.path).sort())
  })

  it("gives a body field list for each POST route and none for a GET route", () => {
    const routes = routeTable()
    for (const route of routes.filter((each) => each.method === "GET")) {
      expect(route.fields, route.path).toStrictEqual({})
    }
    expect(routes.find((route) => route.path === "/auth/sign-in")?.fields).toStrictEqual({
      identifier: true,
      password: true,
      returnTo: false,
    })
  })

  it("lists every route the dispatcher answers, and the dispatcher answers 404 for no route it lists", async () => {
    const auth = fresh()
    const routes = internalsOf(auth).routes()
    expect(routes.length).toBeGreaterThan(0)
    for (const route of routes) {
      const reply = await auth.handle({
        method: route.method,
        url: `${ENV.APP_ORIGIN}${route.path}`,
        headers: new Headers(),
        body: null,
      })
      expect(reply?.status, route.path).not.toBe(404)
    }
    const unknown = await auth.handle({
      method: "GET",
      url: `${ENV.APP_ORIGIN}/auth/not-a-route`,
      headers: new Headers(),
      body: null,
    })
    expect(unknown?.status).toBe(404)
  })

  it("refuses to build when a route has no documentation", () => {
    const routes = routeTable()
    const rest = Object.fromEntries(
      Object.entries(ROUTE_DOCS).filter(([route]) => route !== "/auth/sign-in"),
    )
    expect(() => buildOpenApi(routes, rest, version)).toThrow(
      "/auth/sign-in has no entry in scripts/openapi/routes.ts.",
    )
  })

  it("matches the committed docs/api-reference/openapi.json", async () => {
    const routes = routeTable()
    const document = `${JSON.stringify(buildOpenApi(routes, ROUTE_DOCS, version), null, 2)}\n`
    await expect(document).toMatchFileSnapshot(path.join(root, "docs/api-reference/openapi.json"))
  })
})
