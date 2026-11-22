// ADR 0024 Limits: TanStack Start's global request middleware must reach server functions as well as server routes.
// TanStack Start 1.169 runs `requestMiddleware` for every request, with `handlerType: "serverFn"` for a server function
// call to `/_serverFn/<id>`. These cases pin what test-cap's middleware does with such a call; the example's end-to-end
// test (test/examples/tanstack-start.test.ts) calls a real server function over HTTP on the built app.
import { readFileSync } from "node:fs"
import { createRequire } from "node:module"
import { describe, expect, it } from "vitest"
import {
  type TanstackStartContext,
  tanstackStartMiddleware,
} from "../../src/adapters/tanstack-start/index.js"
import { aal1, aal2, ORIGIN, seedSession, testAuth } from "../support/auth.js"

/** A server function call as TanStack Start's client sends it. */
function serverFnCall(cookie?: string): Request {
  const headers = new Headers({ "x-tsr-serverFn": "true", Origin: ORIGIN })
  if (cookie !== undefined) headers.set("Cookie", `__Host-test-cap=${cookie}`)
  return new Request(`${ORIGIN}/_serverFn/eyJmaWxlIjoiYmlsbGluZyJ9`, {
    method: "POST",
    headers,
    body: '{"data":{"invoice":"inv-1"}}',
  })
}

/** Runs the middleware for a server function call; records whether the server function ran, and with what. */
async function call(request: Request, publicPaths: readonly string[] = ["/"]) {
  const { auth } = testAuth()
  const ran: TanstackStartContext[] = []
  const middleware = tanstackStartMiddleware(auth, { public: publicPaths })
  const result = await middleware({
    request,
    next: (options) => {
      ran.push(options.context)
      return Promise.resolve({ response: new Response("ran") })
    },
  })
  const response = result instanceof Response ? result : result.response
  return { response, ran }
}

describe("server functions under the global middleware", () => {
  it("refuses a signed-out call before the server function runs", async () => {
    const { response, ran } = await call(serverFnCall())
    expect([response.status, await response.text()]).toEqual([401, '{"error":"unauthenticated"}'])
    expect(ran).toEqual([])
  })

  it("refuses a session below the default requirement with what it lacks", async () => {
    const setup = testAuth()
    const { token } = await seedSession(setup, { evidence: aal1(setup.clock) })
    const middleware = tanstackStartMiddleware(setup.auth)
    let ran = false
    const result = await middleware({
      request: serverFnCall(token),
      next: () => {
        ran = true
        return Promise.resolve({ response: new Response("ran") })
      },
    })
    expect(result).toBeInstanceOf(Response)
    expect([(result as Response).status, await (result as Response).text()]).toEqual([
      403,
      '{"error":"step-up"}',
    ])
    expect(ran).toBe(false)
  })

  it("runs the server function for a session at the default requirement, with its subject in the context", async () => {
    const setup = testAuth()
    const { token } = await seedSession(setup, { evidence: aal2(setup.clock) })
    const middleware = tanstackStartMiddleware(setup.auth, { public: ["/"] })
    const request = serverFnCall(token)
    const contexts: TanstackStartContext[] = []
    const result = await middleware({
      request,
      next: (options) => {
        contexts.push(options.context)
        return Promise.resolve({ response: new Response("ran") })
      },
    })
    expect(result).not.toBeInstanceOf(Response)
    expect(contexts).toEqual([{ auth: { subject: "acct-1" } }])
    // The server function's own deserializer reads the body, so the middleware leaves it unread.
    expect(request.bodyUsed).toBe(false)
  })

  it("was verified against the TanStack Start release this repository installs", () => {
    // The end-to-end test proves the ordering on this release; a different release must pass it again.
    const require = createRequire(import.meta.url)
    const manifest = JSON.parse(
      readFileSync(require.resolve("@tanstack/react-start/package.json"), "utf8"),
    ) as { version: string }
    expect(manifest.version).toBe("1.169.5")
  })
})
