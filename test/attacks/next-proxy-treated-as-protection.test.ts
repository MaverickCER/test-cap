// Attack: a Next.js route or server function is reached directly because only `proxy` checked the session.
// Stopped by: `proxy` is for optimistic redirects only; the server helpers are authoritative (ADR 0024 §4). The proxy
// passes what it cannot judge, and the helper next to the data refuses it.
import { describe, expect, it } from "vitest"
import { nextProxy, nextServerAuth } from "../../src/adapters/next/index.js"
import { aal1, aal2, seedSession, testAuth } from "../support/auth.js"
import { webRequest } from "../support/fetch.js"

/** A protected route as the Next.js example writes it: the helper first, the data only on allow. */
function billingRoute(setup: ReturnType<typeof testAuth>) {
  return async (req: Request): Promise<Response> => {
    const serverAuth = nextServerAuth(setup.auth, { headers: () => Promise.resolve(req.headers) })
    const result = await serverAuth.require()
    if (result.outcome !== "allow") {
      return Response.json(
        { error: result.outcome },
        { status: result.outcome === "unauthenticated" ? 401 : 403 },
      )
    }
    return Response.json({ invoices: ["inv-1"] })
  }
}

/** A request through the proxy and then the route, as Next.js runs them when the proxy's matcher covers the path. */
async function viaProxy(setup: ReturnType<typeof testAuth>, req: Request): Promise<Response> {
  return nextProxy(setup.auth, { public: ["/"] })(req) ?? billingRoute(setup)(req)
}

const request = (cookie?: string) =>
  webRequest({
    method: "GET",
    path: "/billing",
    headers: cookie === undefined ? [] : [["Cookie", cookie]],
  })

describe("next-proxy-treated-as-protection", () => {
  it("a forged session cookie passes the proxy, and the server helper refuses it", async () => {
    const setup = testAuth()
    const forged = "__Host-test-cap=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    expect(nextProxy(setup.auth, { public: ["/"] })(request(forged))).toBeUndefined()
    const response = await viaProxy(setup, request(forged))
    expect([response.status, await response.text()]).toEqual([401, '{"error":"unauthenticated"}'])
  })

  it("a revoked session passes the proxy, and the server helper refuses it at once", async () => {
    const setup = testAuth()
    const { token } = await seedSession(setup, { evidence: aal2(setup.clock) })
    await setup.auth.admin.revoke("acct-1")
    const response = await viaProxy(setup, request(`__Host-test-cap=${token}`))
    expect(response.status).toBe(401)
  })

  it("a session below the requirement passes the proxy, and the server helper asks for a step-up", async () => {
    const setup = testAuth()
    const { token } = await seedSession(setup, { evidence: aal1(setup.clock) })
    const response = await viaProxy(setup, request(`__Host-test-cap=${token}`))
    expect([response.status, await response.text()]).toEqual([403, '{"error":"step-up"}'])
  })

  it("a route the proxy's matcher misses is still refused by the server helper", async () => {
    const setup = testAuth()
    const response = await billingRoute(setup)(request())
    expect(response.status).toBe(401)
  })

  it("only a session meeting the requirement reaches the data", async () => {
    const setup = testAuth()
    const { token } = await seedSession(setup, { evidence: aal2(setup.clock) })
    const response = await viaProxy(setup, request(`__Host-test-cap=${token}`))
    expect([response.status, await response.json()]).toEqual([200, { invoices: ["inv-1"] }])
  })
})
