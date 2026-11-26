// Attack: one client sends requests to the auth routes as fast as it can: in parallel, so that each request reads the
// count before any other has written it, or from address after address of the IPv6 /64 it holds.
// Stopped by: every request is counted with the store's atomic `increment` before the route runs, under the client
// key the throttle uses (an IPv4 address or an IPv6 /64), so a parallel burst gets the rule's count and no more, and
// rotation inside a /64 changes nothing (ADR 0009 §8; Better Auth GHSA-p6v2-xcpg-h6xw, GHSA-44jh-23m7-hpcf).
import { describe, expect, it } from "vitest"
import { testAuth } from "../support/auth.js"
import { sendFrom } from "../support/requests.js"

const SIGN_IN = { method: "POST", path: "/auth/sign-in" }

describe("request-flooding", () => {
  it("lets through exactly the rule's count of a parallel burst from one client", async () => {
    const { auth } = testAuth()
    const send = sendFrom(auth)
    const replies = await Promise.all(Array.from({ length: 40 }, () => send(SIGN_IN)))
    const statuses = replies.map((reply) => reply.status)
    expect(statuses.filter((status) => status !== 429)).toHaveLength(10)
    expect(statuses.filter((status) => status === 429)).toHaveLength(30)
  })

  it("lets through exactly 100 of a parallel burst on a route with the default rule", async () => {
    const { auth } = testAuth()
    const send = sendFrom(auth)
    const replies = await Promise.all(
      Array.from({ length: 150 }, () => send({ method: "GET", path: "/auth/session" })),
    )
    expect(replies.filter((reply) => reply.status === 200)).toHaveLength(100)
  })

  it("counts every address of one IPv6 /64 as one client, in any spelling", async () => {
    const { auth } = testAuth()
    const seen: number[] = []
    for (let n = 0; n < 11; n += 1) {
      const address =
        n % 2 === 0 ? `2001:db8:a:b::${(n + 1).toString(16)}` : `2001:0DB8:000a:000b:0:0:0:${n + 1}`
      seen.push((await sendFrom(auth, address)(SIGN_IN)).status)
    }
    expect(seen.slice(0, 10).every((status) => status !== 429)).toBe(true)
    expect(seen[10]).toBe(429)
    expect((await sendFrom(auth, "2001:db8:a:c::1")(SIGN_IN)).status).not.toBe(429)
  })

  it("counts an IPv4 address and its IPv4-mapped IPv6 form as one client", async () => {
    const { auth } = testAuth()
    for (let n = 0; n < 5; n += 1) await sendFrom(auth, "192.0.2.9")(SIGN_IN)
    for (let n = 0; n < 5; n += 1) await sendFrom(auth, "::ffff:192.0.2.9")(SIGN_IN)
    expect((await sendFrom(auth, "192.0.2.9")(SIGN_IN)).status).toBe(429)
  })

  it("never lets a forged X-Forwarded-For pick the client without a trusted proxy", async () => {
    const { auth } = testAuth()
    const send = sendFrom(auth)
    const seen: number[] = []
    for (let n = 0; n < 11; n += 1) {
      const forged = { ...SIGN_IN, headers: [["X-Forwarded-For", `198.51.100.${n}`]] as const }
      seen.push((await send(forged)).status)
    }
    expect(seen[10]).toBe(429)
  })
})
