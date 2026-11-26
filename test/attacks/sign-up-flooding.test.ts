// Attack: one client calls sign-up in a loop. Each call would create an account record, begin a pre-auth session and
// emit an event, so the store fills with records nobody will confirm.
// Stopped by: the request limiter counts sign-up per client (an IPv4 address or an IPv6 /64), 20 an hour by default,
// before the route runs. The 21st call answers 429 before any account, session or event exists (ADR 0009 §8).
import { describe, expect, it } from "vitest"
import { ACCOUNT_COLLECTION } from "../../src/core/accounts.js"
import { SESSION_COLLECTION } from "../../src/sessions/sessions.js"
import { Browser, testAuth } from "../support/auth.js"
import { recordingStore, sendFrom } from "../support/requests.js"

/** A full browser sign-up from `clientAddress`; resolves to the reply's status. */
async function signUp(auth: ReturnType<typeof testAuth>["auth"], n: number, clientAddress: string) {
  const browser = new Browser(sendFrom(auth, clientAddress))
  await browser.start()
  return (await browser.post("/auth/sign-up", { identifier: `bot${n}@example.com` })).status
}

describe("sign-up-flooding", () => {
  it("refuses the 21st sign-up from one client in an hour before any account row exists", async () => {
    const recorded = recordingStore()
    const count = (collection: string) =>
      recorded.created.filter((each) => each === collection).length
    const setup = testAuth({ store: recorded.store })
    const seen: number[] = []
    for (let n = 0; n < 25; n += 1) seen.push(await signUp(setup.auth, n, "198.51.100.4"))
    expect(seen).toEqual([...Array<number>(20).fill(200), ...Array<number>(5).fill(429)])
    expect(count(ACCOUNT_COLLECTION)).toBe(20)
    expect(count(SESSION_COLLECTION)).toBe(20)
    expect(setup.outbox).toHaveLength(20)
  })

  it("counts every address of one IPv6 /64 as one client", async () => {
    const { auth } = testAuth()
    const seen: number[] = []
    for (let n = 0; n < 21; n += 1)
      seen.push(await signUp(auth, n, `2001:db8:5:6::${(n + 1).toString(16)}`))
    expect(seen.at(-1)).toBe(429)
    expect(seen.slice(0, 20).every((status) => status === 200)).toBe(true)
    expect(await signUp(auth, 99, "2001:db8:5:7::1")).toBe(200)
  })

  it("lets another client sign up while one is refused, and the first again after the hour", async () => {
    const setup = testAuth()
    for (let n = 0; n < 20; n += 1) await signUp(setup.auth, n, "198.51.100.4")
    expect(await signUp(setup.auth, 20, "198.51.100.4")).toBe(429)
    expect(await signUp(setup.auth, 21, "198.51.100.5")).toBe(200)
    setup.clock.advance(60 * 60_000)
    expect(await signUp(setup.auth, 22, "198.51.100.4")).toBe(200)
  })
})
