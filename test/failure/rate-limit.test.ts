// The request limiter's counter fails (specs/dependency-failures.md, "The request limiter"): the store's `increment`
// or the app's rate-limiter-flexible limiter throws, rejects, times out or never answers. The limiter fails closed: the request ends
// with the fixed 500 before its route runs, so nothing is created, issued or sent.
import { describe, expect, it } from "vitest"
import type { RateLimiterLike } from "../../src/security/rate-limit.js"
import { Browser, testAuth } from "../support/auth.js"
import { type FaultMode, faultyStore, STORE_DOWN } from "../support/faulty-store.js"
import { sendFrom } from "../support/requests.js"

const MODES: readonly FaultMode[] = ["throw", "reject", "timeout"]

/** A limiter that fails as `mode` says. */
function failingLimiter(mode: FaultMode): RateLimiterLike {
  const limiter = {
    consume() {
      if (mode === "throw") throw new Error(STORE_DOWN)
      if (mode === "reject") return Promise.reject(new Error(STORE_DOWN))
      if (mode === "timeout") {
        return new Promise((_, reject) => {
          setTimeout(() => {
            reject(new Error(STORE_DOWN))
          }, 2)
        })
      }
      return new Promise(() => undefined)
    },
  }
  return limiter as unknown as RateLimiterLike
}

/** Signs up through a browser whose token was fetched while the counter still worked. */
async function signUpWith(setup: ReturnType<typeof testAuth>, arm: () => void) {
  const browser = new Browser(sendFrom(setup.auth))
  await browser.start()
  arm()
  return browser.post("/auth/sign-up", { identifier: "ada@example.com" })
}

describe("the request limiter when its counter fails", () => {
  it("ends sign-up with the fixed 500 before an account exists when the store's increment fails", async () => {
    for (const mode of MODES) {
      const faulty = faultyStore()
      const setup = testAuth({ store: faulty.store })
      const reply = await signUpWith(setup, () => {
        faulty.arm({ op: "increment", call: 1, mode })
      })
      expect([reply.status, reply.text], mode).toEqual([500, '{"error":"internal"}'])
      expect(reply.headers.getSetCookie(), mode).toEqual([])
      expect(faulty.calls(), mode).toEqual(["increment"])
      expect(setup.outbox, mode).toEqual([])
      expect(setup.events, mode).toEqual([])
    }
  })

  it("ends a request, and a page, with the fixed 500 when the app's limiter fails", async () => {
    for (const mode of MODES) {
      const setup = testAuth({ rateLimit: failingLimiter(mode) })
      const send = sendFrom(setup.auth)
      const signUp = await send({ method: "POST", path: "/auth/sign-up" })
      const page = await send({ method: "GET", path: "/auth/sign-in" })
      expect([signUp.status, signUp.text], mode).toEqual([500, '{"error":"internal"}'])
      expect([page.status, page.text], mode).toEqual([500, '{"error":"internal"}'])
      expect(setup.events, mode).toEqual([])
    }
  })

  it("leaves a request pending, with nothing created, when the counter never answers", async () => {
    const setup = testAuth({ rateLimit: failingLimiter("hang") })
    const pending = sendFrom(setup.auth)({ method: "POST", path: "/auth/sign-up" })
    const settled = await Promise.race([
      pending.then(() => "answered"),
      new Promise((resolve) => {
        setTimeout(() => {
          resolve("pending")
        }, 20)
      }),
    ])
    expect(settled).toBe("pending")
    expect(setup.outbox).toEqual([])
  })

  it("lets requests through again once the counter works", async () => {
    let failing = true
    const limiter = {
      consume: () =>
        failing
          ? Promise.reject(new Error(STORE_DOWN))
          : Promise.resolve({ msBeforeNext: 0, remainingPoints: 1 }),
    } as unknown as RateLimiterLike
    const { auth } = testAuth({ rateLimit: limiter })
    const send = sendFrom(auth)
    expect((await send({ method: "GET", path: "/auth/session" })).status).toBe(500)
    failing = false
    expect((await send({ method: "GET", path: "/auth/session" })).status).toBe(200)
  })
})
