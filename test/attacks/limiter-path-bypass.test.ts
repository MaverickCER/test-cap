// Attack: once its budget on a route is spent, a client spells the route's path another way (a trailing slash,
// another letter case, percent-encoding, a doubled slash, a dot segment, or the prefix a gateway adds) so that the
// limiter keys the request differently while the router still runs the route (Better Auth GHSA-x732-6j76-qmhm).
// Stopped by: the limiter keys each request by the route the dispatcher will run, decided on the same raw path the
// dispatcher routes on, never on a normalised copy. Every ambiguous spelling is refused with a 400 before anything is
// counted or run, an unknown spelling is a 404 under one shared key, a path outside the base path is not answered,
// and a query, fragment or absolute-form URL is the same route under the same key (ADR 0003 §2, ADR 0009 §8).
import { describe, expect, it } from "vitest"
import { Browser, testAuth as baseAuth } from "../support/auth.js"
import { CLIENT, sendFrom } from "../support/requests.js"

/**
 * An Auth with the guessing throttle off, so every refusal here is the request limiter's: with it on, the sixth wrong
 * password from one client would be the throttle's 429 instead.
 */
const testAuth = (config: Parameters<typeof baseAuth>[0] = {}) =>
  baseAuth({ throttle: false, ...config })

const BODY = { identifier: "ada@example.com", password: "a wrong password" }

/** Spellings that are not the sign-in route, and the status each gets whatever the budget. */
const OTHER_SPELLINGS: readonly (readonly [string, number])[] = [
  ["/auth/sign-in/", 400],
  ["/auth//sign-in", 400],
  ["//auth/sign-in", 400],
  ["/auth/./sign-in", 400],
  ["/auth/x/../sign-in", 400],
  ["/auth/sign%2Din", 400],
  ["/auth/%73ign-in", 400],
  ["/auth/sign-in%2F", 400],
  ["/auth/sign-in\\", 400],
  ["/auth/Sign-In", 404],
  ["/auth/SIGN-IN", 404],
  ["/auth/sign-in;a=b", 404],
  ["/AUTH/sign-in", 0],
  ["/Auth/sign-in", 0],
]

/** Spellings that are the sign-in route, so they must count under its rule. */
const SAME_ROUTE = [
  "/auth/sign-in?x=1",
  "/auth/sign-in?",
  "/auth/sign-in#top",
  "https://app.example/auth/sign-in",
  "https://evil.example/auth/sign-in",
]

/** A browser holding a synchronizer token, sending from one client. */
async function browserFor(auth: ReturnType<typeof testAuth>["auth"]) {
  const browser = new Browser(sendFrom(auth, CLIENT))
  await browser.start()
  return browser
}

describe("limiter-path-bypass", () => {
  it("never runs the sign-in route for another spelling of its path, before or after the budget is spent", async () => {
    const { auth } = testAuth()
    const browser = await browserFor(auth)
    for (const [path, status] of OTHER_SPELLINGS) {
      expect((await browser.post(path, BODY)).status, path).toBe(status)
    }
    for (let n = 0; n < 10; n += 1) {
      expect((await browser.post("/auth/sign-in", BODY)).status).toBe(401)
    }
    expect((await browser.post("/auth/sign-in", BODY)).status).toBe(429)
    for (const [path, status] of OTHER_SPELLINGS) {
      expect((await browser.post(path, BODY)).status, path).toBe(status)
    }
  })

  it("counts every spelling that does reach the route under the route's own rule", async () => {
    const { auth } = testAuth()
    const browser = await browserFor(auth)
    for (let n = 0; n < 10; n += 1)
      await browser.post(SAME_ROUTE[n % SAME_ROUTE.length] as string, BODY)
    expect((await browser.post("/auth/sign-in", BODY)).status).toBe(429)
    for (const path of SAME_ROUTE) {
      expect((await browser.post(path, BODY)).status, path).toBe(429)
    }
  })

  it("counts spellings no route has under one shared key, so they cannot mint fresh counters", async () => {
    const { auth } = testAuth()
    const send = sendFrom(auth)
    const seen: number[] = []
    for (let n = 0; n < 101; n += 1)
      seen.push((await send({ method: "GET", path: `/auth/x${n}` })).status)
    expect(seen.slice(0, 100).every((status) => status === 404)).toBe(true)
    expect(seen[100]).toBe(429)
  })

  it("answers nothing for the gateway's prefixed path, so the prefix is no way around the rule", async () => {
    const { auth } = testAuth({ publicBasePath: "/accounts" })
    const browser = await browserFor(auth)
    for (let n = 0; n < 10; n += 1) await browser.post("/auth/sign-in", BODY)
    expect((await browser.post("/auth/sign-in", BODY)).status).toBe(429)
    for (const path of [
      "/accounts/auth/sign-in",
      "/accounts//auth/sign-in",
      "/Accounts/auth/sign-in",
    ]) {
      expect((await browser.post(path, BODY)).status, path).not.toBe(401)
    }
    expect((await browser.post("/accounts/auth/sign-in", BODY)).status).toBe(0)
  })

  it("never runs the route for another method, and counts it under the shared key", async () => {
    const { auth } = testAuth()
    const send = sendFrom(auth)
    for (let n = 0; n < 10; n += 1) await send({ method: "POST", path: "/auth/sign-in" })
    expect((await send({ method: "POST", path: "/auth/sign-in" })).status).toBe(429)
    for (const method of ["PUT", "PATCH", "DELETE", "post"]) {
      expect((await send({ method, path: "/auth/sign-in" })).status, method).toBe(405)
    }
  })
})
