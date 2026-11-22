// Dependency: the random source (specs/dependency-failures.md, "The random source"; ADR 0003, ADR 0026 §4,
// ADR 0029). Outside test mode it is Web Crypto, and a custom source is refused at startup. Policy: fail closed. A
// source that throws, or that repeats itself, ends the request with the fixed 500: a token that collides with a
// stored one is never handed out, so no browser is given another's session.
import { describe, expect, it } from "vitest"
import { sequenceRandom, type RandomSource } from "../../src/core/clock.js"
import {
  Browser,
  expectOk,
  inProcess,
  PASSWORD,
  plainRequest,
  type Reply,
  seedAccount,
  testAuth,
} from "../support/auth.js"

/** A source that draws from Web Crypto until `fail` is called, then from `failing`. */
function switchable(failing: RandomSource) {
  let failed = false
  const source: RandomSource = {
    fill: (bytes) => (failed ? failing.fill(bytes) : crypto.getRandomValues(bytes)),
  }
  return {
    source,
    fail: () => {
      failed = true
    },
  }
}

const sessionCookies = (reply: Reply): string[] =>
  reply.headers.getSetCookie().filter((line) => line.startsWith("__Host-test-cap="))

const signIn = (browser: Browser) =>
  browser.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD })

describe("a random source that fails", () => {
  it("that throws: sign-in answers 500 and hands out no token", async () => {
    const random = switchable({
      fill() {
        throw new Error("no entropy")
      },
    })
    const setup = testAuth({ random: random.source })
    await seedAccount(setup, { password: true })
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    random.fail()
    const reply = await signIn(browser)
    expect([reply.status, reply.text]).toEqual([500, '{"error":"internal"}'])
    expect(sessionCookies(reply)).toEqual([])
  })

  it("that repeats itself: the sign-in whose token collides answers 500, and the first session stays its own", async () => {
    const random = switchable(sequenceRandom([7]))
    const setup = testAuth({ random: random.source })
    const { subject } = await seedAccount(setup, { password: true })
    const first = new Browser(inProcess(setup.auth))
    const second = new Browser(inProcess(setup.auth))
    await first.start()
    await second.start()
    random.fail()
    await expectOk(signIn(first))
    const reply = await signIn(second)
    expect([reply.status, reply.text]).toEqual([500, '{"error":"internal"}'])
    expect(sessionCookies(reply)).toEqual([])
    const cookie = `__Host-test-cap=${String(first.cookies.get("__Host-test-cap"))}`
    const request = plainRequest({ method: "GET", path: "/", headers: [["Cookie", cookie]] })
    expect((await setup.auth.session(request))?.subject).toBe(subject)
  })

  it("that only yields bytes the digit draw rejects: sign-up answers 500, sends nothing and issues no session", async () => {
    const random = switchable(sequenceRandom([250]))
    const setup = testAuth({ random: random.source })
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    random.fail()
    const reply = await browser.post("/auth/sign-up", { identifier: "ada@example.com" })
    expect([reply.status, reply.text]).toEqual([500, '{"error":"internal"}'])
    expect(sessionCookies(reply)).toEqual([])
    expect(setup.outbox).toEqual([])
  })
})
