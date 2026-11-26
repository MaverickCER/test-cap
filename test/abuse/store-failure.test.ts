// Dependency failure (ADR 0009, success metric 16): when the store fails while the throttle reads or counts, the
// attempt fails closed with the fixed 500 and no session; a store failure never lets a guess through uncounted.
import { describe, expect, it } from "vitest"
import type { AuthStore } from "../../src/store/port.js"
import { memoryStore } from "../../src/store/memory.js"
import { account, Browser, inProcess, PASSWORD, testAuth } from "../support/auth.js"

/** The memory store, with `operation` failing once `failing` is switched on. */
function flaky(operation: "get" | "increment" | "createUnique") {
  const store = memoryStore()
  const state = { failing: false }
  const wrapped: AuthStore = Object.create(store) as AuthStore
  const original = store[operation].bind(store) as (...args: never[]) => Promise<unknown>
  Object.assign(wrapped, {
    [operation]: (...args: never[]) =>
      state.failing ? Promise.reject(new Error(`store down: ${operation}`)) : original(...args),
  })
  return { store: wrapped, state }
}

describe("store failure under the throttle", () => {
  it.each(["get", "increment"] as const)(
    "answers 500 and issues no session when %s fails",
    async (operation) => {
      const { store, state } = flaky(operation)
      const setup = testAuth({ store })
      await account(setup)
      const browser = new Browser(inProcess(setup.auth))
      await browser.start()
      state.failing = true
      const reply = await browser.post("/auth/sign-in", {
        identifier: "ada@example.com",
        password: operation === "get" ? PASSWORD : "wrong password entirely",
      })
      expect([reply.status, reply.text]).toEqual([500, '{"error":"internal"}'])
      expect(
        reply.headers.getSetCookie().some((cookie) => cookie.startsWith("__Host-test-cap=")),
      ).toBe(false)
    },
  )

  it("answers 500 when writing a block fails, and the next attempt is still throttled once the store is back", async () => {
    const { store, state } = flaky("createUnique")
    const setup = testAuth({ store })
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    const fail = () =>
      browser.post("/auth/sign-in", {
        identifier: "ada@example.com",
        password: "wrong password entirely",
      })
    for (let i = 0; i < 5; i += 1) expect((await fail()).status).toBe(401)
    state.failing = true
    expect((await fail()).status).toBe(500)
    state.failing = false
    // The sixth attempt took the key's slot for its block before the block's write was lost, so the seventh is still
    // refused for that block's span; after it, the eighth is checked and blocks again, and the ninth is refused.
    expect((await fail()).status).toBe(429)
    setup.clock.advance(1_000)
    expect((await fail()).status).toBe(401)
    expect((await fail()).status).toBe(429)
  })
})
