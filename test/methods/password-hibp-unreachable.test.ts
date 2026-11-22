import { afterEach, describe, expect, it, vi } from "vitest"
import { HIBP_TIMEOUT_MS, type HibpFetch, screenWithHibp } from "../../src/methods/password/hibp.js"
import { normalisePassword } from "../../src/methods/password/rules.js"
import { within } from "../support/within.js"

const screen = (...args: Parameters<typeof screenWithHibp>) => within(screenWithHibp(...args))

const SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
const password = normalisePassword("password")

const answer =
  (body: string, status = 200): HibpFetch =>
  () =>
    Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      text: () => Promise.resolve(body),
    })

afterEach(() => {
  vi.useRealTimers()
})

describe("an unreachable HIBP is indeterminate, never a pass (ADR 0010 §3, Open 3)", () => {
  it("times out after 1.5 seconds", () => {
    expect(HIBP_TIMEOUT_MS).toBe(1_500)
  })

  it("is indeterminate when the request does not answer within the timeout, and aborts it", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] })
    let signal: AbortSignal | undefined
    const never: HibpFetch = (_url, init) => {
      signal = init.signal
      return new Promise(() => undefined)
    }
    let settled: string | undefined
    void screenWithHibp(password, never).then((result) => {
      settled = result
    })
    // The SHA-1 runs on Web Crypto, outside the fake clock; wait for the request by real turns of the event loop.
    for (const turn of Array.from({ length: 200 }, (_, index) => index)) {
      if (signal !== undefined) break
      await new Promise((resolve) => setImmediate(resolve, turn))
    }
    expect(signal).toBeDefined()
    await vi.advanceTimersByTimeAsync(HIBP_TIMEOUT_MS - 1)
    expect(settled).toBeUndefined()
    expect(signal?.aborted).toBe(false)
    await vi.advanceTimersByTimeAsync(1)
    expect(settled).toBe("indeterminate")
    expect(signal?.aborted).toBe(true)
  })

  it("leaves no timer behind when the answer comes in time", async () => {
    vi.useFakeTimers()
    expect(await screen(password, answer(`${SUFFIX}:2`))).toBe("breached")
    expect(vi.getTimerCount()).toBe(0)
  })

  it("is indeterminate when the request fails", async () => {
    const failing: HibpFetch = () => Promise.reject(new TypeError("fetch failed"))
    expect(await screen(password, failing)).toBe("indeterminate")
  })

  it("is indeterminate when reading the body fails", async () => {
    const broken: HibpFetch = () =>
      Promise.resolve({ ok: true, status: 200, text: () => Promise.reject(new Error("reset")) })
    expect(await screen(password, broken)).toBe("indeterminate")
  })

  it("is indeterminate on an error status, even with a matching body", async () => {
    expect(await screen(password, answer(`${SUFFIX}:2`, 503))).toBe("indeterminate")
    expect(await screen(password, answer(`${SUFFIX}:2`, 429))).toBe("indeterminate")
  })

  it("is indeterminate when the body holds no well-formed row, since a padded answer always has some", async () => {
    expect(await screen(password, answer(""))).toBe("indeterminate")
    expect(await screen(password, answer("<html>busy</html>"))).toBe("indeterminate")
    expect(await screen(password, answer(`${SUFFIX}:x`))).toBe("indeterminate")
    expect(await screen(password, answer(`${SUFFIX}:`))).toBe("indeterminate")
    expect(await screen(password, answer(`X${SUFFIX}:3`))).toBe("indeterminate")
    expect(await screen(password, answer(`${SUFFIX}:3x`))).toBe("indeterminate")
    expect(await screen(password, answer(`${SUFFIX.slice(1)}:3`))).toBe("indeterminate")
  })
})
