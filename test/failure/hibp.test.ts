// Dependency: the HIBP range API, reached through the app's `hibpFetch` (specs/dependency-failures.md, "HIBP";
// ADR 0010, ADR 0029). Policy: degraded and recorded. When HIBP is down, slow, failing or unreadable, a new password
// is still screened by the bundled blocklist and stored with the screening `indeterminate`, never `clear`; sign-in
// never calls HIBP, so an outage changes no sign-in.
import { describe, expect, it, vi } from "vitest"
import { HIBP_TIMEOUT_MS, type HibpFetch } from "../../src/methods/password/hibp.js"
import { PASSWORD_COLLECTION } from "../../src/methods/password/method.js"
import {
  Browser,
  confirmEmail,
  expectOk,
  hibpClear,
  inProcess,
  PASSWORD,
  TENANT,
  testAuth,
} from "../support/auth.js"

// The slow case waits out the real 1.5-second HIBP timeout once, behind the shared argon2id semaphore.
vi.setConfig({ testTimeout: 10_000 })

const OUTAGES: readonly (readonly [string, HibpFetch])[] = [
  ["is unreachable", () => Promise.reject(new TypeError("getaddrinfo ENOTFOUND"))],
  [
    "answers 503",
    () => Promise.resolve({ ok: false, status: 503, text: () => Promise.resolve("") }),
  ],
  [
    "answers a body that is not a range",
    () =>
      Promise.resolve({ ok: true, status: 200, text: () => Promise.resolve("<html>busy</html>") }),
  ],
  ["never answers", () => new Promise(() => undefined)],
]

/** A browser that signed up and confirmed its address, about to choose a password. */
async function choosing(hibpFetch: HibpFetch) {
  const setup = testAuth({ hibpFetch })
  const browser = new Browser(inProcess(setup.auth))
  await browser.start()
  await expectOk(browser.post("/auth/sign-up", { identifier: "ada@example.com" }))
  await confirmEmail(browser, setup.outbox)
  const subject = ((await browser.get("/auth/session")).json as { session: { subject: string } })
    .session.subject
  return { setup, browser, subject }
}

describe("an HIBP outage", () => {
  it.each(OUTAGES)(
    "that %s: the password is stored as indeterminate, never clear, and the session stays enrolling",
    async (_how, hibpFetch) => {
      const { setup, browser, subject } = await choosing(hibpFetch)
      const started = Date.now()
      const reply = await browser.post("/auth/password", { password: PASSWORD })
      expect(Date.now() - started).toBeLessThan(HIBP_TIMEOUT_MS + 2_000)
      expect([reply.status, reply.text]).toEqual([
        200,
        '{"outcome":"enroll","enrolled":["password"]}',
      ])
      const stored = await setup.store.get(TENANT, PASSWORD_COLLECTION, subject)
      expect((stored?.data as { screening: string }).screening).toBe("indeterminate")
      expect(
        ((await browser.get("/auth/session")).json as { session: { level: unknown } }).session
          .level,
      ).toBeNull()
    },
  )

  it("still refuses a bundled common password while HIBP is down", async () => {
    const { browser } = await choosing(() => Promise.reject(new TypeError("fetch failed")))
    const reply = await browser.post("/auth/password", { password: "iloveyou1" })
    expect([reply.status, reply.text]).toEqual([400, '{"error":"too-common"}'])
  })

  it("is never called by sign-in, so an outage changes no sign-in", async () => {
    let calls = 0
    const counting: HibpFetch = (...args) => {
      calls += 1
      return hibpClear(...args)
    }
    const { setup, browser } = await choosing(counting)
    await expectOk(browser.post("/auth/password", { password: PASSWORD }))
    expect(calls).toBe(1)
    const fresh = new Browser(inProcess(setup.auth))
    await fresh.start()
    const reply = await fresh.post("/auth/sign-in", {
      identifier: "ada@example.com",
      password: PASSWORD,
    })
    expect([reply.status, reply.text]).toEqual([200, '{"outcome":"step-up","returnTo":"/"}'])
    expect(calls).toBe(1)
  })
})
