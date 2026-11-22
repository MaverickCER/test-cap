// Dependency: the app's event sink, `onEvent` (specs/dependency-failures.md, "The event sink"; ADR 0015 §3,
// ADR 0029). Policy: degraded, never changing an outcome. test-cap hands each event over without waiting, so a sink
// that throws, rejects or never answers changes no reply; the event is lost to the app, not to the outcome.
import { describe, expect, it } from "vitest"
import type { EventSink } from "../../src/ocsf/events.js"
import { aal1, seedAccount, seedSession, testAuth } from "../support/auth.js"
import { codeAt } from "../support/totp.js"
import { within } from "../support/within.js"

const SINKS: readonly (readonly [string, EventSink])[] = [
  [
    "throws",
    () => {
      throw new Error("log pipeline down")
    },
  ],
  ["rejects", () => Promise.reject(new Error("log pipeline down"))],
  ["never answers", () => new Promise<void>(() => undefined)],
]

describe("an event sink that fails", () => {
  it.each(SINKS)(
    "that %s: the second factor still answers at once with the level it proved",
    async (_how, onEvent) => {
      const setup = testAuth({ onEvent })
      const { subject, secret } = await seedAccount(setup, { password: true, totp: true })
      const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
      const code = await codeAt(String(secret), setup.clock.now())
      const reply = await within(browser.post("/auth/totp/verify", { code }))
      expect([reply.status, (reply.json as { outcome: string }).outcome]).toEqual([200, "allow"])
    },
  )

  it.each(SINKS)("that %s: a wrong code is still refused", async (_how, onEvent) => {
    const setup = testAuth({ onEvent })
    const { subject } = await seedAccount(setup, { password: true, totp: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    const reply = await within(browser.post("/auth/totp/verify", { code: "000000" }))
    expect([reply.status, reply.text]).toEqual([401, '{"error":"invalid-code"}'])
  })
})
