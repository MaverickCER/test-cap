// Attack: a hijacked session adds an authenticator or makes recovery codes without re-authenticating. Stopped by:
// credential changes need a multi-factor ceremony within the last 15 minutes (ADR 0005).
import { describe, expect, it } from "vitest"
import { CREDENTIAL_CHANGE_WITHIN_MS } from "../../src/core/dispatcher.js"
import { aal2, Browser, PASSWORD, seedAccount, seedSession, testAuth } from "../support/auth.js"
import { codeAt } from "../support/totp.js"
import { within } from "../support/within.js"

describe("sensitive-change-without-reauth", () => {
  it("refuses a new authenticator and new recovery codes on a session whose last multi-factor ceremony is stale", async () => {
    const setup = testAuth()
    const { browser } = await seedSession(setup, { subject: "acct-1", evidence: aal2(setup.clock) })
    setup.clock.advance(CREDENTIAL_CHANGE_WITHIN_MS + 1)
    const expected = {
      error: "step-up",
      missing: [{ kind: "fresh-multi-factor", withinMs: CREDENTIAL_CHANGE_WITHIN_MS }],
    }
    for (const path of ["/auth/totp/enrol", "/auth/recovery-codes"]) {
      const reply = await browser.post(path)
      expect([reply.status, reply.json], path).toEqual([403, expected])
    }
  })

  it("allows them on a session whose multi-factor ceremony is recent", async () => {
    const setup = testAuth()
    const { browser } = await seedSession(setup, { subject: "acct-1", evidence: aal2(setup.clock) })
    expect((await browser.post("/auth/recovery-codes")).status).toBe(200)
  })
})

describe("sensitive-change-without-reauth: what restores the proof", () => {
  /** A stale AAL2 session of an account with a password and TOTP, and the TOTP secret. */
  async function stale(setup: ReturnType<typeof testAuth>) {
    const { subject, secret } = await seedAccount(setup, { password: true, totp: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal2(setup.clock) })
    setup.clock.advance(CREDENTIAL_CHANGE_WITHIN_MS + 1)
    return { browser, secret: secret as string }
  }

  async function stepUp(
    browser: Browser,
    secret: { readonly password: string } | { readonly code: string },
  ) {
    const started = await within(browser.post("/auth/step-up/start"))
    const { challenge } = started.json as { challenge: string }
    return within(browser.post("/auth/step-up", { challenge, ...secret }))
  }

  it("leaves it stale after a step-up with a code alone, which proves one factor", async () => {
    const setup = testAuth()
    const { browser, secret } = await stale(setup)
    expect((await stepUp(browser, { code: await codeAt(secret, setup.clock.now()) })).status).toBe(
      200,
    )
    expect((await within(browser.post("/auth/recovery-codes"))).status).toBe(403)
  })

  it("restores it after a step-up with the password, then one with a code", async () => {
    const setup = testAuth()
    const { browser, secret } = await stale(setup)
    await stepUp(browser, { password: PASSWORD })
    await stepUp(browser, { code: await codeAt(secret, setup.clock.now()) })
    expect((await within(browser.post("/auth/recovery-codes"))).status).toBe(200)
  })

  it("restores it after signing in again: the password, then the code", async () => {
    const setup = testAuth()
    const { browser, secret } = await stale(setup)
    await within(
      browser.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD }),
    )
    await within(
      browser.post("/auth/totp/verify", { code: await codeAt(secret, setup.clock.now()) }),
    )
    expect((await within(browser.post("/auth/recovery-codes"))).status).toBe(200)
  })
})
