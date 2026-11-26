// Attack: an attacker fails sign-in on purpose to lock the owner out. Stopped by: throttling never disables an account
// (ADR 0009 §1), and the failure ceiling stops only the authenticator that failed (§3); the account's other
// authenticators keep working.
import { describe, expect, it } from "vitest"
import {
  account,
  aal1,
  Browser,
  inProcess,
  PASSWORD,
  seedSession,
  testAuth,
} from "../support/auth.js"
import { codeAt } from "../support/totp.js"

describe("lockout-denial-of-service", () => {
  it("never disables the account: once the throttle's wait ends, the owner signs in", async () => {
    const setup = testAuth()
    await account(setup)
    // The attacker waits out every block, so the account's wait climbs, never past its 15-minute cap.
    const waits: number[] = []
    for (let i = 0; i < 30; i += 1) {
      const attacker = new Browser(inProcess(setup.auth))
      await attacker.start()
      const reply = await attacker.post(
        "/auth/sign-in",
        { identifier: "ada@example.com", password: "wrong password entirely" },
        { clientAddress: `198.51.100.${String(i)}` },
      )
      const wait = Number(reply.headers.get("retry-after") ?? 0) * 1000
      if (reply.status === 429) waits.push(wait)
      setup.clock.advance(Math.max(wait, 1_000))
    }
    expect(waits.length).toBeGreaterThan(0)
    expect(Math.max(...waits)).toBeGreaterThan(60_000)
    expect(Math.max(...waits)).toBeLessThanOrEqual(15 * 60_000)
    // The owner waits out the last block, as anyone must, and the account was never disabled.
    setup.clock.advance(15 * 60_000)
    const owner = new Browser(inProcess(setup.auth))
    await owner.start()
    const reply = await owner.post("/auth/sign-in", {
      identifier: "ada@example.com",
      password: PASSWORD,
    })
    expect(reply.status).toBe(200)
  }, 120_000)

  it("leaves the account's TOTP authenticator working when its password reaches the ceiling", async () => {
    // Neither the throttle nor the request limiter may answer first: the ceiling is what this checks.
    const setup = testAuth({ throttle: { freeFailures: 1_000 }, rateLimit: false })
    const { subject, secret } = await account(setup)
    for (let i = 0; i < 100; i += 1) {
      const attacker = new Browser(inProcess(setup.auth))
      await attacker.start()
      await attacker.post("/auth/sign-in", {
        identifier: "ada@example.com",
        password: "wrong password entirely",
      })
    }
    const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    setup.clock.advance(30_000)
    const reply = await browser.post("/auth/totp/verify", {
      code: await codeAt(secret, setup.clock.now()),
    })
    expect(reply.status).toBe(200)
  }, 120_000)

  it("brings a password at the ceiling back through recovery: the replacement is a new authenticator", async () => {
    // Neither the throttle nor the request limiter may answer first: the ceiling is what this checks.
    const setup = testAuth({ throttle: { freeFailures: 1_000 }, rateLimit: false })
    const { browser, secret } = await account(setup)
    await browser.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD })
    setup.clock.advance(30_000)
    await browser.post("/auth/totp/verify", { code: await codeAt(secret, setup.clock.now()) })
    const { codes } = (await browser.post("/auth/recovery-codes")).json as { codes: string[] }
    for (let i = 0; i < 100; i += 1) {
      const attacker = new Browser(inProcess(setup.auth))
      await attacker.start()
      await attacker.post("/auth/sign-in", {
        identifier: "ada@example.com",
        password: "wrong password entirely",
      })
    }
    const signIn = async (password: string) => {
      const owner = new Browser(inProcess(setup.auth))
      await owner.start()
      return owner.post("/auth/sign-in", { identifier: "ada@example.com", password })
    }
    expect((await signIn(PASSWORD)).status).toBe(401)
    const recovering = new Browser(inProcess(setup.auth))
    await recovering.start()
    await recovering.post("/auth/recovery", { identifier: "ada@example.com", code: codes[0] })
    const replaced = await recovering.post("/auth/password", {
      password: "a new passphrase for ada",
    })
    expect(replaced.status).toBe(200)
    await recovering.post("/auth/recovery/finish")
    expect((await signIn("a new passphrase for ada")).json).toMatchObject({ outcome: "step-up" })
  }, 120_000)
})
