// Dependency: the key material, `AUTH_ENCRYPTION_KEY` and `AUTH_CSRF_KEY` (specs/dependency-failures.md, "Key
// material"; ADR 0022, ADR 0027, ADR 0029). Policy: fail closed. A value sealed, keyed or signed under a key id the
// ring no longer holds, or under other bytes with the same id, is refused as a wrong secret is: it never opens,
// redeems or verifies. Keeping the old key after the new one in the ring is the recovery.
import { describe, expect, it } from "vitest"
import {
  aal1,
  account,
  Browser,
  confirmationCode,
  ENV,
  expectOk,
  inProcess,
  keyRing,
  PASSWORD,
  seedAccount,
  seedSession,
  testAuth,
} from "../support/auth.js"
import { codeAt } from "../support/totp.js"

/** The same deployment restarted with other key rings over the same store and clock. */
function restarted(
  setup: ReturnType<typeof testAuth>,
  env: Readonly<Record<string, string | undefined>>,
) {
  return testAuth({ store: setup.store, clock: setup.clock, env: { ...ENV, ...env } }).auth
}

/** `browser`'s cookies and token, sent to `auth`. */
function moved(browser: Browser, auth: ReturnType<typeof restarted>): Browser {
  const next = new Browser(inProcess(auth))
  for (const [name, value] of browser.cookies) next.cookies.set(name, value)
  next.csrf = browser.csrf
  return next
}

const E1 = ENV.AUTH_ENCRYPTION_KEY
const E2 = keyRing("e2", 11)
/** Other bytes under the id `e1`. */
const E1_REPLACED = keyRing("e1", 13)

/** A password session on an account whose TOTP seed is sealed under `e1`, and the code for now. */
async function sealedUnderE1() {
  const setup = testAuth()
  const { subject, secret } = await seedAccount(setup, { password: true, totp: true })
  const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
  const code = await codeAt(String(secret), setup.clock.now())
  return { setup, browser, code, secret: String(secret) }
}

describe("a TOTP seed whose key the ring no longer holds", () => {
  it.each([
    ["the key id has left the ring", E2],
    ["the id now names other bytes", E1_REPLACED],
  ])("is refused as a wrong code when %s, adding no evidence", async (_how, ring) => {
    const { setup, browser, code } = await sealedUnderE1()
    const auth = restarted(setup, { AUTH_ENCRYPTION_KEY: ring })
    const reply = await moved(browser, auth).post("/auth/totp/verify", { code })
    expect([reply.status, reply.text]).toEqual([401, '{"error":"invalid-code"}'])
  })

  it("opens again once the old key is back after the new one, and is then sealed under the new one", async () => {
    const { setup, browser, code, secret } = await sealedUnderE1()
    const both = moved(browser, restarted(setup, { AUTH_ENCRYPTION_KEY: `${E2},${E1}` }))
    const reply = await both.post("/auth/totp/verify", { code })
    expect((reply.json as { outcome: string }).outcome).toBe("allow")
    // That success sealed the seed again under e2, so a ring without e1 now opens it.
    setup.clock.advance(30_000)
    const newOnly = moved(both, restarted(setup, { AUTH_ENCRYPTION_KEY: E2 }))
    const next = await newOnly.post("/auth/totp/verify", {
      code: await codeAt(secret, setup.clock.now()),
    })
    expect((next.json as { outcome: string }).outcome).toBe("allow")
  })
})

describe("an email code keyed under a key the ring no longer holds", () => {
  it.each([
    ["only the new key", E2, 400, '{"error":"invalid-code"}'],
    ["the new key and then the old", `${E2},${E1}`, 200, '{"outcome":"enroll"}'],
  ])("with %s, answers %s", async (_how, ring, status, text) => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    await expectOk(browser.post("/auth/sign-up", { identifier: "ada@example.com" }))
    const code = confirmationCode(setup.outbox, "ada@example.com")
    const auth = restarted(setup, { AUTH_ENCRYPTION_KEY: ring })
    const reply = await moved(browser, auth).post("/auth/email/confirm", { code })
    expect([reply.status, reply.text]).toEqual([status, text])
  })
})

describe("a synchronizer token signed under a key the ring no longer holds", () => {
  it.each([
    ["only the new key", keyRing("c2", 17), 403],
    ["the new key and then the old", `${keyRing("c2", 17)},${ENV.AUTH_CSRF_KEY}`, 200],
  ])("with %s, answers %s", async (_how, ring, status) => {
    const setup = testAuth()
    const { browser } = await seedSession(setup, { evidence: aal1(setup.clock) })
    const auth = restarted(setup, { AUTH_CSRF_KEY: ring })
    const reply = await moved(browser, auth).post("/auth/sign-out")
    expect(reply.status).toBe(status)
  })
})

describe("a key generated at startup, outside production and staging", () => {
  it("refuses every seed and code sealed before a restart, since the restart generates another", async () => {
    const setup = testAuth({ env: { ...ENV, AUTH_ENCRYPTION_KEY: undefined } })
    const { secret, browser } = await account(setup)
    const after = moved(browser, restarted(setup, { AUTH_ENCRYPTION_KEY: undefined }))
    await expectOk(
      after.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD }),
    )
    const code = await codeAt(secret, setup.clock.now())
    const reply = await after.post("/auth/totp/verify", { code })
    expect([reply.status, reply.text]).toEqual([401, '{"error":"invalid-code"}'])
  })
})
