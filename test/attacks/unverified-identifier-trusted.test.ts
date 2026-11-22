// Attack: an identifier saved before anyone proved it is used to find an account, so whoever typed it can sign in to
// that account (or, later, recover or link it).
// Stopped by: only a confirmed identifier resolves to an account. Sign-up saves the address unconfirmed; only a
// redeemed confirmation code writes the record sign-in looks up (ADR 0021 §6, ADR 0008 §4). Sign-in is the only
// lookup by identifier so far; recovery (phase 4) and linking (phase 5) join this test when they land.
import { describe, expect, it } from "vitest"
import { createAccount } from "../../src/core/accounts.js"
import { systemRandom } from "../../src/core/clock.js"
import { setPassword } from "../../src/methods/password/method.js"
import {
  Browser,
  confirmationCode,
  expectOk,
  hibpClear,
  inProcess,
  PASSWORD,
  TENANT,
  testAuth,
} from "../support/auth.js"
import { testHasher } from "../support/argon2.js"

async function signIn(setup: ReturnType<typeof testAuth>, identifier: string) {
  const browser = new Browser(inProcess(setup.auth))
  await browser.start()
  return browser.post("/auth/sign-in", { identifier, password: PASSWORD })
}

describe("unverified-identifier-trusted", () => {
  it("gives an account holding only an unconfirmed address and a valid password the unknown-account reply", async () => {
    const setup = testAuth()
    const subject = await createAccount(setup.store, TENANT, systemRandom, {
      identifier: "ada@example.com",
      now: setup.clock.now(),
    })
    const set = await setPassword(
      {
        clock: setup.clock,
        random: systemRandom,
        store: setup.store,
        hibp: hibpClear,
        hasher: testHasher,
      },
      { tenant: TENANT, accountId: subject, password: PASSWORD, alone: false },
    )
    expect(set.ok).toBe(true)
    const unconfirmed = await signIn(setup, "ada@example.com")
    const unknown = await signIn(setup, "nobody@example.com")
    expect([unconfirmed.status, unconfirmed.text]).toEqual([401, '{"error":"invalid-credentials"}'])
    expect(unconfirmed.text).toBe(unknown.text)
  })

  it("resolves the address only once its code is redeemed", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    await expectOk(browser.post("/auth/sign-up", { identifier: "ada@example.com" }))
    expect((await signIn(setup, "ada@example.com")).status).toBe(401)
    await expectOk(
      browser.post("/auth/email/confirm", {
        code: confirmationCode(setup.outbox, "ada@example.com"),
      }),
    )
    await expectOk(browser.post("/auth/password", { password: PASSWORD }))
    expect((await signIn(setup, "ada@example.com")).status).toBe(200)
  })
})
