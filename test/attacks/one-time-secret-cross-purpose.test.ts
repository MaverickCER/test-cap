// Attack: a one-time secret issued for one flow, account or address is accepted by another. Stopped by: each secret
// binds its purpose, account and identifier, and every lookup uses all three (ADR 0002, 0007).
import { describe, expect, it } from "vitest"
import {
  account,
  Browser,
  confirmationCode,
  inProcess,
  PASSWORD,
  testAuth,
} from "../support/auth.js"
import { codeAt } from "../support/totp.js"

describe("one-time-secret-cross-purpose", () => {
  it("refuses one account's confirmation code for another account", async () => {
    const setup = testAuth()
    const ada = new Browser(inProcess(setup.auth))
    const bob = new Browser(inProcess(setup.auth))
    await Promise.all([ada.start(), bob.start()])
    await ada.post("/auth/sign-up", { identifier: "ada@example.com" })
    await bob.post("/auth/sign-up", { identifier: "bob@example.com" })
    const adasCode = confirmationCode(setup.outbox, "ada@example.com")
    const reply = await bob.post("/auth/email/confirm", { code: adasCode })
    expect([reply.status, reply.text]).toEqual([400, '{"error":"invalid-code"}'])
    // Ada's code is still hers: the refused attempt did not consume it.
    expect((await ada.post("/auth/email/confirm", { code: adasCode })).status).toBe(200)
  })

  it("refuses one account's recovery code for another account, and as a TOTP code", async () => {
    const setup = testAuth()
    const ada = await account(setup)
    await account(setup, "bob@example.com")
    await ada.browser.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD })
    setup.clock.advance(30_000)
    await ada.browser.post("/auth/totp/verify", {
      code: await codeAt(ada.secret, setup.clock.now()),
    })
    const { codes } = (await ada.browser.post("/auth/recovery-codes")).json as { codes: string[] }
    const attacker = new Browser(inProcess(setup.auth))
    await attacker.start()
    const reply = await attacker.post("/auth/recovery", {
      identifier: "bob@example.com",
      code: codes[0],
    })
    expect([reply.status, reply.text]).toEqual([401, '{"error":"invalid-credentials"}'])
    await attacker.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD })
    const asTotp = await attacker.post("/auth/totp/verify", { code: codes[0] })
    expect(asTotp.status).toBe(401)
    // The code still recovers its own account.
    const own = new Browser(inProcess(setup.auth))
    await own.start()
    expect(
      (await own.post("/auth/recovery", { identifier: "ada@example.com", code: codes[0] })).status,
    ).toBe(200)
  })

  it("refuses one account's TOTP enrolment for another account's session", async () => {
    const setup = testAuth()
    const ada = new Browser(inProcess(setup.auth))
    const bob = new Browser(inProcess(setup.auth))
    await Promise.all([ada.start(), bob.start()])
    for (const [browser, identifier] of [
      [ada, "ada@example.com"],
      [bob, "bob@example.com"],
    ] as const) {
      await browser.post("/auth/sign-up", { identifier })
      await browser.post("/auth/email/confirm", {
        code: confirmationCode(setup.outbox, identifier),
      })
      await browser.post("/auth/password", { password: PASSWORD })
    }
    const { authenticatorId, secret } = (await ada.post("/auth/totp/enrol")).json as {
      authenticatorId: string
      secret: string
    }
    const reply = await bob.post("/auth/totp/confirm", {
      authenticatorId,
      code: await codeAt(secret, setup.clock.now()),
    })
    expect(reply.status).toBe(400)
    expect((await bob.get("/auth/session")).json).toMatchObject({ session: { state: "pre-auth" } })
  })
})
