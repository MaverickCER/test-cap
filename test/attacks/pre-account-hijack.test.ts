// Attack: an attacker signs up with the victim's address and a password of their own; the victim later proves the
// address, and the attacker's authenticator still opens the account.
// Stopped by: an unconfirmed sign-up never leaves the pre-auth state and holds no claim on the identifier; the address
// is claimed with createUnique only when its emailed code is redeemed, by the account the code was issued to
// (ADR 0021, ADR 0008 §4).
import { describe, expect, it } from "vitest"
import { IDENTIFIER_COLLECTION } from "../../src/core/accounts.js"
import { PASSWORD_COLLECTION } from "../../src/methods/password/method.js"
import {
  body,
  Browser,
  confirmationCode,
  enrol,
  expectOk,
  inProcess,
  PASSWORD,
  TENANT,
  testAuth,
} from "../support/auth.js"

const VICTIM = "victim@example.com"

describe("pre-account-hijack", () => {
  it("gives the attacker's unconfirmed sign-up no claim, no password and no way past enrolment", async () => {
    const setup = testAuth()
    const attacker = new Browser(inProcess(setup.auth))
    await attacker.start()
    await expectOk(attacker.post("/auth/sign-up", { identifier: VICTIM }))
    const attackerSubject = (
      body(await attacker.get("/auth/session"))["session"] as { subject: string }
    ).subject

    // Without the code from the victim's inbox, the attacker can set no authenticator.
    const password = await attacker.post("/auth/password", { password: "attacker's own password" })
    expect([password.status, password.text]).toEqual([409, '{"error":"confirm-email-first"}'])
    const totp = await attacker.post("/auth/totp/enrol")
    expect([totp.status, totp.text]).toEqual([409, '{"error":"password-first"}'])
    expect(await setup.store.get(TENANT, IDENTIFIER_COLLECTION, VICTIM)).toBeNull()
    expect(await setup.store.get(TENANT, PASSWORD_COLLECTION, attackerSubject)).toBeNull()

    // The victim signs up later (past the one-a-minute send limit), confirms the address from their inbox and enrols.
    setup.clock.advance(60_000)
    const victim = new Browser(inProcess(setup.auth))
    const { subject } = await enrol(victim, setup.clock, setup.outbox, VICTIM)
    expect(subject).not.toBe(attackerSubject)
    expect((await setup.store.get(TENANT, IDENTIFIER_COLLECTION, VICTIM))?.owner).toBe(subject)

    // The attacker's session never leaves enrolment.
    const session = body(await attacker.get("/auth/session"))["session"]
    expect(session).toMatchObject({ subject: attackerSubject, state: "pre-auth", level: null })

    // Sign-in by the address reaches the victim's account only, and the attacker's password never existed.
    const signIn = new Browser(inProcess(setup.auth))
    await signIn.start()
    const wrong = await signIn.post("/auth/sign-in", {
      identifier: VICTIM,
      password: "attacker's own password",
    })
    expect([wrong.status, wrong.text]).toEqual([401, '{"error":"invalid-credentials"}'])
    await expectOk(signIn.post("/auth/sign-in", { identifier: VICTIM, password: PASSWORD }))
    expect(
      (body(await signIn.get("/auth/session"))["session"] as { subject: string }).subject,
    ).toBe(subject)
  })

  it("claims nothing for the attacker's account even with its own code, once the victim holds the address", async () => {
    const setup = testAuth()
    const attacker = new Browser(inProcess(setup.auth))
    await attacker.start()
    await expectOk(attacker.post("/auth/sign-up", { identifier: VICTIM }))
    // The code the attacker's sign-up mailed to the victim, supposing it leaked to the attacker.
    const leaked = confirmationCode(setup.outbox, VICTIM)
    setup.clock.advance(60_000)
    const victim = new Browser(inProcess(setup.auth))
    const { subject } = await enrol(victim, setup.clock, setup.outbox, VICTIM)

    const redeemed = await attacker.post("/auth/email/confirm", { code: leaked })
    expect([redeemed.status, redeemed.text]).toEqual([200, '{"outcome":"enroll"}'])
    expect((await setup.store.get(TENANT, IDENTIFIER_COLLECTION, VICTIM))?.owner).toBe(subject)
    const password = await attacker.post("/auth/password", { password: "attacker's own password" })
    expect(password.text).toBe('{"error":"confirm-email-first"}')
  })

  it("does not let the victim's code confirm the attacker's account", async () => {
    const setup = testAuth()
    const attacker = new Browser(inProcess(setup.auth))
    await attacker.start()
    await expectOk(attacker.post("/auth/sign-up", { identifier: VICTIM }))
    setup.clock.advance(60_000)
    const victim = new Browser(inProcess(setup.auth))
    await victim.start()
    await expectOk(victim.post("/auth/sign-up", { identifier: VICTIM }))
    // The newest email carries the code issued to the victim's own account.
    const victimCode = confirmationCode(setup.outbox, VICTIM)
    const stolen = await attacker.post("/auth/email/confirm", { code: victimCode })
    expect([stolen.status, stolen.text]).toEqual([400, '{"error":"invalid-code"}'])
    expect(await setup.store.get(TENANT, IDENTIFIER_COLLECTION, VICTIM)).toBeNull()
    await expectOk(victim.post("/auth/email/confirm", { code: victimCode }))
  })
})
