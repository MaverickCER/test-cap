// Attack: after a credential change because of a compromise, the attacker's session stays signed in. Stopped by: a
// credential change rotates this session and revokes the account's others (ADR 0006, 0007).
import { describe, expect, it } from "vitest"
import {
  aal2,
  account,
  body,
  brief,
  Browser,
  hookedStore,
  inProcess,
  LOGON,
  PASSWORD,
  seedSession,
  TENANT,
  testAuth,
} from "../support/auth.js"
import { PASSWORD_COLLECTION } from "../../src/methods/password/method.js"
import { SESSION_COLLECTION } from "../../src/sessions/sessions.js"
import { memoryStore } from "../../src/store/memory.js"
import { codeAt } from "../support/totp.js"

describe("sessions-survive-credential-change", () => {
  it("revokes the attacker's session when the owner enrols a new TOTP authenticator", async () => {
    const setup = testAuth()
    const { subject } = await account(setup)
    const attacker = await seedSession(setup, { subject, evidence: aal2(setup.clock) })
    const owner = await seedSession(setup, { subject, evidence: aal2(setup.clock) })
    const begun = await owner.browser.post("/auth/totp/enrol")
    const { authenticatorId, secret } = begun.json as { authenticatorId: string; secret: string }
    setup.clock.advance(30_000)
    await owner.browser.post("/auth/totp/confirm", {
      authenticatorId,
      code: await codeAt(secret, setup.clock.now()),
    })
    expect(body(await attacker.browser.get("/auth/session"))["session"]).toBeNull()
    expect(body(await owner.browser.get("/auth/session"))["session"]).toMatchObject({ subject })
  })

  it("revokes every session when the account is recovered and the password replaced", async () => {
    const setup = testAuth()
    const { subject, browser, secret } = await account(setup)
    await browser.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD })
    setup.clock.advance(30_000)
    await browser.post("/auth/totp/verify", { code: await codeAt(secret, setup.clock.now()) })
    const { codes } = (await browser.post("/auth/recovery-codes")).json as { codes: string[] }
    const attacker = await seedSession(setup, { subject, evidence: aal2(setup.clock) })
    const owner = new Browser(inProcess(setup.auth))
    await owner.start()
    await owner.post("/auth/recovery", { identifier: "ada@example.com", code: codes[0] })
    await owner.post("/auth/password", { password: "an entirely new passphrase" })
    expect(body(await attacker.browser.get("/auth/session"))["session"]).toBeNull()
    expect(body(await browser.get("/auth/session"))["session"]).toBeNull()
  })

  /**
   * The attacker, who knows the old password, signs in; just after that password is checked, `during` runs. The
   * session the sign-in then writes is the one at stake.
   */
  async function raceSignIn(
    during: (setup: ReturnType<typeof testAuth>, subject: string) => Promise<void>,
    before?: (browser: Browser) => Promise<void>,
  ) {
    const state = { armed: false, subject: "" }
    const store = hookedStore(memoryStore(), async (operation, args) => {
      if (!state.armed || operation !== "createUnique") return
      if ((args[1] as { readonly collection?: unknown }).collection !== SESSION_COLLECTION) return
      state.armed = false
      await during(setup, state.subject)
    })
    const setup = testAuth({ store })
    const { subject, browser, secret } = await account(setup)
    state.subject = subject
    if (before !== undefined) {
      await browser.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD })
      setup.clock.advance(30_000)
      await browser.post("/auth/totp/verify", { code: await codeAt(secret, setup.clock.now()) })
      await before(browser)
    }
    const attacker = new Browser(inProcess(setup.auth))
    await attacker.start()
    state.armed = true
    const reply = await attacker.post("/auth/sign-in", {
      identifier: "ada@example.com",
      password: PASSWORD,
    })
    return { setup, subject, reply, attacker, raced: !state.armed }
  }

  it("revokes a session whose sign-in checked the old password while the owner replaced it", async () => {
    const owner = { codes: [] as string[], statuses: [] as number[] }
    const { reply, attacker, raced, setup, subject } = await raceSignIn(
      async (setup, subject) => {
        const browser = new Browser(inProcess(setup.auth))
        await browser.start()
        for (const [path, fields] of [
          ["/auth/recovery", { identifier: "ada@example.com", code: owner.codes[0] ?? "" }],
          ["/auth/password", { password: "an entirely new passphrase" }],
        ] as const) {
          owner.statuses.push((await browser.post(path, fields)).status)
        }
        expect(subject).not.toBe("")
      },
      async (browser) => {
        owner.codes = (
          (await browser.post("/auth/recovery-codes")).json as { codes: string[] }
        ).codes
      },
    )
    expect([raced, owner.statuses]).toEqual([true, [200, 200]])
    expect([reply.status, body(reply)["error"]]).toEqual([401, "invalid-credentials"])
    expect(body(await attacker.get("/auth/session"))["session"]).toBeNull()
    expect(brief(setup.events.at(-1))).toEqual({
      type: LOGON,
      status: "Failure",
      user: subject,
      factors: ["Password"],
      detail: "invalid",
    })
  })

  it("revokes a session whose account lost its password while the password was checked", async () => {
    const deleted = { done: false }
    const { reply, attacker, raced } = await raceSignIn(async (setup, subject) => {
      deleted.done = await setup.store.delete(TENANT, PASSWORD_COLLECTION, subject)
    })
    expect([raced, deleted.done]).toEqual([true, true])
    expect(reply.status).toBe(401)
    expect(body(await attacker.get("/auth/session"))["session"]).toBeNull()
  })

  it("keeps the session when the password did not change while it was checked", async () => {
    const { reply, attacker, raced, subject, setup } = await raceSignIn(async () => {})
    expect(raced).toBe(true)
    expect(reply.status).toBe(200)
    expect(body(await attacker.get("/auth/session"))["session"]).toMatchObject({ subject })
    expect(setup.events.at(-1)).toMatchObject({ status_id: 1 })
  })
})
