// ADR 0015 §2: every phase 3 flow emits exactly the activities its row names. A change of activity is a change to
// this table, never a quiet code edit.
//
// | Flow                  | Event                                                                        |
// | --------------------- | ---------------------------------------------------------------------------- |
// | F01 sign-up           | 3007 Create; 3007 Enable MFA Factors for each authenticator enrolled         |
// | F02 password sign-in  | 3002 Logon, success or failure                                               |
// | F03 TOTP enrolment    | 3007 Enable MFA Factors (on the confirming code)                             |
// | F04 TOTP verification | 3002 Logon, success or failure, with is_mfa and auth_factors                 |
// | F08 email confirmation | 3007 Update ("email confirmed"), success or failure                         |
// | F13 step-up           | 3002 Logon on the existing session, marked as a step-up                      |
// | F14 session lifecycle | issue: the Logon of its flow; sign-out and remote revoke: 3002 Logoff        |
// | F22 adapter transport | none                                                                         |
import { describe, expect, it } from "vitest"
import type { AuthenticationEvent, SecurityEvent } from "../../src/ocsf/events.js"
import { hexEncode, sha256, utf8Encode } from "../../src/core/encoding.js"
import {
  aal1,
  aal2,
  account,
  body,
  brief,
  Browser,
  confirmEmail,
  CREATE,
  ENABLE_MFA,
  expectOk,
  inProcess,
  internalsOfAuth,
  LOGOFF,
  LOGON,
  PASSWORD,
  seedAccount,
  seedSession,
  T0,
  testAuth,
  UPDATE,
} from "../support/auth.js"
import { codeAt } from "../support/totp.js"

const types = (events: readonly unknown[]) =>
  events.map((event) => [(event as SecurityEvent).type_uid, (event as SecurityEvent).status])

describe("the flow-activity map (ADR 0015 §2)", () => {
  it("F01, F08 and F03: sign-up is Create, the confirmed address Update, then Enable MFA Factors for each authenticator", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    await expectOk(browser.post("/auth/sign-up", { identifier: "ada@example.com" }))
    await browser.post("/auth/email/confirm", { code: "not a code" })
    await confirmEmail(browser, setup.outbox)
    await expectOk(browser.post("/auth/password", { password: PASSWORD }))
    const { authenticatorId, secret } = body(await browser.post("/auth/totp/enrol")) as Record<
      string,
      string
    >
    expect(types(setup.events)).toEqual([
      [CREATE, "Success"],
      [UPDATE, "Failure"],
      [UPDATE, "Success"],
      [ENABLE_MFA, "Success"],
    ])
    await expectOk(
      browser.post("/auth/totp/confirm", {
        authenticatorId: authenticatorId ?? "",
        code: await codeAt(secret ?? "", setup.clock.now()),
      }),
    )
    expect(setup.events.map(brief).map((event) => [event["type"], event["factors"]])).toEqual([
      [CREATE, undefined],
      [UPDATE, undefined],
      [UPDATE, undefined],
      [ENABLE_MFA, ["Password"]],
      [ENABLE_MFA, ["OTP"]],
    ])
  })

  it("F02: password sign-in is Logon, success or failure", async () => {
    const setup = testAuth()
    await seedAccount(setup, { password: true })
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    await browser.post("/auth/sign-in", {
      identifier: "ada@example.com",
      password: "wrong password!",
    })
    await browser.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD })
    expect(types(setup.events)).toEqual([
      [LOGON, "Failure"],
      [LOGON, "Success"],
    ])
  })

  it("F04: TOTP verification is Logon with is_mfa and the OTP factor", async () => {
    const setup = testAuth()
    const { subject, secret } = await seedAccount(setup, { totp: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    await browser.post("/auth/totp/verify", { code: "000000" })
    await expectOk(
      browser.post("/auth/totp/verify", { code: await codeAt(secret ?? "", setup.clock.now()) }),
    )
    expect(types(setup.events)).toEqual([
      [LOGON, "Failure"],
      [LOGON, "Success"],
    ])
    const success = setup.events[1] as AuthenticationEvent
    expect([
      success.is_mfa,
      success.auth_factors,
      success.unmapped.test_cap.assurance_level,
    ]).toEqual([true, [{ factor_type_id: 7, factor_type: "OTP", is_totp: true }], "AAL2"])
  })

  it("F13: step-up is Logon marked as a step-up", async () => {
    const setup = testAuth()
    const { subject, secret } = await seedAccount(setup, { totp: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    const { challenge } = body(await browser.post("/auth/step-up/start")) as { challenge: string }
    await expectOk(
      browser.post("/auth/step-up", {
        challenge,
        code: await codeAt(secret ?? "", setup.clock.now()),
      }),
    )
    expect(types(setup.events)).toEqual([[LOGON, "Success"]])
    expect((setup.events[0] as SecurityEvent).unmapped.test_cap.step_up).toBe(true)
  })

  it("F14: sign-out, remote revoke and an admin revoke are Logoff; reading a session emits nothing", async () => {
    const setup = testAuth()
    const first = await seedSession(setup, { subject: "acct-1", evidence: aal2(setup.clock) })
    const second = await seedSession(setup, { subject: "acct-1", evidence: aal2(setup.clock) })
    await first.browser.get("/auth/session")
    await first.browser.get("/auth/sessions")
    await expectOk(first.browser.post("/auth/sessions/revoke", { sessionId: second.id }))
    await expectOk(first.browser.post("/auth/sign-out"))
    await seedSession(setup, { subject: "acct-1", evidence: aal2(setup.clock) })
    expect(await setup.auth.admin.revoke("acct-1")).toBe(1)
    expect(
      setup.events.map(brief).map((event) => [event["type"], event["status"], event["detail"]]),
    ).toEqual([
      [LOGOFF, "Success", "remote-revoke"],
      [LOGOFF, "Success", "sign-out"],
      [LOGOFF, "Success", "admin-revoke"],
    ])
    expect(await setup.auth.admin.revoke("acct-1")).toBe(0)
    expect(setup.events).toHaveLength(3)
  })

  it("F22: deny by default emits nothing", async () => {
    const setup = testAuth()
    const internals = internalsOfAuth(setup.auth)
    const decision = await internals.gate(
      { method: "GET", url: "/private", headers: new Headers(), body: null },
      () => false,
    )
    expect(decision.kind).toBe("respond")
    expect(setup.events).toEqual([])
  })
})

describe("what every event carries", () => {
  it("names the system, the tenant and the time, and the session only by a 16-hex prefix of its stored hash", async () => {
    const setup = testAuth()
    const enrolled = await account(setup)
    setup.events.length = 0
    await expectOk(
      enrolled.browser.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD }),
    )
    const token = enrolled.browser.cookies.get("__Host-test-cap") ?? ""
    const event = setup.events[0] as AuthenticationEvent
    expect(event).toMatchObject({
      class_uid: 3002,
      type_uid: LOGON,
      time: setup.clock.now(),
      metadata: { tenant_uid: "default" },
      service: { name: "billing-web" },
      user: { uid: enrolled.subject },
      session: {
        uid: hexEncode(await sha256(utf8Encode(token))).slice(0, 16),
        created_time: setup.clock.now(),
        expiration_time: setup.clock.now() + 86_400_000,
        is_mfa: false,
      },
      is_mfa: false,
      unmapped: {
        test_cap: { system: "billing-web", subject_kind: "user", assurance_level: "AAL1" },
      },
    })
    expect(JSON.stringify(setup.events)).not.toContain(token)
    expect(JSON.stringify(setup.events)).not.toContain(PASSWORD)
    expect(setup.clock.now()).toBeGreaterThan(T0)
  })

  it("names a CSRF refusal's subject as unknown", async () => {
    const setup = testAuth()
    await new Browser(inProcess(setup.auth)).send({ method: "POST", path: "/auth/sign-in" })
    expect(setup.events.map(brief)).toEqual([
      { type: LOGON, status: "Failure", user: "unknown", detail: "csrf" },
    ])
  })
})
