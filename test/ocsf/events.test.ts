import { describe, expect, it } from "vitest"
import {
  authenticationEvent,
  deliver,
  OCSF_SCHEMA_VERSION,
  userManagementEvent,
  type AuthenticationInput,
  type SecurityEvent,
  type UserManagementActivity,
  type UserManagementInput,
} from "../../src/ocsf/events.js"

/** A stored session hash: the SHA-256 of a token, as 64 lowercase hex characters. */
const HASH = "0123456789abcdef".repeat(4)

const authInput: AuthenticationInput = {
  activity: "logon",
  outcome: "success",
  time: 1_700_000_000_000,
  system: "billing-web",
  tenant: "acme",
  subject: { kind: "user", id: "u_123" },
}

const userInput: UserManagementInput = {
  activity: "create",
  outcome: "success",
  time: 1_700_000_000_000,
  system: "billing-web",
  tenant: "acme",
  subject: { kind: "user", id: "u_123" },
}

/** The OCSF 1.9.0 base-event and class requirements every event must meet. */
function assertOcsfShape(event: SecurityEvent): void {
  expect(event.category_uid).toBe(3)
  expect(event.category_name).toBe("Identity & Access Management")
  expect([3002, 3007]).toContain(event.class_uid)
  expect(event.type_uid).toBe(event.class_uid * 100 + event.activity_id)
  expect(event.type_name).toBe(`${event.class_name}: ${event.activity_name}`)
  expect(Number.isSafeInteger(event.time)).toBe(true)
  expect(event.metadata.version).toBe(OCSF_SCHEMA_VERSION)
  expect(event.metadata.product.name).toBe("test-cap")
  expect(event.user.uid.length).toBeGreaterThan(0)
  expect([1, 2]).toContain(event.severity_id)
  expect([1, 2]).toContain(event.status_id)
  if (event.class_uid === 3002) expect(event.service.name.length).toBeGreaterThan(0)
}

describe("authenticationEvent", () => {
  it("builds a successful logon with every required OCSF 1.9.0 field", () => {
    const event = authenticationEvent(authInput)
    assertOcsfShape(event)
    expect(event).toStrictEqual({
      activity_id: 1,
      activity_name: "Logon",
      category_uid: 3,
      category_name: "Identity & Access Management",
      class_uid: 3002,
      class_name: "Authentication",
      type_uid: 300201,
      type_name: "Authentication: Logon",
      severity_id: 1,
      severity: "Informational",
      status_id: 1,
      status: "Success",
      time: 1_700_000_000_000,
      metadata: {
        version: "1.9.0",
        product: { name: "test-cap", vendor_name: "MaverickCER" },
        tenant_uid: "acme",
      },
      user: { uid: "u_123" },
      service: { name: "billing-web" },
      unmapped: { test_cap: { system: "billing-web", subject_kind: "user" } },
    })
  })

  it("marks a failure as Low severity with its detail", () => {
    const event = authenticationEvent({ ...authInput, outcome: "failure", detail: "throttled" })
    assertOcsfShape(event)
    expect([
      event.status_id,
      event.status,
      event.severity_id,
      event.severity,
      event.status_detail,
    ]).toEqual([2, "Failure", 2, "Low", "throttled"])
  })

  it("maps each activity to its OCSF id", () => {
    expect(authenticationEvent({ ...authInput, activity: "logoff" })).toMatchObject({
      activity_id: 2,
      activity_name: "Logoff",
      type_uid: 300202,
    })
    const switched = authenticationEvent({
      ...authInput,
      activity: "account-switch",
      actor: { kind: "user", id: "admin_1" },
      reason: "support ticket 42",
    })
    assertOcsfShape(switched)
    expect(switched).toMatchObject({
      activity_id: 7,
      activity_name: "Account Switch",
      type_uid: 300207,
      account_switch_type_id: 2,
      account_switch_type: "Impersonate",
      actor: { user: { uid: "admin_1" } },
      user: { uid: "u_123" },
      unmapped: { test_cap: { actor_kind: "user", reason: "support ticket 42" } },
    })
  })

  it("refuses an account switch without the administrator who made it", () => {
    expect(() => authenticationEvent({ ...authInput, activity: "account-switch" })).toThrow(
      new TypeError("An account switch needs the actor who made it."),
    )
  })

  it("carries the session as a 16-hex prefix of its stored hash, never the hash itself", () => {
    const event = authenticationEvent({
      ...authInput,
      session: { hash: HASH, mfa: true, createdAt: 10, expiresAt: 20 },
    })
    expect(event.session).toStrictEqual({
      uid: "0123456789abcdef",
      issuer: "billing-web",
      created_time: 10,
      expiration_time: 20,
      is_mfa: true,
    })
    expect(event.is_mfa).toBe(true)
    expect(JSON.stringify(event)).not.toContain(HASH)
  })

  it("takes is_mfa from the session when not given, and an explicit value over the session's", () => {
    const session = { hash: HASH, mfa: false, createdAt: 0, expiresAt: 1 }
    expect(authenticationEvent({ ...authInput, session }).is_mfa).toBe(false)
    expect(authenticationEvent({ ...authInput, session, mfa: true }).is_mfa).toBe(true)
    expect(authenticationEvent({ ...authInput, mfa: false }).is_mfa).toBe(false)
  })

  it("adds no protocol fields to a local sign-in", () => {
    const event = authenticationEvent(authInput)
    expect(Object.keys(event)).not.toContain("auth_protocol_id")
    expect(Object.keys(event)).not.toContain("auth_protocol")
  })

  it("refuses anything but a stored SHA-256 as the session, such as a raw session token", () => {
    const token = "A".repeat(10) + "b_c-" + "D".repeat(29)
    for (const hash of [token, HASH.toUpperCase(), HASH.slice(1), `${HASH}0`, ""]) {
      expect(
        () =>
          authenticationEvent({
            ...authInput,
            session: { hash, mfa: false, createdAt: 0, expiresAt: 1 },
          }),
        hash,
      ).toThrow(
        new TypeError(
          "session.hash must be the stored SHA-256 of the token: 64 lowercase hex characters.",
        ),
      )
    }
  })

  it("refuses session times that are not whole epoch milliseconds", () => {
    for (const [field, value] of [
      ["createdAt", Number.NaN],
      ["createdAt", -1],
      ["expiresAt", Number.POSITIVE_INFINITY],
      ["expiresAt", 1.5],
    ] as const) {
      const session = { hash: HASH, mfa: false, createdAt: 0, expiresAt: 1, [field]: value }
      expect(() => authenticationEvent({ ...authInput, session }), `${field}=${value}`).toThrow(
        new RangeError(`session.${field} must be whole epoch milliseconds.`),
      )
    }
    const zero = authenticationEvent({
      ...authInput,
      session: { hash: HASH, mfa: false, createdAt: 0, expiresAt: 0 },
    })
    expect([zero.session?.created_time, zero.session?.expiration_time]).toEqual([0, 0])
  })

  it("records the protocol of a federated sign-in", () => {
    expect(authenticationEvent({ ...authInput, protocol: "openid" })).toMatchObject({
      auth_protocol_id: 4,
      auth_protocol: "OpenID",
    })
    expect(authenticationEvent({ ...authInput, protocol: "saml" })).toMatchObject({
      auth_protocol_id: 5,
      auth_protocol: "SAML",
    })
  })

  it("records multi-factor use, factors and test-cap's own facts under unmapped", () => {
    const event = authenticationEvent({
      ...authInput,
      mfa: true,
      factors: ["password", "totp"],
      assurance: "AAL2",
      stepUp: true,
      breakGlass: true,
      deviation: "email sign-in enabled",
    })
    expect(event.is_mfa).toBe(true)
    expect(event.auth_factors).toEqual([
      { factor_type_id: 11, factor_type: "Password" },
      { factor_type_id: 7, factor_type: "OTP", is_totp: true },
    ])
    expect(event.unmapped.test_cap).toStrictEqual({
      system: "billing-web",
      subject_kind: "user",
      assurance_level: "AAL2",
      step_up: true,
      break_glass: true,
      deviation: "email sign-in enabled",
    })
  })

  it("records a session holding no assurance level as null", () => {
    expect(
      authenticationEvent({ ...authInput, assurance: null }).unmapped.test_cap.assurance_level,
    ).toBeNull()
  })

  it("names service and agent subjects", () => {
    expect(
      authenticationEvent({ ...authInput, subject: { kind: "agent", id: "a_1" } }).unmapped.test_cap
        .subject_kind,
    ).toBe("agent")
    expect(
      authenticationEvent({ ...authInput, subject: { kind: "service", id: "s_1" } }).unmapped
        .test_cap.subject_kind,
    ).toBe("service")
  })
})

describe("userManagementEvent", () => {
  const ACTIVITIES: [UserManagementActivity, number, string][] = [
    ["create", 1, "Create"],
    ["update", 2, "Update"],
    ["enable", 4, "Enable"],
    ["disable", 5, "Disable"],
    ["password-change", 8, "Password Change"],
    ["password-reset", 9, "Password Reset"],
    ["enable-mfa-factors", 12, "Enable MFA Factors"],
    ["disable-mfa-factors", 13, "Disable MFA Factors"],
    ["add-programmatic-credentials", 18, "Add Programmatic Credentials"],
    ["remove-programmatic-credentials", 19, "Remove Programmatic Credentials"],
  ]

  it.each(ACTIVITIES)("maps %s to activity %i (%s)", (activity, id, name) => {
    const event = userManagementEvent({ ...userInput, activity })
    assertOcsfShape(event)
    expect(event).toMatchObject({
      class_uid: 3007,
      class_name: "User Management",
      activity_id: id,
      activity_name: name,
      type_uid: 300700 + id,
    })
  })

  it("builds a complete create event", () => {
    expect(userManagementEvent(userInput)).toStrictEqual({
      activity_id: 1,
      activity_name: "Create",
      category_uid: 3,
      category_name: "Identity & Access Management",
      class_uid: 3007,
      class_name: "User Management",
      type_uid: 300701,
      type_name: "User Management: Create",
      severity_id: 1,
      severity: "Informational",
      status_id: 1,
      status: "Success",
      time: 1_700_000_000_000,
      metadata: {
        version: "1.9.0",
        product: { name: "test-cap", vendor_name: "MaverickCER" },
        tenant_uid: "acme",
      },
      user: { uid: "u_123" },
      unmapped: { test_cap: { system: "billing-web", subject_kind: "user" } },
    })
  })

  it("describes an Update in its detail, keeping OCSF's own activity name", () => {
    expect(
      userManagementEvent({ ...userInput, activity: "update", detail: "email confirmed" }),
    ).toMatchObject({ activity_id: 2, activity_name: "Update", status_detail: "email confirmed" })
  })

  it("names an Other activity, and only an Other activity", () => {
    const event = userManagementEvent({
      ...userInput,
      activity: "other",
      otherName: "Recovery Codes Issued",
    })
    assertOcsfShape(event)
    expect(event).toMatchObject({
      activity_id: 99,
      activity_name: "Recovery Codes Issued",
      type_uid: 300799,
    })
    expect(() => userManagementEvent({ ...userInput, activity: "other" })).toThrow(
      new TypeError("An Other activity needs otherName to say what happened."),
    )
    expect(() => userManagementEvent({ ...userInput, otherName: "x" })).toThrow(
      new TypeError("otherName is only for an Other activity."),
    )
  })

  it("records the factors enabled, and the administrator acting on someone else", () => {
    const event = userManagementEvent({
      ...userInput,
      activity: "enable-mfa-factors",
      factors: ["webauthn", "email", "recovery-code"],
      actor: { kind: "user", id: "admin_1" },
    })
    expect(event.auth_factors).toEqual([
      { factor_type_id: 10, factor_type: "WebAuthn" },
      { factor_type_id: 8, factor_type: "Email" },
      { factor_type_id: 99, factor_type: "Recovery Code" },
    ])
    expect(event.actor).toEqual({ user: { uid: "admin_1" } })
    expect(event.unmapped.test_cap.actor_kind).toBe("user")
  })
})

describe("redaction and input checks", () => {
  it("refuses free text that carries a token-like run of 32 or more characters", () => {
    const leaked = `failed for ${"x".repeat(31)}Y`
    const message =
      "detail must not carry a token-like value (a run of 32 or more base64url characters)."
    expect(() => authenticationEvent({ ...authInput, detail: leaked })).toThrow(
      new TypeError(message),
    )
    expect(() => authenticationEvent({ ...authInput, reason: leaked })).toThrow(
      new TypeError(message.replace("detail", "reason")),
    )
    expect(() => authenticationEvent({ ...authInput, deviation: leaked })).toThrow(
      new TypeError(message.replace("detail", "deviation")),
    )
    expect(() =>
      userManagementEvent({ ...userInput, activity: "other", otherName: leaked }),
    ).toThrow(new TypeError(message.replace("detail", "otherName")))
    expect(
      authenticationEvent({ ...authInput, detail: `ok ${"x".repeat(31)}` }).status_detail,
    ).toBe(`ok ${"x".repeat(31)}`)
  })

  it("never names a field after a secret", () => {
    const event = authenticationEvent({
      ...authInput,
      session: { hash: HASH, mfa: true, createdAt: 1, expiresAt: 2 },
      factors: ["password", "totp", "webauthn", "email", "recovery-code"],
      detail: "x",
    })
    const keys = JSON.stringify(event).match(/"[a-z_]+":/g) ?? []
    for (const key of keys) expect(key).not.toMatch(/password|token|code|secret|key"/)
  })

  it("refuses empty identifiers and a time that is not whole epoch milliseconds", () => {
    expect(() => authenticationEvent({ ...authInput, system: "" })).toThrow(
      new TypeError("system must be a non-empty string."),
    )
    expect(() => authenticationEvent({ ...authInput, tenant: "" })).toThrow(
      new TypeError("tenant must be a non-empty string."),
    )
    expect(() => authenticationEvent({ ...authInput, subject: { kind: "user", id: "" } })).toThrow(
      new TypeError("subject.id must be a non-empty string."),
    )
    expect(() => userManagementEvent({ ...userInput, actor: { kind: "user", id: "" } })).toThrow(
      new TypeError("actor.id must be a non-empty string."),
    )
    for (const time of [-1, 1.5, Number.NaN]) {
      expect(() => userManagementEvent({ ...userInput, time })).toThrow(
        new RangeError("time must be whole epoch milliseconds."),
      )
    }
    expect(userManagementEvent({ ...userInput, time: 0 }).time).toBe(0)
  })
})

describe("deliver", () => {
  const event = authenticationEvent(authInput)

  it("hands the event to the sink", async () => {
    const seen: SecurityEvent[] = []
    await deliver((received) => {
      seen.push(received)
    }, event)
    expect(seen).toEqual([event])
  })

  it("resolves when there is no sink, without reporting anything", async () => {
    const reported: unknown[] = []
    await expect(
      deliver(undefined, event, (error) => {
        reported.push(error)
      }),
    ).resolves.toBeUndefined()
    expect(reported).toEqual([])
  })

  it("never rejects when the sink throws or rejects, and reports the error with its event", async () => {
    const reported: [unknown, SecurityEvent][] = []
    const report = (error: unknown, failed: SecurityEvent): void => {
      reported.push([error, failed])
    }
    const thrown = new Error("sink down")
    await expect(
      deliver(
        () => {
          throw thrown
        },
        event,
        report,
      ),
    ).resolves.toBeUndefined()
    await expect(deliver(() => Promise.reject(thrown), event, report)).resolves.toBeUndefined()
    expect(reported).toEqual([
      [thrown, event],
      [thrown, event],
    ])
  })

  it("never rejects even when the error reporter itself throws, or when no reporter is given", async () => {
    const failing = (): void => {
      throw new Error("sink down")
    }
    await expect(
      deliver(failing, event, () => {
        throw new Error("reporter down")
      }),
    ).resolves.toBeUndefined()
    await expect(deliver(failing, event)).resolves.toBeUndefined()
  })

  it("never rejects when an async error reporter rejects, and waits for the reporter", async () => {
    let reporterSettled = false
    const unhandled: unknown[] = []
    const onUnhandled = (reason: unknown): void => {
      unhandled.push(reason)
    }
    process.on("unhandledRejection", onUnhandled)
    try {
      await expect(
        deliver(
          () => {
            throw new Error("sink down")
          },
          event,
          async () => {
            await new Promise((resolve) => setTimeout(resolve, 5))
            reporterSettled = true
            throw new Error("reporter down")
          },
        ),
      ).resolves.toBeUndefined()
      expect(reporterSettled).toBe(true)
      await new Promise((resolve) => setTimeout(resolve, 10))
      expect(unhandled).toEqual([])
    } finally {
      process.off("unhandledRejection", onUnhandled)
    }
  })

  it("waits for an async sink to finish", async () => {
    let finished = false
    await deliver(async () => {
      await new Promise((resolve) => setTimeout(resolve, 5))
      finished = true
    }, event)
    expect(finished).toBe(true)
  })
})
