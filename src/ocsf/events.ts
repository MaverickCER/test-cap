/**
 * Security events (ADR 0015) in OCSF 1.9.0: Authentication (3002) for sign-in, sign-out and account switches, and
 * User Management (3007) for changes to an account and its credentials. OCSF 1.9.0 deprecates Account Change (3001) in
 * favour of User Management, and the owner chose 3007 (2026-11-16).
 *
 * This module depends on nothing else in test-cap, so the shared event types can move to a common home unchanged.
 * Field names are OCSF's own. What OCSF has no field for sits under `unmapped.test_cap`.
 *
 * Redaction is built into the inputs: a session is accepted only as the SHA-256 the store already holds, and an event
 * carries just its first 16 hex characters. Free text that carries a token-like run of characters is refused. No
 * input takes a password, code, token or key.
 */

/** The OCSF schema version these events follow. */
export const OCSF_SCHEMA_VERSION = "1.9.0"

/** Who an event is about, or who acted. */
export interface EventSubject {
  /** The kind of subject: a person, a service using an API key, or an agent acting through a delegation. */
  readonly kind: "user" | "service" | "agent"
  /** The app's stable, opaque id for the subject; never an email address or a token. */
  readonly id: string
}

/** A kind of authentication factor test-cap verifies. */
export type FactorKind = "password" | "totp" | "webauthn" | "email" | "recovery-code"

/** Whether the attempt or change succeeded. */
export type Outcome = "success" | "failure"

/** A session, given by the hash the store holds for it, never by its token. */
export interface SessionRef {
  /** The stored SHA-256 of the session token, as 64 lowercase hex characters. Only its first 16 are emitted. */
  readonly hash: string
  /** Whether the session's evidence is multi-factor. */
  readonly mfa: boolean
  /** When the session began, in epoch milliseconds. */
  readonly createdAt: number
  /** When the session ends at the latest, in epoch milliseconds. */
  readonly expiresAt: number
}

/** The inputs both classes share. */
export interface EventInput {
  /** When it happened, in epoch milliseconds. */
  readonly time: number
  /** Which system emitted the event (`APP_SYSTEM_ID`). */
  readonly system: string
  /** The tenant the subject belongs to. */
  readonly tenant: string
  /** Whom the event is about. */
  readonly subject: EventSubject
  /** Who acted, when that is not the subject: an administrator impersonating or managing someone. */
  readonly actor?: EventSubject | undefined
  /** Whether the attempt or change succeeded. */
  readonly outcome: Outcome
  /** A short explanation, such as why a sign-in failed. Free text: never a secret. */
  readonly detail?: string | undefined
  /** The factors involved. */
  readonly factors?: readonly FactorKind[] | undefined
}

/** An Authentication (3002) activity test-cap reports. */
export type AuthenticationActivity = "logon" | "logoff" | "account-switch"

/** The inputs of an Authentication event. */
export interface AuthenticationInput extends EventInput {
  /** What happened. An account switch is an administrator impersonating the subject. */
  readonly activity: AuthenticationActivity
  /** The session the event concerns. */
  readonly session?: SessionRef | undefined
  /** Whether the sign-in was multi-factor. */
  readonly mfa?: boolean | undefined
  /** The federation protocol of a federated sign-in. */
  readonly protocol?: "openid" | "saml" | undefined
  /** The assurance level the session holds afterwards; `null` for a session that holds none. */
  readonly assurance?: "AAL1" | "AAL2" | "AAL3" | null | undefined
  /** True when the sign-in added evidence to an existing session. */
  readonly stepUp?: boolean | undefined
  /** True for an emergency break-glass session. */
  readonly breakGlass?: boolean | undefined
  /** The declared deviation from a strict default that made this sign-in possible. Free text: never a secret. */
  readonly deviation?: string | undefined
  /** The stated reason for an impersonation or break-glass. Free text: never a secret. */
  readonly reason?: string | undefined
}

/** A User Management (3007) activity test-cap reports. */
export type UserManagementActivity =
  | "create"
  | "update"
  | "enable"
  | "disable"
  | "password-change"
  | "password-reset"
  | "enable-mfa-factors"
  | "disable-mfa-factors"
  | "add-programmatic-credentials"
  | "remove-programmatic-credentials"
  | "other"

/** The inputs of a User Management event. */
export interface UserManagementInput extends EventInput {
  /** What changed. */
  readonly activity: UserManagementActivity
  /** The name of an `other` activity, such as "Recovery Codes Issued". Free text: never a secret. */
  readonly otherName?: string | undefined
}

/** An OCSF user, identified only by the app's opaque id. */
export interface OcsfUser {
  /** The app's opaque subject id. */
  readonly uid: string
}

/** An OCSF authentication factor. */
export interface OcsfAuthFactor {
  /** OCSF's factor type id. */
  readonly factor_type_id: number
  /** OCSF's caption for the factor type. */
  readonly factor_type: string
  /** True for a time-based one-time password. */
  readonly is_totp?: true
}

/** What test-cap records that OCSF has no field for. */
export interface TestCapFacts {
  /** Which system emitted the event. */
  readonly system: string
  /** The kind of subject the event is about. */
  readonly subject_kind: EventSubject["kind"]
  /** The kind of the acting subject, when there is one. */
  readonly actor_kind?: EventSubject["kind"]
  /** The session's assurance level afterwards; `null` when it holds none. */
  readonly assurance_level?: "AAL1" | "AAL2" | "AAL3" | null
  /** True for a step-up. */
  readonly step_up?: true
  /** True for a break-glass session. */
  readonly break_glass?: true
  /** The declared deviation that made the event possible. */
  readonly deviation?: string
  /** The stated reason for an impersonation or break-glass. */
  readonly reason?: string
}

/** The product that emitted an event: test-cap itself. */
export interface OcsfProduct {
  /** The product's name. */
  readonly name: "test-cap"
  /** The product's vendor. */
  readonly vendor_name: "MaverickCER"
}

/** OCSF event metadata. */
export interface OcsfMetadata {
  /** The OCSF schema version. */
  readonly version: "1.9.0"
  /** The product that emitted the event. */
  readonly product: OcsfProduct
  /** The tenant the subject belongs to. */
  readonly tenant_uid: string
}

/** The subject who acted, when it is not the subject the event is about. */
export interface OcsfActor {
  /** The acting subject. */
  readonly user: OcsfUser
}

/** The system that authenticated the subject. */
export interface OcsfService {
  /** The system's id (`APP_SYSTEM_ID`). */
  readonly name: string
}

/** A session, identified by a prefix of the hash the store holds for it. */
export interface OcsfSession {
  /** The first 16 hex characters of the stored SHA-256 of the token. */
  readonly uid: string
  /** The system that issued the session. */
  readonly issuer: string
  /** When the session began, in epoch milliseconds. */
  readonly created_time: number
  /** When the session ends at the latest, in epoch milliseconds. */
  readonly expiration_time: number
  /** Whether the session's evidence is multi-factor. */
  readonly is_mfa: boolean
}

/** OCSF's container for attributes it has no field for. */
export interface OcsfUnmapped {
  /** test-cap's own facts. */
  readonly test_cap: TestCapFacts
}

/** The fields every test-cap event carries: OCSF's base event. */
export interface OcsfBaseEvent {
  /** OCSF's activity id within the class. */
  readonly activity_id: number
  /** OCSF's caption for the activity. */
  readonly activity_name: string
  /** Identity & Access Management. */
  readonly category_uid: 3
  /** The category's caption. */
  readonly category_name: "Identity & Access Management"
  /** The class caption. */
  readonly class_name: string
  /** `class_uid * 100 + activity_id`. */
  readonly type_uid: number
  /** "Class: Activity". */
  readonly type_name: string
  /** 1 Informational for a success, 2 Low for a failure. */
  readonly severity_id: 1 | 2
  /** The severity's caption. */
  readonly severity: "Informational" | "Low"
  /** 1 Success or 2 Failure. */
  readonly status_id: 1 | 2
  /** The status caption. */
  readonly status: "Success" | "Failure"
  /** Why, for a failure or an unusual success. */
  readonly status_detail?: string
  /** When it happened, in epoch milliseconds. */
  readonly time: number
  /** The schema version, the product, and the tenant. */
  readonly metadata: OcsfMetadata
  /** Whom the event is about. */
  readonly user: OcsfUser
  /** Who acted, when not the subject. */
  readonly actor?: OcsfActor
  /** The factors involved. */
  readonly auth_factors?: readonly OcsfAuthFactor[]
  /** test-cap's facts that OCSF has no field for. */
  readonly unmapped: OcsfUnmapped
}

/** An OCSF Authentication (3002) event. */
export interface AuthenticationEvent extends OcsfBaseEvent {
  /** Authentication. */
  readonly class_uid: 3002
  /** The system that authenticated the subject; OCSF requires a service or a destination endpoint. */
  readonly service: OcsfService
  /** The session, by a prefix of its stored hash. */
  readonly session?: OcsfSession
  /** Whether the sign-in was multi-factor. */
  readonly is_mfa?: boolean
  /** 4 OpenID or 5 SAML. */
  readonly auth_protocol_id?: 4 | 5
  /** The protocol's caption. */
  readonly auth_protocol?: "OpenID" | "SAML"
  /** 2 Impersonate, on an account switch. */
  readonly account_switch_type_id?: 2
  /** The switch type's caption. */
  readonly account_switch_type?: "Impersonate"
}

/** An OCSF User Management (3007) event. */
export interface UserManagementEvent extends OcsfBaseEvent {
  /** User Management. */
  readonly class_uid: 3007
}

/** Every event test-cap emits. */
export type SecurityEvent = AuthenticationEvent | UserManagementEvent

/** The app's event sink. It may be async; test-cap waits for it but never lets it change an outcome. */
export type EventSink = (event: SecurityEvent) => void | Promise<void>

const AUTHENTICATION: Readonly<Record<AuthenticationActivity, readonly [number, string]>> = {
  logon: [1, "Logon"],
  logoff: [2, "Logoff"],
  "account-switch": [7, "Account Switch"],
}

const USER_MANAGEMENT: Readonly<
  Record<Exclude<UserManagementActivity, "other">, readonly [number, string]>
> = {
  create: [1, "Create"],
  update: [2, "Update"],
  enable: [4, "Enable"],
  disable: [5, "Disable"],
  "password-change": [8, "Password Change"],
  "password-reset": [9, "Password Reset"],
  "enable-mfa-factors": [12, "Enable MFA Factors"],
  "disable-mfa-factors": [13, "Disable MFA Factors"],
  "add-programmatic-credentials": [18, "Add Programmatic Credentials"],
  "remove-programmatic-credentials": [19, "Remove Programmatic Credentials"],
}

const FACTORS: Readonly<Record<FactorKind, OcsfAuthFactor>> = {
  password: { factor_type_id: 11, factor_type: "Password" },
  totp: { factor_type_id: 7, factor_type: "OTP", is_totp: true },
  webauthn: { factor_type_id: 10, factor_type: "WebAuthn" },
  email: { factor_type_id: 8, factor_type: "Email" },
  "recovery-code": { factor_type_id: 99, factor_type: "Recovery Code" },
}

/** Looked up with `get`, so an absent protocol adds no fields without a branch of its own. */
const PROTOCOLS = new Map<
  AuthenticationInput["protocol"],
  Pick<AuthenticationEvent, "auth_protocol_id" | "auth_protocol">
>([
  ["openid", { auth_protocol_id: 4, auth_protocol: "OpenID" }],
  ["saml", { auth_protocol_id: 5, auth_protocol: "SAML" }],
])

const STORED_HASH = /^[0-9a-f]{64}$/
/** A run this long of base64url characters looks like a token, a key or a hash: never free text. */
const TOKEN_LIKE = /[A-Za-z0-9_-]{32}/

function nonEmpty(value: string, name: string): void {
  if (value === "") throw new TypeError(`${name} must be a non-empty string.`)
}

function freeText(value: string | undefined, name: string): void {
  // An absent value reads as the nine letters "undefined", which never matches.
  if (TOKEN_LIKE.test(String(value))) {
    throw new TypeError(
      `${name} must not carry a token-like value (a run of 32 or more base64url characters).`,
    )
  }
}

function epochMs(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${name} must be whole epoch milliseconds.`)
  }
}

function base(
  classUid: 3002 | 3007,
  className: string,
  [activityId, activityName]: readonly [number, string],
  input: EventInput,
  facts: Omit<TestCapFacts, "system" | "subject_kind" | "actor_kind">,
): OcsfBaseEvent & { readonly class_uid: 3002 | 3007 } {
  epochMs(input.time, "time")
  nonEmpty(input.system, "system")
  nonEmpty(input.tenant, "tenant")
  nonEmpty(input.subject.id, "subject.id")
  if (input.actor !== undefined) nonEmpty(input.actor.id, "actor.id")
  freeText(input.detail, "detail")
  const success = input.outcome === "success"
  return {
    activity_id: activityId,
    activity_name: activityName,
    category_uid: 3,
    category_name: "Identity & Access Management",
    class_uid: classUid,
    class_name: className,
    type_uid: classUid * 100 + activityId,
    type_name: `${className}: ${activityName}`,
    severity_id: success ? 1 : 2,
    severity: success ? "Informational" : "Low",
    status_id: success ? 1 : 2,
    status: success ? "Success" : "Failure",
    ...(input.detail === undefined ? {} : { status_detail: input.detail }),
    time: input.time,
    metadata: {
      version: OCSF_SCHEMA_VERSION,
      product: { name: "test-cap", vendor_name: "MaverickCER" },
      tenant_uid: input.tenant,
    },
    user: { uid: input.subject.id },
    ...(input.actor === undefined ? {} : { actor: { user: { uid: input.actor.id } } }),
    ...(input.factors === undefined
      ? {}
      : { auth_factors: input.factors.map((kind) => FACTORS[kind]) }),
    unmapped: {
      test_cap: {
        system: input.system,
        subject_kind: input.subject.kind,
        ...(input.actor === undefined ? {} : { actor_kind: input.actor.kind }),
        ...facts,
      },
    },
  }
}

/** Builds an Authentication (3002) event. Throws on an input that could leak a secret or break the schema. */
export function authenticationEvent(input: AuthenticationInput): AuthenticationEvent {
  if (input.activity === "account-switch" && input.actor === undefined) {
    throw new TypeError("An account switch needs the actor who made it.")
  }
  if (input.session !== undefined) {
    if (!STORED_HASH.test(input.session.hash)) {
      throw new TypeError(
        "session.hash must be the stored SHA-256 of the token: 64 lowercase hex characters.",
      )
    }
    epochMs(input.session.createdAt, "session.createdAt")
    epochMs(input.session.expiresAt, "session.expiresAt")
  }
  freeText(input.deviation, "deviation")
  freeText(input.reason, "reason")
  const event = base(3002, "Authentication", AUTHENTICATION[input.activity], input, {
    ...(input.assurance === undefined ? {} : { assurance_level: input.assurance }),
    ...(input.stepUp === true ? { step_up: true as const } : {}),
    ...(input.breakGlass === true ? { break_glass: true as const } : {}),
    ...(input.deviation === undefined ? {} : { deviation: input.deviation }),
    ...(input.reason === undefined ? {} : { reason: input.reason }),
  })
  const mfa = input.mfa ?? input.session?.mfa
  return {
    ...event,
    class_uid: 3002,
    service: { name: input.system },
    ...(input.session === undefined
      ? {}
      : {
          session: {
            uid: input.session.hash.slice(0, 16),
            issuer: input.system,
            created_time: input.session.createdAt,
            expiration_time: input.session.expiresAt,
            is_mfa: input.session.mfa,
          },
        }),
    ...(mfa === undefined ? {} : { is_mfa: mfa }),
    ...PROTOCOLS.get(input.protocol),
    ...(input.activity === "account-switch"
      ? { account_switch_type_id: 2 as const, account_switch_type: "Impersonate" as const }
      : {}),
  }
}

/** Builds a User Management (3007) event. Throws on an input that could leak a secret or break the schema. */
export function userManagementEvent(input: UserManagementInput): UserManagementEvent {
  let activity: readonly [number, string]
  if (input.activity === "other") {
    if (input.otherName === undefined) {
      throw new TypeError("An Other activity needs otherName to say what happened.")
    }
    freeText(input.otherName, "otherName")
    activity = [99, input.otherName]
  } else {
    if (input.otherName !== undefined)
      throw new TypeError("otherName is only for an Other activity.")
    activity = USER_MANAGEMENT[input.activity]
  }
  return { ...base(3007, "User Management", activity, input, {}), class_uid: 3007 }
}

/**
 * Hands `event` to `sink` and resolves once the sink finishes. It never rejects: a sink that throws or rejects is
 * reported to `onSinkError`, and a reporter that throws or rejects is ignored, so an event sink never decides whether someone
 * signs in (ADR 0015).
 */
export async function deliver(
  sink: EventSink | undefined,
  event: SecurityEvent,
  onSinkError: (error: unknown, event: SecurityEvent) => void | Promise<void> = () => undefined,
): Promise<void> {
  if (sink === undefined) return
  try {
    await sink(event)
  } catch (error) {
    try {
      await onSinkError(error, event)
    } catch {
      // A failing reporter must not change the outcome either; the sink's error has nowhere further to go.
    }
  }
}
