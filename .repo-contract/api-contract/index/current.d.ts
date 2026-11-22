/**
 * test-cap: the internal authentication package for MaverickCER apps.
 *
 * This entry holds `createAuth` and the policy that configures it (phase 3), and the foundation's public contract
 * (phase 2): the byte transport an adapter speaks, the store port an app implements, the injected clock and random
 * source, the deployment modes, and the two error types. Adapters live in their own entries, such as
 * `test-cap/express`.
 * @packageDocumentation
 */

/** An argon2id cost: memory in KiB, passes and lanes. ADR 0018 fixes it; only test mode may pass another (ADR 0026 §4). */
export declare interface Argon2Cost {
    /** Memory in KiB. */
    readonly memoryKiB: number;
    /** Passes over the memory. */
    readonly iterations: number;
    /** Lanes. */
    readonly parallelism: number;
}

/**
 * What one successful ceremony proves, recorded as data (ADR 0005 §1). Methods produce `AuthenticationEvidence`;
 * the assurance model computes a session's level from the evidence still valid and never from a stored level.
 */
/** A NIST SP 800-63B-4 authenticator assurance level. */
export declare type AssuranceLevel = "AAL1" | "AAL2" | "AAL3";

/** One record of an audit stream. */
export declare interface AuditEntry {
    /** The audit stream the entry belongs to. */
    readonly stream: string;
    /** The entry's position in its stream: 1 for the first, one more for each next. */
    readonly seq: number;
    /** The JSON document appended at this position. */
    readonly record: JsonValue;
}

/** What `createAuth` returns (ADR 0003 §6). */
export declare interface Auth<Id extends string = "default"> {
    /** Serves every `/auth/*` route; `null` for a path outside them, so the adapter passes the request on. */
    handle(req: PlainRequest): Promise<PlainResponse | null>;
    /** The request's session, read from the store; `null` when it has none, or it is revoked or expired. */
    session(req: PlainRequest): Promise<SessionInfo | null>;
    /** Whether the request's session meets the requirement under `requirementId`, as one of five outcomes. */
    require(req: PlainRequest, requirementId: Id): Promise<RequireResult>;
    /** The server-side calls. */
    readonly admin: AuthAdmin;
}

/** The server-side calls (ADR 0012, ADR 0014). Phase 3 has `revoke`. */
export declare interface AuthAdmin {
    /** Revokes every session of the account, with immediate visibility; resolves to how many it revoked. */
    revoke(subject: string): Promise<number>;
}

/** What `createAuth` takes (ADR 0026). `Id` is the union of the policy's requirement ids. */
export declare interface AuthConfig<Id extends string = "default"> {
    /** The app's store. Production refuses a store that is not durable. */
    readonly store: AuthStore;
    /** The policy from `defineAuthPolicy`; without one, every requirement is the default AAL2. */
    readonly policy?: AuthPolicy<Id> | undefined;
    /**
     * The environment: `process.env`, env-cap's parsed values or a plain object with the same names. Read are
     * `APP_ENV`, `APP_ORIGIN`, `APP_SYSTEM_ID` (required in every mode: it names the system in every security event),
     * `AUTH_ENCRYPTION_KEY` and `AUTH_CSRF_KEY` (ADR 0022).
     */
    readonly env: Readonly<Record<string, string | undefined>>;
    /** The tenant every operation is scoped to (ADR 0012); `default` when absent. */
    readonly tenant?: TenantId | undefined;
    /** A clock for tests. Any mode but `test` refuses to start with one (ADR 0026 §4). */
    readonly clock?: Clock | undefined;
    /** A random source for tests. Any mode but `test` refuses to start with one (ADR 0026 §4). */
    readonly random?: RandomSource | undefined;
    /**
     * An argon2id cost for tests, so a suite does not spend the ADR 0018 cost on every sign-in. Any mode but `test`
     * refuses to start with one (ADR 0018 §1, ADR 0026 §4).
     */
    readonly argon2Cost?: Argon2Cost | undefined;
    /**
     * The fetch the HIBP breach check calls (ADR 0010), usually the global `fetch`. test-cap reaches no network on its
     * own, so the app hands it the capability.
     */
    readonly hibpFetch: HibpFetch;
    /**
     * The app's mail sender. Sign-up mails the address a confirmation code through it (ADR 0021); test-cap does not
     * wait for it, and a sender that throws changes no reply.
     */
    readonly sendEmail: SendEmail;
    /** Receives every security event (ADR 0015). A sink that throws never changes an outcome. */
    readonly onEvent?: EventSink | undefined;
    /** The app's own proxies (ADR 0009 §5); read by the throttles, which arrive in phase 4. */
    readonly trustedProxies?: TrustedProxies | undefined;
}

/** An Authentication (3002) activity test-cap reports. */
export declare type AuthenticationActivity = "logon" | "logoff" | "account-switch";

/** An OCSF Authentication (3002) event. */
export declare interface AuthenticationEvent extends OcsfBaseEvent {
    /** Authentication. */
    readonly class_uid: 3002;
    /** The system that authenticated the subject; OCSF requires a service or a destination endpoint. */
    readonly service: OcsfService;
    /** The session, by a prefix of its stored hash. */
    readonly session?: OcsfSession;
    /** Whether the sign-in was multi-factor. */
    readonly is_mfa?: boolean;
    /** 4 OpenID or 5 SAML. */
    readonly auth_protocol_id?: 4 | 5;
    /** The protocol's caption. */
    readonly auth_protocol?: "OpenID" | "SAML";
    /** 2 Impersonate, on an account switch. */
    readonly account_switch_type_id?: 2;
    /** The switch type's caption. */
    readonly account_switch_type?: "Impersonate";
}

/** What one successful ceremony proves. A failed ceremony produces none. */
export declare interface AuthenticationEvidence {
    /** The method whose ceremony produced this evidence. */
    readonly method: AuthenticationMethod;
    /** The id of the authenticator used, so its own expiry and failure counters can be found. */
    readonly authenticatorId: string;
    /** The factors this one ceremony proved; a passkey with user verification proves two. */
    readonly factors: readonly Factor[];
    /** True when the ceremony is bound to the origin, so a phishing site cannot relay it. */
    readonly phishingResistant: boolean;
    /** True when a captured response cannot be used again. */
    readonly replayResistant: boolean;
    /** How the key behind a possession factor is held; `unknown` for knowledge factors and federation. */
    readonly keyProtection: KeyProtection;
    /** Whether the authenticator verified the person (PIN or biometric) during this ceremony. */
    readonly userVerified: boolean;
    /** Whether attestation was verified to a trusted root during registration. */
    readonly attestationVerified: boolean;
    /** When the ceremony completed, in milliseconds since the epoch, from the injected clock. */
    readonly at: number;
    /** For federation only: the issuer and the upstream authentication context it reported. */
    readonly federation?: {
        /** The issuer that authenticated the person, as listed in the trust config. */
        readonly issuer: string;
        /** The authentication context class the issuer reported, or `null` when it sent none. */
        readonly acr: string | null;
        /** The authentication methods the issuer reported, as sent. */
        readonly amr: readonly string[];
        /**
         * When the person authenticated at the issuer (OIDC `auth_time`, SAML `AuthnInstant`), in milliseconds since the
         * epoch. A trusted issuer's maximum authentication age runs from it, never from `at`.
         */
        readonly authTime: number;
    };
}

/** The inputs of an Authentication event. */
export declare interface AuthenticationInput extends EventInput {
    /** What happened. An account switch is an administrator impersonating the subject. */
    readonly activity: AuthenticationActivity;
    /** The session the event concerns. */
    readonly session?: SessionRef | undefined;
    /** Whether the sign-in was multi-factor. */
    readonly mfa?: boolean | undefined;
    /** The federation protocol of a federated sign-in. */
    readonly protocol?: "openid" | "saml" | undefined;
    /** The assurance level the session holds afterwards; `null` for a session that holds none. */
    readonly assurance?: "AAL1" | "AAL2" | "AAL3" | null | undefined;
    /** True when the sign-in added evidence to an existing session. */
    readonly stepUp?: boolean | undefined;
    /** True for an emergency break-glass session. */
    readonly breakGlass?: boolean | undefined;
    /** The declared deviation from a strict default that made this sign-in possible. Free text: never a secret. */
    readonly deviation?: string | undefined;
    /** The stated reason for an impersonation or break-glass. Free text: never a secret. */
    readonly reason?: string | undefined;
}

/** The methods that produce evidence. Email sign-in and recovery codes produce none (ADR 0005 §5, ADR 0007). */
export declare type AuthenticationMethod = "password" | "totp" | "passkey" | "recovery-code" | "oidc" | "saml";

/** A validated policy. `Id` is the union of its requirement ids. */
export declare interface AuthPolicy<Id extends string> {
    /** The policy version. */
    readonly version: string;
    /** Every relaxation of a strict default, for the policy report. */
    readonly deviations: readonly Deviation[];
    /** The session limits in force. */
    readonly timeouts: SessionTimeouts;
    /** The trust config in force. */
    readonly trust: TrustConfig;
    /** The requirement under `id`; throws on an id the policy does not define. */
    requirement(id: Id): Requirement;
    /** The session's assurance at `now`, or `null` when the session has passed a limit. */
    assurance(session: SessionState, now: number): SessionAssurance | null;
    /** Whether the session's assurance meets the requirement under `id`, as one of five outcomes. */
    require(session: SessionState | null, id: Id, now: number): RequireResult;
}

/** What `defineAuthPolicy` takes. */
export declare interface AuthPolicyInput<Id extends string> {
    /** Names this policy, so a report can say which one computed a session's assurance. */
    readonly version: string;
    /** The requirements, by test-cap requirement id such as `billing.update`. */
    readonly requirements?: {
        readonly [K in Id]: Requirement;
    } | undefined;
    /** The requirement deny by default applies; AAL2 when absent. Below AAL2 is a deviation. */
    readonly defaultRequirement?: Requirement | undefined;
    /** Turns on email sign-in codes and magic links: a deviation that adds no assurance. */
    readonly emailSignIn?: boolean | undefined;
    /** Session limits; a limit longer than ADR 0006 sets is a deviation. */
    readonly timeouts?: Partial<SessionTimeouts> | undefined;
    /** The identity providers whose upstream context may count, up to AAL2. */
    readonly trust?: TrustConfig | undefined;
}

/** The store an app gives `createAuth`. */
export declare interface AuthStore extends StoreOperations {
    /** A short name for messages, such as `memory` or `sql`. */
    readonly kind: string;
    /** False for a store that loses state on restart or is not shared between processes; production refuses it. */
    readonly durable: boolean;
    /**
     * Optional. The steps in `fn` commit together or not at all. `fn` must use the handle it receives, never the
     * outer store.
     */
    transaction?<T>(fn: (tx: StoreTransaction) => Promise<T>): Promise<T>;
}

/**
 * The injected clock and random source (ADR 0003). Every expiry, window and time step reads a `Clock`; every token,
 * code and challenge draws from a `RandomSource`. The defaults read the system clock and Web Crypto.
 */
/** The time source every flow reads. */
export declare interface Clock {
    /** Epoch milliseconds. */
    now(): number;
}

/** A configuration test-cap refuses to start with. `problems` lists every one found, not only the first. */
export declare class ConfigError extends Error {
    /** One sentence per failed check, in the order found; never empty. */
    readonly problems: readonly string[];
    constructor(problems: readonly string[]);
}

/** Options for a run. */
export declare interface ConformanceOptions {
    /** Parallel calls per race check (default 25, at least 2). */
    readonly concurrency?: number;
}

/** Every check's outcome; `passed` is true only when none failed. */
export declare interface ConformanceReport {
    /** True only when no check failed. */
    readonly passed: boolean;
    /** One result per check, in the kit's order. */
    readonly results: readonly ConformanceResult[];
}

/** One check's outcome. `detail` shows what the store did against what was required. */
export declare interface ConformanceResult {
    /** The check's stable identifier, such as `consume-once-concurrent`. */
    readonly id: string;
    /** The guarantee the check tests, as one sentence. */
    readonly title: string;
    /** True when the store kept the guarantee or the check was skipped. */
    readonly passed: boolean;
    /** True when the check does not apply (a store without `transaction`). */
    readonly skipped?: boolean;
    /** Present only on a failure: what the guarantee required and what the store gave, or what the check threw. */
    readonly detail?: string;
}

/** A fixed-window counter after an increment. */
export declare interface CounterState {
    /** Increments in the current window, this one included; at least 1. */
    readonly count: number;
    /** When this window started (epoch ms). */
    readonly windowStart: number;
    /** When the next increment starts a new window (epoch ms). */
    readonly resetAt: number;
}

/** Checks the deployment, then builds the `Auth`. Throws one `ConfigError` naming every problem (ADR 0026 §4). */
export declare function createAuth<Id extends string = "default">(config: AuthConfig<Id>): Auth<Id>;

/**
 * Validates a policy and returns it. Throws a `ConfigError` listing every problem: an empty version, a malformed or
 * reserved requirement id, an unknown level, a bad time limit, or a trust config that maps anything to AAL3.
 */
export declare function defineAuthPolicy<const Id extends string = never>(input: AuthPolicyInput<Id>): AuthPolicy<Id | "default">;

/**
 * Deployment mode and the startup checks (ADR 0026). `APP_ENV` sets the mode; a missing or unknown value is
 * production, so a mistyped variable fails safe. Production and staging refuse to start without an HTTPS origin, a
 * durable store and well-formed secrets. The checks look at presence and shape only: a key that is long and random
 * but leaked still passes.
 */
/** The deployment modes every cap shares (ADR 0022). */
export declare type DeploymentMode = "production" | "staging" | "development" | "test";

/** A line of the policy that relaxes a strict default (ADR 0005 §6). */
export declare interface Deviation {
    /** Which default it relaxes. */
    readonly kind: "email-sign-in" | "default-below-aal2" | "timeout-lengthened";
    /** One sentence for the policy report. */
    readonly detail: string;
}

/** One email test-cap asks the app to send (ADR 0021). */
export declare interface EmailMessage {
    /** The normalised address to send to. */
    readonly to: string;
    /** The subject line. */
    readonly subject: string;
    /** The plain-text body. */
    readonly text: string;
}

/** The inputs both classes share. */
export declare interface EventInput {
    /** When it happened, in epoch milliseconds. */
    readonly time: number;
    /** Which system emitted the event (`APP_SYSTEM_ID`). */
    readonly system: string;
    /** The tenant the subject belongs to. */
    readonly tenant: string;
    /** Whom the event is about. */
    readonly subject: EventSubject;
    /** Who acted, when that is not the subject: an administrator impersonating or managing someone. */
    readonly actor?: EventSubject | undefined;
    /** Whether the attempt or change succeeded. */
    readonly outcome: Outcome;
    /** A short explanation, such as why a sign-in failed. Free text: never a secret. */
    readonly detail?: string | undefined;
    /** The factors involved. */
    readonly factors?: readonly FactorKind[] | undefined;
}

/** The app's event sink. It may be async; test-cap waits for it but never lets it change an outcome. */
export declare type EventSink = (event: SecurityEvent) => void | Promise<void>;

/** Who an event is about, or who acted. */
export declare interface EventSubject {
    /** The kind of subject: a person, a service using an API key, or an agent acting through a delegation. */
    readonly kind: "user" | "service" | "agent";
    /** The app's stable, opaque id for the subject; never an email address or a token. */
    readonly id: string;
}

/** The kinds of proof an authenticator gives. */
export declare type Factor = "knowledge" | "possession" | "inherence";

/** A kind of authentication factor test-cap verifies. */
export declare type FactorKind = "password" | "totp" | "webauthn" | "email" | "recovery-code";

/** The levels a trust config may map an upstream context to: federated evidence stops at AAL2. */
export declare type FederatedLevel = "AAL1" | "AAL2";

/** Length limits in code points after NFC, each with its error, so a limit can never fail without a message. */
export declare interface FieldLength {
    /** The minimum length. */
    readonly min: number;
    /** The maximum length. */
    readonly max: number;
    /** The error under the minimum. */
    readonly tooShort: string;
    /** The error over the maximum. */
    readonly tooLong: string;
}

/** A form's fields: one or more, so the first always exists. */
export declare type FieldList = readonly [first: FieldState, ...rest: FieldState[]];

/** A pattern a whole value must match, and the error when it does not. */
export declare interface FieldPattern {
    /** A regular expression source, matched against the whole value. */
    readonly source: string;
    /** The error when the value does not match. */
    readonly message: string;
}

/** One field and its state. */
export declare interface FieldState {
    /** The form field name the server reads. */
    readonly name: "identifier" | "password" | "code";
    /** The input type. */
    readonly type: "email" | "password" | "text";
    /** The visible label. */
    readonly label: string;
    /** The help text under the field, replaced by `error` while there is one. */
    readonly help: string;
    /** The `autocomplete` value password managers and browsers read. */
    readonly autocomplete: "username webauthn" | "current-password" | "new-password" | "one-time-code";
    /** The on-screen keyboard to offer. */
    readonly inputmode?: "email" | "numeric";
    /** Length limits in code points, each with the error it shows. */
    readonly length?: FieldLength;
    /** The whole value must match `source` (after whitespace is stripped, when `stripWhitespace`); else `message`. */
    readonly pattern?: FieldPattern;
    /** True for a code, which people often type with spaces. */
    readonly stripWhitespace?: true;
    /** True for a password or code: its value is never kept or written back. */
    readonly secret: boolean;
    /** The value to show again; always empty for a secret. */
    readonly value: string;
    /** The current error, or `null`. */
    readonly error: string | null;
    /** The error when the field is empty. */
    readonly requiredMessage: string;
}

/** Why a flow refused a valid-looking submission. */
export declare interface FlowOutcome {
    /** What went wrong, in words that never reveal whether an account exists. */
    readonly error: "invalid-credentials" | "invalid-code" | "too-common" | "breached" | "rate-limited" | "unexpected";
    /** For `rate-limited`: how long until the next attempt is allowed. */
    readonly retryAfterMs?: number | undefined;
}

/**
 * The form model (ADR 0025 §1): a framework-free description of each sign-in form that the default pages and the
 * React components both render, so the UX contract is tested once and holds in both.
 *
 * A model holds its fields, each field's help and error text, the error row's text, and every string, all replaceable
 * through `messages`. Validation here is the same validation the browser script runs, read from the same limits the
 * server enforces. A model never keeps a password or code: after an error only the identifier comes back
 * (ADR 0025 Open 2), so no secret is ever written into a page.
 */
/**
 * The forms in the first slice: sign-in, sign-up, email confirmation, choosing a password, the second-factor challenge,
 * TOTP enrolment and step-up. Sign-up follows the API: `sign-up` posts the identifier to `/auth/sign-up`, then
 * `email-confirm` posts the emailed code to `/auth/email/confirm`, then `password` posts the new password to
 * `/auth/password`, then `totp-enrol` confirms the authenticator app.
 */
export declare type FormId = "sign-in" | "sign-up" | "email-confirm" | "password" | "mfa" | "totp-enrol" | "step-up";

/** A form and its state. */
export declare interface FormModel {
    /** Which form. */
    readonly id: FormId;
    /** The page title. */
    readonly title: string;
    /** The submit button's text. */
    readonly submitLabel: string;
    /** The fields, identifier first. */
    readonly fields: FieldList;
    /** The error row's text, or `null`. */
    readonly globalError: string | null;
    /** Every string, with the app's replacements applied. */
    readonly messages: Messages;
}

/** Options for `createForm`. */
export declare interface FormOptions {
    /** Replacements for any of the default strings. */
    readonly messages?: Partial<Messages> | undefined;
    /** True when a deviation lets a password alone satisfy a requirement: the minimum rises to 15 (ADR 0010). */
    readonly passwordAlone?: boolean | undefined;
}

/** The fetch the check calls; the global `fetch` fits it. */
export declare type HibpFetch = (url: string, init: {
    readonly method: "GET";
    readonly headers: Readonly<Record<string, string>>;
    readonly signal: AbortSignal;
}) => Promise<HibpResponse>;

/** The part of a fetch response the check reads. */
export declare interface HibpResponse {
    /** True for a 2xx status. */
    readonly ok: boolean;
    /** The HTTP status. */
    readonly status: number;
    /** The body as text. */
    text(): Promise<string>;
}

/** Plain JSON: what a store must be able to persist and return unchanged. */
export declare type JsonValue = null | boolean | number | string | readonly JsonValue[] | {
    readonly [key: string]: JsonValue;
};

/** How the key behind a possession factor is held: `non-exportable` is required for AAL3 (ADR 0005 §3). */
export declare type KeyProtection = "non-exportable" | "syncable" | "unknown";

/** Every string the forms show. Each one can be replaced; `{min}`, `{max}` and `{seconds}` are filled in. */
export declare interface Messages {
    /** Sign-in page title. */
    readonly signInTitle: string;
    /** Sign-in button. */
    readonly signInSubmit: string;
    /** Sign-up page title. */
    readonly signUpTitle: string;
    /** Sign-up button. */
    readonly signUpSubmit: string;
    /** Email confirmation page title. */
    readonly emailConfirmTitle: string;
    /** Email confirmation button. */
    readonly emailConfirmSubmit: string;
    /** The button that mails a new confirmation code. */
    readonly resendSubmit: string;
    /** Sign-out page title. */
    readonly signOutTitle: string;
    /** Sign-out button. */
    readonly signOutSubmit: string;
    /** The link from sign-in to sign-up. */
    readonly signUpLink: string;
    /** The link from sign-up to sign-in. */
    readonly signInLink: string;
    /** Title of the page that sets the new account's password. */
    readonly passwordTitle: string;
    /** Button of the page that sets the new account's password. */
    readonly passwordSubmit: string;
    /** Second-factor page title. */
    readonly mfaTitle: string;
    /** Second-factor button. */
    readonly mfaSubmit: string;
    /** TOTP enrolment page title. */
    readonly totpEnrolTitle: string;
    /** TOTP enrolment button. */
    readonly totpEnrolSubmit: string;
    /** Step-up page title. */
    readonly stepUpTitle: string;
    /** Step-up button. */
    readonly stepUpSubmit: string;
    /** The identifier's label. */
    readonly identifierLabel: string;
    /** The identifier's help on sign-in. */
    readonly identifierHelp: string;
    /** The identifier's help on sign-up. */
    readonly identifierSignUpHelp: string;
    /** The password's label. */
    readonly passwordLabel: string;
    /** A current password's help. */
    readonly currentPasswordHelp: string;
    /** A new password's help; `{min}` and `{max}` are the length limits. */
    readonly newPasswordHelp: string;
    /** The code's label. */
    readonly codeLabel: string;
    /** The code's help when signing in or stepping up. */
    readonly codeHelp: string;
    /** The code's help while enrolling an authenticator app. */
    readonly totpEnrolCodeHelp: string;
    /** The emailed code's help on the confirmation page. */
    readonly emailCodeHelp: string;
    /** The setup key's label on the enrolment page. */
    readonly totpSecretLabel: string;
    /** The setup key's help on the enrolment page. */
    readonly totpSecretHelp: string;
    /** A missing identifier. */
    readonly identifierRequired: string;
    /** A missing password. */
    readonly passwordRequired: string;
    /** A missing code. */
    readonly codeRequired: string;
    /** An identifier that is not an email address. */
    readonly badEmail: string;
    /** A password under the minimum; `{min}` is the minimum. */
    readonly tooShort: string;
    /** A password over the maximum; `{max}` is the maximum. */
    readonly tooLong: string;
    /** A code that is not six digits. */
    readonly badCode: string;
    /** An emailed code that is not six digits. */
    readonly badEmailCode: string;
    /** A failed sign-in. The same words whether or not the account exists. */
    readonly invalidCredentials: string;
    /** A wrong code. */
    readonly invalidCode: string;
    /** A wrong emailed code. */
    readonly invalidEmailCode: string;
    /** A new password on the blocklist. */
    readonly passwordTooCommon: string;
    /** A new password found in a breach. */
    readonly passwordBreached: string;
    /** Rate-limited, with the wait in whole seconds as `{seconds}`. */
    readonly rateLimitedSeconds: string;
    /** Rate-limited for one second. */
    readonly rateLimitedOneSecond: string;
    /** Rate-limited for an unknown time. */
    readonly rateLimitedUnknown: string;
    /** A failure on the server's side. */
    readonly unexpected: string;
    /** The show-password toggle while the password is hidden. */
    readonly showPassword: string;
    /** The show-password toggle while the password is shown. */
    readonly hidePassword: string;
}

/** One thing a `step-up` asks for. */
export declare type MissingEvidence = {
    /** A higher level. */
    readonly kind: "level";
    /** The level the requirement needs. */
    readonly level: AssuranceLevel;
} | {
    /** Phishing-resistant evidence, such as a passkey. */
    readonly kind: "phishing-resistance";
} | {
    /** Evidence of multiple factors fresher than `withinMs`. */
    readonly kind: "fresh-multi-factor";
    /** How recent, in milliseconds, it must be. */
    readonly withinMs: number;
} | {
    /** A phishing-resistant ceremony fresher than `withinMs`. */
    readonly kind: "fresh-phishing-resistance";
    /** How recent, in milliseconds, it must be. */
    readonly withinMs: number;
};

/** A record to create. */
export declare interface NewRecord {
    /** The collection to create the record in; a non-empty string. */
    readonly collection: string;
    /** The record's key, unique within its tenant and collection; a non-empty string. */
    readonly key: string;
    /** Who the record belongs to, a non-empty string; `null` for none. */
    readonly owner: string | null;
    /** Epoch ms after which `consumeOnce` refuses the record, a whole number; absent or `null` for none. */
    readonly expiresAt?: number | null | undefined;
    /** The record's JSON document. */
    readonly data: JsonValue;
}

/** The subject who acted, when it is not the subject the event is about. */
export declare interface OcsfActor {
    /** The acting subject. */
    readonly user: OcsfUser;
}

/** An OCSF authentication factor. */
export declare interface OcsfAuthFactor {
    /** OCSF's factor type id. */
    readonly factor_type_id: number;
    /** OCSF's caption for the factor type. */
    readonly factor_type: string;
    /** True for a time-based one-time password. */
    readonly is_totp?: true;
}

/** The fields every test-cap event carries: OCSF's base event. */
export declare interface OcsfBaseEvent {
    /** OCSF's activity id within the class. */
    readonly activity_id: number;
    /** OCSF's caption for the activity. */
    readonly activity_name: string;
    /** Identity & Access Management. */
    readonly category_uid: 3;
    /** The category's caption. */
    readonly category_name: "Identity & Access Management";
    /** The class caption. */
    readonly class_name: string;
    /** `class_uid * 100 + activity_id`. */
    readonly type_uid: number;
    /** "Class: Activity". */
    readonly type_name: string;
    /** 1 Informational for a success, 2 Low for a failure. */
    readonly severity_id: 1 | 2;
    /** The severity's caption. */
    readonly severity: "Informational" | "Low";
    /** 1 Success or 2 Failure. */
    readonly status_id: 1 | 2;
    /** The status caption. */
    readonly status: "Success" | "Failure";
    /** Why, for a failure or an unusual success. */
    readonly status_detail?: string;
    /** When it happened, in epoch milliseconds. */
    readonly time: number;
    /** The schema version, the product, and the tenant. */
    readonly metadata: OcsfMetadata;
    /** Whom the event is about. */
    readonly user: OcsfUser;
    /** Who acted, when not the subject. */
    readonly actor?: OcsfActor;
    /** The factors involved. */
    readonly auth_factors?: readonly OcsfAuthFactor[];
    /** test-cap's facts that OCSF has no field for. */
    readonly unmapped: OcsfUnmapped;
}

/** OCSF event metadata. */
export declare interface OcsfMetadata {
    /** The OCSF schema version. */
    readonly version: "1.9.0";
    /** The product that emitted the event. */
    readonly product: OcsfProduct;
    /** The tenant the subject belongs to. */
    readonly tenant_uid: string;
}

/** The product that emitted an event: test-cap itself. */
export declare interface OcsfProduct {
    /** The product's name. */
    readonly name: "test-cap";
    /** The product's vendor. */
    readonly vendor_name: "MaverickCER";
}

/** The system that authenticated the subject. */
export declare interface OcsfService {
    /** The system's id (`APP_SYSTEM_ID`). */
    readonly name: string;
}

/** A session, identified by a prefix of the hash the store holds for it. */
export declare interface OcsfSession {
    /** The first 16 hex characters of the stored SHA-256 of the token. */
    readonly uid: string;
    /** The system that issued the session. */
    readonly issuer: string;
    /** When the session began, in epoch milliseconds. */
    readonly created_time: number;
    /** When the session ends at the latest, in epoch milliseconds. */
    readonly expiration_time: number;
    /** Whether the session's evidence is multi-factor. */
    readonly is_mfa: boolean;
}

/** OCSF's container for attributes it has no field for. */
export declare interface OcsfUnmapped {
    /** test-cap's own facts. */
    readonly test_cap: TestCapFacts;
}

/** An OCSF user, identified only by the app's opaque id. */
export declare interface OcsfUser {
    /** The app's opaque subject id. */
    readonly uid: string;
}

/** Whether the attempt or change succeeded. */
export declare type Outcome = "success" | "failure";

/** One asset as the dispatcher serves it. */
export declare interface PageAsset {
    /** The path the page links to: the base, then `test-cap.<hash>.<extension>`. */
    readonly path: string;
    /** The `Content-Type` to send. */
    readonly contentType: string;
    /** The bytes to send, with immutable caching (ADR 0026). */
    readonly body: Uint8Array;
}

/** The hashed asset paths a page loads. */
export declare interface PageAssets {
    /** The browser script, such as `/auth/assets/test-cap.0123456789ab.js`. */
    readonly script: string;
    /** The optional stylesheet. Without it the page is unstyled, for the app's own CSS. */
    readonly style?: string | undefined;
}

/** The script and the stylesheet. */
export declare interface PageAssetSet {
    /** The browser script. */
    readonly script: PageAsset;
    /** The optional stylesheet. */
    readonly style: PageAsset;
}

/** What a page needs besides its form model. */
export declare interface PageContext {
    /** Where the form posts: a path on this origin. */
    readonly action: string;
    /** The synchronizer token for CSRF (ADR 0011), sent as the hidden field `csrfToken` the dispatcher reads. */
    readonly csrfToken: string;
    /** The hashed asset paths. */
    readonly assets: PageAssets;
    /** The page language (default `en`). */
    readonly lang?: string | undefined;
    /** The base32 setup key, on the TOTP enrolment page only. */
    readonly totpSecret?: string | undefined;
    /** Links shown under the form. */
    readonly links?: readonly PageLink[] | undefined;
    /**
     * Values the route needs from the step before, posted as hidden fields after the token: `authenticatorId` on the
     * TOTP enrolment page, `challenge` on the step-up page. Each value has the token's shape.
     */
    readonly hidden?: Readonly<Record<string, string>> | undefined;
    /** Where a second form, with the token alone, posts for a new emailed code: the email confirmation page's resend. */
    readonly resend?: string | undefined;
}

/** A link to another page, such as from sign-in to sign-up. */
export declare interface PageLink {
    /** A path on this origin. */
    readonly href: string;
    /** The link text. */
    readonly text: string;
}

/**
 * The byte transport contract between adapters and the core (ADR 0003). Adapters convert their framework's request
 * into a `PlainRequest` and write the `PlainResponse` back; they parse nothing.
 */
/** A request as bytes. */
export declare interface PlainRequest {
    /** The HTTP method exactly as received, such as `POST`. */
    readonly method: string;
    /** Absolute (scheme, host, path and query) or origin-form (`/path?query`), exactly as received. */
    readonly url: string;
    /** Repeated headers keep every value. */
    readonly headers: Headers;
    /** The raw body, or `null` when there is none. */
    readonly body: Uint8Array | null;
    /** The socket's peer address. Never a forwarded header (ADR 0009). */
    readonly clientAddress?: string | undefined;
    /** Aborts when the client goes away; the core stops before its next store write. */
    readonly signal?: AbortSignal | undefined;
}

/** A response as bytes. Each `Set-Cookie` value stays separate (`headers.getSetCookie()`). */
export declare interface PlainResponse {
    /** The HTTP status code. */
    readonly status: number;
    /** The response headers; the adapter writes each `Set-Cookie` value as its own header line. */
    readonly headers: Headers;
    /** The raw body, or `null` when there is none. */
    readonly body: Uint8Array | null;
}

/**
 * The random source every token, code and challenge draws from. It must be cryptographically secure in production;
 * a predictable source makes every token guessable.
 */
export declare interface RandomSource {
    /** Fills `bytes` with random values and returns the same array. */
    fill(bytes: Uint8Array): Uint8Array;
}

/** The fields `update` may change. Absent fields keep their value. */
export declare interface RecordChange {
    /** The new JSON document, replacing the old one whole. */
    readonly data?: JsonValue;
    /** The new expiry (epoch ms, a whole number), or `null` to remove it. */
    readonly expiresAt?: number | null;
}

/** What a route or operation needs from the session's assurance. */
export declare interface Requirement {
    /** The lowest level that satisfies it. */
    readonly level: AssuranceLevel;
    /** True when the session must hold phishing-resistant evidence. */
    readonly phishingResistant?: boolean | undefined;
    /** How recent, in milliseconds, the evidence proving multiple factors must be. */
    readonly multiFactorWithinMs?: number | undefined;
    /** How recent, in milliseconds, the last phishing-resistant ceremony must be. */
    readonly phishingResistantWithinMs?: number | undefined;
}

/** The answer of `require`: exactly one of five outcomes (ADR 0005 §7). */
export declare type RequireResult = {
    /** The session meets the requirement. */
    readonly outcome: "allow";
    /** The account the session belongs to. */
    readonly subject: string;
    /** The session's assurance, as computed for this answer. */
    readonly assurance: SessionAssurance;
} | {
    /** A session exists, but its assurance falls short. */
    readonly outcome: "step-up";
    /** The account the session belongs to. */
    readonly subject: string;
    /** What a step-up must add. */
    readonly missing: readonly MissingEvidence[];
    /** The session's assurance, as computed for this answer. */
    readonly assurance: SessionAssurance;
} | {
    /** The session is in the pre-auth state: MFA is not set up yet. */
    readonly outcome: "enroll";
} | {
    /** The session came from recovery and may only restore authenticators. */
    readonly outcome: "recovery-only";
} | {
    /** No valid session. */
    readonly outcome: "unauthenticated";
};

/** Every event test-cap emits. */
export declare type SecurityEvent = AuthenticationEvent | UserManagementEvent;

/** The app's mail sender (ADR 0021 §2). */
export declare type SendEmail = (message: EmailMessage) => Promise<void>;

/** A session's assurance, recomputed from the evidence still valid on every read (ADR 0005 §2). */
export declare interface SessionAssurance {
    /** The level the valid evidence supports; `null` when none is valid. */
    readonly level: AssuranceLevel | null;
    /** The evidence still valid. */
    readonly evidence: readonly AuthenticationEvidence[];
    /** The latest time from which the evidence still proves multiple factors; `null` when it does not. */
    readonly lastMultiFactorAt: number | null;
    /** The last phishing-resistant ceremony test-cap ran; `null` for none. */
    readonly lastPhishingResistantAt: number | null;
    /** The newest step-up of each method the session completed. */
    readonly stepUps: readonly StepUpRecord[];
    /** The version of the policy that computed this. */
    readonly policyVersion: string;
    /** When the session ends unless it serves a request first. */
    readonly idleExpiresAt: number;
    /** When the session ends whatever it does. */
    readonly absoluteExpiresAt: number;
}

/** A session as the session endpoint reports it (ADR 0006): what it is, never its token. */
export declare interface SessionInfo {
    /** The session's public id, the one the session list and remote revoke use. */
    readonly id: string;
    /** The account it belongs to. */
    readonly subject: string;
    /** `authenticated`, or `pre-auth` while MFA is not yet set up, or `recovery-only`. */
    readonly state: "authenticated" | "pre-auth" | "recovery-only";
    /** The level its still-valid evidence supports; `null` when none does. */
    readonly level: "AAL1" | "AAL2" | "AAL3" | null;
    /** The methods of its still-valid evidence. */
    readonly methods: readonly AuthenticationMethod[];
    /** When the session ends unless it serves a request first (epoch ms). */
    readonly idleExpiresAt: number;
    /** When the session ends whatever it does (epoch ms). */
    readonly absoluteExpiresAt: number;
}

/** The session states `require` distinguishes (ADR 0005 §7, ADR 0007). */
export declare type SessionKind = "authenticated" | "pre-auth" | "recovery-only";

/** A session, given by the hash the store holds for it, never by its token. */
export declare interface SessionRef {
    /** The stored SHA-256 of the session token, as 64 lowercase hex characters. Only its first 16 are emitted. */
    readonly hash: string;
    /** Whether the session's evidence is multi-factor. */
    readonly mfa: boolean;
    /** When the session began, in epoch milliseconds. */
    readonly createdAt: number;
    /** When the session ends at the latest, in epoch milliseconds. */
    readonly expiresAt: number;
}

/** What the session store holds about one session; never a stored level. */
export declare interface SessionState {
    /** The account the session belongs to. */
    readonly subject: string;
    /** The session's state. */
    readonly state: SessionKind;
    /** The newest evidence of each (method, authenticator) the session gathered, valid or not (ADR 0005 §2). */
    readonly evidence: readonly AuthenticationEvidence[];
    /** The newest step-up of each method the session completed, oldest first (ADR 0005 §2). */
    readonly stepUps: readonly StepUpRecord[];
    /** When the session entered its state; the absolute limit counts from here. */
    readonly startedAt: number;
    /** The last request the session served; the idle limit counts from here. */
    readonly lastSeenAt: number;
}

/** The idle and absolute session limits, in milliseconds (ADR 0006 §4 and Open 2). */
export declare interface SessionTimeouts {
    /** Inactivity after which an authenticated session ends. */
    readonly aal2IdleMs: number;
    /** Age after which an authenticated session ends, and after which a piece of evidence stops counting. */
    readonly aal2AbsoluteMs: number;
    /** Inactivity after which no evidence counts towards AAL3. */
    readonly aal3IdleMs: number;
    /** Age after which a piece of evidence stops counting towards AAL3. */
    readonly aal3AbsoluteMs: number;
    /** Inactivity after which a pre-auth or recovery-only session ends. */
    readonly restrictedIdleMs: number;
    /** Age after which a pre-auth or recovery-only session ends. */
    readonly restrictedAbsoluteMs: number;
}

/** The SQL dialects `sqlStore` writes. */
export declare type SqlDialect = "postgres" | "sqlite" | "mysql";

/** A value sent as a statement parameter. */
export declare type SqlParam = string | number | null;

/** The app's query function: runs one statement with its parameters on the app's own connection. */
export declare type SqlQuery = (sql: string, params: readonly SqlParam[]) => Promise<SqlResult>;

/** What the app's query function returns for one statement. */
export declare interface SqlResult {
    /** The rows a `SELECT` or a `RETURNING` clause produced; empty for any other statement. */
    readonly rows: readonly Readonly<Record<string, unknown>>[];
    /**
     * How many rows an `INSERT`, `UPDATE` or `DELETE` changed. An upsert that changed nothing must report 0 (for MySQL,
     * connect without the FOUND_ROWS flag).
     */
    readonly affectedRows: number;
}

/** Options for `sqlStore`. */
export declare interface SqlStoreOptions {
    /** Which SQL the store writes. */
    readonly dialect: SqlDialect;
    /** Runs every statement outside a transaction. */
    readonly query: SqlQuery;
    /** Required for MySQL; elsewhere it enables `AuthStore.transaction`. */
    readonly transaction?: SqlTransaction | undefined;
    /** Prefix for the three table names; lowercase letters, digits and underscores (default `test_cap_`). */
    readonly tablePrefix?: string | undefined;
}

/** Runs `fn` inside one database transaction, with a `query` bound to it; commits on success, rolls back on throw. */
export declare type SqlTransaction = <T>(fn: (query: SqlQuery) => Promise<T>) => Promise<T>;

/** One step-up a session completed. */
export declare interface StepUpRecord {
    /** When the step-up ceremony completed. */
    readonly at: number;
    /** The method that completed it. */
    readonly method: AuthenticationMethod;
}

/** A record as stored. Every read returns a copy; changing it changes nothing stored. */
export declare interface StoredRecord {
    /** The collection the record belongs to, such as `session`. */
    readonly collection: string;
    /** The record's key, unique within its tenant and collection. */
    readonly key: string;
    /** Who the record belongs to, for `listByOwner` and `revokeByOwner`; `null` for none. */
    readonly owner: string | null;
    /** 1 on creation, plus one on every change. */
    readonly version: number;
    /** Epoch ms after which `consumeOnce` refuses the record; `null` for none. */
    readonly expiresAt: number | null;
    /** When the record was revoked; `null` while it is not. Never reset once set. */
    readonly revokedAt: number | null;
    /** When `consumeOnce` took the record; `null` until then. */
    readonly consumedAt: number | null;
    /** The record's JSON document, as last written. */
    readonly data: JsonValue;
}

/** The operations a transaction's steps run with. */
export declare interface StoreOperations {
    /** Tenant-scoped uniqueness: of any number of concurrent creates of one key, exactly one gets `created`. */
    createUnique(tenant: TenantId, record: NewRecord): Promise<"created" | "exists">;
    /** The record at `key` in the collection, revoked and consumed ones included; `null` when there is none. */
    get(tenant: TenantId, collection: string, key: string): Promise<StoredRecord | null>;
    /** The owner's records in one collection, oldest first, revoked and consumed ones included. */
    listByOwner(tenant: TenantId, collection: string, owner: string): Promise<readonly StoredRecord[]>;
    /** Optimistic update: applies only when the stored version is `expectedVersion`. */
    update(tenant: TenantId, collection: string, key: string, expectedVersion: number, change: RecordChange): Promise<"updated" | "conflict" | "missing">;
    /**
     * Sets `revokedAt` unless already set. Once this resolves, no read returns the record unrevoked. `false` when there
     * is no such record.
     */
    revoke(tenant: TenantId, collection: string, key: string, at: number): Promise<boolean>;
    /** Revokes every unrevoked record of the owner in the collection, except `except`; returns how many. */
    revokeByOwner(tenant: TenantId, collection: string, owner: string, at: number, options?: {
        readonly except?: string | undefined;
    }): Promise<number>;
    /** Removes the record; `false` when there was no such record. */
    delete(tenant: TenantId, collection: string, key: string): Promise<boolean>;
    /**
     * Atomic single use: takes the record if it exists, is unconsumed, unrevoked and `now < expiresAt`. Of any number of
     * concurrent calls on one key, exactly one gets the record; the rest get `null`.
     */
    consumeOnce(tenant: TenantId, collection: string, key: string, now: number): Promise<StoredRecord | null>;
    /**
     * Atomic fixed-window counter: no concurrent increment is lost. A call at or after `resetAt` starts a new window at
     * `now` with a count of 1.
     */
    increment(tenant: TenantId, counter: string, windowMs: number, now: number): Promise<CounterState>;
    /** Forgets the counter, so the next `increment` starts a new window with a count of 1. */
    resetCounter(tenant: TenantId, counter: string): Promise<void>;
    /**
     * Appends to an audit stream. The first `seq` is 1 and each next one is the last plus one: a higher `seq` is a
     * `gap`, a used one a `duplicate`, also under concurrency (ADR 0020).
     */
    appendAudit(tenant: TenantId, stream: string, seq: number, record: JsonValue): Promise<"appended" | "gap" | "duplicate">;
    /** Up to `limit` entries with `seq >= fromSeq`, in `seq` order. */
    readAudit(tenant: TenantId, stream: string, fromSeq: number, limit: number): Promise<readonly AuditEntry[]>;
}

/** What the startup check needs to know about the store. */
export declare interface StoreTraits {
    /** The store's short name, such as `memory`, used in the refusal message. */
    readonly kind: string;
    /** False for a store that loses state on restart or is not shared between processes. */
    readonly durable: boolean;
}

/** The handle a transaction's function receives. */
export declare type StoreTransaction = StoreOperations;

/**
 * The `AuthStore` port (ADR 0002). test-cap never opens a connection: the app supplies a store, and every guarantee
 * the flows rely on is an operation of this port, so the hard part (atomicity) is tested once, in the store, by the
 * conformance kit. Every operation is scoped to one tenant (ADR 0012).
 *
 * Records are JSON documents addressed by collection and key, with an optional owner (usually an account id) to list
 * by, a version for optimistic updates, and the three lifecycle times flows check: expiry, revocation, consumption.
 */
/** A tenant id. Single-tenant apps use one constant tenant. */
export declare type TenantId = string;

/** What test-cap records that OCSF has no field for. */
export declare interface TestCapFacts {
    /** Which system emitted the event. */
    readonly system: string;
    /** The kind of subject the event is about. */
    readonly subject_kind: EventSubject["kind"];
    /** The kind of the acting subject, when there is one. */
    readonly actor_kind?: EventSubject["kind"];
    /** The session's assurance level afterwards; `null` when it holds none. */
    readonly assurance_level?: "AAL1" | "AAL2" | "AAL3" | null;
    /** True for a step-up. */
    readonly step_up?: true;
    /** True for a break-glass session. */
    readonly break_glass?: true;
    /** The declared deviation that made the event possible. */
    readonly deviation?: string;
    /** The stated reason for an impersonation or break-glass. */
    readonly reason?: string;
}

/** A request refused by the transport. The message is for logs; responses carry only the code. */
export declare class TransportError extends Error {
    /** Why the request was refused; the only detail a response may carry. */
    readonly code: TransportErrorCode;
    /** The HTTP status the dispatcher answers with: 413 for `body-too-large`, 415 for `unsupported-media-type`, else 400. */
    readonly status: number;
    constructor(code: TransportErrorCode, message: string);
}

/**
 * The error model. A request the core refuses before any flow runs raises a `TransportError`, which the dispatcher
 * turns into its status code. A configuration that cannot run raises a `ConfigError` at startup, listing every problem
 * at once (ADR 0003, ADR 0026).
 */
/** Why the transport refused a request. */
export declare type TransportErrorCode = "aborted" | "ambiguous-header" | "body-too-large" | "duplicate-field" | "invalid-path" | "malformed-body" | "too-many-fields" | "unsupported-media-type";

/** The issuers whose upstream context may count. */
export declare type TrustConfig = readonly TrustedIssuer[];

/** One issuer whose reported authentication context may count, up to AAL2 (ADR 0005 §3). */
export declare interface TrustedIssuer {
    /** The issuer, exactly as its tokens or assertions name it. */
    readonly issuer: string;
    /** Upstream `acr` values and the level each counts as. */
    readonly acr?: Readonly<Record<string, FederatedLevel>> | undefined;
    /** Upstream `amr` values and the level each counts as; the highest mapped value wins. */
    readonly amr?: Readonly<Record<string, FederatedLevel>> | undefined;
    /** How long after the upstream authentication its mapped level holds, in milliseconds; AAL1 after that. */
    readonly maxAuthAgeMs: number;
}

/** The addresses of the app's own proxies, whose `X-Forwarded-For` may be read (ADR 0009 §5). */
export declare type TrustedProxies = readonly string[];

/** A User Management (3007) activity test-cap reports. */
export declare type UserManagementActivity = "create" | "update" | "enable" | "disable" | "password-change" | "password-reset" | "enable-mfa-factors" | "disable-mfa-factors" | "add-programmatic-credentials" | "remove-programmatic-credentials" | "other";

/** An OCSF User Management (3007) event. */
export declare interface UserManagementEvent extends OcsfBaseEvent {
    /** User Management. */
    readonly class_uid: 3007;
}

/** The inputs of a User Management event. */
export declare interface UserManagementInput extends EventInput {
    /** What changed. */
    readonly activity: UserManagementActivity;
    /** The name of an `other` activity, such as "Recovery Codes Issued". Free text: never a secret. */
    readonly otherName?: string | undefined;
}

export { }
