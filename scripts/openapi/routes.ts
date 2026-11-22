/**
 * What the dispatcher's route table cannot say about each `/auth/*` route: a summary, and each reply with the error
 * codes it carries. The paths, methods and body fields come from the route table itself (`routes()` on the dispatcher),
 * and test/docs/openapi.test.ts fails when this table and the route table disagree in either direction.
 */

/** One documented reply: its description and, for an error, the codes `{ "error": "<code>" }` may carry. */
export interface ReplyDoc {
  readonly description: string
  readonly codes?: readonly string[]
}

/** One route's documentation. */
export interface RouteDoc {
  readonly summary: string
  readonly description: string
  /** The route's own replies, by status. Replies every route or every `POST` can give are added for it. */
  readonly replies: Readonly<Record<string, ReplyDoc>>
}

const ISSUED =
  "A session was issued or changed. `outcome` is what the default requirement now says; a form post that ends at `allow` is a 303 to `returnTo` instead. The next CSRF token is in the `X-CSRF-Token` header."
const NO_SESSION: ReplyDoc = { description: "No session.", codes: ["unauthenticated"] }
const SHORTFALL: ReplyDoc = {
  description: "No session, or one that has not finished enrolment.",
  codes: ["unauthenticated"],
}
const NOT_ALLOWED: ReplyDoc = {
  description: "The session does not meet the default requirement.",
  codes: ["enroll", "recovery-only", "step-up"],
}
const ENROLLING: ReplyDoc = {
  description: "The session neither is enrolling nor meets the default requirement.",
  codes: ["recovery-only", "step-up"],
}
const BAD_RETURN_TO: ReplyDoc = {
  description: "`returnTo` is not a same-origin relative path.",
  codes: ["invalid-return-to"],
}

export const ROUTE_DOCS: Readonly<Record<string, RouteDoc>> = {
  "/auth/session": {
    summary: "Read the session and get a CSRF token",
    description:
      "Returns the request's session, or `null`, and a synchronizer token for the next `POST`. A browser with no cookie gets a pre-session cookie the token is bound to.",
    replies: { "200": { description: "`{ session, csrfToken }`." } },
  },
  "/auth/sign-up": {
    summary: "Start an account",
    description:
      "Creates an account in the `pre-auth` state and mails the address a confirmation code, within the send limits of `/auth/email/resend`. Never looks an account up, so the reply says nothing about whether the address is taken.",
    replies: {
      "200": { description: ISSUED },
      "400": {
        description: "The identifier or `returnTo` is not acceptable.",
        codes: ["invalid-identifier", "invalid-return-to"],
      },
    },
  },
  "/auth/email/confirm": {
    summary: "Confirm the address with the emailed code",
    description:
      "Redeems the 6-digit code sign-up mailed, once, within 24 hours, and claims the address for the `pre-auth` session's account. The reply is the same when another account already confirmed the address; then nothing is claimed. Each attempt counts, over the code's whole life: after 5 the code dies, and further attempts answer 429 until a resend issues a new code. Confirming adds no assurance.",
    replies: {
      "200": { description: '`{ outcome: "enroll" }`.' },
      "400": { description: "The code was refused.", codes: ["invalid-code"] },
      "401": NO_SESSION,
      "403": { description: "The session is not enrolling.", codes: ["not-enrolling"] },
      "409": { description: "The account typed no address.", codes: ["no-identifier"] },
      "429": {
        description: "Too many attempts; `Retry-After` gives the wait in seconds.",
        codes: ["rate-limited"],
      },
    },
  },
  "/auth/email/resend": {
    summary: "Send a new confirmation code",
    description:
      "Mails a new code to the address and retires the old one, at most once a minute and 5 times an hour per address, and 20 times an hour per IP address or IPv6 /64. Over a limit nothing is sent and the reply is the same; `retryAfterMs` is the wait before the next send.",
    replies: {
      "200": { description: '`{ outcome: "enroll", retryAfterMs }`.' },
      "401": NO_SESSION,
      "403": { description: "The session is not enrolling.", codes: ["not-enrolling"] },
      "409": {
        description: "The address is already confirmed, or the account typed none.",
        codes: ["already-confirmed", "no-identifier"],
      },
    },
  },
  "/auth/password": {
    summary: "Set the password during enrolment",
    description:
      "Sets the password of a `pre-auth` session's account once its address is confirmed. At least 8 characters inside MFA (15 when a deviation lets a password alone pass), at most 256, screened against a blocklist and HIBP.",
    replies: {
      "200": { description: '`{ outcome: "enroll", enrolled: ["password"] }`.' },
      "400": {
        description: "The password was refused.",
        codes: ["too-short", "too-long", "too-common", "breached"],
      },
      "401": NO_SESSION,
      "403": { description: "The session is not enrolling.", codes: ["not-enrolling"] },
      "409": {
        description: "The address is not confirmed yet, or a concurrent change won.",
        codes: ["confirm-email-first", "conflict"],
      },
      "503": { description: "The argon2id concurrency limit is full.", codes: ["busy"] },
    },
  },
  "/auth/totp/enrol": {
    summary: "Begin TOTP enrolment",
    description:
      "Creates an unconfirmed authenticator and returns its secret for the authenticator app, replacing any enrolment of the account still waiting for its code. An account holds at most 5 TOTP authenticators.",
    replies: {
      "200": { description: "`{ authenticatorId, secret }`." },
      "401": NO_SESSION,
      "403": ENROLLING,
      "409": {
        description:
          "Enrolment sets the password first, or the account already holds 5 TOTP authenticators.",
        codes: ["password-first", "too-many-authenticators"],
      },
    },
  },
  "/auth/totp/confirm": {
    summary: "Confirm TOTP enrolment",
    description:
      "Confirms the authenticator with a current code. During enrolment this completes the account and the session reaches AAL2.",
    replies: {
      "200": { description: ISSUED },
      "400": {
        description: "The code or `returnTo` is not acceptable.",
        codes: ["invalid-code", "invalid-return-to"],
      },
      "401": NO_SESSION,
      "403": ENROLLING,
      "409": { description: "Enrolment sets the password first.", codes: ["password-first"] },
    },
  },
  "/auth/sign-in": {
    summary: "Sign in with a password",
    description:
      "Signs in with a confirmed identifier and a password. Every failure is the same 401 after the same argon2id work, whether or not the account exists.",
    replies: {
      "200": { description: ISSUED },
      "400": BAD_RETURN_TO,
      "401": {
        description: "The identifier and password do not match.",
        codes: ["invalid-credentials"],
      },
      "503": { description: "The argon2id concurrency limit is full.", codes: ["busy"] },
    },
  },
  "/auth/totp/verify": {
    summary: "Add a TOTP code after a password",
    description:
      "Adds the second factor to a signed-in session. A code from a time step already used is refused.",
    replies: {
      "200": { description: ISSUED },
      "400": BAD_RETURN_TO,
      "401": {
        description: "No session, or the code was refused.",
        codes: ["unauthenticated", "invalid-code"],
      },
      "403": {
        description: "The session has not finished enrolment.",
        codes: ["enroll", "recovery-only"],
      },
    },
  },
  "/auth/step-up/start": {
    summary: "Open a step-up",
    description: "Returns a single-use challenge bound to this session.",
    replies: {
      "200": { description: "`{ challenge }`." },
      "401": SHORTFALL,
      "403": {
        description: "The session has not finished enrolment.",
        codes: ["enroll", "recovery-only"],
      },
    },
  },
  "/auth/step-up": {
    summary: "Complete a step-up",
    description:
      "Adds fresh evidence with either `password` or `code`, never both, and rotates the session token.",
    replies: {
      "200": { description: ISSUED },
      "400": {
        description: "Both secrets were sent, or `returnTo` is not acceptable.",
        codes: ["one-secret", "invalid-return-to"],
      },
      "401": {
        description: "No session, or the secret was refused.",
        codes: ["unauthenticated", "invalid-credentials"],
      },
      "403": {
        description:
          "The challenge is not this session's, or the session has not finished enrolment.",
        codes: ["invalid-challenge", "enroll", "recovery-only"],
      },
      "503": { description: "The argon2id concurrency limit is full.", codes: ["busy"] },
    },
  },
  "/auth/sign-out": {
    summary: "Sign out",
    description: "Ends the current session, if any, and clears its cookie.",
    replies: { "200": { description: '`{ outcome: "unauthenticated" }`.' } },
  },
  "/auth/sessions": {
    summary: "List the account's sessions",
    description:
      "Every session of the account: `id`, `current`, `state`, `startedAt`, `lastSeenAt`, `methods`.",
    replies: { "200": { description: "`{ sessions }`." }, "401": NO_SESSION, "403": NOT_ALLOWED },
  },
  "/auth/sessions/revoke": {
    summary: "Revoke one session",
    description:
      "Ends one of the account's sessions. The next request on it fails, with no cache in between.",
    replies: {
      "200": {
        description: "`{ revoked: true }`; revoking the current session also clears its cookie.",
      },
      "401": NO_SESSION,
      "403": NOT_ALLOWED,
      "404": { description: "No such session on this account.", codes: ["not-found"] },
    },
  },
}

/** Replies every `POST` can give before its route runs: the body checks and CSRF (ADR 0003, ADR 0011). */
export const POST_REPLIES: Readonly<Record<string, ReplyDoc>> = {
  "400": {
    description: "The body was refused before the route ran.",
    codes: [
      "undeclared-field",
      "invalid-field",
      "missing-field",
      "malformed-body",
      "duplicate-field",
      "too-many-fields",
      "ambiguous-header",
      "aborted",
    ],
  },
  "403": { description: "The `Origin` or the synchronizer token was refused.", codes: ["csrf"] },
  "413": { description: "The body is over the limit.", codes: ["body-too-large"] },
  "415": { description: "The body is neither a form nor JSON.", codes: ["unsupported-media-type"] },
}

/** Replies any route can give. */
export const ANY_REPLIES: Readonly<Record<string, ReplyDoc>> = {
  "400": { description: "A path two parsers could read differently.", codes: ["invalid-path"] },
  "405": {
    description: "The wrong method; `Allow` names the right one.",
    codes: ["method-not-allowed"],
  },
  "500": { description: "An unexpected error; the body is fixed.", codes: ["internal"] },
}
