/**
 * The form model (ADR 0025 §1): a framework-free description of each sign-in form that the default pages and the
 * React components both render, so the UX contract is tested once and holds in both.
 *
 * A model holds its fields, each field's help and error text, the error row's text, and every string, all replaceable
 * through `messages`. Validation here is the same validation the browser script runs, read from the same limits the
 * server enforces. A model never keeps a password or code: after an error only the identifier comes back
 * (ADR 0025 Open 2), so no secret is ever written into a page.
 */

import {
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_ALONE,
  PASSWORD_MIN_WITH_MFA,
} from "../methods/password/rules.js"
import { CONFIRMATION_DIGITS } from "../core/email.js"
import { TOTP_DIGITS } from "../methods/totp/totp.js"

/**
 * The forms in the first slice: sign-in, sign-up, email confirmation, choosing a password, the second-factor challenge,
 * TOTP enrolment and step-up. Sign-up follows the API: `sign-up` posts the identifier to `/auth/sign-up`, then
 * `email-confirm` posts the emailed code to `/auth/email/confirm`, then `password` posts the new password to
 * `/auth/password`, then `totp-enrol` confirms the authenticator app.
 */
export type FormId =
  "sign-in" | "sign-up" | "email-confirm" | "password" | "mfa" | "totp-enrol" | "step-up"

/** Every string the forms show. Each one can be replaced; `{min}`, `{max}` and `{seconds}` are filled in. */
export interface Messages {
  /** Sign-in page title. */
  readonly signInTitle: string
  /** Sign-in button. */
  readonly signInSubmit: string
  /** Sign-up page title. */
  readonly signUpTitle: string
  /** Sign-up button. */
  readonly signUpSubmit: string
  /** Email confirmation page title. */
  readonly emailConfirmTitle: string
  /** Email confirmation button. */
  readonly emailConfirmSubmit: string
  /** The button that mails a new confirmation code. */
  readonly resendSubmit: string
  /** Sign-out page title. */
  readonly signOutTitle: string
  /** Sign-out button. */
  readonly signOutSubmit: string
  /** The link from sign-in to sign-up. */
  readonly signUpLink: string
  /** The link from sign-up to sign-in. */
  readonly signInLink: string
  /** Title of the page that sets the new account's password. */
  readonly passwordTitle: string
  /** Button of the page that sets the new account's password. */
  readonly passwordSubmit: string
  /** Second-factor page title. */
  readonly mfaTitle: string
  /** Second-factor button. */
  readonly mfaSubmit: string
  /** TOTP enrolment page title. */
  readonly totpEnrolTitle: string
  /** TOTP enrolment button. */
  readonly totpEnrolSubmit: string
  /** Step-up page title. */
  readonly stepUpTitle: string
  /** Step-up button. */
  readonly stepUpSubmit: string
  /** The identifier's label. */
  readonly identifierLabel: string
  /** The identifier's help on sign-in. */
  readonly identifierHelp: string
  /** The identifier's help on sign-up. */
  readonly identifierSignUpHelp: string
  /** The password's label. */
  readonly passwordLabel: string
  /** A current password's help. */
  readonly currentPasswordHelp: string
  /** A new password's help; `{min}` and `{max}` are the length limits. */
  readonly newPasswordHelp: string
  /** The code's label. */
  readonly codeLabel: string
  /** The code's help when signing in or stepping up. */
  readonly codeHelp: string
  /** The code's help while enrolling an authenticator app. */
  readonly totpEnrolCodeHelp: string
  /** The emailed code's help on the confirmation page. */
  readonly emailCodeHelp: string
  /** The setup key's label on the enrolment page. */
  readonly totpSecretLabel: string
  /** The setup key's help on the enrolment page. */
  readonly totpSecretHelp: string
  /** A missing identifier. */
  readonly identifierRequired: string
  /** A missing password. */
  readonly passwordRequired: string
  /** A missing code. */
  readonly codeRequired: string
  /** An identifier that is not an email address. */
  readonly badEmail: string
  /** A password under the minimum; `{min}` is the minimum. */
  readonly tooShort: string
  /** A password over the maximum; `{max}` is the maximum. */
  readonly tooLong: string
  /** A code that is not six digits. */
  readonly badCode: string
  /** An emailed code that is not six digits. */
  readonly badEmailCode: string
  /** A failed sign-in. The same words whether or not the account exists. */
  readonly invalidCredentials: string
  /** A wrong code. */
  readonly invalidCode: string
  /** A wrong emailed code. */
  readonly invalidEmailCode: string
  /** A new password on the blocklist. */
  readonly passwordTooCommon: string
  /** A new password found in a breach. */
  readonly passwordBreached: string
  /** Rate-limited, with the wait in whole seconds as `{seconds}`. */
  readonly rateLimitedSeconds: string
  /** Rate-limited for one second. */
  readonly rateLimitedOneSecond: string
  /** Rate-limited for an unknown time. */
  readonly rateLimitedUnknown: string
  /** The app's credential-stuffing challenge is needed, and this page cannot show it. */
  readonly challengeRequired: string
  /** The step-up form's challenge expired or was used: nothing was checked, so the person only needs to try again. */
  readonly challengeExpired: string
  /** A failure on the server's side. */
  readonly unexpected: string
  /** The show-password toggle while the password is hidden. */
  readonly showPassword: string
  /** The show-password toggle while the password is shown. */
  readonly hidePassword: string
}

/** The English defaults. */
export const DEFAULT_MESSAGES: Messages = {
  signInTitle: "Sign in",
  signInSubmit: "Sign in",
  signUpTitle: "Create your account",
  signUpSubmit: "Create account",
  emailConfirmTitle: "Confirm your email",
  emailConfirmSubmit: "Confirm",
  resendSubmit: "Send a new code",
  signOutTitle: "Sign out",
  signOutSubmit: "Sign out",
  signUpLink: "Create an account",
  signInLink: "I already have an account",
  passwordTitle: "Choose a password",
  passwordSubmit: "Continue",
  mfaTitle: "Enter your code",
  mfaSubmit: "Verify",
  totpEnrolTitle: "Set up your authenticator app",
  totpEnrolSubmit: "Turn on",
  stepUpTitle: "Confirm it's you",
  stepUpSubmit: "Continue",
  identifierLabel: "Email",
  identifierHelp: "The email address on your account.",
  identifierSignUpHelp: "You'll use this email address to sign in.",
  passwordLabel: "Password",
  currentPasswordHelp: "Paste it from your password manager if you use one.",
  newPasswordHelp:
    "At least {min} characters. A few unrelated words make a strong, memorable password.",
  codeLabel: "Code",
  codeHelp: "The 6-digit code from your authenticator app.",
  totpEnrolCodeHelp: "Enter the 6-digit code the app shows once you've added the key.",
  emailCodeHelp: "The 6-digit code in the email we sent you.",
  totpSecretLabel: "Setup key",
  totpSecretHelp: "Add this key to your authenticator app, then enter the code it shows.",
  identifierRequired: "Enter your email.",
  passwordRequired: "Enter your password.",
  codeRequired: "Enter the code.",
  badEmail: "Enter an email address, like name@example.org.",
  tooShort: "Use at least {min} characters.",
  tooLong: "Use at most {max} characters.",
  badCode: "Enter the 6 digits from your authenticator app.",
  badEmailCode: "Enter the 6 digits from the email.",
  invalidCredentials: "That email and password didn't work together. Check both and try again.",
  invalidCode: "That code didn't work. Codes change every 30 seconds, so try the newest one.",
  invalidEmailCode: "That code didn't work. Use the code in the newest email we sent.",
  passwordTooCommon: "That password is too common. Choose one that is harder to guess.",
  passwordBreached: "That password has appeared in a data breach. Choose a different one.",
  rateLimitedSeconds: "Too many attempts. Try again in {seconds} seconds.",
  rateLimitedOneSecond: "Too many attempts. Try again in 1 second.",
  rateLimitedUnknown: "Too many attempts. Try again in a moment.",
  challengeRequired: "This sign-in needs an extra check that this page cannot show.",
  challengeExpired: "This form expired. Enter your code again.",
  unexpected: "Something went wrong on our side. Please try again.",
  showPassword: "Show password",
  hidePassword: "Hide password",
}

/** A pattern a whole value must match, and the error when it does not. */
export interface FieldPattern {
  /** A regular expression source, matched against the whole value. */
  readonly source: string
  /** The error when the value does not match. */
  readonly message: string
}

/** Length limits in code points after NFC, each with its error, so a limit can never fail without a message. */
export interface FieldLength {
  /** The minimum length. */
  readonly min: number
  /** The maximum length. */
  readonly max: number
  /** The error under the minimum. */
  readonly tooShort: string
  /** The error over the maximum. */
  readonly tooLong: string
}

/** One field and its state. */
export interface FieldState {
  /** The form field name the server reads. */
  readonly name: "identifier" | "password" | "code"
  /** The input type. */
  readonly type: "email" | "password" | "text"
  /** The visible label. */
  readonly label: string
  /** The help text under the field, replaced by `error` while there is one. */
  readonly help: string
  /** The `autocomplete` value password managers and browsers read. */
  readonly autocomplete: "username webauthn" | "current-password" | "new-password" | "one-time-code"
  /** The on-screen keyboard to offer. */
  readonly inputmode?: "email" | "numeric"
  /** Length limits in code points, each with the error it shows. */
  readonly length?: FieldLength
  /** The whole value must match `source` (after whitespace is stripped, when `stripWhitespace`); else `message`. */
  readonly pattern?: FieldPattern
  /** True for a code, which people often type with spaces. */
  readonly stripWhitespace?: true
  /** True for a password or code: its value is never kept or written back. */
  readonly secret: boolean
  /** The value to show again; always empty for a secret. */
  readonly value: string
  /** The current error, or `null`. */
  readonly error: string | null
  /** The error when the field is empty. */
  readonly requiredMessage: string
}

/** A form's fields: one or more, so the first always exists. */
export type FieldList = readonly [first: FieldState, ...rest: FieldState[]]

/** A form and its state. */
export interface FormModel {
  /** Which form. */
  readonly id: FormId
  /** The page title. */
  readonly title: string
  /** The submit button's text. */
  readonly submitLabel: string
  /** The fields, identifier first. */
  readonly fields: FieldList
  /** The error row's text, or `null`. */
  readonly globalError: string | null
  /** Every string, with the app's replacements applied. */
  readonly messages: Messages
}

/** Options for `createForm`. */
export interface FormOptions {
  /** Replacements for any of the default strings. */
  readonly messages?: Partial<Messages> | undefined
  /** True when a deviation lets a password alone satisfy a requirement: the minimum rises to 15 (ADR 0010). */
  readonly passwordAlone?: boolean | undefined
}

function fill(template: string, values: Readonly<Record<string, number>>): string {
  return template.replace(/\{(min|max|seconds)\}/g, (match, key: string) =>
    values[key] === undefined ? match : String(values[key]),
  )
}

const EMAIL = "[^\\s@]+@[^\\s@]+"

function identifier(messages: Messages, signUp: boolean): FieldState {
  return {
    name: "identifier",
    type: "email",
    label: messages.identifierLabel,
    help: signUp ? messages.identifierSignUpHelp : messages.identifierHelp,
    autocomplete: "username webauthn",
    inputmode: "email",
    pattern: { source: EMAIL, message: messages.badEmail },
    secret: false,
    value: "",
    error: null,
    requiredMessage: messages.identifierRequired,
  }
}

function passwordBase(messages: Messages) {
  return {
    name: "password",
    type: "password",
    label: messages.passwordLabel,
    secret: true,
    value: "",
    error: null,
    requiredMessage: messages.passwordRequired,
  } as const
}

function currentPassword(messages: Messages): FieldState {
  return {
    ...passwordBase(messages),
    help: messages.currentPasswordHelp,
    autocomplete: "current-password",
  }
}

function newPassword(messages: Messages, min: number): FieldState {
  const limits = { min, max: PASSWORD_MAX_LENGTH }
  return {
    ...passwordBase(messages),
    help: fill(messages.newPasswordHelp, limits),
    autocomplete: "new-password",
    length: {
      min,
      max: PASSWORD_MAX_LENGTH,
      tooShort: fill(messages.tooShort, limits),
      tooLong: fill(messages.tooLong, limits),
    },
  }
}

function code(messages: Messages, help: string, bad: string, digits = TOTP_DIGITS): FieldState {
  return {
    name: "code",
    type: "text",
    label: messages.codeLabel,
    help,
    autocomplete: "one-time-code",
    inputmode: "numeric",
    pattern: { source: `[0-9]{${digits}}`, message: bad },
    stripWhitespace: true,
    secret: true,
    value: "",
    error: null,
    requiredMessage: messages.codeRequired,
  }
}

/** A new, empty form. */
export function createForm(id: FormId, options: FormOptions = {}): FormModel {
  const messages: Messages = { ...DEFAULT_MESSAGES, ...options.messages }
  const min = options.passwordAlone === true ? PASSWORD_MIN_ALONE : PASSWORD_MIN_WITH_MFA
  const forms: Readonly<Record<FormId, () => Omit<FormModel, "id" | "globalError" | "messages">>> =
    {
      "sign-in": () => ({
        title: messages.signInTitle,
        submitLabel: messages.signInSubmit,
        fields: [identifier(messages, false), currentPassword(messages)],
      }),
      "sign-up": () => ({
        title: messages.signUpTitle,
        submitLabel: messages.signUpSubmit,
        fields: [identifier(messages, true)],
      }),
      "email-confirm": () => ({
        title: messages.emailConfirmTitle,
        submitLabel: messages.emailConfirmSubmit,
        fields: [
          code(messages, messages.emailCodeHelp, messages.badEmailCode, CONFIRMATION_DIGITS),
        ],
      }),
      password: () => ({
        title: messages.passwordTitle,
        submitLabel: messages.passwordSubmit,
        fields: [newPassword(messages, min)],
      }),
      mfa: () => ({
        title: messages.mfaTitle,
        submitLabel: messages.mfaSubmit,
        fields: [code(messages, messages.codeHelp, messages.badCode)],
      }),
      "totp-enrol": () => ({
        title: messages.totpEnrolTitle,
        submitLabel: messages.totpEnrolSubmit,
        fields: [code(messages, messages.totpEnrolCodeHelp, messages.badCode)],
      }),
      "step-up": () => ({
        title: messages.stepUpTitle,
        submitLabel: messages.stepUpSubmit,
        fields: [code(messages, messages.codeHelp, messages.badCode)],
      }),
    }
  return { id, globalError: null, messages, ...forms[id]() }
}

/** The value as the server and the browser both check it: whitespace removed from a code, nothing else changed. */
function prepared(field: FieldState, raw: string): string {
  return field.stripWhitespace === true ? raw.replace(/\s/g, "") : raw
}

/** The error for `raw` in `field`, or `null`. Length counts code points after NFC, as the password rules do. */
function check(field: FieldState, raw: string): string | null {
  const value = prepared(field, raw)
  if (value === "") return field.requiredMessage
  if (field.length !== undefined) {
    const count = [...value.normalize("NFC")].length
    if (count < field.length.min) return field.length.tooShort
    if (count > field.length.max) return field.length.tooLong
  }
  if (field.pattern !== undefined && !new RegExp(`^(?:${field.pattern.source})$`).test(value)) {
    return field.pattern.message
  }
  return null
}

/** Maps every field, keeping the type's promise that there is at least one. */
function mapFields(model: FormModel, change: (field: FieldState) => FieldState): FieldList {
  const [first, ...rest] = model.fields
  return [change(first), ...rest.map(change)]
}

/** Checks a submission. Keeps the identifier to show again, never a password or code, and clears the error row. */
export function validateForm(
  model: FormModel,
  input: Readonly<Record<string, unknown>>,
): FormModel {
  return {
    ...model,
    globalError: null,
    fields: mapFields(model, (field) => {
      const submitted = input[field.name]
      const raw = typeof submitted === "string" ? submitted : ""
      return { ...field, value: field.secret ? "" : raw, error: check(field, raw) }
    }),
  }
}

/** True when no field has an error. */
export function isValid(model: FormModel): boolean {
  return model.fields.every((field) => field.error === null)
}

/** Why a flow refused a valid-looking submission. */
export interface FlowOutcome {
  /** What went wrong, in words that never reveal whether an account exists. */
  readonly error:
    | "invalid-credentials"
    | "invalid-code"
    | "too-common"
    | "breached"
    | "rate-limited"
    | "challenge-required"
    | "invalid-challenge"
    | "unexpected"
  /** For `rate-limited`: how long until the next attempt is allowed. */
  readonly retryAfterMs?: number | undefined
}

function rateLimited(messages: Messages, retryAfterMs: number | undefined): string {
  if (retryAfterMs === undefined) return messages.rateLimitedUnknown
  const seconds = Math.ceil(retryAfterMs / 1000)
  return seconds === 1
    ? messages.rateLimitedOneSecond
    : fill(messages.rateLimitedSeconds, { seconds })
}

/** Puts a flow's refusal in the error row. Secret values are cleared; the identifier stays. */
export function withOutcome(model: FormModel, outcome: FlowOutcome): FormModel {
  const { messages } = model
  const text: Readonly<Record<FlowOutcome["error"], () => string>> = {
    "invalid-credentials": () => messages.invalidCredentials,
    "invalid-code": () =>
      model.id === "email-confirm" ? messages.invalidEmailCode : messages.invalidCode,
    "too-common": () => messages.passwordTooCommon,
    breached: () => messages.passwordBreached,
    "rate-limited": () => rateLimited(messages, outcome.retryAfterMs),
    "challenge-required": () => messages.challengeRequired,
    "invalid-challenge": () => messages.challengeExpired,
    unexpected: () => messages.unexpected,
  }
  return {
    ...model,
    globalError: text[outcome.error](),
    fields: mapFields(model, (field) => (field.secret ? { ...field, value: "" } : field)),
  }
}

/** Puts `error` on the field named `name`: the server refused a value the browser's own checks let through. */
export function withFieldError(
  model: FormModel,
  name: FieldState["name"],
  error: string,
): FormModel {
  return {
    ...model,
    fields: mapFields(model, (field) => (field.name === name ? { ...field, error } : field)),
  }
}

/** Where focus goes after a submit: the first field with an error, else the error row (`"global"`), else the first field. */
export function focusTarget(model: FormModel): string {
  const invalid = model.fields.find((field) => field.error !== null)
  if (invalid !== undefined) return invalid.name
  if (model.globalError !== null) return "global"
  return model.fields[0].name
}
