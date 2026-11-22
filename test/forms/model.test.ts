import { describe, expect, it } from "vitest"
import {
  createForm,
  DEFAULT_MESSAGES,
  focusTarget,
  isValid,
  validateForm,
  withFieldError,
  withOutcome,
  type FormId,
} from "../../src/forms/model.js"

const ALL_FORMS: FormId[] = [
  "sign-in",
  "sign-up",
  "email-confirm",
  "password",
  "mfa",
  "totp-enrol",
  "step-up",
]

describe("createForm", () => {
  it("puts the identifier first and asks for what each form needs", () => {
    const names = (id: FormId): string[] => createForm(id).fields.map((field) => field.name)
    expect(names("sign-in")).toEqual(["identifier", "password"])
    // Sign-up follows the API: /auth/sign-up takes the identifier alone, /auth/password the password (ADR 0025 §4).
    expect(names("sign-up")).toEqual(["identifier"])
    expect(names("email-confirm")).toEqual(["code"])
    expect(names("password")).toEqual(["password"])
    expect(names("mfa")).toEqual(["code"])
    expect(names("totp-enrol")).toEqual(["code"])
    expect(names("step-up")).toEqual(["code"])
  })

  it("gives each field the autocomplete and inputmode password managers and keyboards expect", () => {
    const signIn = createForm("sign-in").fields
    expect(signIn.map((f) => [f.type, f.autocomplete, f.inputmode])).toEqual([
      ["email", "username webauthn", "email"],
      ["password", "current-password", undefined],
    ])
    expect(createForm("password").fields[0]).toMatchObject({
      type: "password",
      autocomplete: "new-password",
    })
    for (const id of ["mfa", "totp-enrol", "step-up"] as const) {
      expect(createForm(id).fields[0]).toMatchObject({
        type: "text",
        autocomplete: "one-time-code",
        inputmode: "numeric",
        pattern: { source: "[0-9]{6}", message: "Enter the 6 digits from your authenticator app." },
        stripWhitespace: true,
      })
    }
    // The emailed code is typed in, never followed from a link (ADR 0021), with its own help and error.
    expect(createForm("email-confirm").fields[0]).toMatchObject({
      type: "text",
      autocomplete: "one-time-code",
      inputmode: "numeric",
      help: "The 6-digit code in the email we sent you.",
      pattern: { source: "[0-9]{6}", message: "Enter the 6 digits from the email." },
      stripWhitespace: true,
      secret: true,
    })
  })

  it("asks for at least 8 characters when the password is one of two factors, 15 when it stands alone", () => {
    expect(createForm("password").fields[0].length).toStrictEqual({
      min: 8,
      max: 256,
      tooShort: "Use at least 8 characters.",
      tooLong: "Use at most 256 characters.",
    })
    expect(createForm("sign-in").fields[1]?.length).toBeUndefined()
    expect(createForm("password", { passwordAlone: true }).fields[0]).toMatchObject({
      length: {
        min: 15,
        max: 256,
        tooShort: "Use at least 15 characters.",
        tooLong: "Use at most 256 characters.",
      },
    })
    expect(createForm("password").fields[0].help).toBe(
      "At least 8 characters. A few unrelated words make a strong, memorable password.",
    )
  })

  it("starts empty, valid and without errors, with the titles and labels of each form", () => {
    for (const id of ALL_FORMS) {
      const form = createForm(id)
      expect(form.id).toBe(id)
      expect(form.globalError).toBeNull()
      expect(form.fields.every((field) => field.value === "" && field.error === null)).toBe(true)
    }
    expect([createForm("sign-in").title, createForm("sign-in").submitLabel]).toEqual([
      "Sign in",
      "Sign in",
    ])
    expect([createForm("sign-up").title, createForm("sign-up").submitLabel]).toEqual([
      "Create your account",
      "Create account",
    ])
    expect([createForm("email-confirm").title, createForm("email-confirm").submitLabel]).toEqual([
      "Confirm your email",
      "Confirm",
    ])
    expect([createForm("password").title, createForm("password").submitLabel]).toEqual([
      "Choose a password",
      "Continue",
    ])
    expect([createForm("mfa").title, createForm("mfa").submitLabel]).toEqual([
      "Enter your code",
      "Verify",
    ])
    expect([createForm("totp-enrol").title, createForm("totp-enrol").submitLabel]).toEqual([
      "Set up your authenticator app",
      "Turn on",
    ])
    expect([createForm("step-up").title, createForm("step-up").submitLabel]).toEqual([
      "Confirm it's you",
      "Continue",
    ])
  })

  it("lets every string be replaced, and only the strings given", () => {
    const form = createForm("sign-in", {
      messages: { signInTitle: "Welcome back", identifierLabel: "Work email" },
    })
    expect(form.title).toBe("Welcome back")
    expect(form.fields[0]?.label).toBe("Work email")
    expect(form.fields[1]?.label).toBe(DEFAULT_MESSAGES.passwordLabel)
    expect(form.messages.showPassword).toBe("Show password")
  })

  it("leaves a placeholder it has no value for exactly as written", () => {
    const form = createForm("password", {
      messages: { newPasswordHelp: "{min} now, {seconds} later." },
    })
    expect(form.fields[0].help).toBe("8 now, {seconds} later.")
  })

  it("gives the identifier its own help on sign-up", () => {
    expect(createForm("sign-up").fields[0].help).toBe("You'll use this email address to sign in.")
    expect(createForm("sign-in").fields[0].help).toBe("The email address on your account.")
  })

  it("fills {min} and {max} in a replaced message", () => {
    const form = createForm("password", {
      messages: { newPasswordHelp: "Between {min} and {max}.", tooShort: "Need {min}+." },
    })
    expect(form.fields[0].help).toBe("Between 8 and 256.")
    expect(validateForm(form, { password: "x" }).fields[0].error).toBe("Need 8+.")
  })
})

describe("validateForm", () => {
  it("accepts a complete submission and keeps the identifier but never a password or code", () => {
    const form = validateForm(createForm("sign-in"), {
      identifier: "ada@example.org",
      password: "correct horse",
    })
    expect(isValid(form)).toBe(true)
    expect(form.fields.map((f) => f.value)).toEqual(["ada@example.org", ""])
    const code = validateForm(createForm("mfa"), { code: "123456" })
    expect(isValid(code)).toBe(true)
    expect(code.fields[0]?.value).toBe("")
  })

  it("names every missing field, in the field's own words", () => {
    const form = validateForm(createForm("sign-in"), {})
    expect(form.fields.map((f) => f.error)).toEqual(["Enter your email.", "Enter your password."])
    expect(isValid(form)).toBe(false)
    expect(isValid(validateForm(createForm("sign-in"), { identifier: "a@b.c" }))).toBe(false)
  })

  it("checks the email shape", () => {
    expect(
      validateForm(createForm("sign-in"), { identifier: "ada", password: "x" }).fields[0]?.error,
    ).toBe("Enter an email address, like name@example.org.")
    expect(
      validateForm(createForm("sign-in"), { identifier: "a b@c.d", password: "x" }).fields[0]
        ?.error,
    ).toBe("Enter an email address, like name@example.org.")
  })

  it("counts password length in code points after NFC, at both limits", () => {
    const at = (password: string) => validateForm(createForm("password"), { password }).fields[0]
    expect(at("1234567")?.error).toBe("Use at least 8 characters.")
    expect(at("12345678")?.error).toBeNull()
    expect(at("🔐🔐🔐🔐🔐🔐🔐🔐")?.error).toBeNull()
    expect(at("é".repeat(8))?.error).toBeNull()
    expect(at("x".repeat(256))?.error).toBeNull()
    expect(at("x".repeat(257))?.error).toBe("Use at most 256 characters.")
  })

  it("never trims or rejects spaces in a password, and only checks that one was given", () => {
    const form = validateForm(createForm("sign-in"), { identifier: "a@b.c", password: " " })
    expect(form.fields[1]?.error).toBeNull()
  })

  it("accepts a code with spaces, as apps and people often write it, and refuses anything else", () => {
    const code = (value: string) =>
      validateForm(createForm("mfa"), { code: value }).fields[0]?.error
    expect(code("123 456")).toBeNull()
    expect(code(" 123456 ")).toBeNull()
    expect(code("12345")).toBe("Enter the 6 digits from your authenticator app.")
    expect(code("1234567")).toBe("Enter the 6 digits from your authenticator app.")
    expect(code("12345a")).toBe("Enter the 6 digits from your authenticator app.")
    expect(code("")).toBe("Enter the code.")
  })

  it("treats a non-string value as missing", () => {
    expect(validateForm(createForm("mfa"), { code: ["123456"] }).fields[0]?.error).toBe(
      "Enter the code.",
    )
  })

  it("clears an earlier global error", () => {
    const failed = withOutcome(createForm("mfa"), { error: "invalid-code" })
    expect(validateForm(failed, { code: "123456" }).globalError).toBeNull()
  })
})

describe("withOutcome", () => {
  it("shows the same message whether or not the account exists", () => {
    const form = withOutcome(
      validateForm(createForm("sign-in"), { identifier: "a@b.c", password: "x" }),
      {
        error: "invalid-credentials",
      },
    )
    expect(form.globalError).toBe(
      "That email and password didn't work together. Check both and try again.",
    )
    expect(form.fields[0]?.value).toBe("a@b.c")
    expect(form.fields[1]?.value).toBe("")
  })

  it("says how long to wait when rate-limited, rounding up to whole seconds", () => {
    expect(
      withOutcome(createForm("sign-in"), { error: "rate-limited", retryAfterMs: 1_001 })
        .globalError,
    ).toBe("Too many attempts. Try again in 2 seconds.")
    expect(
      withOutcome(createForm("sign-in"), { error: "rate-limited", retryAfterMs: 1_000 })
        .globalError,
    ).toBe("Too many attempts. Try again in 1 second.")
    expect(withOutcome(createForm("sign-in"), { error: "rate-limited" }).globalError).toBe(
      "Too many attempts. Try again in a moment.",
    )
  })

  it("has a message for a wrong code and for an unexpected failure", () => {
    expect(withOutcome(createForm("mfa"), { error: "invalid-code" }).globalError).toBe(
      "That code didn't work. Codes change every 30 seconds, so try the newest one.",
    )
    expect(withOutcome(createForm("email-confirm"), { error: "invalid-code" }).globalError).toBe(
      "That code didn't work. Use the code in the newest email we sent.",
    )
    expect(withOutcome(createForm("mfa"), { error: "unexpected" }).globalError).toBe(
      "Something went wrong on our side. Please try again.",
    )
  })

  it("says why a new password was refused", () => {
    expect(withOutcome(createForm("password"), { error: "too-common" }).globalError).toBe(
      "That password is too common. Choose one that is harder to guess.",
    )
    expect(withOutcome(createForm("password"), { error: "breached" }).globalError).toBe(
      "That password has appeared in a data breach. Choose a different one.",
    )
  })
})

describe("withFieldError", () => {
  it("puts the server's refusal on the one field it names, keeping the others and the values", () => {
    const submitted = validateForm(createForm("sign-in"), {
      identifier: "ada@localhost",
      password: "x",
    })
    const refused = withFieldError(
      submitted,
      "identifier",
      "Enter an email address, like name@example.org.",
    )
    expect(refused.fields.map((field) => [field.name, field.value, field.error])).toEqual([
      ["identifier", "ada@localhost", "Enter an email address, like name@example.org."],
      ["password", "", null],
    ])
    expect(focusTarget(refused)).toBe("identifier")
    expect(refused.globalError).toBeNull()
  })
})

describe("focusTarget", () => {
  it("is the first field with an error, then the error row, then the first field", () => {
    expect(focusTarget(validateForm(createForm("sign-in"), { identifier: "a@b.c" }))).toBe(
      "password",
    )
    expect(focusTarget(validateForm(createForm("sign-in"), {}))).toBe("identifier")
    expect(focusTarget(withOutcome(createForm("mfa"), { error: "invalid-code" }))).toBe("global")
    expect(focusTarget(createForm("mfa"))).toBe("code")
  })
})
