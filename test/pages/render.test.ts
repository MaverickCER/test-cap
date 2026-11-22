import { within } from "@testing-library/dom"
import axe from "axe-core"
import { JSDOM, type TestDocument, type TestElement } from "jsdom"
import { describe, expect, it } from "vitest"
import {
  createForm,
  validateForm,
  withOutcome,
  type FormId,
  type FormModel,
} from "../../src/forms/model.js"
import { renderPage, renderSignOutPage, type PageContext } from "../../src/pages/render.js"

const context: PageContext = {
  action: "/auth/sign-in",
  csrfToken: "c3JmLXRva2VuLWZvci10ZXN0cw",
  assets: {
    script: "/auth/assets/test-cap.0123456789ab.js",
    style: "/auth/assets/test-cap.ba9876543210.css",
  },
}

function page(model: FormModel, extra: Partial<PageContext> = {}): TestDocument {
  return new JSDOM(renderPage(model, { ...context, ...extra })).window.document
}

const IDS: FormId[] = [
  "sign-in",
  "sign-up",
  "email-confirm",
  "password",
  "mfa",
  "totp-enrol",
  "step-up",
]
const enrol = { totpSecret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" }

describe("renderPage: the document", () => {
  it("is a complete UTF-8 document in the given language, titled by the form", () => {
    const doc = page(createForm("sign-in"))
    expect(renderPage(createForm("sign-in"), context).startsWith("<!doctype html>")).toBe(true)
    expect(doc.documentElement.lang).toBe("en")
    expect(page(createForm("sign-in"), { lang: "de-AT" }).documentElement.lang).toBe("de-AT")
    expect(doc.querySelector("meta[charset]")?.getAttribute("charset")).toBe("utf-8")
    expect(doc.title).toBe("Sign in")
    expect(within(doc.body).getByRole("heading", { level: 1 }).textContent).toBe("Sign in")
  })

  it("loads its script and optional stylesheet from the hashed asset paths, with no inline script or style", () => {
    const doc = page(createForm("sign-in"))
    const scripts = [...doc.querySelectorAll("script")]
    expect(
      scripts.map((s) => [s.getAttribute("src"), s.hasAttribute("defer"), s.textContent]),
    ).toEqual([["/auth/assets/test-cap.0123456789ab.js", true, ""]])
    expect(
      [...doc.querySelectorAll('link[rel="stylesheet"]')].map((l) => l.getAttribute("href")),
    ).toEqual(["/auth/assets/test-cap.ba9876543210.css"])
    expect(doc.querySelectorAll("style, [style]")).toHaveLength(0)
    const unstyled = page(createForm("sign-in"), { assets: { script: context.assets.script } })
    expect(unstyled.querySelectorAll('link[rel="stylesheet"]')).toHaveLength(0)
  })

  it("sends no referrer", () => {
    expect(
      page(createForm("sign-in")).querySelector('meta[name="referrer"]')?.getAttribute("content"),
    ).toBe("no-referrer")
  })

  it("posts to the action with the CSRF token", () => {
    const form = page(createForm("sign-in")).querySelector("form")
    expect([form?.method, form?.getAttribute("action")]).toEqual(["post", "/auth/sign-in"])
    // `csrfToken` is the body field the dispatcher reads; any other name is an undeclared field and a 400.
    expect(form?.querySelector<TestElement>('input[type="hidden"][name="csrfToken"]')?.value).toBe(
      context.csrfToken,
    )
  })

  it("posts each hidden value the route needs, after the CSRF token", () => {
    const form = page(createForm("step-up"), {
      hidden: { challenge: "Y2hhbGxlbmdl" },
    }).querySelector("form")
    expect(
      [...(form?.querySelectorAll<TestElement>('input[type="hidden"]') ?? [])].map((input) => [
        input.getAttribute("name"),
        input.value,
      ]),
    ).toStrictEqual([
      ["csrfToken", context.csrfToken],
      ["challenge", "Y2hhbGxlbmdl"],
    ])
  })

  it("accepts a token in the dispatcher's key id, time and MAC shape", () => {
    const token = "k1.1794855793133.ZFnei9lZl9Hms1iAKeh2JsT368DFUXAcIqsxZEDIJo0"
    const form = page(createForm("sign-in"), { csrfToken: token }).querySelector("form")
    expect(form?.querySelector<TestElement>('input[name="csrfToken"]')?.value).toBe(token)
  })

  it("refuses an action, asset path, link, token, secret or language that could escape the page", () => {
    const model = createForm("sign-in")
    const bad: [Partial<PageContext>, string][] = [
      [
        { action: "//evil.example/x" },
        "action must be a path on this origin, such as /auth/sign-in.",
      ],
      [
        { action: "https://evil.example" },
        "action must be a path on this origin, such as /auth/sign-in.",
      ],
      [{ action: "/auth/x?y" }, "action must be a path on this origin, such as /auth/sign-in."],
      [
        { assets: { script: "//cdn.example/x.js" } },
        "assets.script must be a path on this origin, such as /auth/sign-in.",
      ],
      [
        { assets: { script: context.assets.script, style: "javascript:x" } },
        "assets.style must be a path on this origin, such as /auth/sign-in.",
      ],
      [
        { links: [{ href: "javascript:alert(1)", text: "x" }] },
        "links[0].href must be a path on this origin, such as /auth/sign-in.",
      ],
      [{ csrfToken: 'a"><x' }, "csrfToken must be base64url segments joined by dots."],
      [{ csrfToken: "" }, "csrfToken must be base64url segments joined by dots."],
      [{ csrfToken: "a..b" }, "csrfToken must be base64url segments joined by dots."],
      [{ lang: 'en"><x' }, "lang must be a language tag such as en or de-AT."],
      [
        { hidden: { 'x"><y': "v" } },
        "hidden field names must be letters and digits, such as challenge.",
      ],
      [
        { hidden: { csrfToken: "v" } },
        "hidden field names must be letters and digits, such as challenge.",
      ],
      [
        { hidden: { challenge: 'v"><x' } },
        "hidden.challenge must be base64url segments joined by dots.",
      ],
      [
        { resend: "//evil.example" },
        "resend must be a path on this origin, such as /auth/sign-in.",
      ],
    ]
    for (const [extra, message] of bad) {
      expect(() => renderPage(model, { ...context, ...extra }), message).toThrow(
        new TypeError(message),
      )
    }
    expect(() =>
      renderPage(createForm("totp-enrol"), { ...context, totpSecret: "not base32!" }),
    ).toThrow(new TypeError("totpSecret must be base32."))
    expect(() => renderPage(createForm("totp-enrol"), context)).toThrow(
      new TypeError("The TOTP enrolment page needs totpSecret."),
    )
  })

  it("writes the head exactly, with no stylesheet when none is given", () => {
    const markup = renderPage(createForm("sign-in"), {
      ...context,
      assets: { script: context.assets.script },
    })
    expect(markup).toContain(
      '<meta name="referrer" content="no-referrer"><title>Sign in</title><script src="/auth/assets/test-cap.0123456789ab.js" defer></script></head>',
    )
  })

  it("writes exactly the attributes each kind of input needs", () => {
    const names = (doc: TestDocument, name: string): string[] =>
      [...(doc.querySelector(`[name="${name}"]`)?.attributes ?? [])].map((a) => a.name)
    expect(names(page(createForm("sign-in")), "identifier")).toEqual([
      "id",
      "name",
      "type",
      "autocomplete",
      "inputmode",
      "required",
      "aria-describedby",
      "autofocus",
      "data-test-cap",
      "data-help",
      "data-required-message",
      "data-pattern",
      "data-pattern-message",
    ])
    expect(names(page(createForm("sign-in")), "password")).toEqual([
      "id",
      "name",
      "type",
      "autocomplete",
      "required",
      "aria-describedby",
      "data-test-cap",
      "data-help",
      "data-required-message",
    ])
    expect(names(page(validateForm(createForm("mfa"), { code: "x" })), "code")).toEqual([
      "id",
      "name",
      "type",
      "autocomplete",
      "inputmode",
      "required",
      "aria-describedby",
      "aria-invalid",
      "autofocus",
      "data-test-cap",
      "data-help",
      "data-required-message",
      "data-pattern",
      "data-pattern-message",
      "data-strip",
    ])
  })

  it("puts exactly a label, an input, the toggle for a password, and a note in each field", () => {
    const children = (doc: TestDocument, name: string): string[] =>
      [...(doc.querySelector(`[data-field="${name}"]`)?.querySelectorAll(":scope > *") ?? [])].map(
        (e) => e.tagName,
      )
    const signIn = page(createForm("sign-in"))
    expect(children(signIn, "identifier")).toEqual(["LABEL", "INPUT", "P"])
    expect(children(signIn, "password")).toEqual(["LABEL", "INPUT", "BUTTON", "P"])
    expect(signIn.querySelector('[data-field="identifier"]')?.textContent).toBe(
      "EmailThe email address on your account.",
    )
  })

  it("puts exactly the title, the form and any links in the page, and no setup key outside enrolment", () => {
    const children = (doc: TestDocument): string[] =>
      [...(doc.querySelector("main")?.querySelectorAll(":scope > *") ?? [])].map((e) => e.tagName)
    expect(children(page(createForm("sign-in")))).toEqual(["H1", "FORM"])
    expect(
      children(page(createForm("sign-in"), { links: [{ href: "/auth/sign-up", text: "x" }] })),
    ).toEqual(["H1", "FORM", "P"])
    expect(children(page(createForm("totp-enrol"), enrol))).toEqual(["H1", "DIV", "FORM"])
    expect(
      page(createForm("sign-in")).querySelector("main")?.textContent?.startsWith("Sign inEmail"),
    ).toBe(true)
    const linked =
      page(createForm("sign-in"), { links: [] }).querySelector("main")?.textContent ?? ""
    expect(linked.endsWith("Sign in")).toBe(true)
  })

  it("writes no links element when there are no links", () => {
    expect(
      page(createForm("sign-in"), { links: [] }).querySelector('[data-test-cap="links"]'),
    ).toBeNull()
    expect(page(createForm("sign-in")).querySelector('[data-test-cap="links"]')).toBeNull()
  })

  it("renders links to the app's other pages", () => {
    const doc = page(createForm("sign-in"), {
      links: [{ href: "/auth/sign-up", text: "Create an account" }],
    })
    const link = within(doc.body).getByRole("link", { name: "Create an account" })
    expect(link.getAttribute("href")).toBe("/auth/sign-up")
  })
})

describe("renderPage: the UX contract (ADR 0025 §5)", () => {
  it("#1 elements are unstyled and carry data-test-cap hooks", () => {
    const doc = page(createForm("sign-in"))
    for (const hook of [
      "page",
      "title",
      "form",
      "field",
      "label",
      "input",
      "note",
      "global-error",
      "submit",
    ]) {
      expect(doc.querySelector(`[data-test-cap="${hook}"]`), hook).not.toBeNull()
    }
    expect(doc.querySelector("[class]")).toBeNull()
  })

  it("#2 every field has a label, and help text linked by aria-describedby", () => {
    for (const id of IDS) {
      const doc = page(createForm(id), id === "totp-enrol" ? enrol : {})
      for (const field of createForm(id).fields) {
        const input = within(doc.body).getByLabelText(field.label)
        const note = doc.getElementById(input.getAttribute("aria-describedby") ?? "")
        expect(note?.textContent, `${id}/${field.name}`).toBe(field.help)
        expect(input.getAttribute("data-help")).toBe(field.help)
      }
    }
  })

  it("#3 a field error replaces its help text and sets aria-invalid", () => {
    const doc = page(validateForm(createForm("sign-in"), { identifier: "ada" }))
    const email = within(doc.body).getByLabelText("Email")
    expect(email.getAttribute("aria-invalid")).toBe("true")
    const note = doc.getElementById(email.getAttribute("aria-describedby") ?? "")
    expect(note?.textContent).toBe("Enter an email address, like name@example.org.")
    expect(note?.getAttribute("data-state")).toBe("error")
    const valid = page(createForm("sign-in"))
    expect(within(valid.body).getByLabelText("Email").hasAttribute("aria-invalid")).toBe(false)
  })

  it("#4 global errors go in a role=alert row directly above the submit button", () => {
    const doc = page(withOutcome(createForm("mfa"), { error: "invalid-code" }))
    const alert = within(doc.body).getByRole("alert")
    expect(alert.textContent).toBe(
      "That code didn't work. Codes change every 30 seconds, so try the newest one.",
    )
    expect(alert.nextElementSibling?.getAttribute("data-test-cap")).toBe("submit")
    const clean = page(createForm("mfa"))
    expect(within(clean.body).getByRole("alert").textContent).toBe("")
  })

  it("#5 focus starts on the first invalid field, the error row, or the first field", () => {
    const autofocused = (doc: TestDocument) => doc.querySelector("[autofocus]")
    expect(
      autofocused(page(validateForm(createForm("sign-in"), { identifier: "a@b.c" })))?.getAttribute(
        "name",
      ),
    ).toBe("password")
    const global = autofocused(page(withOutcome(createForm("mfa"), { error: "invalid-code" })))
    expect([global?.getAttribute("role"), global?.getAttribute("tabindex")]).toEqual([
      "alert",
      "-1",
    ])
    expect(autofocused(page(createForm("sign-in")))?.getAttribute("name")).toBe("identifier")
    expect(page(createForm("sign-in")).querySelectorAll("[autofocus]")).toHaveLength(1)
  })

  it("#6 autocomplete and inputmode are correct", () => {
    const signIn = page(createForm("sign-in"))
    const email = within(signIn.body).getByLabelText("Email")
    expect([
      email.getAttribute("type"),
      email.getAttribute("autocomplete"),
      email.getAttribute("inputmode"),
    ]).toEqual(["email", "username webauthn", "email"])
    expect(within(signIn.body).getByLabelText("Password").getAttribute("autocomplete")).toBe(
      "current-password",
    )
    expect(
      within(page(createForm("password")).body)
        .getByLabelText("Password")
        .getAttribute("autocomplete"),
    ).toBe("new-password")
    const code = within(page(createForm("mfa")).body).getByLabelText("Code")
    expect([code.getAttribute("autocomplete"), code.getAttribute("inputmode")]).toEqual([
      "one-time-code",
      "numeric",
    ])
  })

  it("#7 a code is one input, never split boxes", () => {
    for (const id of ["mfa", "totp-enrol", "step-up"] as const) {
      expect(
        page(createForm(id), id === "totp-enrol" ? enrol : {}).querySelectorAll(
          '[data-test-cap="input"]',
        ),
      ).toHaveLength(1)
    }
  })

  it("#8 passwords have a show-password toggle, shown once the script runs, and nothing blocks paste", () => {
    const doc = page(createForm("sign-in"))
    const toggle = doc.querySelector('[data-test-cap="toggle-password"]')
    expect(toggle?.tagName).toBe("BUTTON")
    expect(toggle?.getAttribute("type")).toBe("button")
    expect(toggle?.hasAttribute("hidden")).toBe(true)
    expect(toggle?.getAttribute("aria-controls")).toBe(
      within(doc.body).getByLabelText("Password").id,
    )
    expect(toggle?.hasAttribute("aria-pressed")).toBe(false)
    expect([toggle?.getAttribute("data-show"), toggle?.getAttribute("data-hide")]).toEqual([
      "Show password",
      "Hide password",
    ])
    expect(renderPage(createForm("sign-in"), context)).not.toMatch(
      /onpaste|onkeydown|maxlength|readonly/i,
    )
  })

  it("#9 the identifier comes first", () => {
    for (const id of ["sign-in", "sign-up"] as const) {
      const inputs = [...page(createForm(id)).querySelectorAll('[data-test-cap="input"]')]
      expect(inputs[0]?.getAttribute("name")).toBe("identifier")
    }
  })

  it("#10 the identifier is kept after an error, and a password or code never is", () => {
    const failed = withOutcome(
      validateForm(createForm("sign-in"), {
        identifier: "ada@example.org",
        password: "secret-password",
      }),
      { error: "invalid-credentials" },
    )
    const markup = renderPage(failed, context)
    expect(
      within(new JSDOM(markup).window.document.body).getByLabelText<TestElement>("Email").value,
    ).toBe("ada@example.org")
    expect(markup).not.toContain("secret-password")
    const passwordInput = within(
      new JSDOM(markup).window.document.body,
    ).getByLabelText<TestElement>("Password")
    expect(passwordInput.hasAttribute("value")).toBe(false)
  })

  it("#12 a rate limit shows how long to wait", () => {
    const doc = page(
      withOutcome(createForm("sign-in"), { error: "rate-limited", retryAfterMs: 30_000 }),
    )
    expect(within(doc.body).getByRole("alert").textContent).toBe(
      "Too many attempts. Try again in 30 seconds.",
    )
  })

  it("#14 every string comes from the model's messages", () => {
    const form = createForm("sign-in", {
      messages: {
        signInTitle: "Anmelden",
        signInSubmit: "Weiter",
        showPassword: "Zeigen",
        hidePassword: "Verbergen",
      },
    })
    const doc = page(form)
    expect(doc.title).toBe("Anmelden")
    expect(within(doc.body).getByRole("button", { name: "Weiter" })).not.toBeNull()
    expect(doc.querySelector('[data-test-cap="toggle-password"]')?.textContent).toBe("Zeigen")
  })

  it("escapes every model string, so a hostile replacement cannot inject markup", () => {
    const hostile = `<img src=x onerror=alert(1)>`
    const markup = renderPage(
      createForm("sign-in", { messages: { signInTitle: hostile, identifierHelp: hostile } }),
      context,
    )
    expect(markup).not.toContain("<img")
    const doc = new JSDOM(markup).window.document
    expect(doc.title).toBe(hostile)
    expect(doc.querySelector("img")).toBeNull()
  })

  it("passes the browser script everything it validates with, from the same model", () => {
    const input = within(page(createForm("password")).body).getByLabelText("Password")
    expect(
      Object.fromEntries(
        [...input.attributes]
          .filter((a) => a.name.startsWith("data-"))
          .map((a) => [a.name, a.value]),
      ),
    ).toEqual({
      "data-test-cap": "input",
      "data-help":
        "At least 8 characters. A few unrelated words make a strong, memorable password.",
      "data-required-message": "Enter your password.",
      "data-min": "8",
      "data-max": "256",
      "data-too-short-message": "Use at least 8 characters.",
      "data-too-long-message": "Use at most 256 characters.",
    })
    const code = within(page(createForm("mfa")).body).getByLabelText("Code")
    expect([
      code.getAttribute("data-pattern"),
      code.getAttribute("data-strip"),
      code.getAttribute("data-pattern-message"),
    ]).toEqual(["[0-9]{6}", "whitespace", "Enter the 6 digits from your authenticator app."])
    expect(code.hasAttribute("required")).toBe(true)
  })
})

describe("renderPage: TOTP enrolment", () => {
  it("shows the setup key in groups of four, with its label and help", () => {
    const doc = page(createForm("totp-enrol"), enrol)
    const key = doc.querySelector('[data-test-cap="totp-secret"] code')
    expect(key?.textContent).toBe("JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP")
    expect(doc.querySelector('[data-test-cap="totp-secret"]')?.textContent).toContain("Setup key")
    expect(doc.querySelector('[data-test-cap="totp-secret"]')?.textContent).toContain(
      "Add this key to your authenticator app, then enter the code it shows.",
    )
  })

  it("never shows a setup key on any other page", () => {
    expect(page(createForm("mfa"), enrol).querySelector('[data-test-cap="totp-secret"]')).toBeNull()
  })
})

describe("renderPage: email confirmation", () => {
  it("offers a second form that mails a new code, with the same token and no fields", () => {
    const doc = page(createForm("email-confirm"), {
      action: "/auth/email/confirm",
      resend: "/auth/email/resend",
    })
    const forms = [...doc.querySelectorAll("form")]
    expect(
      forms.map((form) => [form.getAttribute("action"), form.getAttribute("data-test-cap")]),
    ).toEqual([
      ["/auth/email/confirm", "form"],
      ["/auth/email/resend", "resend"],
    ])
    const resend = forms[1]
    expect(
      [...(resend?.querySelectorAll<TestElement>("input") ?? [])].map((input) => [
        input.getAttribute("type"),
        input.getAttribute("name"),
        input.getAttribute("value"),
      ]),
    ).toEqual([["hidden", "csrfToken", context.csrfToken]])
    const button = resend?.querySelector("button")
    expect([
      button?.getAttribute("type"),
      button?.getAttribute("data-test-cap"),
      button?.textContent,
    ]).toEqual(["submit", "resend-submit", "Send a new code"])
    expect(resend?.getAttribute("method")).toBe("post")
  })

  it("has no resend form unless the context names one", () => {
    expect(page(createForm("email-confirm")).querySelectorAll("form")).toHaveLength(1)
  })
})

describe("renderSignOutPage", () => {
  const html = renderSignOutPage(createForm("sign-in").messages, {
    ...context,
    action: "/auth/sign-out",
  })
  const doc = new JSDOM(html).window.document

  it("is a complete page with one button that posts the token to the action", () => {
    expect(html.startsWith("<!doctype html>")).toBe(true)
    expect([doc.title, doc.querySelector("h1")?.textContent]).toEqual(["Sign out", "Sign out"])
    const form = doc.querySelector("form")
    expect([form?.getAttribute("method"), form?.getAttribute("action")]).toEqual([
      "post",
      "/auth/sign-out",
    ])
    expect(html).toContain(
      `<form method="post" action="/auth/sign-out" data-test-cap="form" data-form="sign-out"><input type="hidden" name="csrfToken" value="${context.csrfToken}"><button type="submit" data-test-cap="submit">Sign out</button></form>`,
    )
    expect(doc.querySelector("main")?.getAttribute("data-form")).toBe("sign-out")
    expect([...doc.querySelectorAll("script")].map((script) => script.getAttribute("src"))).toEqual(
      [context.assets.script],
    )
    expect(doc.querySelector('link[rel="stylesheet"]')?.getAttribute("href")).toBe(
      context.assets.style,
    )
    expect(doc.querySelector('meta[name="referrer"]')?.getAttribute("content")).toBe("no-referrer")
  })

  it("checks its context as every page does", () => {
    expect(() =>
      renderSignOutPage(createForm("sign-in").messages, { ...context, action: "//x" }),
    ).toThrow(new TypeError("action must be a path on this origin, such as /auth/sign-in."))
  })

  it("has no axe violations", async () => {
    const dom = new JSDOM(html, { runScripts: "outside-only" })
    dom.window.eval(axe.source)
    const results = await (dom.window as unknown as { axe: typeof axe }).axe.run(
      dom.window.document,
      { rules: { "color-contrast": { enabled: false } } },
    )
    expect(results.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([])
  })
})

describe("renderPage: accessibility (axe)", () => {
  const cases: [string, FormModel, Partial<PageContext>][] = [
    ...IDS.map((id): [string, FormModel, Partial<PageContext>] => [
      id,
      createForm(id),
      id === "totp-enrol" ? enrol : {},
    ]),
    ["sign-in with errors", validateForm(createForm("sign-in"), { identifier: "x" }), {}],
    ["mfa with a global error", withOutcome(createForm("mfa"), { error: "invalid-code" }), {}],
  ]

  it.each(cases)("%s has no violations", async (_name, model, extra) => {
    const dom = new JSDOM(renderPage(model, { ...context, ...extra }), {
      runScripts: "outside-only",
    })
    dom.window.eval(axe.source)
    const results = await (dom.window as unknown as { axe: typeof axe }).axe.run(
      dom.window.document,
      {
        rules: { "color-contrast": { enabled: false } },
      },
    )
    expect(results.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([])
  })
})
