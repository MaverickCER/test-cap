// The default pages and the dispatcher must agree on what a form posts: the field names, the CSRF field and the
// route. Each page's own form, filled in and submitted the way a browser submits it, reaches its route's own logic:
// never a 400 for an undeclared or missing field, and never a 403 for the CSRF token. Sign-up follows the API's
// order: the identifier at /auth/sign-up, the emailed code at /auth/email/confirm, then the password at
// /auth/password, then TOTP enrolment; the journey test walks it on the pages auth.handle itself serves.
import { JSDOM, type TestDocument } from "jsdom"
import { describe, expect, it } from "vitest"
import { createAuth } from "../../src/core/auth.js"
import { createForm, type FormId } from "../../src/forms/model.js"
import { renderPage, type PageContext } from "../../src/pages/render.js"
import { memoryStore } from "../../src/store/memory.js"
import {
  Browser,
  confirmationCode,
  discardEmail,
  ENV,
  hibpClear,
  inProcess,
  ORIGIN,
  PASSWORD,
  type Reply,
  testAuth,
} from "../support/auth.js"
import { codeAt } from "../support/totp.js"
import { TEST_ARGON2_COST } from "../support/argon2.js"

const ROUTES: Readonly<Record<FormId, string>> = {
  "sign-in": "/auth/sign-in",
  "sign-up": "/auth/sign-up",
  "email-confirm": "/auth/email/confirm",
  password: "/auth/password",
  mfa: "/auth/totp/verify",
  "totp-enrol": "/auth/totp/confirm",
  "step-up": "/auth/step-up",
}
const HIDDEN: Readonly<Record<FormId, Readonly<Record<string, string>> | undefined>> = {
  "sign-in": undefined,
  "sign-up": undefined,
  "email-confirm": undefined,
  password: undefined,
  mfa: undefined,
  "totp-enrol": { authenticatorId: "YXV0aGVudGljYXRvcg" },
  "step-up": { challenge: "Y2hhbGxlbmdl" },
}
const TYPED: Readonly<Record<string, string>> = {
  identifier: "ada@example.com",
  password: PASSWORD,
  code: "123456",
}

/** The form's fields as a browser posts them: each hidden input's value, and `typed` for the rest. */
function filledIn(page: TestDocument, typed: Readonly<Record<string, string>>): URLSearchParams {
  const body = new URLSearchParams()
  for (const control of page.querySelectorAll('form[data-test-cap="form"] input[name]')) {
    const name = control.getAttribute("name") as string
    body.append(
      name,
      control.getAttribute("type") === "hidden"
        ? (control.getAttribute("value") ?? "")
        : (typed[name] ?? ""),
    )
  }
  return body
}

/** Submits the page's own form, to its own action, as a browser does. */
function post(browser: Browser, page: TestDocument, typed: Readonly<Record<string, string>>) {
  return browser.send({
    method: "POST",
    path: page.querySelector("form")?.getAttribute("action") as string,
    headers: [
      ["Origin", ORIGIN],
      ["Content-Type", "application/x-www-form-urlencoded"],
    ],
    body: filledIn(page, typed).toString(),
  })
}

/** `form`'s page, rendered with the browser's current token, as a document. */
function render(
  browser: Browser,
  form: FormId,
  extra: Pick<PageContext, "totpSecret" | "hidden"> = {},
): TestDocument {
  const html = renderPage(createForm(form), {
    action: ROUTES[form],
    csrfToken: browser.csrf as string,
    assets: { script: "/auth/assets/test-cap.000000000000.js" },
    ...extra,
  })
  return new JSDOM(html).window.document
}

/** Renders `form`'s page with a real token, submits it as a browser would, and returns the reply's status and error. */
async function submit(form: FormId): Promise<readonly [number, string | undefined]> {
  const auth = createAuth({
    store: memoryStore(),
    env: ENV,
    hibpFetch: hibpClear,
    sendEmail: discardEmail,
    argon2Cost: TEST_ARGON2_COST,
  })
  const browser = new Browser(inProcess(auth))
  await browser.start()
  const page = render(browser, form, {
    totpSecret: form === "totp-enrol" ? "JBSWY3DPEHPK3PXP" : undefined,
    // What the server hands the page from the step before: the authenticator being confirmed, the open challenge.
    ...(HIDDEN[form] === undefined ? {} : { hidden: HIDDEN[form] }),
  })
  const reply = await post(browser, page, TYPED)
  return [reply.status, (reply.json as { error?: string } | undefined)?.error]
}

describe("each default page's form against the dispatcher", () => {
  it.each([
    "sign-in",
    "sign-up",
    "email-confirm",
    "password",
    "mfa",
    "totp-enrol",
    "step-up",
  ] as const)(
    "%s posts exactly the fields its route declares, with a token it accepts",
    async (form) => {
      const [, error] = await submit(form)
      expect(["undeclared-field", "missing-field", "invalid-field", "csrf"]).not.toContain(error)
    },
  )

  it("sign-up, email confirmation, password and TOTP enrolment, each submitted from the page auth.handle serves, enrol the account", async () => {
    const { auth, clock, outbox } = testAuth()
    const browser = new Browser(inProcess(auth))
    /** The page auth.handle serves at `path`, as a browser opens it. */
    const open = async (path: string): Promise<TestDocument> => {
      const reply = await browser.send({ method: "GET", path, headers: [["Accept", "text/html"]] })
      expect([path, reply.status]).toEqual([path, 200])
      return new JSDOM(reply.text).window.document
    }
    /** Submits the page's own form as a browser does, asking for HTML, and expects a 303 to `next`. */
    const step = async (
      page: TestDocument,
      typed: Readonly<Record<string, string>>,
      next: string,
    ): Promise<Reply> => {
      const reply = await browser.send({
        method: "POST",
        path: page.querySelector("form")?.getAttribute("action") as string,
        headers: [
          ["Origin", ORIGIN],
          ["Content-Type", "application/x-www-form-urlencoded"],
          ["Accept", "text/html"],
        ],
        body: filledIn(page, typed).toString(),
      })
      expect([reply.status, reply.headers.get("location")]).toEqual([303, next])
      return reply
    }

    const signUp = await open("/auth/sign-up")
    expect([...filledIn(signUp, TYPED).keys()].sort()).toEqual(["csrfToken", "identifier"])
    await step(signUp, TYPED, "/auth/email/confirm")

    const confirm = await open("/auth/email/confirm")
    expect([...filledIn(confirm, TYPED).keys()].sort()).toEqual(["code", "csrfToken"])
    await step(confirm, { code: confirmationCode(outbox, "ada@example.com") }, "/auth/password")

    const password = await open("/auth/password")
    expect([...filledIn(password, TYPED).keys()].sort()).toEqual(["csrfToken", "password"])
    await step(password, TYPED, "/auth/totp/enrol")

    const totp = await open("/auth/totp/enrol")
    expect([...filledIn(totp, TYPED).keys()].sort()).toEqual([
      "authenticatorId",
      "code",
      "csrfToken",
    ])
    const secret = (
      totp.querySelector('[data-test-cap="totp-secret"] code')?.textContent ?? ""
    ).replaceAll(" ", "")
    await step(totp, { code: await codeAt(secret, clock.now()) }, "/")

    const session = await browser.get("/auth/session")
    expect((session.json as { session: { level: string } }).session.level).toBe("AAL2")
  })
})
