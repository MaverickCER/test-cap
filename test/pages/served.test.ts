// The default pages and their hashed assets, served by `auth.handle` (ADR 0025 §4, architecture "Routes"): each page
// under the strict CSP with no inline script and `no-store`; each asset under its content hash, immutable, with its
// content type. A form post that asks for HTML answers with a 303 to the next step or the page again with the
// refusal; a JSON post keeps its JSON.
import { JSDOM, type TestDocument } from "jsdom"
import { describe, expect, it } from "vitest"
import { CONFIRMATION_FAILURE_LIMIT } from "../../src/core/email.js"
import { CLIENT_SCRIPT, pageAssets, STYLESHEET } from "../../src/pages/assets.js"
import { CONTENT_SECURITY_POLICY } from "../../src/security/headers.js"
import {
  aal1,
  aal2,
  body,
  Browser,
  confirmationCode,
  confirmEmail,
  expectOk,
  inProcess,
  ORIGIN,
  PASSWORD,
  type Reply,
  seedAccount,
  seedSession,
  testAuth,
} from "../support/auth.js"
import { codeAt } from "../support/totp.js"

type Setup = ReturnType<typeof testAuth>

/** Every page `auth.handle` serves, and the form it shows. */
const PAGES = [
  ["/auth/sign-up", "sign-up"],
  ["/auth/email/confirm", "email-confirm"],
  ["/auth/password", "password"],
  ["/auth/totp/enrol", "totp-enrol"],
  ["/auth/sign-in", "sign-in"],
  ["/auth/step-up", "step-up"],
  ["/auth/sign-out", "sign-out"],
] as const

const doc = (reply: Reply): TestDocument => new JSDOM(reply.text).window.document

/** A browser that has signed up and gone as far as `upTo` in enrolment: by default, the TOTP step comes next. */
async function enrolling(
  setup: Setup,
  upTo: "sign-up" | "confirm" | "password" = "password",
): Promise<Browser> {
  const browser = new Browser(inProcess(setup.auth))
  await browser.start()
  await expectOk(browser.post("/auth/sign-up", { identifier: "ada@example.com" }))
  if (upTo === "sign-up") return browser
  await confirmEmail(browser, setup.outbox)
  if (upTo === "password") await expectOk(browser.post("/auth/password", { password: PASSWORD }))
  return browser
}

/** A page as a browser asks for it. */
function open(browser: Browser, path: string): Promise<Reply> {
  return browser.send({ method: "GET", path, headers: [["Accept", "text/html"]] })
}

/** A form post as a browser sends it from a page: urlencoded, the token in its field, HTML accepted. */
function submit(browser: Browser, path: string, fields: Record<string, string>): Promise<Reply> {
  return browser.send({
    method: "POST",
    path,
    headers: [
      ["Origin", ORIGIN],
      ["Content-Type", "application/x-www-form-urlencoded"],
      ["Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"],
    ],
    body: new URLSearchParams({ ...fields, csrfToken: browser.csrf ?? "" }).toString(),
  })
}

/** The page's own token, as the browser would post it next. */
function tokenOf(page: TestDocument): string {
  return page.querySelector('input[name="csrfToken"]')?.getAttribute("value") ?? ""
}

/** A browser on every page: one that is enrolling with a password (for TOTP enrolment), else signed in at AAL1. */
async function browserFor(setup: Setup, path: string): Promise<Browser> {
  if (path === "/auth/totp/enrol") return enrolling(setup)
  if (path === "/auth/step-up") {
    const { subject } = await seedAccount(setup, {
      password: true,
      totp: true,
      identifier: "bo@example.com",
    })
    return (await seedSession(setup, { subject, evidence: aal1(setup.clock) })).browser
  }
  return new Browser(inProcess(setup.auth))
}

describe("GET on a default page", () => {
  it.each(PAGES)(
    "%s serves the %s page under the strict CSP, uncached, with its hashed assets",
    async (path, form) => {
      const setup = testAuth()
      const browser = await browserFor(setup, path)
      const reply = await open(browser, path)
      expect(reply.status).toBe(200)
      expect(Object.fromEntries(reply.headers)).toMatchObject({
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "content-security-policy": CONTENT_SECURITY_POLICY,
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
      })
      const page = doc(reply)
      expect(page.querySelector("main")?.getAttribute("data-form")).toBe(form)
      const { script, style } = await pageAssets()
      expect(
        [...page.querySelectorAll("script")].map((each) => [
          each.getAttribute("src"),
          each.textContent,
        ]),
      ).toEqual([[script.path, ""]])
      expect(page.querySelector('link[rel="stylesheet"]')?.getAttribute("href")).toBe(style.path)
      expect(page.querySelector("form")?.getAttribute("action")).toBe(
        path === "/auth/totp/enrol" ? "/auth/totp/confirm" : path,
      )
    },
  )

  it("never allows inline script or style on any page", async () => {
    const setup = testAuth()
    for (const [path] of PAGES) {
      const reply = await open(await browserFor(setup, path), path)
      const policy = reply.headers.get("content-security-policy") ?? ""
      expect(policy, path).not.toContain("unsafe-inline")
      expect(policy, path).toContain("script-src 'self'")
      expect(policy, path).toContain("style-src 'self'")
      expect(doc(reply).querySelectorAll("script:not([src]), style, [style]"), path).toHaveLength(0)
    }
  })

  it("gives a browser with no cookie a pre-session cookie its page token is bound to", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    const reply = await open(browser, "/auth/sign-up")
    expect(reply.headers.getSetCookie()).toEqual([
      expect.stringMatching(
        /^__Host-test-cap-csrf=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Lax$/,
      ),
    ])
    browser.csrf = tokenOf(doc(reply))
    const created = await submit(browser, "/auth/sign-up", { identifier: "ada@example.com" })
    expect([created.status, created.headers.get("location")]).toEqual([303, "/auth/email/confirm"])
    // A browser that already holds a cookie gets no new one.
    expect((await open(browser, "/auth/sign-in")).headers.getSetCookie()).toEqual([])
  })

  it("links sign-in and sign-up to each other, and the confirmation page to a resend", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    const links = async (path: string) =>
      [...doc(await open(browser, path)).querySelectorAll("a")].map((a) => [
        a.getAttribute("href"),
        a.textContent,
      ])
    expect(await links("/auth/sign-in")).toEqual([["/auth/sign-up", "Create an account"]])
    expect(await links("/auth/sign-up")).toEqual([["/auth/sign-in", "I already have an account"]])
    const confirm = doc(await open(browser, "/auth/email/confirm"))
    expect(confirm.querySelector('form[data-test-cap="resend"]')?.getAttribute("action")).toBe(
      "/auth/email/resend",
    )
  })

  it("asks for 15 characters on the password page when a deviation lets a password alone pass", async () => {
    const { defineAuthPolicy } = await import("../../src/assurance/policy.js")
    const setup = testAuth({
      policy: defineAuthPolicy({ version: "v", defaultRequirement: { level: "AAL1" } }),
    })
    const page = doc(await open(new Browser(inProcess(setup.auth)), "/auth/password"))
    expect(page.querySelector('input[name="password"]')?.getAttribute("data-min")).toBe("15")
    const strict = doc(await open(new Browser(inProcess(testAuth().auth)), "/auth/password"))
    expect(strict.querySelector('input[name="password"]')?.getAttribute("data-min")).toBe("8")
  })

  it("begins TOTP enrolment on its page, showing the setup key and posting the authenticator back", async () => {
    const setup = testAuth()
    const browser = await enrolling(setup)
    const page = doc(await open(browser, "/auth/totp/enrol"))
    const secret =
      page.querySelector('[data-test-cap="totp-secret"] code')?.textContent?.replaceAll(" ", "") ??
      ""
    const authenticatorId =
      page.querySelector('input[name="authenticatorId"]')?.getAttribute("value") ?? ""
    expect(secret).toMatch(/^[A-Z2-7]{32}$/)
    browser.csrf = tokenOf(page)
    const done = await submit(browser, "/auth/totp/confirm", {
      authenticatorId,
      code: await codeAt(secret, setup.clock.now()),
    })
    expect([done.status, done.headers.get("location")]).toEqual([303, "/"])
  })

  it("sends TOTP enrolment to sign-in without a session, and to the password page before a password", async () => {
    const setup = testAuth()
    const signedOut = await open(new Browser(inProcess(setup.auth)), "/auth/totp/enrol")
    expect([signedOut.status, signedOut.headers.get("location"), signedOut.text]).toEqual([
      303,
      "/auth/sign-in",
      "",
    ])
    const noPassword = await open(await enrolling(setup, "confirm"), "/auth/totp/enrol")
    expect([noPassword.status, noPassword.headers.get("location")]).toEqual([303, "/auth/password"])
  })

  it("lets a session at the default requirement add an authenticator from the TOTP page, password or not", async () => {
    const setup = testAuth()
    const { subject } = await seedAccount(setup, { password: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal2(setup.clock) })
    expect((await open(browser, "/auth/totp/enrol")).status).toBe(200)
    // An account that signed in without a password (in later phases, by passkey) is not sent to choose one.
    const passwordless = await seedSession(setup, { evidence: aal2(setup.clock) })
    expect((await open(passwordless.browser, "/auth/totp/enrol")).status).toBe(200)
  })

  it("opens a step-up challenge on its page, and sends a session-less visitor to sign-in", async () => {
    const setup = testAuth()
    const signedOut = await open(new Browser(inProcess(setup.auth)), "/auth/step-up")
    expect([signedOut.status, signedOut.headers.get("location")]).toEqual([303, "/auth/sign-in"])
    const { subject, secret } = await seedAccount(setup, { password: true, totp: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    const page = doc(await open(browser, "/auth/step-up"))
    const challenge = page.querySelector('input[name="challenge"]')?.getAttribute("value") ?? ""
    expect(challenge).toMatch(/^[A-Za-z0-9_-]{22}$/)
    browser.csrf = tokenOf(page)
    const done = await submit(browser, "/auth/step-up", {
      challenge,
      code: await codeAt(secret ?? "", setup.clock.now()),
    })
    expect([done.status, done.headers.get("location")]).toEqual([303, "/"])
  })
})

describe("GET /auth/assets/<hash>", () => {
  it("serves each asset under its content hash, immutable, with its content type", async () => {
    const setup = testAuth()
    const { script, style } = await pageAssets()
    for (const [asset, text] of [
      [script, CLIENT_SCRIPT],
      [style, STYLESHEET],
    ] as const) {
      const reply = await new Browser(inProcess(setup.auth)).get(asset.path)
      expect([reply.status, reply.text]).toEqual([200, text])
      expect(Object.fromEntries(reply.headers)).toMatchObject({
        "content-type": asset.contentType,
        "cache-control": "public, max-age=31536000, immutable",
        "content-security-policy": CONTENT_SECURITY_POLICY,
        "x-content-type-options": "nosniff",
      })
      expect(reply.headers.getSetCookie()).toEqual([])
    }
    expect([script.contentType, style.contentType]).toEqual([
      "text/javascript; charset=utf-8",
      "text/css; charset=utf-8",
    ])
  })

  it("answers 404 for any other name, and 405 for any other method", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    for (const path of [
      "/auth/assets/test-cap.000000000000.js",
      "/auth/assets",
      "/auth/assets/x/y",
    ]) {
      const reply = await browser.get(path)
      expect([path, reply.status, reply.text, reply.headers.get("cache-control")]).toEqual([
        path,
        404,
        '{"error":"not-found"}',
        "no-store",
      ])
    }
    const { script } = await pageAssets()
    const post = await browser.send({ method: "POST", path: script.path })
    expect([post.status, post.text, post.headers.get("allow")]).toEqual([
      405,
      '{"error":"method-not-allowed"}',
      "GET",
    ])
  })
})

describe("a form post that accepts HTML", () => {
  it("walks sign-up to AAL2 by redirects: confirm, password, TOTP, then returnTo", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    browser.csrf = tokenOf(doc(await open(browser, "/auth/sign-up")))
    const created = await submit(browser, "/auth/sign-up", { identifier: "ada@example.com" })
    expect([created.status, created.headers.get("location"), created.text]).toEqual([
      303,
      "/auth/email/confirm",
      "",
    ])
    expect(created.headers.getSetCookie()).toEqual([expect.stringMatching(/^__Host-test-cap=/)])
    expect(created.headers.get("cache-control")).toBe("no-store")

    browser.csrf = tokenOf(doc(await open(browser, "/auth/email/confirm")))
    const confirmed = await submit(browser, "/auth/email/confirm", {
      code: confirmationCode(setup.outbox, "ada@example.com"),
    })
    expect([confirmed.status, confirmed.headers.get("location")]).toEqual([303, "/auth/password"])

    browser.csrf = tokenOf(doc(await open(browser, "/auth/password")))
    const chosen = await submit(browser, "/auth/password", { password: PASSWORD })
    expect([chosen.status, chosen.headers.get("location")]).toEqual([303, "/auth/totp/enrol"])
  })

  it("sends a resend back to the confirmation page", async () => {
    const setup = testAuth()
    const browser = await enrolling(setup, "sign-up")
    setup.clock.advance(60_000)
    const resent = await submit(browser, "/auth/email/resend", {})
    expect([resent.status, resent.headers.get("location")]).toEqual([303, "/auth/email/confirm"])
    expect(setup.outbox).toHaveLength(2)
  })

  it("sends a password-only sign-in to the step-up page, and a full one to returnTo", async () => {
    const setup = testAuth()
    const { secret } = await seedAccount(setup, { password: true, totp: true })
    const browser = new Browser(inProcess(setup.auth))
    browser.csrf = tokenOf(doc(await open(browser, "/auth/sign-in")))
    const signedIn = await submit(browser, "/auth/sign-in", {
      identifier: "ada@example.com",
      password: PASSWORD,
    })
    expect([signedIn.status, signedIn.headers.get("location")]).toEqual([303, "/auth/step-up"])
    const page = doc(await open(browser, "/auth/step-up"))
    browser.csrf = tokenOf(page)
    const done = await submit(browser, "/auth/step-up", {
      challenge: page.querySelector('input[name="challenge"]')?.getAttribute("value") ?? "",
      code: await codeAt(secret ?? "", setup.clock.now()),
      returnTo: "/billing",
    })
    expect([done.status, done.headers.get("location")]).toEqual([303, "/billing"])
  })

  it("signs out to the sign-in page, clearing the cookie", async () => {
    const setup = testAuth()
    const { browser } = await seedSession(setup, { evidence: aal2(setup.clock) })
    browser.csrf = tokenOf(doc(await open(browser, "/auth/sign-out")))
    const out = await submit(browser, "/auth/sign-out", {})
    expect([out.status, out.headers.get("location")]).toEqual([303, "/auth/sign-in"])
    expect(out.headers.getSetCookie()).toEqual([
      expect.stringMatching(/^__Host-test-cap=-; .*Max-Age=0;/),
    ])
  })

  it("shows a failed sign-in on the page again, keeping the identifier and never the password", async () => {
    const setup = testAuth()
    await seedAccount(setup, { password: true })
    const browser = new Browser(inProcess(setup.auth))
    browser.csrf = tokenOf(doc(await open(browser, "/auth/sign-in")))
    const reply = await submit(browser, "/auth/sign-in", {
      identifier: "ada@example.com",
      password: "a wrong password",
    })
    expect([reply.status, reply.headers.get("content-type")]).toEqual([
      401,
      "text/html; charset=utf-8",
    ])
    const page = doc(reply)
    expect(page.querySelector('[role="alert"]')?.textContent).toBe(
      "That email and password didn't work together. Check both and try again.",
    )
    expect(page.querySelector('input[name="identifier"]')?.getAttribute("value")).toBe(
      "ada@example.com",
    )
    expect(page.querySelector('input[name="password"]')?.hasAttribute("value")).toBe(false)
    expect(reply.text).not.toContain("a wrong password")
    // The page carries a fresh token, so the next try goes through.
    browser.csrf = tokenOf(page)
    const again = await submit(browser, "/auth/sign-in", {
      identifier: "ada@example.com",
      password: PASSWORD,
    })
    expect(again.status).toBe(303)
  })

  it("escapes an identifier it shows again", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    browser.csrf = tokenOf(doc(await open(browser, "/auth/sign-up")))
    const reply = await submit(browser, "/auth/sign-up", {
      identifier: '"><script>alert(1)</script>',
    })
    expect(reply.status).toBe(400)
    expect(reply.text).not.toContain("<script>alert")
    expect(doc(reply).querySelector('input[name="identifier"]')?.getAttribute("value")).toBe(
      '"><script>alert(1)</script>',
    )
    expect(
      doc(reply).querySelector('[data-field="identifier"] [data-test-cap="note"]')?.textContent,
    ).toBe("Enter an email address, like name@example.org.")
  })

  it("shows an address the core refuses, though it passes the page's own check, as the field's error", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    browser.csrf = tokenOf(doc(await open(browser, "/auth/sign-up")))
    const reply = await submit(browser, "/auth/sign-up", { identifier: "ada@localhost" })
    expect(reply.status).toBe(400)
    const page = doc(reply)
    expect(
      page.querySelector('[data-field="identifier"] [data-test-cap="note"]')?.textContent,
    ).toBe("Enter an email address, like name@example.org.")
    expect(page.querySelector('input[name="identifier"]')?.getAttribute("aria-invalid")).toBe(
      "true",
    )
    expect(page.querySelector('[role="alert"]')?.textContent).toBe("")
  })

  it("shows a wrong emailed code, then the wait once the attempts run out", async () => {
    const setup = testAuth()
    const browser = await enrolling(setup, "sign-up")
    browser.csrf = tokenOf(doc(await open(browser, "/auth/email/confirm")))
    const wrong = await submit(browser, "/auth/email/confirm", { code: "000000" })
    expect(wrong.status).toBe(400)
    const page = doc(wrong)
    expect(page.querySelector('[role="alert"]')?.textContent).toBe(
      "That code didn't work. Use the code in the newest email we sent.",
    )
    expect(page.querySelector('form[data-test-cap="resend"]')).not.toBeNull()
    for (let attempt = 1; attempt < CONFIRMATION_FAILURE_LIMIT; attempt += 1) {
      await submit(browser, "/auth/email/confirm", { code: "000000" })
    }
    setup.clock.advance(1_000)
    const waiting = await submit(browser, "/auth/email/confirm", { code: "000000" })
    expect(waiting.status).toBe(429)
    expect(doc(waiting).querySelector('[role="alert"]')?.textContent).toBe(
      "Too many attempts. Try again in 86399 seconds.",
    )
  })

  it("names a refused password, and shows a short one as the field's own error", async () => {
    const setup = testAuth()
    const browser = await enrolling(setup, "confirm")
    const common = await submit(browser, "/auth/password", { password: "password1234" })
    expect([common.status, doc(common).querySelector('[role="alert"]')?.textContent]).toEqual([
      400,
      "That password is too common. Choose one that is harder to guess.",
    ])
    const short = await submit(browser, "/auth/password", { password: "short" })
    expect(short.status).toBe(400)
    expect(
      doc(short).querySelector('[data-field="password"] [data-test-cap="note"]')?.textContent,
    ).toBe("Use at least 8 characters.")
    expect(doc(short).querySelector('[role="alert"]')?.textContent).toBe("")
  })

  it("names a breached password", async () => {
    const setup = testAuth({
      hibpFetch: () =>
        Promise.resolve({
          ok: true,
          status: 200,
          // The SHA-1 suffix of "correct horse battery staple", reported as breached.
          text: () => Promise.resolve("AD6438836DBE526AA231ABDE2D0EEF74D42:3"),
        }),
    })
    const browser = await enrolling(setup, "confirm")
    const reply = await submit(browser, "/auth/password", { password: PASSWORD })
    expect(doc(reply).querySelector('[role="alert"]')?.textContent).toBe(
      "That password has appeared in a data breach. Choose a different one.",
    )
  })

  it("shows a wrong TOTP code with a new enrolment, since a setup key is shown once", async () => {
    const setup = testAuth()
    const browser = await enrolling(setup)
    const page = doc(await open(browser, "/auth/totp/enrol"))
    const key = page.querySelector('[data-test-cap="totp-secret"] code')?.textContent
    const authenticatorId =
      page.querySelector('input[name="authenticatorId"]')?.getAttribute("value") ?? ""
    browser.csrf = tokenOf(page)
    const wrong = await submit(browser, "/auth/totp/confirm", { authenticatorId, code: "000000" })
    expect(wrong.status).toBe(400)
    const again = doc(wrong)
    expect(again.querySelector('[role="alert"]')?.textContent).toBe(
      "That code didn't work. Codes change every 30 seconds, so try the newest one.",
    )
    const newKey = again.querySelector('[data-test-cap="totp-secret"] code')?.textContent ?? ""
    expect(newKey).toMatch(/^[A-Z2-7 ]+$/)
    expect(newKey).not.toBe(key)
    const newId = again.querySelector('input[name="authenticatorId"]')?.getAttribute("value") ?? ""
    expect(newId).not.toBe(authenticatorId)
    // The new enrolment works; the first one is gone.
    browser.csrf = tokenOf(again)
    const done = await submit(browser, "/auth/totp/confirm", {
      authenticatorId: newId,
      code: await codeAt(newKey.replaceAll(" ", ""), setup.clock.now()),
    })
    expect([done.status, done.headers.get("location")]).toEqual([303, "/"])
  })

  it("shows a wrong step-up code with a fresh challenge", async () => {
    const setup = testAuth()
    const { subject } = await seedAccount(setup, { password: true, totp: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    const page = doc(await open(browser, "/auth/step-up"))
    const challenge = page.querySelector('input[name="challenge"]')?.getAttribute("value") ?? ""
    browser.csrf = tokenOf(page)
    const wrong = await submit(browser, "/auth/step-up", { challenge, code: "000000" })
    expect(wrong.status).toBe(401)
    const again = doc(wrong)
    expect(again.querySelector('[role="alert"]')?.textContent).toBe(
      "That code didn't work. Codes change every 30 seconds, so try the newest one.",
    )
    expect(again.querySelector('input[name="challenge"]')?.getAttribute("value")).toMatch(
      /^[A-Za-z0-9_-]{22}$/,
    )
  })

  it("shows a refused challenge on the step-up page as an unexpected failure, not a wrong code", async () => {
    const setup = testAuth()
    const { subject, secret } = await seedAccount(setup, { password: true, totp: true })
    const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
    browser.csrf = tokenOf(doc(await open(browser, "/auth/step-up")))
    const reply = await submit(browser, "/auth/step-up", {
      challenge: "Y2hhbGxlbmdlY2hhbGxlbmdl",
      code: await codeAt(secret ?? "", setup.clock.now()),
    })
    expect(reply.status).toBe(403)
    expect(doc(reply).querySelector('[role="alert"]')?.textContent).toBe(
      "Something went wrong on our side. Please try again.",
    )
  })

  it("sends a ceremony that still falls short of the default requirement to the step-up page", async () => {
    const { defineAuthPolicy } = await import("../../src/assurance/policy.js")
    const setup = testAuth({
      policy: defineAuthPolicy({ version: "aal3", defaultRequirement: { level: "AAL3" } }),
    })
    // TOTP enrolment completes at AAL2, below this policy's default.
    const browser = await enrolling(setup)
    const page = doc(await open(browser, "/auth/totp/enrol"))
    const secret =
      page.querySelector('[data-test-cap="totp-secret"] code')?.textContent?.replaceAll(" ", "") ??
      ""
    browser.csrf = tokenOf(page)
    const enrolled = await submit(browser, "/auth/totp/confirm", {
      authenticatorId:
        page.querySelector('input[name="authenticatorId"]')?.getAttribute("value") ?? "",
      code: await codeAt(secret, setup.clock.now()),
    })
    expect([enrolled.status, enrolled.headers.get("location")]).toEqual([303, "/auth/step-up"])
    // A step-up with the same authenticators cannot reach AAL3 either.
    setup.clock.advance(30_000)
    const stepUp = doc(await open(browser, "/auth/step-up"))
    browser.csrf = tokenOf(stepUp)
    const steppedUp = await submit(browser, "/auth/step-up", {
      challenge: stepUp.querySelector('input[name="challenge"]')?.getAttribute("value") ?? "",
      code: await codeAt(secret, setup.clock.now()),
    })
    expect([steppedUp.status, steppedUp.headers.get("location")]).toEqual([303, "/auth/step-up"])
  })

  it("shows a refused resend on the confirmation page", async () => {
    const setup = testAuth()
    const browser = await enrolling(setup, "confirm")
    browser.csrf = tokenOf(doc(await open(browser, "/auth/email/confirm")))
    const reply = await submit(browser, "/auth/email/resend", {})
    expect(reply.status).toBe(409)
    const page = doc(reply)
    expect(page.querySelector("main")?.getAttribute("data-form")).toBe("email-confirm")
    expect(page.querySelector('[role="alert"]')?.textContent).toBe(
      "Something went wrong on our side. Please try again.",
    )
  })

  it("shows a refused sign-out on the sign-out page again, with a new token", async () => {
    const setup = testAuth()
    const { browser } = await seedSession(setup, { evidence: aal2(setup.clock) })
    browser.csrf = "c1.1.forged"
    const reply = await submit(browser, "/auth/sign-out", {})
    expect(reply.status).toBe(403)
    const page = doc(reply)
    expect(page.querySelector("main")?.getAttribute("data-form")).toBe("sign-out")
    browser.csrf = tokenOf(page)
    const out = await submit(browser, "/auth/sign-out", {})
    expect([out.status, out.headers.get("location")]).toEqual([303, "/auth/sign-in"])
  })

  it("sends a refusal for a missing session to the sign-in page", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    browser.csrf = tokenOf(doc(await open(browser, "/auth/email/confirm")))
    for (const [path, fields] of [
      ["/auth/email/confirm", { code: "123456" }],
      ["/auth/password", { password: PASSWORD }],
      ["/auth/step-up", { challenge: "Y2hhbGxlbmdlY2hhbGxlbmdl", code: "123456" }],
    ] as const) {
      const reply = await submit(browser, path, fields)
      expect([path, reply.status, reply.headers.get("location")]).toEqual([
        path,
        303,
        "/auth/sign-in",
      ])
      expect(reply.headers.getSetCookie()).toEqual([])
    }
  })

  it("shows a CSRF refusal on the page with a new token, and acts on nothing", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    browser.csrf = "c1.1.forged"
    const reply = await submit(browser, "/auth/sign-up", { identifier: "ada@example.com" })
    expect(reply.status).toBe(403)
    const page = doc(reply)
    expect(page.querySelector('[role="alert"]')?.textContent).toBe(
      "Something went wrong on our side. Please try again.",
    )
    expect(setup.outbox).toEqual([])
    browser.csrf = tokenOf(page)
    expect((await submit(browser, "/auth/sign-up", { identifier: "ada@example.com" })).status).toBe(
      303,
    )
  })

  it("reads the form's media type in any case and with parameters", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    browser.csrf = tokenOf(doc(await open(browser, "/auth/sign-up")))
    const reply = await browser.send({
      method: "POST",
      path: "/auth/sign-up",
      headers: [
        ["Origin", ORIGIN],
        ["Content-Type", "Application/X-WWW-Form-Urlencoded; charset=UTF-8"],
        ["Accept", "text/html"],
      ],
      body: new URLSearchParams({
        identifier: "ada@example.com",
        csrfToken: browser.csrf,
      }).toString(),
    })
    expect([reply.status, reply.headers.get("location")]).toEqual([303, "/auth/email/confirm"])
  })

  it("keeps JSON for a JSON post, and for a form post that does not ask for HTML", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    const json = await browser.post("/auth/sign-up", { identifier: "ada@example.com" })
    expect([json.status, json.headers.get("content-type")]).toEqual([
      200,
      "application/json; charset=utf-8",
    ])
    const form = await browser.postForm("/auth/sign-up", { identifier: "bo@example.com" })
    expect([form.status, form.text]).toEqual([200, '{"outcome":"enroll","returnTo":"/"}'])
    const refused = await browser.post(
      "/auth/sign-up",
      { identifier: "ada" },
      { headers: [["Accept", "text/html"]] },
    )
    expect([refused.status, refused.text]).toEqual([400, '{"error":"invalid-identifier"}'])
  })

  it("keeps JSON on routes that have no page", async () => {
    const setup = testAuth()
    const { browser } = await seedSession(setup, { evidence: aal2(setup.clock) })
    const listed = await browser.send({
      method: "GET",
      path: "/auth/sessions",
      headers: [["Accept", "text/html"]],
    })
    expect(listed.headers.get("content-type")).toBe("application/json; charset=utf-8")
    const started = await submit(browser, "/auth/step-up/start", {})
    expect([started.status, Object.keys(body(started))]).toEqual([200, ["challenge"]])
  })
})
