import { JSDOM, type TestDocument, type TestElement, type TestWindow } from "jsdom"
import { describe, expect, it } from "vitest"
import { createForm, type FormId } from "../../src/forms/model.js"
import { CLIENT_SCRIPT, pageAssets, STYLESHEET } from "../../src/pages/assets.js"
import { utf8Decode } from "../../src/core/encoding.js"
import { renderPage } from "../../src/pages/render.js"

const context = {
  action: "/auth/x",
  csrfToken: "dG9rZW4",
  assets: { script: "/auth/assets/test-cap.0123456789ab.js" },
  totpSecret: "JBSWY3DPEHPK3PXP",
}

/** A page with the client script running, as the browser runs it after parsing (`defer`). */
function enhanced(id: FormId): { window: TestWindow; doc: TestDocument } {
  const dom = new JSDOM(renderPage(createForm(id), context), { runScripts: "outside-only" })
  dom.window.eval(CLIENT_SCRIPT)
  return { window: dom.window, doc: dom.window.document }
}

function field(doc: TestDocument, name: string): { input: TestElement; note: TestElement } {
  const input = doc.querySelector(`[name="${name}"]`)
  const note = doc.getElementById(input?.getAttribute("aria-describedby") ?? "")
  if (input === null || note === null) throw new Error(`no field ${name}`)
  return { input, note }
}

function type(window: TestWindow, input: TestElement, value: string): void {
  input.value = value
  input.dispatchEvent(new window.Event("input", { bubbles: true }))
}

function blur(window: TestWindow, input: TestElement): void {
  input.dispatchEvent(new window.FocusEvent("blur"))
}

function submit(window: TestWindow, doc: TestDocument): boolean {
  const form = doc.querySelector("form")
  if (form === null) throw new Error("no form")
  return form.dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }))
}

describe("the client script", () => {
  it("turns off native validation, since the script shows the errors itself", () => {
    const { doc } = enhanced("sign-in")
    expect(doc.querySelector("form")?.hasAttribute("novalidate")).toBe(true)
  })

  it("#3 on blur, an error replaces the help text; once fixed, the help text returns", () => {
    const { window, doc } = enhanced("sign-in")
    const { input, note } = field(doc, "identifier")
    type(window, input, "ada")
    blur(window, input)
    expect([
      input.getAttribute("aria-invalid"),
      note.textContent,
      note.getAttribute("data-state"),
    ]).toEqual(["true", "Enter an email address, like name@example.org.", "error"])
    type(window, input, "ada@example.org")
    expect([
      input.hasAttribute("aria-invalid"),
      note.textContent,
      note.hasAttribute("data-state"),
    ]).toEqual([false, "The email address on your account.", false])
  })

  it("#10 validates on blur only once something was typed, so tabbing through stays quiet", () => {
    const { window, doc } = enhanced("sign-in")
    const { input, note } = field(doc, "identifier")
    blur(window, input)
    expect([input.hasAttribute("aria-invalid"), note.textContent]).toEqual([
      false,
      "The email address on your account.",
    ])
  })

  it("does not show an error while typing a field that has none yet", () => {
    const { window, doc } = enhanced("sign-in")
    const { input } = field(doc, "identifier")
    type(window, input, "a")
    expect(input.hasAttribute("aria-invalid")).toBe(false)
  })

  it("checks length in code points after NFC and the minimum and maximum, as the server does", () => {
    const { window, doc } = enhanced("password")
    const { input, note } = field(doc, "password")
    for (const [value, shown] of [
      ["1234567", "Use at least 8 characters."],
      [
        "🔐🔐🔐🔐🔐🔐🔐🔐",
        "At least 8 characters. A few unrelated words make a strong, memorable password.",
      ],
      [
        "é".repeat(8),
        "At least 8 characters. A few unrelated words make a strong, memorable password.",
      ],
      ["x".repeat(257), "Use at most 256 characters."],
    ] as const) {
      type(window, input, value)
      blur(window, input)
      expect(note.textContent, value).toBe(shown)
    }
  })

  it("strips spaces from a code before checking it", () => {
    const { window, doc } = enhanced("mfa")
    const { input, note } = field(doc, "code")
    type(window, input, "123 456")
    blur(window, input)
    expect(note.textContent).toBe("The 6-digit code from your authenticator app.")
    type(window, input, "12345")
    blur(window, input)
    expect(note.textContent).toBe("Enter the 6 digits from your authenticator app.")
  })

  it("#5 a submit with errors is stopped, every error shows, and focus goes to the first invalid field", () => {
    const { window, doc } = enhanced("sign-in")
    expect(submit(window, doc)).toBe(false)
    expect(field(doc, "identifier").note.textContent).toBe("Enter your email.")
    expect(field(doc, "password").note.textContent).toBe("Enter your password.")
    expect(doc.activeElement?.getAttribute("name")).toBe("identifier")
    type(window, field(doc, "identifier").input, "ada@example.org")
    expect(submit(window, doc)).toBe(false)
    expect(doc.activeElement?.getAttribute("name")).toBe("password")
  })

  it("#11 a valid submit goes ahead once, marked busy; a second is blocked", () => {
    const { window, doc } = enhanced("sign-in")
    type(window, field(doc, "identifier").input, "ada@example.org")
    type(window, field(doc, "password").input, "correct horse battery")
    expect(submit(window, doc)).toBe(true)
    expect(doc.querySelector("form")?.getAttribute("aria-busy")).toBe("true")
    expect(doc.querySelector('[data-test-cap="submit"]')?.getAttribute("aria-disabled")).toBe(
      "true",
    )
    expect(submit(window, doc)).toBe(false)
  })

  it("clears the busy state when the browser restores the page from its back-forward cache", () => {
    const { window, doc } = enhanced("sign-in")
    type(window, field(doc, "identifier").input, "ada@example.org")
    type(window, field(doc, "password").input, "correct horse battery")
    submit(window, doc)
    window.dispatchEvent(new window.PageTransitionEvent("pageshow", { persisted: false }))
    expect(doc.querySelector("form")?.getAttribute("aria-busy")).toBe("true")
    window.dispatchEvent(new window.PageTransitionEvent("pageshow", { persisted: true }))
    expect(doc.querySelector("form")?.hasAttribute("aria-busy")).toBe(false)
    expect(doc.querySelector('[data-test-cap="submit"]')?.hasAttribute("aria-disabled")).toBe(false)
    expect(submit(window, doc)).toBe(true)
  })

  it("#8 shows the password toggle, which switches the input and its own label", () => {
    const { doc } = enhanced("sign-in")
    const toggle = doc.querySelector('[data-test-cap="toggle-password"]')
    const { input } = field(doc, "password")
    expect(toggle?.hasAttribute("hidden")).toBe(false)
    toggle?.click()
    expect([input.type, toggle?.textContent]).toEqual(["text", "Hide password"])
    toggle?.click()
    expect([input.type, toggle?.textContent]).toEqual(["password", "Show password"])
  })

  it("runs on a page without a form, and on a form without a password, without throwing", () => {
    const dom = new JSDOM("<!doctype html><p>nothing here</p>", { runScripts: "outside-only" })
    expect(() => dom.window.eval(CLIENT_SCRIPT)).not.toThrow()
    expect(() => enhanced("mfa")).not.toThrow()
  })
})

describe("pageAssets", () => {
  it("names each asset by a hash of its content, under the base path", async () => {
    const assets = await pageAssets()
    expect(assets.script.path).toMatch(/^\/auth\/assets\/test-cap\.[0-9a-f]{12}\.js$/)
    expect(assets.style.path).toMatch(/^\/auth\/assets\/test-cap\.[0-9a-f]{12}\.css$/)
    expect(assets.script.path.slice(-15, -3)).not.toBe(assets.style.path.slice(-16, -4))
    expect([assets.script.contentType, assets.style.contentType]).toEqual([
      "text/javascript; charset=utf-8",
      "text/css; charset=utf-8",
    ])
    expect(utf8Decode(assets.script.body)).toBe(CLIENT_SCRIPT)
    expect(utf8Decode(assets.style.body)).toBe(STYLESHEET)
    expect((await pageAssets("/login/static/")).script.path).toBe(
      assets.script.path.replace("/auth/assets/", "/login/static/"),
    )
  })

  it("gives the same names every time", async () => {
    expect((await pageAssets()).script.path).toBe((await pageAssets()).script.path)
  })

  it("refuses a base path that is not a directory on this origin", async () => {
    for (const base of ["auth/assets/", "/auth/assets", "//cdn.example/", "/a b/"]) {
      await expect(pageAssets(base), base).rejects.toThrow(
        new TypeError(
          "The asset base must be a directory path on this origin, such as /auth/assets/.",
        ),
      )
    }
  })

  it("#15 #16 the optional stylesheet sizes targets for touch and respects reduced motion", () => {
    expect(STYLESHEET).toContain("@media (prefers-reduced-motion: reduce)")
    // The 44 px target size covers every control as one rule; a selector dropped from the group loses it silently.
    expect(STYLESHEET).toContain(
      '[data-test-cap="input"],\n[data-test-cap="submit"],\n[data-test-cap="toggle-password"] {\n  min-height: 2.75rem;',
    )
    // Links take the accent colour in both schemes: a browser default blue is unreadable on the dark surface.
    expect(STYLESHEET).toContain('[data-test-cap="link"] {\n  color: var(--test-cap-accent);\n}')
    expect(STYLESHEET).not.toMatch(/url\(|@import/)
  })
})
