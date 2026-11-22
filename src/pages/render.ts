/**
 * The default pages (ADR 0025 §4): pure functions from a form model to a complete HTML document. The dispatcher sends
 * them with its security headers (ADR 0011) and serves the hashed assets they name.
 *
 * Progressive enhancement: every form posts to the server and works without JavaScript; the script only adds blur
 * validation, focus after a failed submit, the busy state and the show-password toggle. There is no inline script or
 * style, so a strict CSP holds. Every value goes through the escaping renderer.
 */

import { focusTarget, type FieldState, type FormModel, type Messages } from "../forms/model.js"
import { join, markup, type Html } from "./html.js"

/** The hashed asset paths a page loads. */
export interface PageAssets {
  /** The browser script, such as `/auth/assets/test-cap.0123456789ab.js`. */
  readonly script: string
  /** The optional stylesheet. Without it the page is unstyled, for the app's own CSS. */
  readonly style?: string | undefined
}

/** A link to another page, such as from sign-in to sign-up. */
export interface PageLink {
  /** A path on this origin. */
  readonly href: string
  /** The link text. */
  readonly text: string
}

/** What a page needs besides its form model. */
export interface PageContext {
  /** Where the form posts: a path on this origin. */
  readonly action: string
  /** The synchronizer token for CSRF (ADR 0011), sent as the hidden field `csrfToken` the dispatcher reads. */
  readonly csrfToken: string
  /** The hashed asset paths. */
  readonly assets: PageAssets
  /** The page language (default `en`). */
  readonly lang?: string | undefined
  /** The base32 setup key, on the TOTP enrolment page only. */
  readonly totpSecret?: string | undefined
  /** Links shown under the form. */
  readonly links?: readonly PageLink[] | undefined
  /**
   * Values the route needs from the step before, posted as hidden fields after the token: `authenticatorId` on the
   * TOTP enrolment page, `challenge` on the step-up page. Each value has the token's shape.
   */
  readonly hidden?: Readonly<Record<string, string>> | undefined
  /** Where a second form, with the token alone, posts for a new emailed code: the email confirmation page's resend. */
  readonly resend?: string | undefined
}

/** A path on this origin: no scheme, no host, no query and no doubled slash. */
const LOCAL_PATH = /^\/[A-Za-z0-9._~/-]*$/
/** The dispatcher's token: base64url segments joined by dots (key id, time, MAC). */
const TOKEN = /^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$/
const BASE32 = /^[A-Z2-7]+$/
/** A hidden field's name: letters and digits, never the token's own name. */
const FIELD_NAME = /^[A-Za-z][A-Za-z0-9]*$/
const LANGUAGE = /^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$/

function localPath(value: string, name: string): void {
  if (!LOCAL_PATH.test(value) || value.includes("//")) {
    throw new TypeError(`${name} must be a path on this origin, such as /auth/sign-in.`)
  }
}

/** Checks what every page's context holds: the action, the asset paths, the token and the language. */
function checkCommon(context: PageContext): void {
  localPath(context.action, "action")
  localPath(context.assets.script, "assets.script")
  if (context.assets.style !== undefined) localPath(context.assets.style, "assets.style")
  if (!TOKEN.test(context.csrfToken)) {
    throw new TypeError("csrfToken must be base64url segments joined by dots.")
  }
  if (context.lang !== undefined && !LANGUAGE.test(context.lang)) {
    throw new TypeError("lang must be a language tag such as en or de-AT.")
  }
}

/** Checks the context and returns the setup key the page shows: present exactly on the TOTP enrolment page. */
function checkContext(model: FormModel, context: PageContext): string | undefined {
  checkCommon(context)
  context.links?.forEach((link, index) => {
    localPath(link.href, `links[${index}].href`)
  })
  if (context.resend !== undefined) localPath(context.resend, "resend")
  for (const [name, value] of Object.entries(context.hidden ?? {})) {
    if (!FIELD_NAME.test(name) || name === "csrfToken") {
      throw new TypeError("hidden field names must be letters and digits, such as challenge.")
    }
    if (!TOKEN.test(value)) {
      throw new TypeError(`hidden.${name} must be base64url segments joined by dots.`)
    }
  }
  if (model.id === "totp-enrol") {
    if (context.totpSecret === undefined)
      throw new TypeError("The TOTP enrolment page needs totpSecret.")
    if (!BASE32.test(context.totpSecret)) throw new TypeError("totpSecret must be base32.")
    return context.totpSecret
  }
  return undefined
}

/** ` name="value"` when `value` is set, else nothing. */
function attribute(name: string, value: string | number | undefined): Html {
  return value === undefined ? markup`` : markup` ${name}="${value}"`
}

function flag(name: string, on: boolean): Html {
  return on ? markup` ${name}` : markup``
}

function fieldMarkup(field: FieldState, focused: boolean, model: FormModel): Html {
  const id = `tc-${field.name}`
  const noteId = `${id}-note`
  const invalid = field.error !== null
  const toggle =
    field.type === "password"
      ? markup`<button type="button" data-test-cap="toggle-password" aria-controls="${id}" data-show="${model.messages.showPassword}" data-hide="${model.messages.hidePassword}" hidden>${model.messages.showPassword}</button>`
      : markup``
  const attributes = join([
    attribute("inputmode", field.inputmode),
    attribute("value", field.value === "" ? undefined : field.value),
    markup` required aria-describedby="${noteId}"`,
    attribute("aria-invalid", invalid ? "true" : undefined),
    flag("autofocus", focused),
    markup` data-test-cap="input"`,
    attribute("data-help", field.help),
    attribute("data-required-message", field.requiredMessage),
    attribute("data-min", field.length?.min),
    attribute("data-max", field.length?.max),
    attribute("data-too-short-message", field.length?.tooShort),
    attribute("data-too-long-message", field.length?.tooLong),
    attribute("data-pattern", field.pattern?.source),
    attribute("data-pattern-message", field.pattern?.message),
    attribute("data-strip", field.stripWhitespace === true ? "whitespace" : undefined),
  ])
  return markup`<div data-test-cap="field" data-field="${field.name}"><label for="${id}" data-test-cap="label">${field.label}</label><input id="${id}" name="${field.name}" type="${field.type}" autocomplete="${field.autocomplete}"${attributes}>${toggle}<p id="${noteId}" data-test-cap="note"${attribute("data-state", invalid ? "error" : undefined)}>${field.error ?? field.help}</p></div>`
}

/** The setup key in groups of four, which is easier to read and type. */
function grouped(secret: string): string {
  return secret.replace(/(.{4})(?=.)/g, "$1 ")
}

function secretMarkup(model: FormModel, secret: string): Html {
  return markup`<div data-test-cap="totp-secret"><p id="tc-secret-label">${model.messages.totpSecretLabel}</p><p><code aria-labelledby="tc-secret-label">${grouped(secret)}</code></p><p data-test-cap="note">${model.messages.totpSecretHelp}</p></div>`
}

function hiddenMarkup(hidden: PageContext["hidden"]): Html {
  return join(
    Object.entries(hidden ?? {}).map(
      ([name, value]) => markup`<input type="hidden" name="${name}" value="${value}">`,
    ),
  )
}

function linksMarkup(links: readonly PageLink[] | undefined): Html {
  if (links === undefined || links.length === 0) return markup``
  return markup`<p data-test-cap="links">${join(links.map((link) => markup`<a href="${link.href}" data-test-cap="link">${link.text}</a> `))}</p>`
}

/** The token field every form posts first. */
function tokenMarkup(context: PageContext): Html {
  return markup`<input type="hidden" name="csrfToken" value="${context.csrfToken}">`
}

function resendMarkup(model: FormModel, context: PageContext): Html {
  if (context.resend === undefined) return markup``
  return markup`<form method="post" action="${context.resend}" data-test-cap="resend">${tokenMarkup(context)}<button type="submit" data-test-cap="resend-submit">${model.messages.resendSubmit}</button></form>`
}

/** The document around a page's `<main>`: language, referrer policy, title, and the hashed script and stylesheet. */
function documentMarkup(context: PageContext, title: string, form: string, main: Html): string {
  const style =
    context.assets.style === undefined
      ? markup``
      : markup`<link rel="stylesheet" href="${context.assets.style}">`
  return markup`<!doctype html><html lang="${context.lang ?? "en"}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><title>${title}</title>${style}<script src="${context.assets.script}" defer></script></head><body><main data-test-cap="page" data-form="${form}"><h1 data-test-cap="title">${title}</h1>${main}</main></body></html>`
    .value
}

/** Renders a complete page for `model`. Throws on a context value that could escape the page. */
export function renderPage(model: FormModel, context: PageContext): string {
  const secret = checkContext(model, context)
  const focus = focusTarget(model)
  const fields = join(model.fields.map((field) => fieldMarkup(field, field.name === focus, model)))
  return documentMarkup(
    context,
    model.title,
    model.id,
    markup`${secret === undefined ? markup`` : secretMarkup(model, secret)}<form method="post" action="${context.action}" data-test-cap="form" data-form="${model.id}">${tokenMarkup(context)}${hiddenMarkup(context.hidden)}${fields}<p id="tc-global" data-test-cap="global-error" role="alert" tabindex="-1"${flag("autofocus", focus === "global")}>${model.globalError ?? ""}</p><button type="submit" data-test-cap="submit">${model.submitLabel}</button></form>${resendMarkup(model, context)}${linksMarkup(context.links)}`,
  )
}

/**
 * Renders the sign-out page: one button that posts the token to `context.action`, so signing out is never a `GET` a
 * link or an image on another site could trigger. Throws on a context value that could escape the page.
 */
export function renderSignOutPage(messages: Messages, context: PageContext): string {
  checkCommon(context)
  return documentMarkup(
    context,
    messages.signOutTitle,
    "sign-out",
    markup`<form method="post" action="${context.action}" data-test-cap="form" data-form="sign-out">${tokenMarkup(context)}<button type="submit" data-test-cap="submit">${messages.signOutSubmit}</button></form>`,
  )
}
