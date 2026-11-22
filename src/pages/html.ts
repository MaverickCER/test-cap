/**
 * The one escaping renderer (ADR 0011, ADR 0025 §4). Every page is written with the `markup` tag, which escapes every
 * interpolated string. Only a fragment that `markup` itself built goes in unescaped, so markup can only come from the
 * templates in this package, never from a value.
 */

/** Markup built by `markup`, safe to insert as it is. */
export class Html {
  /** The markup. */
  readonly value: string

  /** Only `markup` and `join` make one. */
  constructor(value: string) {
    this.value = value
  }
}

const ENTITIES: Readonly<Record<string, string>> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
}

/** Escapes the five characters that can end a text node or a quoted attribute. */
export function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (char) => ENTITIES[char] ?? char)
}

/** A value `markup` accepts: markup it built, text to escape, a number, or nothing. */
export type Interpolation = Html | string | number | null | undefined | false

function render(value: Interpolation): string {
  if (value instanceof Html) return value.value
  if (value === null || value === undefined || value === false) return ""
  return escapeHtml(String(value))
}

/** Builds markup from a template, escaping every interpolated value that is not itself `Html`. (Not named `html`, so
 * Prettier leaves the templates' whitespace exactly as written.) */
export function markup(strings: TemplateStringsArray, ...values: readonly Interpolation[]): Html {
  // A template always has one more string than values, so every index read here exists.
  let out = String(strings[0])
  values.forEach((value, index) => {
    out += render(value) + String(strings[index + 1])
  })
  return new Html(out)
}

/** Joins fragments with nothing between them. */
export function join(parts: readonly Html[]): Html {
  return new Html(parts.map((part) => part.value).join(""))
}
