/**
 * Body handling. The core alone reads the content type, enforces the size limit and parses forms and JSON, so every
 * adapter shares one interpretation of a request (ADR 0003). Anything ambiguous is refused, never normalised.
 */

import { TransportError } from "../core/errors.js"
import { utf8Decode } from "../core/encoding.js"
import { singleHeader } from "./headers.js"
import type { PlainRequest } from "./types.js"

/** 64 KiB: enough for every form and JSON auth route (ADR 0003). */
export const DEFAULT_BODY_LIMIT = 65_536
const DEFAULT_MAX_FIELDS = 64
const DEFAULT_MAX_DEPTH = 8

/** A record with no prototype, so a field named `__proto__` or `constructor` is only data. */
export type Fields = Record<string, unknown>

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) throw new TransportError("aborted", "The request was aborted.")
}

/** The body's bytes, after the declared and actual lengths are checked against `limit`. */
export function readBody(request: PlainRequest, options: { limit?: number } = {}): Uint8Array {
  const limit = options.limit ?? DEFAULT_BODY_LIMIT
  if (!Number.isInteger(limit) || limit < 1)
    throw new RangeError("The body limit must be a positive integer.")
  throwIfAborted(request.signal)
  const body = request.body ?? new Uint8Array(0)
  const declared = singleHeader(request.headers, "content-length")
  if (declared !== null) {
    if (!/^\d+$/.test(declared)) {
      throw new TransportError("malformed-body", "Content-Length is not a decimal number.")
    }
    if (Number(declared) > limit)
      throw new TransportError("body-too-large", "The declared body is over the limit.")
    if (Number(declared) !== body.length) {
      throw new TransportError("malformed-body", "Content-Length does not match the body received.")
    }
  }
  if (body.length > limit) throw new TransportError("body-too-large", "The body is over the limit.")
  return body
}

/** A parsed `Content-Type`. Only UTF-8 bodies are accepted. */
export interface ContentType {
  readonly mediaType: string
}

/** Parses a `Content-Type` value, refusing any charset but UTF-8. */
export function parseContentType(value: string): ContentType {
  // `split` always returns at least one element, so the first is a string.
  const [type, ...parameters] = value.split(";") as [string, ...string[]]
  const mediaType = type.trim().toLowerCase()
  if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(mediaType)) {
    throw new TransportError("unsupported-media-type", "The content type is malformed.")
  }
  for (const parameter of parameters) {
    const equals = parameter.indexOf("=")
    if (equals === -1)
      throw new TransportError("unsupported-media-type", "A content-type parameter is malformed.")
    const name = parameter.slice(0, equals).trim().toLowerCase()
    const raw = parameter.slice(equals + 1).trim()
    // A lone `"` passes this test and unquotes to "", which is refused as a charset just as `"` is.
    const unquoted = raw.startsWith('"') && raw.endsWith('"') ? raw.slice(1, -1) : raw
    if (name === "charset" && unquoted.toLowerCase() !== "utf-8") {
      throw new TransportError("unsupported-media-type", "Only UTF-8 bodies are accepted.")
    }
  }
  return { mediaType }
}

function decode(bytes: Uint8Array): string {
  try {
    return utf8Decode(bytes)
  } catch {
    throw new TransportError("malformed-body", "The body is not valid UTF-8.")
  }
}

/**
 * One name or value of a form: `+` is a space, then percent escapes are decoded. A malformed escape, or escapes whose
 * bytes are not UTF-8, are refused rather than replaced with U+FFFD, so two different bodies never parse alike.
 */
function formComponent(raw: string): string {
  try {
    return decodeURIComponent(raw.replaceAll("+", " "))
  } catch {
    throw new TransportError("malformed-body", "A form field is not valid percent-encoded UTF-8.")
  }
}

/**
 * Parses a URL-encoded form (the WHATWG `application/x-www-form-urlencoded` parser, with fatal UTF-8). A repeated
 * field is refused, so no two parsers can disagree on which value won. `URLSearchParams` is not used: its string
 * constructor drops a leading `?`, and it decodes bad UTF-8 to U+FFFD.
 */
export function parseForm(bytes: Uint8Array, options: { maxFields?: number } = {}): Fields {
  const maxFields = options.maxFields ?? DEFAULT_MAX_FIELDS
  const fields: Fields = Object.create(null) as Fields
  let count = 0
  for (const pair of decode(bytes).split("&")) {
    if (pair === "") continue
    count += 1
    if (count > maxFields)
      throw new TransportError("too-many-fields", "The form has too many fields.")
    const equals = pair.indexOf("=")
    const name = formComponent(equals === -1 ? pair : pair.slice(0, equals))
    const value = equals === -1 ? "" : formComponent(pair.slice(equals + 1))
    if (Object.hasOwn(fields, name))
      throw new TransportError("duplicate-field", `The field "${name}" is repeated.`)
    fields[name] = value
  }
  return fields
}

/** The keys one JSON object has shown so far, and whether the next string is a key. */
interface ObjectFrame {
  readonly keys: Set<string>
  expectingKey: boolean
}

/**
 * The tokens `checkStructure` reads: an opening or closing bracket, a comma, or a whole string. A string is matched
 * whole, so a bracket, comma or escaped quote inside one is never read as structure. Characters between tokens
 * (numbers, literals, whitespace, colons) are skipped.
 */
const JSON_TOKEN = /[[{]|[\]}]|,|"(?:[^"\\]|\\.)*"/g

/**
 * Walks JSON text and refuses a key repeated within one object (JSON.parse keeps the last silently), nesting deeper
 * than `maxDepth`, and more than `maxFields` top-level keys. It reads text `JSON.parse` has accepted, and its loop is
 * bounded by the matches the engine finds in that text.
 */
function checkStructure(text: string, maxDepth: number, maxFields: number): void {
  // One entry per open bracket; `null` for an array, which has no keys.
  const stack: (ObjectFrame | null)[] = []
  for (const [token] of text.matchAll(JSON_TOKEN)) {
    if (token === "{" || token === "[") {
      stack.push(token === "{" ? { keys: new Set(), expectingKey: true } : null)
      if (stack.length > maxDepth)
        throw new TransportError("malformed-body", "The JSON body is nested too deeply.")
      continue
    }
    if (token === "}" || token === "]") {
      stack.pop()
      continue
    }
    const top = stack.at(-1)
    if (!top) continue
    if (token === ",") {
      top.expectingKey = true
    } else if (top.expectingKey) {
      const key = JSON.parse(token) as string
      if (top.keys.has(key))
        throw new TransportError("duplicate-field", `The key "${key}" is repeated.`)
      top.keys.add(key)
      top.expectingKey = false
      if (stack.length === 1 && top.keys.size > maxFields) {
        throw new TransportError("too-many-fields", "The JSON body has too many fields.")
      }
    }
  }
}

/** A `JSON.parse` reviver that leaves every object without a prototype; the engine calls it innermost first. */
function dropPrototype(_key: string, value: unknown): unknown {
  // JSON.parse builds every object on Object.prototype, and arrays and primitives never are.
  if (value !== null && Object.getPrototypeOf(value) === Object.prototype) {
    Object.setPrototypeOf(value, null)
  }
  return value
}

/** Parses a JSON object body; every object in it has no prototype. */
export function parseJsonObject(
  bytes: Uint8Array,
  options: { maxFields?: number; maxDepth?: number } = {},
): Fields {
  const text = decode(bytes)
  let value: unknown
  try {
    // This parse only validates: V8's parser does not recurse, so deep nesting costs nothing here.
    value = JSON.parse(text)
  } catch {
    throw new TransportError("malformed-body", "The body is not valid JSON.")
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TransportError("malformed-body", "The JSON body must be an object.")
  }
  checkStructure(
    text,
    options.maxDepth ?? DEFAULT_MAX_DEPTH,
    options.maxFields ?? DEFAULT_MAX_FIELDS,
  )
  // A reviver walks the result recursively, so it runs only once `checkStructure` has bounded the depth.
  return JSON.parse(text, dropPrototype) as Fields
}

/** The body kinds a route can accept. */
export type BodyKind = "form" | "json"

/** A parsed body. `empty` is a request with no body and no content type. */
export interface ParsedBody {
  readonly kind: BodyKind | "empty"
  readonly fields: Fields
}

const MEDIA_TYPE: Readonly<Record<BodyKind, string>> = {
  form: "application/x-www-form-urlencoded",
  json: "application/json",
}

/** Reads and parses a request body that a route accepts as one of `accept`. */
export async function parseBody(
  request: PlainRequest,
  options: {
    accept?: readonly BodyKind[]
    limit?: number
    maxFields?: number
    maxDepth?: number
  } = {},
): Promise<ParsedBody> {
  const accept = options.accept ?? ["form", "json"]
  const bytes = readBody(request, options)
  const header = singleHeader(request.headers, "content-type")
  if (header === null) {
    if (bytes.length === 0) return { kind: "empty", fields: Object.create(null) as Fields }
    throw new TransportError("unsupported-media-type", "A body was sent without a content type.")
  }
  const { mediaType } = parseContentType(header)
  const kind = accept.find((candidate) => MEDIA_TYPE[candidate] === mediaType)
  if (kind === undefined) {
    throw new TransportError(
      "unsupported-media-type",
      "This route does not accept that content type.",
    )
  }
  return {
    kind,
    fields: kind === "form" ? parseForm(bytes, options) : parseJsonObject(bytes, options),
  }
}
