/**
 * Deployment mode and the startup checks (ADR 0026). `APP_ENV` sets the mode; a missing or unknown value is
 * production, so a mistyped variable fails safe. Production and staging refuse to start without an HTTPS origin, a
 * durable store and well-formed secrets. The checks look at presence and shape only: a key that is long and random
 * but leaked still passes.
 */

import { base64UrlDecode } from "./encoding.js"
import { ConfigError } from "./errors.js"

/** The deployment modes every cap shares (ADR 0022). */
export type DeploymentMode = "production" | "staging" | "development" | "test"

const MODES: ReadonlySet<unknown> = new Set(["production", "staging", "development", "test"])

/** The mode `APP_ENV` names; `fallback` is true when the value was missing, not a string, or unknown. */
export function resolveDeploymentMode(appEnv: unknown): {
  readonly mode: DeploymentMode
  readonly fallback: boolean
} {
  return MODES.has(appEnv)
    ? { mode: appEnv as DeploymentMode, fallback: false }
    : { mode: "production", fallback: true }
}

/** Production and staging get the same checks. */
export function isProductionLike(mode: DeploymentMode): boolean {
  return mode === "production" || mode === "staging"
}

/** One key of a rotating key ring. */
export interface RingKey {
  readonly id: string
  readonly bytes: Uint8Array
}

const MIN_KEY_BYTES = 32
const KEY_ID = /^[A-Za-z0-9_-]{1,32}$/

/** True for keys a person typed rather than generated: one repeated byte, a counting run, or a short repeat. */
function looksLikeExample(bytes: Uint8Array): boolean {
  for (let period = 1; period <= 8; period += 1) {
    if (bytes.every((byte, index) => byte === bytes[index % period])) return true
  }
  return bytes.every(
    (byte, index) => index === 0 || byte === (((bytes[index - 1] ?? 0) + 1) & 0xff),
  )
}

/**
 * Parses a key ring: comma-separated `id:base64url` entries, the first one current (ADR 0022). Every problem is
 * named; `keys` is empty when there is any.
 */
export function parseKeyRing(
  variable: string,
  value: string,
): { readonly keys: readonly RingKey[]; readonly problems: readonly string[] } {
  if (value === "") return { keys: [], problems: [`${variable} is empty.`] }
  const keys: RingKey[] = []
  const problems: string[] = []
  const seen = new Set<string>()
  value.split(",").forEach((entry, index) => {
    const label = `${variable} entry ${index + 1}`
    const colon = entry.indexOf(":")
    if (colon === -1) {
      problems.push(`${label} is not "id:base64url".`)
      return
    }
    const id = entry.slice(0, colon)
    if (!KEY_ID.test(id)) {
      problems.push(`${label} has an invalid key id.`)
      return
    }
    if (seen.has(id)) {
      problems.push(`${label} repeats the key id "${id}".`)
      return
    }
    seen.add(id)
    let bytes: Uint8Array
    try {
      bytes = base64UrlDecode(entry.slice(colon + 1))
    } catch {
      problems.push(`${label} is not valid base64url.`)
      return
    }
    if (bytes.length < MIN_KEY_BYTES) {
      problems.push(`${label} is shorter than ${MIN_KEY_BYTES} bytes.`)
      return
    }
    if (looksLikeExample(bytes)) {
      problems.push(`${label} looks like an example or default key, not a random one.`)
      return
    }
    keys.push({ id, bytes })
  })
  return problems.length === 0 ? { keys, problems } : { keys: [], problems }
}

/** What the startup check needs to know about the store. */
export interface StoreTraits {
  /** The store's short name, such as `memory`, used in the refusal message. */
  readonly kind: string
  /** False for a store that loses state on restart or is not shared between processes. */
  readonly durable: boolean
}

/** The inputs of the startup check. `secrets` maps each key ring the enabled capabilities need to its value. */
export interface ReadinessInput {
  readonly mode: DeploymentMode
  readonly origin: string
  readonly store: StoreTraits
  readonly secrets: Readonly<Record<string, string | undefined>>
  /**
   * Which of the injected sources the app replaced. Outside test mode both must be the system ones: a fixed clock
   * freezes every expiry, and a predictable random source makes every token guessable (requirements Open 13).
   */
  readonly custom?: { readonly clock: boolean; readonly random: boolean } | undefined
}

const LOOPBACK: ReadonlySet<string> = new Set(["localhost", "127.0.0.1", "[::1]"])

/** Why `origin` is not acceptable as APP_ORIGIN in `mode`, or `undefined` when it is. */
export function originProblem(origin: string, mode: DeploymentMode): string | undefined {
  let url: URL
  try {
    url = new URL(origin)
  } catch {
    url = new URL("invalid:")
  }
  // Rebuilding the origin from scheme and host leaves out any user info, path, query or fragment, and drops a default
  // port and an uppercase host, so only the exact form a browser sends in `Origin` equals its rebuilt form. The CSRF
  // check compares `Origin` with APP_ORIGIN as strings (ADR 0011), so any other spelling would refuse every request.
  const bare =
    (url.protocol === "https:" || url.protocol === "http:") &&
    `${url.protocol}//${url.host}` === origin
  if (!bare) {
    return "APP_ORIGIN must be a bare origin exactly as browsers send it, such as https://app.example (scheme, lowercase host, and a port only if not the default)."
  }
  if (url.protocol === "https:") return undefined
  if (isProductionLike(mode)) return `APP_ORIGIN must use https in ${mode}.`
  return LOOPBACK.has(url.hostname)
    ? undefined
    : "APP_ORIGIN must use https unless the host is localhost, 127.0.0.1 or [::1]."
}

/** Every reason this setup must not start; empty when it may. */
export function checkReadiness(input: ReadinessInput): readonly string[] {
  const strict = isProductionLike(input.mode)
  const problems: string[] = []
  const origin = originProblem(input.origin, input.mode)
  if (origin !== undefined) problems.push(origin)
  if (strict && !input.store.durable) {
    problems.push(
      `The "${input.store.kind}" store keeps nothing across restarts or processes; ${input.mode} needs a durable store.`,
    )
  }
  for (const [variable, value] of Object.entries(input.secrets)) {
    if (value === undefined) {
      if (strict) problems.push(`${variable} is missing.`)
    } else {
      problems.push(...parseKeyRing(variable, value).problems)
    }
  }
  if (input.mode !== "test" && input.custom?.clock === true) {
    problems.push(`A custom Clock is for tests only; ${input.mode} must use the system clock.`)
  }
  if (input.mode !== "test" && input.custom?.random === true) {
    problems.push(`A custom RandomSource is for tests only; ${input.mode} must use Web Crypto.`)
  }
  return problems
}

/** Throws one `ConfigError` listing every problem `checkReadiness` finds. */
export function assertReady(input: ReadinessInput): void {
  const problems = checkReadiness(input)
  if (problems.length > 0) throw new ConfigError(problems)
}
