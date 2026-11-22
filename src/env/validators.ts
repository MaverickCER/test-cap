/**
 * Validators for test-cap's environment variables (ADR 0022). They apply the same rules as the startup check in
 * `core/mode.ts`, so env-cap's validation and `createAuth`'s refusal can never disagree. Each returns `true` or a
 * message that names the variable and never its value, the shape env-cap validators use.
 */

import {
  exampleKeyProblems,
  isProductionLike,
  parseKeyRing,
  resolveDeploymentMode,
  type DeploymentMode,
} from "../core/mode.js"

/** The raw environment a validator may consult. */
export type RawValues = Readonly<Record<string, unknown>>

function modeOf(raw: RawValues): DeploymentMode {
  return resolveDeploymentMode(raw["APP_ENV"]).mode
}

/** APP_ENV must name a mode exactly: under env-cap an unknown value fails loudly instead of falling back. */
export function appEnvProblem(value: string): true | string {
  return resolveDeploymentMode(value).fallback
    ? "APP_ENV must be production, staging, development or test."
    : true
}

const SYSTEM_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/

/** APP_SYSTEM_ID names the system in events and audit records. */
export function systemIdProblem(value: string): true | string {
  return SYSTEM_ID.test(value)
    ? true
    : "APP_SYSTEM_ID must be 1-64 letters, digits, dots, dashes or underscores, starting with a letter or digit."
}

/**
 * A key ring variable: required outside development and test, well formed whenever it is set, and never a published
 * example key in production or staging.
 */
export function keyRingVariableProblem(
  variable: string,
  value: string,
  raw: RawValues,
): true | string {
  const mode = modeOf(raw)
  if (value === "") return isProductionLike(mode) ? `${variable} is missing.` : true
  const problems = [
    ...parseKeyRing(variable, value).problems,
    ...exampleKeyProblems(variable, value, mode),
  ]
  return problems.length === 0 ? true : problems.join(" ")
}

/**
 * A PEM variable: required outside development and test, and exactly one block with the expected label. Lines may end
 * in CRLF or LF. RFC 7468 also allows a bare CR, but OpenSSL, which loads the key, cannot read it, so it is refused.
 */
export function pemProblem(
  variable: string,
  label: string,
  value: string,
  raw: RawValues,
): true | string {
  const trimmed = value.trim().replace(/\r\n/g, "\n")
  if (trimmed === "") return isProductionLike(modeOf(raw)) ? `${variable} is missing.` : true
  const block = new RegExp(
    `^-----BEGIN ${label}-----\\n[A-Za-z0-9+/=\\n]+\\n-----END ${label}-----$`,
  )
  return block.test(trimmed) ? true : `${variable} must be one PEM block labelled ${label}.`
}
