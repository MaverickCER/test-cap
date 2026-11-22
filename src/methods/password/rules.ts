/**
 * The password verifier rules (ADR 0010 §1 and §5). A password is normalised once, to NFC, as soon as it is received;
 * the length rules count that string in code points and argon2id hashes that same string. Nothing else changes it:
 * no truncation, trimming or case folding, and no composition rules.
 */

import { BUNDLED_BLOCKLIST } from "./blocklist.js"

/** The minimum length while the policy requires multi-factor authentication for every route that accepts it. */
export const PASSWORD_MIN_WITH_MFA = 8
/** The minimum length when a deviation lets a password alone satisfy a requirement. */
export const PASSWORD_MIN_ALONE = 15
/** The maximum length, which also bounds the argon2id input (ADR 0018 §3). */
export const PASSWORD_MAX_LENGTH = 256
/** Context words shorter than this are ignored: a short name would block too many passwords. */
const MIN_CONTEXT_WORD = 4

declare const normalised: unique symbol
/** A password in Unicode NFC. Only `normalisePassword` makes one, so nothing hashes an unnormalised password. */
export type NormalisedPassword = string & { readonly [normalised]: true }

/** The one normalisation step: Unicode NFC. */
export function normalisePassword(raw: string): NormalisedPassword {
  return raw.normalize("NFC") as NormalisedPassword
}

/** The number of code points, the unit NIST counts characters in. */
export function codePointLength(text: string): number {
  return [...text].length
}

/** Why a password's length is not acceptable, or `undefined` when it is. */
export function checkPasswordLength(
  password: NormalisedPassword,
  options: { readonly alone: boolean },
): "too-short" | "too-long" | undefined {
  const length = codePointLength(password)
  if (length > PASSWORD_MAX_LENGTH) return "too-long"
  const minimum = options.alone ? PASSWORD_MIN_ALONE : PASSWORD_MIN_WITH_MFA
  return length < minimum ? "too-short" : undefined
}

/**
 * True when the password is on the bundled list (compared whole, ignoring case) or contains one of the context words,
 * such as the app's system id or the account identifier (ignoring case).
 */
export function isBlocklisted(
  password: NormalisedPassword,
  contextWords: readonly string[],
): boolean {
  const folded = password.toLowerCase()
  if (BUNDLED_BLOCKLIST.has(folded)) return true
  return contextWords.some((word) => {
    const candidate = word.normalize("NFC").toLowerCase()
    return codePointLength(candidate) >= MIN_CONTEXT_WORD && folded.includes(candidate)
  })
}
